"""
Lambda handler for Yearly CVE Total Forecast.

Triggered by EventBridge (daily or on-demand).
Downloads NVD data, runs XGBoost adaptive bias forecast, saves to DynamoDB.
"""

import os
import warnings

# Suppress noisy warnings in Lambda (joblib multiprocessing, xgboost glibc)
os.environ.setdefault("LOKY_MAX_CPU_COUNT", "1")
warnings.filterwarnings("ignore", message=".*joblib will operate in serial mode.*")
warnings.filterwarnings("ignore", message=".*old version of glibc.*")
warnings.filterwarnings("ignore", category=FutureWarning, module="xgboost")

import gc
import json
import logging
import shutil
import time
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict

import boto3
from boto3.dynamodb.conditions import Key
from botocore.config import Config as BotoConfig

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("yearly-forecast")

from config import DYNAMO_TABLE, DYNAMO_REGION, TARGET_YEAR
from nvd_downloader import download_nvd
from forecast_engine import forecast_yearly


# ── DynamoDB helpers ──

_dynamo = None


def _get_dynamo():
    global _dynamo
    if _dynamo is None:
        _dynamo = boto3.resource(
            "dynamodb",
            config=BotoConfig(retries={"max_attempts": 3, "mode": "adaptive"},
                              region_name=DYNAMO_REGION),
        )
    return _dynamo


def _to_dynamo(obj: Any) -> Any:
    """Recursively convert Python types to DynamoDB-safe types."""
    import math

    # Handle None first
    if obj is None:
        return None

    # numpy scalar types -> native Python first
    if hasattr(obj, 'item'):
        obj = obj.item()

    # bool MUST be checked before int (bool is subclass of int)
    if isinstance(obj, bool):
        return obj

    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            return None
        return Decimal(str(round(obj, 6)))

    if isinstance(obj, int):
        return Decimal(str(obj))

    if isinstance(obj, dict):
        return {k: _to_dynamo(v) for k, v in obj.items() if _to_dynamo(v) is not None}

    if isinstance(obj, (list, tuple)):
        return [_to_dynamo(v) for v in obj]

    if isinstance(obj, datetime):
        return obj.isoformat()

    if isinstance(obj, str):
        return obj

    # Last resort: stringify
    return str(obj)


def _clean_tmp():
    tmp = Path("/tmp")
    for item in tmp.iterdir():
        try:
            if item.is_file():
                item.unlink()
            elif item.is_dir():
                shutil.rmtree(item)
        except Exception:
            pass
    logger.info("Cleaned /tmp")


def save_forecast(result: Dict[str, Any], target_year: int) -> None:
    """Save forecast result to DynamoDB with PK = target year."""
    table = _get_dynamo().Table(DYNAMO_TABLE)
    now = datetime.utcnow()

    item = {
        "year": str(target_year),  # PK
        "last_forecast_epoch": Decimal(str(int(time.time()))),
        "last_forecast_iso": now.isoformat() + "Z",
        "status": result.get("status", "failed"),
    }

    if result["status"] == "success":
        item.update({
            "model": result["model"],
            "target_year": result["target_year"],
            "forecast_total": result["forecast_total"],
            "actual_months_count": result["actual_months_count"],
            "actual_months_total": result["actual_months_total"],
            "forecasted_months_count": result["forecasted_months_count"],
            "forecasted_months_total": result["forecasted_months_total"],
            "year_complete": result["year_complete"],
            "last_data_month": result["last_data_month"],
            "forecast_monthly": result["forecast_monthly"],
            "has_actual_target": result["has_actual_target"],
            "target_actual_total": result.get("target_actual_total"),
            "target_diff_pct": result.get("target_diff_pct"),
            "bias_correction_pct": result["bias_correction_pct"],
            "ensemble": result["ensemble"],
            "backtest": result["backtest"],
            "historical_yearly": result["historical_yearly"],
            "historical_monthly": result["historical_monthly"],
            "projected_growth_pct": result.get("projected_growth_pct"),
            "accuracy": result.get("accuracy"),
        })
    else:
        item["error"] = result.get("error", "unknown")[:500]

    safe = {k: _to_dynamo(v) for k, v in item.items() if v is not None}
    table.put_item(Item=safe)
    logger.info("Saved yearly forecast for %d to %s", target_year, DYNAMO_TABLE)


# ── Lambda entry point ──

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    t_start = time.time()
    logger.info("=== Yearly CVE Forecast started ===")
    logger.info("Event: %s", json.dumps(event, default=str)[:500])

    _clean_tmp()

    # Allow target_year override from event
    target_year = event.get("target_year", TARGET_YEAR)
    logger.info("Target year: %d", target_year)

    # Download NVD data
    try:
        nvd_path = download_nvd()
    except Exception as e:
        logger.exception("Failed to download NVD data")
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}

    # Run forecast
    try:
        result = forecast_yearly(nvd_path, target_year)
    except Exception as e:
        logger.exception("Forecast failed")
        result = {"status": "failed", "error": str(e)[:300]}

    # Free NVD file
    try:
        os.remove(nvd_path)
    except OSError:
        pass
    gc.collect()

    # Save to DynamoDB
    try:
        save_forecast(result, target_year)
    except Exception as e:
        logger.exception("Failed to save to DynamoDB")
        return {"statusCode": 500, "body": json.dumps({"error": f"DynamoDB save failed: {e}"})}

    elapsed = time.time() - t_start
    logger.info("=== Complete in %.0fs ===", elapsed)

    body = {
        "target_year": target_year,
        "status": result.get("status"),
        "forecast_total": result.get("forecast_total"),
        "elapsed_sec": round(elapsed, 1),
    }
    if result.get("backtest", {}).get("diff_pct") is not None:
        body["backtest_error_pct"] = result["backtest"]["diff_pct"]

    return {"statusCode": 200, "body": json.dumps(body, default=str)}


# ── Local testing ──

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--year", type=int, default=TARGET_YEAR)
    parser.add_argument("--local-nvd", type=str, default=None)
    args = parser.parse_args()

    if args.local_nvd:
        nvd_path = args.local_nvd
    else:
        nvd_path = download_nvd()

    result = forecast_yearly(nvd_path, args.year)
    print(json.dumps(result, indent=2, default=str))
