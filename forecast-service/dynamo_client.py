"""
DynamoDB client for reading CPEs and writing forecast results.
"""

import time
import logging
from datetime import datetime
from decimal import Decimal
from typing import Any, Dict, List, Optional

import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.config import Config as BotoConfig

from config import (
    DYNAMO_TABLE_CPES,
    DYNAMO_TABLE_RESULTS,
    DYNAMO_REGION,
    FORECAST_TTL_SEC,
)

logger = logging.getLogger(__name__)

# Retry config for DynamoDB
_boto_config = BotoConfig(
    retries={"max_attempts": 3, "mode": "adaptive"},
    region_name=DYNAMO_REGION,
)

_dynamo_resource = None


def _get_dynamo():
    """Lazy-init DynamoDB resource (reused across warm Lambda invocations)."""
    global _dynamo_resource
    if _dynamo_resource is None:
        _dynamo_resource = boto3.resource("dynamodb", config=_boto_config)
    return _dynamo_resource


# ────────────────────────────────────────────────────────────
# READ: Get all unique CPEs from forecast-cpes table
# ────────────────────────────────────────────────────────────

def get_all_cpes() -> List[str]:
    """
    Scan the forecast-cpes DynamoDB table and return a list of all CPE strings.
    The table PK is 'cpe' (the CPE name string).
    """
    table = _get_dynamo().Table(DYNAMO_TABLE_CPES)
    cpes: List[str] = []
    params: Dict[str, Any] = {"ProjectionExpression": "cpe"}

    while True:
        resp = table.scan(**params)
        for item in resp.get("Items", []):
            cpe_val = item.get("cpe")
            if cpe_val:
                cpes.append(str(cpe_val))

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        params["ExclusiveStartKey"] = last_key

    logger.info("Loaded %d CPEs from %s", len(cpes), DYNAMO_TABLE_CPES)
    return cpes


# ────────────────────────────────────────────────────────────
# WRITE: Update CPE forecastability tier in forecast-cpes table
# ────────────────────────────────────────────────────────────

def update_cpe_forecastability(cpe: str, scoring: Dict[str, Any]) -> None:
    """
    Write forecastability assessment back to the forecast-cpes table.

    Adds/updates these attributes on the existing CPE item:
        forecastable       (BOOL)   — True/False
        forecastability_tier  (S)   — HIGH / MEDIUM / LOW / NOT_FORECASTABLE
        forecastability_score (N)   — 0-100
        recommended_granularity (S) — weekly / monthly / quarterly / null
        total_cves         (N)      — number of CVEs found in NVD
        forecastability_reason (S)  — reason if not forecastable
        forecastability_updated (S) — ISO timestamp
    """
    table = _get_dynamo().Table(DYNAMO_TABLE_CPES)
    now = datetime.utcnow().isoformat() + "Z"

    update_expr = (
        "SET forecastable = :fc, "
        "forecastability_tier = :tier, "
        "forecastability_score = :score, "
        "recommended_granularity = :gran, "
        "total_cves = :cves, "
        "forecastability_reason = :reason, "
        "forecastability_updated = :updated"
    )
    expr_values = {
        ":fc": scoring.get("forecastable", False),
        ":tier": scoring.get("tier", "NOT_FORECASTABLE"),
        ":score": _to_dynamo(scoring.get("score", 0)),
        ":gran": scoring.get("recommended_granularity") or "none",
        ":cves": _to_dynamo(scoring.get("total_cves", 0)),
        ":reason": scoring.get("reason", "")[:500],
        ":updated": now,
    }

    try:
        table.update_item(
            Key={"cpe": cpe},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_values,
        )
        logger.debug("Updated forecastability for %s -> %s (%.1f)",
                      cpe, scoring.get("tier"), scoring.get("score", 0))
    except Exception as e:
        logger.warning("Failed to update forecastability for %s: %s", cpe, e)


# ────────────────────────────────────────────────────────────
# READ: Check which CPEs already have recent forecasts
# ────────────────────────────────────────────────────────────

def get_recently_forecast_cpes() -> Dict[str, float]:
    """
    Returns {cpe: last_forecast_epoch} for CPEs that were forecast
    within the FORECAST_TTL_SEC window.
    """
    table = _get_dynamo().Table(DYNAMO_TABLE_RESULTS)
    cutoff = Decimal(str(time.time() - FORECAST_TTL_SEC))
    recently: Dict[str, float] = {}

    params: Dict[str, Any] = {
        "ProjectionExpression": "cpe, last_forecast_epoch",
        "FilterExpression": Attr("last_forecast_epoch").gte(cutoff),
    }

    while True:
        resp = table.scan(**params)
        for item in resp.get("Items", []):
            cpe_val = item.get("cpe")
            epoch = item.get("last_forecast_epoch")
            if cpe_val and epoch:
                recently[str(cpe_val)] = float(epoch)

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        params["ExclusiveStartKey"] = last_key

    logger.info("Found %d CPEs with recent forecasts (TTL=%ds)", len(recently), FORECAST_TTL_SEC)
    return recently


# ────────────────────────────────────────────────────────────
# WRITE: Save forecast result for a CPE
# ────────────────────────────────────────────────────────────

def _to_dynamo(obj: Any) -> Any:
    """Recursively convert Python types to DynamoDB-safe types."""
    if isinstance(obj, float):
        if obj != obj:  # NaN
            return None
        return Decimal(str(round(obj, 6)))
    if isinstance(obj, int):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: _to_dynamo(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, (list, tuple)):
        return [_to_dynamo(v) for v in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj


def save_forecast_result(cpe: str, result: Dict[str, Any]) -> None:
    """
    Write a single CPE forecast result to the cpe-forecast-results table.

    Item schema:
        PK: cpe (string) — the full CPE name
        last_forecast_epoch (number) — epoch timestamp of this forecast
        last_forecast_iso (string)  — ISO timestamp
        model (string)              — model used (arima / xgboost / hybrid)
        granularity (string)        — weekly / monthly / quarterly
        vendor (string)             — vendor extracted from CPE
        product (string)            — product extracted from CPE

        # Annual / total prediction (Diff%-optimised)
        annual_predicted_total (number) — forecasted CVE count for the year
        annual_actual_total (number)    — actual CVE count (if test year)
        annual_diff_pct (number)        — (pred-actual)/actual * 100

        # Short-term prediction (MAPE-optimised)
        shortterm_predicted_total (number)
        shortterm_mape (number)
        shortterm_diff_pct (number)

        # Period-level forecasts (list of {date, predicted, actual})
        annual_periods (list)    — Diff%-optimised per-period forecasts
        shortterm_periods (list) — MAPE-optimised per-period forecasts

        # Metrics
        mae (number)
        rmse (number)
        train_periods (number)
        test_periods (number)
        status (string) — "success" or "failed"
        error (string)  — error message if failed
    """
    table = _get_dynamo().Table(DYNAMO_TABLE_RESULTS)
    now = datetime.utcnow()

    item: Dict[str, Any] = {
        "cpe": cpe,
        "last_forecast_epoch": Decimal(str(int(time.time()))),
        "last_forecast_iso": now.isoformat() + "Z",
        "status": result.get("status", "failed"),
    }

    if result.get("status") == "success":
        item.update({
            "model": result.get("model", "unknown"),
            "granularity": result.get("granularity", "unknown"),
            "vendor": result.get("vendor", ""),
            "product": result.get("product", ""),
            "version": result.get("version", "*"),
            "forecast_level": result.get("forecast_level", "product"),

            # ── FORECAST ── the main output ──
            "forecast_start": result.get("forecast_start"),
            "forecast_end": result.get("forecast_end"),
            "forecast_total": result.get("forecast_total"),
            "forecast_total_mape_optimised": result.get("forecast_total_mape_optimised"),
            "forecast_periods": result.get("forecast_periods", []),
            "forecast_periods_mape_optimised": result.get("forecast_periods_mape_optimised", []),

            # ── BACKTEST ── accuracy proof ──
            "backtest_start": result.get("backtest_start"),
            "backtest_end": result.get("backtest_end"),
            "backtest_actual_total": result.get("backtest_actual_total"),
            "backtest_predicted_total": result.get("backtest_predicted_total"),
            "backtest_diff_pct": result.get("backtest_diff_pct"),
            "backtest_mape": result.get("backtest_mape"),
            "backtest_annual_periods": result.get("backtest_annual_periods", []),
            "backtest_shortterm_periods": result.get("backtest_shortterm_periods", []),

            # ── HISTORICAL ── yearly trend ──
            "historical_yearly": result.get("historical_yearly", []),

            # ── ACCURACY METRICS ──
            "mae": result.get("mae"),
            "rmse": result.get("rmse"),
            "train_periods": result.get("train_periods"),
            "test_periods": result.get("test_periods"),
        })
    elif result.get("status") == "not_forecastable":
        item.update({
            "vendor": result.get("vendor", ""),
            "product": result.get("product", ""),
            "forecastability_tier": result.get("forecastability_tier", "NOT_FORECASTABLE"),
            "forecastability_score": result.get("forecastability_score", 0),
            "error": result.get("error", "Not forecastable")[:500],
        })
    else:
        item["error"] = result.get("error", "unknown")[:500]

    # Convert all values to DynamoDB-safe types and strip Nones
    safe_item = {k: _to_dynamo(v) for k, v in item.items() if v is not None}
    table.put_item(Item=safe_item)
    logger.debug("Saved forecast for %s", cpe)


# ────────────────────────────────────────────────────────────
# WRITE: Batch save (for efficiency)
# ────────────────────────────────────────────────────────────

def batch_save_forecast_results(results: List[Dict[str, Any]]) -> int:
    """
    Batch-write multiple forecast results. Returns count of items written.
    DynamoDB batch_write_item handles up to 25 items per call.
    """
    table = _get_dynamo().Table(DYNAMO_TABLE_RESULTS)
    written = 0

    with table.batch_writer() as batch:
        for result in results:
            cpe = result.get("cpe")
            if not cpe:
                continue
            now = datetime.utcnow()

            item: Dict[str, Any] = {
                "cpe": cpe,
                "last_forecast_epoch": Decimal(str(int(time.time()))),
                "last_forecast_iso": now.isoformat() + "Z",
                "status": result.get("status", "failed"),
            }

            if result.get("status") == "success":
                item.update({
                    "model": result.get("model", "unknown"),
                    "granularity": result.get("granularity", "unknown"),
                    "vendor": result.get("vendor", ""),
                    "product": result.get("product", ""),
                    "version": result.get("version", "*"),
                    "forecast_level": result.get("forecast_level", "product"),
                    "forecast_start": result.get("forecast_start"),
                    "forecast_end": result.get("forecast_end"),
                    "forecast_total": result.get("forecast_total"),
                    "forecast_total_mape_optimised": result.get("forecast_total_mape_optimised"),
                    "forecast_periods": result.get("forecast_periods", []),
                    "forecast_periods_mape_optimised": result.get("forecast_periods_mape_optimised", []),
                    "backtest_start": result.get("backtest_start"),
                    "backtest_end": result.get("backtest_end"),
                    "backtest_actual_total": result.get("backtest_actual_total"),
                    "backtest_predicted_total": result.get("backtest_predicted_total"),
                    "backtest_diff_pct": result.get("backtest_diff_pct"),
                    "backtest_mape": result.get("backtest_mape"),
                    "backtest_annual_periods": result.get("backtest_annual_periods", []),
                    "backtest_shortterm_periods": result.get("backtest_shortterm_periods", []),
                    "historical_yearly": result.get("historical_yearly", []),
                    "mae": result.get("mae"),
                    "rmse": result.get("rmse"),
                    "train_periods": result.get("train_periods"),
                    "test_periods": result.get("test_periods"),
                })
            else:
                item["error"] = result.get("error", "unknown")[:500]

            safe_item = {k: _to_dynamo(v) for k, v in item.items() if v is not None}
            batch.put_item(Item=safe_item)
            written += 1

    logger.info("Batch-wrote %d forecast results", written)
    return written
