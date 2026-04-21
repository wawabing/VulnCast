"""
AWS Lambda handler for the CPE Forecast Service.

Triggered every 30 minutes by EventBridge.  Each invocation:
  1. Reads all unique CPEs from the forecast-cpes DynamoDB table
  2. Filters out CPEs that were forecast recently (within TTL)
  3. Downloads the NVD data fresh from the URL
  4. Runs dual-optimised ARIMA forecasts (Diff% + MAPE) per CPE
  5. Writes results to cpe-forecast-results DynamoDB table

Respects Lambda's 15-minute timeout by tracking elapsed time and
stopping gracefully before the limit.
"""

import gc
import json
import logging
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Set

# Configure logging before imports
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("forecast-service")

from config import LAMBDA_BUDGET_SEC, DEFAULT_MODEL, PER_CPE_TIMEOUT_SEC
from nvd_downloader import download_nvd, parse_nvd
from dynamo_client import (
    get_all_cpes,
    get_recently_forecast_cpes,
    save_forecast_result,
    update_cpe_forecastability,
)
from forecast_engine import forecast_cpe, parse_cpe
from forecastability import score_cpe


def _clean_tmp():
    """Remove leftover files in /tmp from previous invocations."""
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


def _extract_vendors(cpes: List[str]) -> Set[str]:
    """Extract the unique vendor names from a list of CPE strings."""
    vendors = set()
    for cpe in cpes:
        parsed = parse_cpe(cpe)
        if parsed["vendor"]:
            vendors.add(parsed["vendor"])
    return vendors


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda entry point.

    EventBridge sends an event every 30 minutes.  The event payload is ignored;
    all config comes from environment variables.
    """
    t_start = time.time()
    logger.info("=== CPE Forecast Service started ===")
    logger.info("Event: %s", json.dumps(event, default=str)[:500])

    # Clean up /tmp from any previous invocation (container reuse)
    _clean_tmp()

    # ── 1. Load CPE list from DynamoDB ──────────────────────
    all_cpes = get_all_cpes()
    if not all_cpes:
        logger.warning("No CPEs found in DynamoDB — nothing to forecast")
        return _response(200, "No CPEs to forecast", 0, 0, 0)

    # ── 2. Filter out recently-forecast CPEs ────────────────
    recent = get_recently_forecast_cpes()
    pending_cpes = [c for c in all_cpes if c not in recent]
    logger.info(
        "CPEs: %d total, %d recently forecast, %d pending",
        len(all_cpes), len(recent), len(pending_cpes),
    )

    if not pending_cpes:
        logger.info("All CPEs have recent forecasts — nothing to do")
        return _response(200, "All CPEs up to date", len(all_cpes), 0, 0)

    # ── 3. Download & parse NVD data (vendor-filtered) ──────
    target_vendors = _extract_vendors(pending_cpes)
    logger.info("Target vendors: %s", target_vendors)
    try:
        nvd_path = download_nvd()
        df = parse_nvd(nvd_path, target_vendors=target_vendors)
        # Delete the local file to free ephemeral storage
        try:
            os.remove(nvd_path)
        except OSError:
            pass
        gc.collect()
    except Exception as e:
        logger.exception("Failed to download/parse NVD data")
        return _response(500, f"NVD download failed: {e}", len(all_cpes), 0, 0)

    if len(df) == 0:
        logger.error("NVD data is empty after parsing")
        return _response(500, "NVD data empty", len(all_cpes), 0, 0)

    # ── 4. Score forecastability & write tiers back ─────────
    forecastable_cpes = []
    skipped_unforecastable = 0

    for cpe in pending_cpes:
        parsed = parse_cpe(cpe)
        scoring = score_cpe(df, parsed["vendor"], parsed["product"], parsed["version"])

        # Write tier back to forecast-cpes table
        update_cpe_forecastability(cpe, scoring)

        if scoring["forecastable"]:
            forecastable_cpes.append(cpe)
        else:
            skipped_unforecastable += 1
            # Save a result so we don't re-check every 30 min
            save_forecast_result(cpe, {
                "status": "not_forecastable",
                "error": scoring.get("reason", "Not forecastable"),
                "vendor": parsed["vendor"],
                "product": parsed["product"],
                "forecastability_tier": scoring["tier"],
                "forecastability_score": scoring["score"],
            })
            logger.info("  [SKIP] %s -> %s (score: %.1f, level: %s, reason: %s)",
                        cpe, scoring["tier"], scoring["score"],
                        scoring.get("forecast_level", "?"), scoring.get("reason", ""))

    logger.info(
        "Forecastability: %d forecastable, %d not forecastable (of %d pending)",
        len(forecastable_cpes), skipped_unforecastable, len(pending_cpes),
    )

    # ── 5. Run forecasts on forecastable CPEs ───────────────
    success_count = 0
    fail_count = 0
    skipped_timeout = 0

    for i, cpe in enumerate(forecastable_cpes):
        # Check time budget
        elapsed = time.time() - t_start
        remaining = LAMBDA_BUDGET_SEC - elapsed
        if remaining < PER_CPE_TIMEOUT_SEC:
            skipped_timeout = len(forecastable_cpes) - i
            logger.warning(
                "Time budget exhausted (%.0fs elapsed, %ds remaining). "
                "Skipping %d remaining CPEs — they'll be picked up next run.",
                elapsed, int(remaining), skipped_timeout,
            )
            break

        logger.info(
            "[%d/%d] Forecasting: %s (%.0fs elapsed)",
            i + 1, len(forecastable_cpes), cpe, elapsed,
        )

        try:
            result = forecast_cpe(df, cpe, model_name=DEFAULT_MODEL)
            save_forecast_result(cpe, result)

            if result.get("status") == "success":
                success_count += 1
                logger.info(
                    "  -> OK | %s | forecast %s to %s: %d CVEs | "
                    "Backtest Diff: %+.1f%% | MAPE: %.1f%%",
                    result.get("granularity", "?"),
                    result.get("forecast_start", "?"),
                    result.get("forecast_end", "?"),
                    result.get("forecast_total", 0),
                    result.get("backtest_diff_pct", 0),
                    result.get("backtest_mape", 0),
                )
            else:
                fail_count += 1
                logger.warning("  -> FAIL: %s", result.get("error", "unknown"))

        except Exception as e:
            fail_count += 1
            logger.exception("  -> EXCEPTION for %s: %s", cpe, e)
            # Save failure record so we don't retry immediately
            save_forecast_result(cpe, {"status": "failed", "error": str(e)[:300]})

    # ── 6. Summary ──────────────────────────────────────────
    total_elapsed = time.time() - t_start
    logger.info(
        "=== Complete: %d success, %d failed, %d not_forecastable, "
        "%d skipped (timeout), %.0fs total ===",
        success_count, fail_count, skipped_unforecastable,
        skipped_timeout, total_elapsed,
    )

    return _response(
        200,
        f"Forecast complete: {success_count} success, {fail_count} failed, "
        f"{skipped_timeout} deferred",
        len(all_cpes),
        success_count,
        fail_count,
    )


def _response(status: int, message: str, total_cpes: int,
              success: int, failed: int) -> Dict[str, Any]:
    return {
        "statusCode": status,
        "body": json.dumps({
            "message": message,
            "total_cpes": total_cpes,
            "forecasts_success": success,
            "forecasts_failed": failed,
        }),
    }


# ────────────────────────────────────────────────────────────
# Local execution (for testing outside Lambda)
# ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    """
    Run locally for development/testing:
        python handler.py
        python handler.py --cpe "cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:*:*"
    """
    import argparse

    parser = argparse.ArgumentParser(description="CPE Forecast Service (local mode)")
    parser.add_argument("--cpe", type=str, default=None,
                        help="Test with a single CPE instead of reading from DynamoDB")
    parser.add_argument("--local-nvd", type=str, default=None,
                        help="Use a local NVD file instead of downloading")
    parser.add_argument("--skip-dynamo", action="store_true",
                        help="Skip DynamoDB writes (print results to stdout)")
    args = parser.parse_args()

    if args.local_nvd:
        df = parse_nvd(args.local_nvd)
    else:
        nvd_path = download_nvd()
        df = parse_nvd(nvd_path)

    if args.cpe:
        # Single CPE test
        result = forecast_cpe(df, args.cpe, model_name=DEFAULT_MODEL)
        print(json.dumps(result, indent=2, default=str))
        if not args.skip_dynamo:
            save_forecast_result(args.cpe, result)
            print(f"\nSaved to DynamoDB: {result.get('status')}")
    else:
        # Full pipeline
        result = lambda_handler({"source": "local"}, None)
        print(json.dumps(result, indent=2))
