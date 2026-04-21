"""
Configuration for the CPE Forecast Service.
Environment variables override defaults.
"""

import calendar
import os
from datetime import date, timedelta

# ── DynamoDB Tables ──────────────────────────────────────────
DYNAMO_TABLE_CPES = os.environ.get("DYNAMO_TABLE_CPES", "forecast-cpes")
DYNAMO_TABLE_RESULTS = os.environ.get("DYNAMO_TABLE_RESULTS", "cpe-forecast-results")
DYNAMO_REGION = os.environ.get("AWS_REGION", "eu-west-2")

# ── NVD Data Source ──────────────────────────────────────────
NVD_URL = os.environ.get("NVD_URL", "https://nvd.handsonhacking.org/nvd.jsonl")
NVD_LOCAL_PATH = "/tmp/nvd.jsonl"          # Lambda /tmp directory

# ── S3 Cache for NVD data (download once per day, reuse from S3) ──
NVD_S3_BUCKET = os.environ.get("NVD_S3_BUCKET", "cpe-forecast-nvd-cache")
NVD_S3_KEY = os.environ.get("NVD_S3_KEY", "nvd-cache/nvd.jsonl")
NVD_CACHE_TTL_SEC = int(os.environ.get("NVD_CACHE_TTL_SEC", "86400"))  # 24 hours

# ── Forecast Settings ───────────────────────────────────────
START_YEAR = int(os.environ.get("START_YEAR", "2017"))

# Default model: arima is most reliable for this use case
DEFAULT_MODEL = os.environ.get("DEFAULT_MODEL", "arima")

# Max seconds to spend per CPE forecast (safety valve)
PER_CPE_TIMEOUT_SEC = int(os.environ.get("PER_CPE_TIMEOUT_SEC", "120"))

# Lambda has 15-min max. Reserve 60s for startup/teardown.
LAMBDA_BUDGET_SEC = int(os.environ.get("LAMBDA_BUDGET_SEC", "840"))

# How often forecasts are refreshed (seconds). CPEs forecast more recently
# than this are skipped so we don't redo work every 30 minutes.
FORECAST_TTL_SEC = int(os.environ.get("FORECAST_TTL_SEC", "86400"))  # 24 hours

# ARIMA grid — reduced for speed inside Lambda
ARIMA_P = [0, 1, 2]
ARIMA_D = [0, 1]
ARIMA_Q = [0, 1, 2]

# XGBoost grid — reduced for speed inside Lambda
XGB_N_ESTIMATORS = [50, 100]
XGB_MAX_DEPTH = [3, 5]
XGB_LEARNING_RATE = [0.05, 0.1]

# Granularity candidates
CANDIDATE_GRANULARITIES = ["weekly", "monthly", "quarterly"]


# ── Rolling Window Calculation ──────────────────────────────
# Instead of fixed years, the window is calculated dynamically so the
# service always forecasts the next 12 months from the most recent
# completed month — and uses all available data up to that point.

def _add_months(year: int, month: int, n: int):
    """Add n months to a year/month pair. Returns (year, month)."""
    month += n
    year += (month - 1) // 12
    month = (month - 1) % 12 + 1
    return year, month


def _last_day(year: int, month: int) -> date:
    """Return the last day of the given month."""
    return date(year, month, calendar.monthrange(year, month)[1])


def get_rolling_window(reference_date: date = None) -> dict:
    """
    Calculate the rolling forecast window based on the current date.

    Example — if today is March 5, 2026:
      start_date:      2017-01-01  (historical start)
      data_end:        2026-02-28  (end of last completed month)
      train_end:       2025-02-28  (training cutoff for backtest)
      backtest_start:  2025-03-01  (start of 12-month backtest window)
      backtest_end:    2026-02-28  (= data_end)
      forecast_start:  2026-03-01  (start of 12-month forecast)
      forecast_end:    2027-02-28  (end of forecast window)
    """
    if reference_date is None:
        reference_date = date.today()

    cur_year, cur_month = reference_date.year, reference_date.month

    # End of last completed month = data cutoff
    prev_year, prev_month = _add_months(cur_year, cur_month, -1)
    data_end = _last_day(prev_year, prev_month)

    # Backtest: 12-month window ending at data_end
    bt_year, bt_month = _add_months(cur_year, cur_month, -12)
    backtest_start = date(bt_year, bt_month, 1)
    backtest_end = data_end

    # Training for backtest: everything before backtest_start
    train_end = backtest_start - timedelta(days=1)

    # Forecast: next 12 months starting from current month
    forecast_start = date(cur_year, cur_month, 1)
    fc_end_year, fc_end_month = _add_months(cur_year, cur_month, 11)
    forecast_end = _last_day(fc_end_year, fc_end_month)

    return {
        "start_date": date(START_YEAR, 1, 1),
        "train_end": train_end,
        "backtest_start": backtest_start,
        "backtest_end": backtest_end,
        "data_end": data_end,
        "forecast_start": forecast_start,
        "forecast_end": forecast_end,
    }
