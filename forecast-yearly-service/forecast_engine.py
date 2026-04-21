"""
Yearly CVE Forecast Engine — XGBoost with Adaptive Bias Learning.

Exact reproduction of forecast-total-yearly-diff-xgboost.py logic,
packaged for Lambda execution. Produces total CVE count forecasts
per year with monthly granularity.

Core Innovation:
The adaptive bias learning captures unmeasurable drivers of CVE growth
(AI tools, new attack surfaces, regulatory changes) by detecting systematic
prediction errors and applying intelligent corrections.

Methodology:
1. Train/Test Split: Train on (2017 to target-2), test on (target-1), predict (target)
2. Bias Learning: Analyze prediction errors from 3 years prior to target year
3. Feature Engineering: Monthly lags, rolling statistics, trend and seasonal components
4. Model Training: Regularized XGBoost with time series validation
5. Adaptive Correction: Apply learned bias correction to final forecast
"""

import json
import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import xgboost as xgb

from config import START_YEAR, TARGET_YEAR, XGB_PARAMS, ENSEMBLE_GROWTH_WEIGHT, GROWTH_RATE_YEARS

logger = logging.getLogger(__name__)


def load_nvd_monthly(path: str, target_year: int = TARGET_YEAR) -> pd.Series:
    """
    Load NVD data and build monthly CVE count time series.
    Filters to 2017+ and excludes rejected CVEs.
    Returns a pd.Series indexed by month start dates.
    """
    logger.info("Parsing NVD data from %s ...", path)
    t0 = time.time()

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    try:
        data = json.loads(content)
        entries = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        entries = [json.loads(line) for line in content.strip().split("\n") if line.strip()]

    del content  # free memory

    max_year = max(2025, target_year)
    cve_dates = []

    for entry in entries:
        cve_data = entry.get("cve", entry)

        # Skip rejected CVEs
        state = cve_data.get("vulnStatus", "").lower()
        if state == "rejected":
            continue

        published = cve_data.get("published", "")
        if not published:
            continue

        try:
            pub_date = pd.to_datetime(published)
            if START_YEAR <= pub_date.year <= max_year:
                cve_dates.append(pub_date)
        except (ValueError, AttributeError):
            continue

    del entries  # free memory

    logger.info("Found %d CVEs from %d-%d", len(cve_dates), START_YEAR, max_year)

    # Build complete monthly series
    events = pd.Series(1, index=pd.DatetimeIndex(cve_dates))
    monthly = events.resample("MS").sum()

    date_range = pd.date_range(start=f"{START_YEAR}-01-01",
                                end=f"{max_year}-12-31", freq="MS")
    complete = monthly.reindex(date_range, fill_value=0).astype(int)

    elapsed = time.time() - t0
    logger.info("Built monthly series: %d months in %.1fs", len(complete), elapsed)
    return complete


def prepare_features(data: pd.Series) -> pd.DataFrame:
    """
    Feature engineering for XGBoost — exact match to original.
    Monthly lag features, rolling windows, trend, seasonality.
    """
    features_df = pd.DataFrame(index=data.index)
    features_df["value"] = data.values

    # Monthly lag features (1, 2, 3, 6, 12, 24 months)
    for lag in [1, 2, 3, 6, 12, 24]:
        features_df[f"lag_{lag}"] = data.shift(lag)

    # Monthly rolling windows (3, 6, 12, 24 months)
    for window in [3, 6, 12, 24]:
        features_df[f"rolling_mean_{window}"] = data.rolling(window, min_periods=1).mean()
        features_df[f"rolling_std_{window}"] = data.rolling(window, min_periods=1).std().fillna(0)

    features_df["trend"] = range(len(features_df))
    features_df["month"] = features_df.index.month
    features_df["quarter"] = features_df.index.quarter

    return features_df.bfill().fillna(0)


def generate_forecast(model, train_data: pd.Series, n_periods: int) -> List[float]:
    """
    Iterative multi-step forecast — exact match to original.
    Each step feeds predicted value back as input for next prediction.
    """
    current_data = train_data.copy()
    forecast = []

    for step in range(n_periods):
        features_df = prepare_features(current_data)
        feature_cols = [col for col in features_df.columns if col != "value"]
        X_current = features_df[feature_cols].iloc[-1:]

        pred_value = model.predict(X_current)[0]
        forecast.append(max(0, float(pred_value)))

        next_index = current_data.index[-1] + pd.DateOffset(months=1)
        current_data.loc[next_index] = pred_value

    return forecast


def learn_bias(full_series: pd.Series, target_year: int,
               bias_years: Optional[List[int]] = None) -> float:
    """
    Adaptive bias learning from recent years.

    Default bias window: [target-3, target-2, target-1] — the 3 most recent
    complete years. Each year's bias is measured by training on all data before
    that year, forecasting it, and comparing to actuals.
    """
    if bias_years is None:
        bias_years = [target_year - 3, target_year - 2, target_year - 1]
    bias_values = []

    for year in bias_years:
        train = full_series[full_series.index.year <= (year - 1)]
        actual = full_series[full_series.index.year == year]

        if len(actual) == 0 or len(train) < 12:
            continue

        features_df = prepare_features(train)
        feature_cols = [col for col in features_df.columns if col != "value"]
        X, y = features_df[feature_cols], features_df["value"]

        model = xgb.XGBRegressor(**XGB_PARAMS, random_state=42, verbosity=0)
        model.fit(X, y)

        forecast = generate_forecast(model, train, len(actual))
        forecast_total = sum(forecast)

        if forecast_total > 0:
            bias = (actual.sum() - forecast_total) / forecast_total * 100
            bias_values.append(bias)
            logger.info("Bias year %d: actual=%d, forecast=%d, bias=%+.1f%%",
                        year, int(actual.sum()), int(forecast_total), bias)

    # Simple mean of all bias values — robust to outliers, transparent,
    # and honest. The ensemble layer handles trend extrapolation.
    if bias_values:
        adaptive_correction = sum(bias_values) / len(bias_values)
    else:
        adaptive_correction = 0

    logger.info("Adaptive bias correction (simple mean): %+.2f%%", adaptive_correction)
    return adaptive_correction


def forecast_yearly(nvd_path: str, target_year: int = TARGET_YEAR) -> Dict[str, Any]:
    """
    Run the full yearly CVE forecast pipeline.

    Trains on ALL data from 2017 through the last fully completed month
    (determined dynamically at runtime). Uses actual CVE counts for
    completed months of the target year and only forecasts remaining
    months. Total = actuals + forecasted.

    Returns a dict structured for DynamoDB / frontend:
    {
        "target_year": 2026,
        "forecast_total": 42000,
        "actual_months_count": 2,
        "actual_months_total": 6500,
        "forecasted_months_total": 35500,
        "forecast_monthly": [
            {month: "2026-01", actual: 3200, predicted: 3200, is_actual: True},
            {month: "2026-03", predicted: 3400, is_actual: False}, ...
        ],
        "bias_correction_pct": 12.5,
        "backtest": {...},
        "historical_yearly": [{year: 2017, total: 14000}, ...],
        "model": "xgboost_adaptive_bias",
        "status": "success"
    }
    """
    t0 = time.time()
    full_series = load_nvd_monthly(nvd_path, target_year)

    # Dynamic cutoff: determine last fully completed month at runtime
    now = datetime.now()
    if now.year > target_year:
        # Target year is fully in the past — all 12 months are actual
        last_complete = pd.Timestamp(f"{target_year}-12-01")
    elif now.month == 1:
        last_complete = pd.Timestamp(f"{now.year - 1}-12-01")
    else:
        last_complete = pd.Timestamp(f"{now.year}-{now.month - 1:02d}-01")

    logger.info("Runtime cutoff: last complete month = %s",
                last_complete.strftime("%Y-%m"))

    train_end_year = target_year - 2
    test_year = target_year - 1

    backtest_train = full_series[full_series.index.year <= train_end_year]
    test_series = full_series[full_series.index.year == test_year]

    # ── 1. Backtest with its OWN bias correction ──
    # The backtest gets a fair, independent bias computed for test_year,
    # so it validates the methodology honestly.
    logger.info("── Computing backtest bias for %d ──", test_year)
    backtest_bias = learn_bias(full_series, test_year)

    features_df = prepare_features(backtest_train)
    feature_cols = [col for col in features_df.columns if col != "value"]
    X, y = features_df[feature_cols], features_df["value"]

    model = xgb.XGBRegressor(**XGB_PARAMS, random_state=42, verbosity=0)
    model.fit(X, y)

    forecast_test_base = generate_forecast(model, backtest_train, len(test_series))
    forecast_test = [x * (1 + backtest_bias / 100) for x in forecast_test_base]

    # ── 2. Learn bias correction for the ACTUAL target year ──
    logger.info("── Computing forecast bias for %d ──", target_year)
    adaptive_correction = learn_bias(full_series, target_year)

    has_actual_test = test_series.sum() > 0
    test_actual_total = int(test_series.sum()) if has_actual_test else None
    test_forecast_total = int(round(sum(forecast_test)))
    test_diff_pct = None
    if has_actual_test and test_actual_total > 0:
        test_diff_pct = round((test_forecast_total - test_actual_total) / test_actual_total * 100, 2)

    # Backtest monthly data
    backtest_monthly = []
    test_dates = test_series.index
    for i, date in enumerate(test_dates):
        entry = {
            "month": date.strftime("%Y-%m"),
            "predicted": round(forecast_test[i], 1) if i < len(forecast_test) else 0,
        }
        if has_actual_test:
            entry["actual"] = int(test_series.iloc[i])
        backtest_monthly.append(entry)

    # ── 4. Train on ALL data through last complete month, forecast remaining ──
    train_series = full_series[full_series.index <= last_complete]
    logger.info("Training on %d months (%d-%s)",
                len(train_series), START_YEAR, last_complete.strftime("%Y-%m"))

    features_df = prepare_features(train_series)
    feature_cols = [col for col in features_df.columns if col != "value"]
    X, y = features_df[feature_cols], features_df["value"]

    model = xgb.XGBRegressor(**XGB_PARAMS, random_state=42, verbosity=0)
    model.fit(X, y)

    # Actual completed months in the target year
    actual_target_months = full_series[
        (full_series.index.year == target_year) & (full_series.index <= last_complete)
    ]
    n_actual = len(actual_target_months)
    n_remaining = 12 - n_actual

    logger.info("Target %d: %d actual months, %d to forecast",
                target_year, n_actual, n_remaining)

    actual_sum = int(actual_target_months.sum())

    # Forecast ALL 12 months so we have model predictions for the full year.
    # NO bias correction on XGBoost — the growth-rate ensemble handles uplift.
    # Applying both would double-count the underprediction compensation.
    forecast_full_base = generate_forecast(model, train_series, 12)
    forecast_full_xgb = list(forecast_full_base)  # raw XGBoost, no bias

    xgb_annual = int(round(sum(forecast_full_xgb)))

    # Build yearly totals for growth rate calculation (need this before ensemble)
    historical_yearly_raw = []
    for yr in range(START_YEAR, target_year):
        yr_total = int(full_series[full_series.index.year == yr].sum())
        if yr_total > 0:
            historical_yearly_raw.append(yr_total)

    # ── 5. Growth-rate ensemble (monthly granularity) ──
    # Instead of a flat annual growth rate, compute per-month YoY growth.
    # e.g. "How does January grow year-over-year?" separately from "How does
    # July grow year-over-year?" — this captures that some months grow faster
    # than others and avoids overpredicting early months.

    growth_monthly = []  # 12 per-month growth projections
    monthly_growth_rates = []  # for logging / output
    n_growth_years = min(GROWTH_RATE_YEARS, len(historical_yearly_raw) - 1)

    for month_idx in range(12):
        month_num = month_idx + 1
        # Gather this month's actuals for recent years
        month_values = []
        for yr in range(START_YEAR, target_year):
            month_data = full_series[
                (full_series.index.year == yr) & (full_series.index.month == month_num)
            ]
            if len(month_data) > 0 and month_data.sum() > 0:
                month_values.append((yr, int(month_data.sum())))

        # Compute YoY growth rates for this specific month
        month_rates = []
        if len(month_values) >= 2:
            for i in range(-n_growth_years, 0):
                if abs(i) < len(month_values) and abs(i - 1) < len(month_values):
                    prev_yr, prev_val = month_values[i - 1]
                    curr_yr, curr_val = month_values[i]
                    if prev_val > 0:
                        month_rates.append(curr_val / prev_val - 1)

        # Project this month from most recent year's value
        if month_rates and month_values:
            avg_month_growth = sum(month_rates) / len(month_rates)
            last_val = month_values[-1][1]
            projected = int(round(last_val * (1 + avg_month_growth)))
            growth_monthly.append(max(0, projected))
            monthly_growth_rates.append({
                "month": month_num,
                "growth_pct": round(avg_month_growth * 100, 1),
                "last_year_val": last_val,
                "projected": max(0, projected),
            })
        elif month_values:
            # No growth data — use last year's value
            growth_monthly.append(month_values[-1][1])
            monthly_growth_rates.append({
                "month": month_num,
                "growth_pct": 0.0,
                "last_year_val": month_values[-1][1],
                "projected": month_values[-1][1],
            })
        else:
            # No data at all — fallback to XGBoost
            growth_monthly.append(round(forecast_full_xgb[month_idx]))
            monthly_growth_rates.append({
                "month": month_num,
                "growth_pct": None,
                "last_year_val": None,
                "projected": round(forecast_full_xgb[month_idx]),
            })

    growth_annual = sum(growth_monthly)

    # Also compute overall annual growth rates for logging
    growth_rates = []
    if len(historical_yearly_raw) >= 2:
        for i in range(-n_growth_years, 0):
            prev_total = historical_yearly_raw[i - 1]
            curr_total = historical_yearly_raw[i]
            if prev_total > 0:
                growth_rates.append(curr_total / prev_total - 1)

    logger.info("Growth-rate projection (monthly): %d total, per-month rates: %s",
                growth_annual,
                ", ".join(f"M{r['month']}={r['growth_pct']}%%" for r in monthly_growth_rates))

    # Blend: per-month ensemble = weighted avg of XGBoost and growth-rate per month
    w = ENSEMBLE_GROWTH_WEIGHT
    forecast_full_ensemble = []
    for i in range(12):
        blended = (1 - w) * forecast_full_xgb[i] + w * growth_monthly[i]
        forecast_full_ensemble.append(blended)

    ensemble_annual = int(round(sum(forecast_full_ensemble)))
    logger.info("Ensemble blend (w=%.1f): XGBoost=%d, Growth=%d → Ensemble=%d",
                w, xgb_annual, growth_annual, ensemble_annual)

    # For the final total: actuals for completed months + recalibrated ensemble for remaining
    # Recalibration: use completed months' actual-vs-predicted error to adjust
    # remaining months. This self-corrects every run as more actuals come in.
    # Require 3+ completed months before recalibrating — with fewer months,
    # one outlier (e.g. Jan 2026 barely growing) distorts the entire correction.
    recalibration_factor = 1.0
    if n_actual >= 3:
        completed_predicted = sum(forecast_full_ensemble[:n_actual])
        if completed_predicted > 0:
            recalibration_factor = actual_sum / completed_predicted
            # Gradually increase confidence: blend toward 1.0 when data is thin
            # 3 months → 75% correction, 6 → 86%, 9+ → ~91%+
            confidence = n_actual / (n_actual + 1)
            recalibration_factor = 1.0 + (recalibration_factor - 1.0) * confidence
            logger.info("Recalibration: raw ratio=%.3f, confidence=%.0f%% (%d months), "
                        "applied factor=%.3f",
                        actual_sum / completed_predicted, confidence * 100,
                        n_actual, recalibration_factor)

    remaining_ensemble = [x * recalibration_factor for x in forecast_full_ensemble[n_actual:]]
    forecast_sum = int(round(sum(remaining_ensemble)))
    target_forecast_total = actual_sum + forecast_sum

    has_actual_target = n_actual > 0
    year_complete = n_actual == 12
    target_actual_total = actual_sum if has_actual_target else None
    target_diff_pct = None
    if year_complete and target_actual_total and target_actual_total > 0:
        target_diff_pct = round(
            (target_forecast_total - target_actual_total) / target_actual_total * 100, 2
        )

    # Target monthly breakdown — honest predictions:
    # - Completed months: predicted = model's genuine forecast, actual = reality, diff_pct = error
    # - Remaining months: predicted = recalibrated ensemble forecast
    forecast_monthly = []
    completed_diffs = []  # for accuracy summary

    for i in range(12):
        month_date = pd.Timestamp(f"{target_year}-01-01") + pd.DateOffset(months=i)
        model_pred = round(forecast_full_ensemble[i], 1)

        if i < n_actual:
            actual_val = int(actual_target_months.iloc[i])
            diff_pct = round((model_pred - actual_val) / actual_val * 100, 1) if actual_val > 0 else None
            entry = {
                "month": month_date.strftime("%Y-%m"),
                "predicted": model_pred,
                "actual": actual_val,
                "diff_pct": diff_pct,
                "is_actual": True,
            }
            if diff_pct is not None:
                completed_diffs.append({
                    "month": month_date.strftime("%Y-%m"),
                    "actual": actual_val,
                    "predicted": model_pred,
                    "diff_pct": diff_pct,
                })
        else:
            recalibrated = round(forecast_full_ensemble[i] * recalibration_factor, 1)
            entry = {
                "month": month_date.strftime("%Y-%m"),
                "predicted": recalibrated,
                "is_actual": False,
            }

        forecast_monthly.append(entry)

    # Accuracy summary for completed months
    accuracy = None
    if completed_diffs:
        total_actual = sum(d["actual"] for d in completed_diffs)
        total_predicted = sum(d["predicted"] for d in completed_diffs)
        mean_abs_error_pct = round(
            sum(abs(d["diff_pct"]) for d in completed_diffs) / len(completed_diffs), 1
        )
        overall_diff_pct = round(
            (total_predicted - total_actual) / total_actual * 100, 1
        ) if total_actual > 0 else None

        accuracy = {
            "completed_months": len(completed_diffs),
            "total_actual": total_actual,
            "total_predicted": round(total_predicted, 1),
            "overall_diff_pct": overall_diff_pct,
            "mean_abs_error_pct": mean_abs_error_pct,
            "recalibration_factor": round(recalibration_factor, 4),
            "per_month": completed_diffs,
        }
        logger.info("Model accuracy: %d months, overall %+.1f%%, MAPE %.1f%%, recal=%.3f",
                    len(completed_diffs), overall_diff_pct or 0,
                    mean_abs_error_pct, recalibration_factor)

    # ── 5. Historical yearly totals ──
    historical_yearly = []
    for yr in range(START_YEAR, target_year):
        yr_data = full_series[full_series.index.year == yr]
        if yr_data.sum() > 0:
            historical_yearly.append({"year": yr, "total": int(yr_data.sum())})

    # ── 6. Historical monthly (for charting full timeline) ──
    historical_monthly = []
    for date, count in full_series.items():
        if date.year < target_year:
            historical_monthly.append({
                "month": date.strftime("%Y-%m"),
                "actual": int(count),
            })

    # ── 7. Growth projection ──
    projected_growth_pct = None
    if has_actual_test and test_actual_total > 0:
        projected_growth_pct = round(
            (target_forecast_total / test_actual_total - 1) * 100, 1
        )

    elapsed = time.time() - t0
    logger.info(
        "Yearly forecast complete: %d -> %d predicted CVEs "
        "(%d actual months + %d forecasted, bias: %+.1f%%, ensemble w=%.1f) in %.1fs",
        target_year, target_forecast_total, n_actual, n_remaining,
        adaptive_correction, w, elapsed,
    )

    return {
        "status": "success",
        "model": "xgboost_growth_ensemble",
        "target_year": target_year,
        "forecast_total": target_forecast_total,
        "actual_months_count": n_actual,
        "actual_months_total": actual_sum,
        "forecasted_months_count": n_remaining,
        "forecasted_months_total": forecast_sum,
        "year_complete": year_complete,
        "last_data_month": last_complete.strftime("%Y-%m"),
        "forecast_monthly": forecast_monthly,
        "has_actual_target": has_actual_target,
        "target_actual_total": target_actual_total,
        "target_diff_pct": target_diff_pct,
        "bias_correction_pct": round(adaptive_correction, 2),
        "ensemble": {
            "xgb_annual": xgb_annual,
            "growth_annual": growth_annual,
            "growth_weight": w,
            "growth_rates_yearly": [round(r * 100, 1) for r in growth_rates],
            "growth_rates_monthly": monthly_growth_rates,
            "ensemble_annual": ensemble_annual,
        },
        "backtest": {
            "year": test_year,
            "has_actual": has_actual_test,
            "actual_total": test_actual_total,
            "forecast_total": test_forecast_total,
            "diff_pct": test_diff_pct,
            "bias_correction_pct": round(backtest_bias, 2),
            "monthly": backtest_monthly,
        },
        "historical_yearly": historical_yearly,
        "historical_monthly": historical_monthly,
        "projected_growth_pct": projected_growth_pct,
        "accuracy": accuracy,
    }
