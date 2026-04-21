"""
CPE Forecast Engine — adapted from V2 forecast.py for Lambda execution.

Takes the parsed NVD DataFrame and a CPE string, extracts vendor/product,
runs dual-optimised ARIMA (Diff% + MAPE) forecasting, and returns a result
dict ready for DynamoDB.
"""

import logging
import time
import warnings
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")
logging.getLogger("statsmodels").setLevel(logging.ERROR)

from statsmodels.tsa.statespace.sarimax import SARIMAX
from statsmodels.tools.sm_exceptions import ConvergenceWarning
warnings.filterwarnings("ignore", category=ConvergenceWarning)

from datetime import date

from config import (
    START_YEAR,
    get_rolling_window,
    ARIMA_P,
    ARIMA_D,
    ARIMA_Q,
    CANDIDATE_GRANULARITIES,
    PER_CPE_TIMEOUT_SEC,
)

logger = logging.getLogger(__name__)


# ============================================================
# CPE PARSING
# ============================================================

def parse_cpe(cpe_string: str) -> Dict[str, str]:
    """
    Parse a CPE 2.3 string into vendor, product, version.
    Example: cpe:2.3:a:microsoft:windows_10:10.0:*:*:*:*:*:*:*
    """
    parts = cpe_string.split(":")
    return {
        "vendor": parts[3] if len(parts) > 3 else "",
        "product": parts[4] if len(parts) > 4 else "",
        "version": parts[5] if len(parts) > 5 else "*",
    }


# ============================================================
# DATA FILTERING
# ============================================================

def filter_for_cpe(df: pd.DataFrame, vendor: str, product: str,
                   version: str = "*") -> pd.DataFrame:
    """
    Filter the NVD DataFrame to rows matching a vendor:product:version.
    If version is '*' or empty, matches all versions (product-level).
    Deduplicates by CVE + vendor + product (+ version if specified).
    """
    mask = df["vendor"] == vendor
    if product and product != "*":
        mask &= df["product"] == product
    if version and version != "*":
        mask &= df["version"] == version
    filtered = df[mask].copy()
    dedup_cols = ["CVE", "vendor"]
    if product and product != "*":
        dedup_cols.append("product")
    if version and version != "*":
        dedup_cols.append("version")
    return filtered.drop_duplicates(subset=dedup_cols)


# ============================================================
# TIME SERIES CONSTRUCTION
# ============================================================

def _freq_for_granularity(granularity: str) -> str:
    return {"weekly": "W-MON", "monthly": "MS", "quarterly": "QS"}.get(granularity, "MS")


def build_time_series(entity_df: pd.DataFrame, granularity: str = "monthly",
                      start_date=None, end_date=None) -> pd.DataFrame:
    """Build a regular time series of CVE counts."""
    freq = _freq_for_granularity(granularity)

    if start_date is None:
        start_date = f"{START_YEAR}-01-01"
    if end_date is None:
        end_date = str(date.today())

    start_str = str(start_date)
    end_str = str(end_date)

    filtered = entity_df[
        (entity_df["Published"] >= start_str) &
        (entity_df["Published"] <= end_str)
    ].copy()

    if len(filtered) == 0:
        return pd.DataFrame(columns=["date", "cve_count"])

    events = pd.Series(1, index=pd.DatetimeIndex(filtered["Published"]))
    counts = events.resample(freq).sum()

    full_range = pd.date_range(
        start=pd.Timestamp(start_str).to_period(freq[0]).start_time,
        end=end_str, freq=freq,
    )
    ts = counts.reindex(full_range, fill_value=0).astype(int)
    return pd.DataFrame({"date": ts.index, "cve_count": ts.values})


def _forecast_future_dates(granularity: str, start_date, end_date) -> pd.DatetimeIndex:
    """Generate the date index for future forecast periods."""
    freq = _freq_for_granularity(granularity)
    return pd.date_range(start=str(start_date), end=str(end_date), freq=freq)


# ============================================================
# SEASONAL FEATURES
# ============================================================

def get_patch_tuesday(year: int, month: int) -> pd.Timestamp:
    first_day = pd.Timestamp(year=year, month=month, day=1)
    first_tuesday = first_day + pd.Timedelta(days=(1 - first_day.weekday()) % 7)
    return first_tuesday + pd.Timedelta(days=7)


def week_contains_patch_tuesday(week_start: pd.Timestamp) -> bool:
    week_end = week_start + pd.Timedelta(days=6)
    pt = get_patch_tuesday(week_start.year, week_start.month)
    if week_start <= pt <= week_end:
        return True
    if week_start.month != week_end.month:
        pt_next = get_patch_tuesday(week_end.year, week_end.month)
        return week_start <= pt_next <= week_end
    return False


def add_seasonal_features(ts_df: pd.DataFrame, granularity: str) -> pd.DataFrame:
    ts_df = ts_df.copy()
    ts_df["month"] = ts_df["date"].dt.month
    if granularity == "weekly":
        ts_df["is_patch_tuesday"] = ts_df["date"].apply(week_contains_patch_tuesday).astype(int)
    else:
        ts_df["is_patch_tuesday"] = 0
    return ts_df


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

def split_train_test(ts_df: pd.DataFrame, train_end, backtest_start) -> Tuple[pd.DataFrame, pd.DataFrame]:
    train = ts_df[ts_df["date"] <= pd.Timestamp(train_end)].copy().reset_index(drop=True)
    test = ts_df[ts_df["date"] >= pd.Timestamp(backtest_start)].copy().reset_index(drop=True)
    return train, test


# ============================================================
# ARIMA TUNING (dual optimisation)
# ============================================================

def tune_arima(train_df: pd.DataFrame, test_df: pd.DataFrame,
               optimise: str = "diff",
               use_seasonal_exog: bool = False) -> Tuple[Optional[np.ndarray], dict, float]:
    """
    Grid-search SARIMAX(p,d,q) with reduced grid for Lambda speed.
    optimise: "diff" -> minimise |Σpred - Σactual| / Σactual  (annual total)
              "mape" -> minimise per-period MAPE               (short-term)
    """
    train_y = train_df["cve_count"].values
    actual = test_df["cve_count"].values

    exog_cols = ["month", "is_patch_tuesday"]
    train_exog = train_df[exog_cols].values if (use_seasonal_exog and "month" in train_df.columns) else None
    test_exog = test_df[exog_cols].values if train_exog is not None else None

    best_score = float("inf")
    best_params, best_preds = {}, None

    for p in ARIMA_P:
        for d in ARIMA_D:
            for q in ARIMA_Q:
                try:
                    model = SARIMAX(train_y, exog=train_exog, order=(p, d, q),
                                    enforce_stationarity=False,
                                    enforce_invertibility=False)
                    fitted = model.fit(disp=False)
                    preds = np.maximum(fitted.forecast(steps=len(test_df), exog=test_exog), 0)

                    diff_pct = abs(actual.sum() - preds.sum()) / max(actual.sum(), 1) * 100
                    mape = np.mean(np.abs((actual - preds) / np.maximum(actual, 1))) * 100

                    if optimise == "mape":
                        ratio = preds.sum() / max(actual.sum(), 1)
                        score = mape + (max(0, 0.5 - ratio) * 1000)
                    else:
                        score = diff_pct

                    if score < best_score:
                        best_score = score
                        best_params = {"p": p, "d": d, "q": q,
                                       "seasonal_exog": train_exog is not None}
                        best_preds = preds
                except Exception:
                    pass

    return best_preds, best_params, best_score


# ============================================================
# EVALUATION
# ============================================================

def evaluate(actual: np.ndarray, predictions: np.ndarray) -> dict:
    pred = np.maximum(predictions, 0)
    mae = float(np.mean(np.abs(actual - pred)))
    rmse = float(np.sqrt(np.mean((actual - pred) ** 2)))
    mask = actual > 0
    mape = float(np.mean(np.abs((actual[mask] - pred[mask]) / actual[mask])) * 100) if mask.any() else 0.0
    total_actual = int(actual.sum())
    total_pred = int(round(pred.sum()))
    diff_pct = (total_pred - total_actual) / max(total_actual, 1) * 100
    return {
        "MAE": round(mae, 2),
        "RMSE": round(rmse, 2),
        "MAPE": round(mape, 2),
        "Total_Actual": total_actual,
        "Total_Pred": total_pred,
        "Diff_Pct": round(diff_pct, 2),
    }


# ============================================================
# AUTO-GRANULARITY SELECTION
# ============================================================

def choose_best_granularity(entity_df: pd.DataFrame, window: dict) -> str:
    """Quick probe with ARIMA(1,1,1) to pick best granularity."""
    best_gran = "monthly"
    best_score = float("inf")

    for gran in CANDIDATE_GRANULARITIES:
        try:
            ts = build_time_series(entity_df, gran,
                                   start_date=window["start_date"],
                                   end_date=window["data_end"])
            if len(ts) < 10:
                continue
            nonzero_ratio = (ts["cve_count"] > 0).mean()
            if nonzero_ratio < 0.15:
                continue

            ts_s = add_seasonal_features(ts, gran)
            train, test = split_train_test(ts_s,
                                           window["train_end"],
                                           window["backtest_start"])
            if len(train) < 8 or len(test) == 0:
                continue

            m = SARIMAX(train["cve_count"].values, order=(1, 1, 1),
                        enforce_stationarity=False, enforce_invertibility=False)
            fit = m.fit(disp=False)
            preds = np.maximum(fit.forecast(steps=len(test)), 0)
            actual = test["cve_count"].values

            diff = abs(actual.sum() - preds.sum()) / max(actual.sum(), 1) * 100
            mape = np.mean(np.abs((actual - preds) / np.maximum(actual, 1))) * 100
            score = diff * 0.4 + mape * 0.6

            if score < best_score:
                best_score = score
                best_gran = gran
        except Exception:
            pass

    return best_gran


# ============================================================
# MAIN FORECAST PIPELINE (per CPE)
# ============================================================

def _generate_forecast(
    entity_df: pd.DataFrame,
    granularity: str,
    best_params: dict,
    use_seasonal_exog: bool,
    window: dict,
) -> Tuple[Optional[np.ndarray], pd.DatetimeIndex]:
    """
    Retrain on ALL available data (start_date → data_end) using the best
    ARIMA params found during backtesting, then forecast the next 12 months.
    """
    full_ts = build_time_series(entity_df, granularity,
                                start_date=window["start_date"],
                                end_date=window["data_end"])
    if len(full_ts) < 10:
        return None, pd.DatetimeIndex([])

    full_ts = add_seasonal_features(full_ts, granularity)
    full_y = full_ts["cve_count"].values

    exog_cols = ["month", "is_patch_tuesday"]
    full_exog = full_ts[exog_cols].values if use_seasonal_exog else None

    # Future dates for the forecast window
    future_dates = _forecast_future_dates(granularity,
                                          window["forecast_start"],
                                          window["forecast_end"])
    n_future = len(future_dates)

    # Build future exog (month + patch tuesday features)
    if use_seasonal_exog:
        future_df = pd.DataFrame({"date": future_dates})
        future_df = add_seasonal_features(future_df, granularity)
        future_exog = future_df[exog_cols].values
    else:
        future_exog = None

    p = best_params.get("p", 1)
    d = best_params.get("d", 1)
    q = best_params.get("q", 1)

    try:
        model = SARIMAX(full_y, exog=full_exog, order=(p, d, q),
                        enforce_stationarity=False,
                        enforce_invertibility=False)
        fitted = model.fit(disp=False)
        preds = np.maximum(fitted.forecast(steps=n_future, exog=future_exog), 0)
        return preds, future_dates
    except Exception as e:
        logger.warning("Forecast failed with params (%d,%d,%d): %s", p, d, q, e)
        return None, future_dates


def forecast_cpe(df: pd.DataFrame, cpe_string: str,
                 model_name: str = "arima") -> Dict[str, Any]:
    """
    Run dual-optimised forecast for a single CPE using a rolling window.

    Pipeline:
      1. Backtest: Train on historical data, test on last 12 months → accuracy
      2. Forecast: Retrain on ALL data through last completed month,
         forecast next 12 months → predictions

    The window is calculated dynamically — always forecasts 12 months ahead
    from the most recent completed month.
    """
    t0 = time.time()
    parsed = parse_cpe(cpe_string)
    vendor = parsed["vendor"]
    product = parsed["product"]

    window = get_rolling_window()

    result: Dict[str, Any] = {
        "cpe": cpe_string,
        "vendor": vendor,
        "product": product,
        "model": model_name,
        "status": "failed",
    }

    try:
        # Build candidate levels: version → product → vendor
        version = parsed["version"]
        levels = []
        if version and version != "*":
            levels.append(("version", vendor, product, version))
        if product and product != "*":
            levels.append(("product", vendor, product, "*"))
        levels.append(("vendor", vendor, "*", "*"))

        # Try each level until we find one with enough data
        entity_df = None
        forecast_level = None
        used_vendor = vendor
        used_product = product
        used_version = version

        for level_name, v, p, ver in levels:
            candidate_df = filter_for_cpe(df, v, p, ver)
            unique_cves = candidate_df["CVE"].nunique() if len(candidate_df) > 0 else 0
            logger.info("  Level %s (%s:%s:%s) -> %d unique CVEs",
                        level_name, v, p, ver, unique_cves)
            if unique_cves >= 5:
                entity_df = candidate_df
                forecast_level = level_name
                used_vendor = v
                used_product = p
                used_version = ver
                break

        if entity_df is None or len(entity_df) == 0:
            result["error"] = f"Insufficient data at all levels for {vendor}:{product}:{version}"
            logger.warning("No usable data for CPE %s at any level", cpe_string)
            return result

        result["version"] = used_version
        result["forecast_level"] = forecast_level
        logger.info("  Using level: %s (%s:%s:%s)",
                    forecast_level, used_vendor, used_product, used_version)

        # 2. Choose granularity
        granularity = choose_best_granularity(entity_df, window)
        result["granularity"] = granularity

        # 3. Build time series up to data_end (all completed months)
        ts_df = build_time_series(entity_df, granularity,
                                  start_date=window["start_date"],
                                  end_date=window["data_end"])
        if len(ts_df) < 10:
            result["error"] = f"Insufficient time series ({len(ts_df)} periods)"
            return result

        ts_seasonal = add_seasonal_features(ts_df, granularity)
        train, test = split_train_test(ts_seasonal,
                                        window["train_end"],
                                        window["backtest_start"])

        if len(test) == 0:
            result["error"] = "No test data available"
            return result

        actual = test["cve_count"].values

        # ═══════════════════════════════════════════════════
        # PHASE A: BACKTEST (rolling 12-month validation)
        # ═══════════════════════════════════════════════════

        # ─── Run 1: Diff%-optimised (annual total accuracy) ───
        preds_diff, params_diff, score_diff = tune_arima(
            train, test, optimise="diff", use_seasonal_exog=False)

        # ─── Run 2: MAPE-optimised (per-period accuracy) ───
        preds_mape, params_mape, score_mape = tune_arima(
            train, test, optimise="mape", use_seasonal_exog=True)

        if preds_diff is None and preds_mape is None:
            result["error"] = "All ARIMA configurations failed"
            return result

        # Use whichever succeeded as fallback
        if preds_diff is None:
            preds_diff = preds_mape
            params_diff = params_mape
        if preds_mape is None:
            preds_mape = preds_diff
            params_mape = params_diff

        # Evaluate backtest
        diff_metrics = evaluate(actual, preds_diff)
        mape_metrics = evaluate(actual, preds_mape)

        # Backtest period data
        test_dates = test["date"].dt.strftime("%Y-%m-%d").tolist()
        backtest_annual_periods = [
            {"date": d, "predicted": round(float(p), 1), "actual": int(a)}
            for d, p, a in zip(test_dates, preds_diff, actual)
        ]
        backtest_shortterm_periods = [
            {"date": d, "predicted": round(float(p), 1), "actual": int(a)}
            for d, p, a in zip(test_dates, preds_mape, actual)
        ]

        # ═══════════════════════════════════════════════════
        # PHASE B: FORECAST next 12 months (retrain on ALL data)
        # ═══════════════════════════════════════════════════

        # Use Diff%-optimised params for the annual forecast
        forecast_preds, forecast_dates = _generate_forecast(
            entity_df, granularity, params_diff,
            use_seasonal_exog=False, window=window)

        # Also generate MAPE-optimised forecast for comparison
        forecast_preds_mape, _ = _generate_forecast(
            entity_df, granularity, params_mape,
            use_seasonal_exog=True, window=window)

        if forecast_preds is None and forecast_preds_mape is None:
            result["error"] = "Forecast generation failed"
            return result

        # Fallbacks
        if forecast_preds is None:
            forecast_preds = forecast_preds_mape
        if forecast_preds_mape is None:
            forecast_preds_mape = forecast_preds

        forecast_date_strs = [d.strftime("%Y-%m-%d") for d in forecast_dates]

        # Forecast periods (what the frontend will chart)
        forecast_periods = [
            {"date": d, "predicted": round(float(p), 1)}
            for d, p in zip(forecast_date_strs, forecast_preds)
        ]
        forecast_periods_mape = [
            {"date": d, "predicted": round(float(p), 1)}
            for d, p in zip(forecast_date_strs, forecast_preds_mape)
        ]

        # Historical yearly totals for context
        yearly_totals = []
        hist_start = window["start_date"].year
        hist_end = window["data_end"].year
        for yr in range(hist_start, hist_end + 1):
            yr_count = int(entity_df[
                (entity_df["Published"].dt.year == yr)
            ]["CVE"].nunique())
            yearly_totals.append({"year": yr, "cve_count": yr_count})

        # ═══════════════════════════════════════════════════
        # ASSEMBLE RESULT
        # ═══════════════════════════════════════════════════
        result.update({
            "status": "success",
            "granularity": granularity,
            "version": version,
            "forecast_level": forecast_level,

            # ── FORECAST — what the frontend displays ──
            "forecast_start": str(window["forecast_start"]),
            "forecast_end": str(window["forecast_end"]),
            "forecast_total": int(round(forecast_preds.sum())),
            "forecast_total_mape_optimised": int(round(forecast_preds_mape.sum())),
            "forecast_periods": forecast_periods,
            "forecast_periods_mape_optimised": forecast_periods_mape,

            # ── BACKTEST — accuracy proof ──
            "backtest_start": str(window["backtest_start"]),
            "backtest_end": str(window["backtest_end"]),
            "backtest_actual_total": diff_metrics["Total_Actual"],
            "backtest_predicted_total": diff_metrics["Total_Pred"],
            "backtest_diff_pct": diff_metrics["Diff_Pct"],
            "backtest_mape": mape_metrics["MAPE"],
            "backtest_annual_periods": backtest_annual_periods,
            "backtest_shortterm_periods": backtest_shortterm_periods,

            # ── HISTORICAL — yearly trend for context ──
            "historical_yearly": yearly_totals,

            # ── ACCURACY METRICS ──
            "mae": diff_metrics["MAE"],
            "rmse": diff_metrics["RMSE"],
            "train_periods": len(train),
            "test_periods": len(test),

            # ── MODEL PARAMS (debug) ──
            "params_diff": params_diff,
            "params_mape": params_mape,
        })

        elapsed = time.time() - t0
        logger.info(
            "CPE %s -> OK | %s | forecast %s to %s: %d CVEs | "
            "Backtest Diff%%: %+.1f%% | MAPE: %.1f%% | %.1fs",
            cpe_string, granularity,
            window["forecast_start"], window["forecast_end"],
            int(round(forecast_preds.sum())),
            diff_metrics["Diff_Pct"], mape_metrics["MAPE"], elapsed,
        )

    except Exception as e:
        result["error"] = str(e)[:300]
        logger.exception("Forecast failed for %s", cpe_string)

    return result
