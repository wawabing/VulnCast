"""
Lightweight forecastability scorer for Lambda.

Adapted from forecastability_v2.py — computes a quick forecastability score
for a single CPE's vendor:product against the NVD DataFrame. Determines
whether it's worth running the expensive ARIMA forecast.

Scoring uses 6 statistical metrics:
  1. ACF1           — autocorrelation at lag-1
  2. ApEn           — approximate entropy (regularity)
  3. Trend strength — STL decomposition
  4. Seasonal str.  — STL decomposition
  5. ADF score      — stationarity test
  6. Naive MAPE     — empirical naive forecast accuracy

Score 0-100 → tier: HIGH (≥45), MEDIUM (≥35), LOW (≥1), NOT_FORECASTABLE (<1)
"""

import logging
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from config import get_rolling_window

logger = logging.getLogger(__name__)

# ── Thresholds ──
HIGH_THRESHOLD = 45
MEDIUM_THRESHOLD = 35
LOW_THRESHOLD = 1

# Product-level gates
MIN_ACTIVE_PERIODS = 20
MIN_CVE_COUNT = 20

# Score weights (sum to 1.0)
W_ACF = 0.20
W_ENTROPY = 0.20
W_TREND = 0.15
W_SEASONAL = 0.15
W_NAIVE = 0.20
W_ADF = 0.10

# Granularities to evaluate
GRANULARITIES = {"W": "weekly", "M": "monthly", "Q": "quarterly"}


# ============================================================
# TIME SERIES
# ============================================================

def _build_ts(dates: pd.Series, granularity: str, end_date=None) -> pd.Series:
    """Build a regular CVE count time series from publication dates."""
    freq_map = {"W": "W-MON", "M": "MS", "Q": "QS"}
    freq = freq_map.get(granularity, "MS")

    if len(dates) == 0:
        return pd.Series(dtype=float)

    if end_date is None:
        end_date = str(get_rolling_window()["data_end"])

    events = pd.Series(1, index=pd.DatetimeIndex(dates))
    counts = events.resample(freq).sum()
    full_range = pd.date_range(start=counts.index.min(), end=str(end_date), freq=freq)
    return counts.reindex(full_range, fill_value=0).astype(float)


# ============================================================
# STATISTICAL METRICS
# ============================================================

def _acf1(ts: pd.Series) -> float:
    if len(ts) < 10:
        return 0.0
    try:
        from statsmodels.tsa.stattools import acf
        vals = acf(ts.values, nlags=1, fft=True)
        return float(abs(vals[1]))
    except Exception:
        return 0.0


def _approximate_entropy(ts: pd.Series, m: int = 2, r_factor: float = 0.2) -> float:
    data = ts.values
    N = len(data)
    if N < 20:
        return 0.0
    r = r_factor * np.std(data)
    if r == 0:
        return 1.0

    def _phi(m_val):
        patterns = np.array([data[i:i + m_val] for i in range(N - m_val + 1)])
        counts = np.zeros(len(patterns))
        for i, pat_i in enumerate(patterns):
            counts[i] = np.sum(np.max(np.abs(patterns - pat_i), axis=1) <= r)
        counts /= len(patterns)
        return np.mean(np.log(counts + 1e-10))

    try:
        apen = abs(_phi(m) - _phi(m + 1))
    except Exception:
        return 0.0
    return float(max(0.0, 1.0 - apen / 2.5))


def _stl_strengths(ts: pd.Series, granularity: str) -> Tuple[float, float]:
    period_map = {"W": 52, "M": 12, "Q": 4}
    period = period_map.get(granularity, 12)
    if len(ts) < 2 * period + 1:
        return 0.0, 0.0
    try:
        from statsmodels.tsa.seasonal import STL
        result = STL(ts, period=period, robust=True).fit()
        var_r = np.var(result.resid)
        trend_str = max(0.0, 1.0 - var_r / (np.var(result.trend + result.resid) + 1e-10))
        seas_str = max(0.0, 1.0 - var_r / (np.var(result.seasonal + result.resid) + 1e-10))
        return float(trend_str), float(seas_str)
    except Exception:
        return 0.0, 0.0


def _adf_score(ts: pd.Series) -> float:
    if len(ts) < 15:
        return 0.0
    try:
        from statsmodels.tsa.stattools import adfuller
        result = adfuller(ts.values, autolag="AIC")
        return float(max(0.0, 1.0 - result[1]))
    except Exception:
        return 0.0


def _naive_mape_score(ts: pd.Series, granularity: str) -> float:
    n = len(ts)
    season_lag = {"W": 52, "M": 12, "Q": 4}.get(granularity, 12)
    if n < season_lag * 2:
        if n < 5:
            return 0.0
        actual = ts.values[1:]
        forecast = ts.values[:-1]
    else:
        split = int(n * 0.75)
        test_vals = ts.values[split:]
        lag = min(season_lag, split)
        forecast = ts.values[split - lag: split - lag + len(test_vals)]
        actual = test_vals
        if len(forecast) != len(actual):
            min_len = min(len(forecast), len(actual))
            forecast, actual = forecast[:min_len], actual[:min_len]

    mask = actual > 0
    if mask.sum() == 0:
        return 0.0
    mape = np.mean(np.abs((actual[mask] - forecast[mask]) / actual[mask]))
    return float(max(0.0, 1.0 - mape / 2.0))


# ============================================================
# SCORE AT ONE GRANULARITY
# ============================================================

def _score_at_granularity(dates: pd.Series, granularity: str, end_date=None) -> dict:
    ts = _build_ts(dates, granularity, end_date=end_date)
    total_cves = len(dates)
    active = int((ts > 0).sum())
    total_periods = len(ts)

    result = {
        "granularity": GRANULARITIES.get(granularity, granularity),
        "total_cves": total_cves,
        "active_periods": active,
        "total_periods": total_periods,
        "non_zero_ratio": round(active / max(total_periods, 1), 4),
        "score": 0.0,
        "gate_pass": False,
        "gate_reason": "",
    }

    if total_cves < MIN_CVE_COUNT:
        result["gate_reason"] = f"Below min CVE count ({total_cves} < {MIN_CVE_COUNT})"
        return result

    if active < MIN_ACTIVE_PERIODS:
        result["gate_reason"] = f"Below min active periods ({active} < {MIN_ACTIVE_PERIODS})"
        return result

    # Check recent activity
    recent_cutoff = int(len(ts) * 0.8)
    if ts.iloc[recent_cutoff:].sum() == 0:
        result["gate_reason"] = "No recent activity"
        return result

    result["gate_pass"] = True

    acf_val = _acf1(ts)
    entropy_val = _approximate_entropy(ts)
    trend_val, seasonal_val = _stl_strengths(ts, granularity)
    adf_val = _adf_score(ts)
    naive_val = _naive_mape_score(ts, granularity)

    raw = (
        W_ACF * acf_val +
        W_ENTROPY * entropy_val +
        W_TREND * trend_val +
        W_SEASONAL * seasonal_val +
        W_NAIVE * naive_val +
        W_ADF * adf_val
    )
    result["score"] = round(raw * 100, 2)
    return result


# ============================================================
# PUBLIC API
# ============================================================

def assign_tier(score: float) -> str:
    if score >= HIGH_THRESHOLD:
        return "HIGH"
    elif score >= MEDIUM_THRESHOLD:
        return "MEDIUM"
    elif score >= LOW_THRESHOLD:
        return "LOW"
    else:
        return "NOT_FORECASTABLE"


def score_cpe(df: pd.DataFrame, vendor: str, product: str,
              version: str = "*") -> Dict:
    """
    Score a single CPE for forecastability with cascade: version → product → vendor.

    Tries version-level first. If not forecastable, falls back to product-level,
    then vendor-level. Returns the best result along with the level used.

    Returns:
        {
            "forecastable": bool,
            "tier": "HIGH" | "MEDIUM" | "LOW" | "NOT_FORECASTABLE",
            "score": float (0-100),
            "recommended_granularity": str,
            "total_cves": int,
            "reason": str (if not forecastable),
            "forecast_level": "version" | "product" | "vendor"
        }
    """
    # Build cascade levels
    levels = []
    if version and version != "*":
        levels.append(("version", vendor, product, version))
    if product and product != "*":
        levels.append(("product", vendor, product, "*"))
    levels.append(("vendor", vendor, "*", "*"))

    for level_name, v, p, ver in levels:
        result = _score_at_level(df, v, p, ver)
        if result["forecastable"]:
            result["forecast_level"] = level_name
            return result

    # Nothing was forecastable — return the last (vendor-level) result
    result["forecast_level"] = levels[-1][0]
    return result


def _score_at_level(df: pd.DataFrame, vendor: str, product: str,
                    version: str) -> Dict:
    """Score forecastability at a single level (version, product, or vendor)."""
    mask = df["vendor"] == vendor
    if product and product != "*":
        mask &= df["product"] == product
    if version and version != "*":
        mask &= df["version"] == version

    entity_df = df[mask]
    if len(entity_df) == 0:
        return {
            "forecastable": False,
            "tier": "NOT_FORECASTABLE",
            "score": 0.0,
            "recommended_granularity": None,
            "total_cves": 0,
            "reason": f"No NVD data for {vendor}:{product}:{version}",
        }

    # Deduplicate
    dedup_cols = ["CVE", "vendor"]
    if product and product != "*":
        dedup_cols.append("product")
    if version and version != "*":
        dedup_cols.append("version")
    entity_df = entity_df.drop_duplicates(subset=dedup_cols)
    dates = entity_df["Published"]
    unique_cves = entity_df["CVE"].nunique()

    # Quick gate: absolute minimum
    if unique_cves < 5:
        return {
            "forecastable": False,
            "tier": "NOT_FORECASTABLE",
            "score": 0.0,
            "recommended_granularity": None,
            "total_cves": unique_cves,
            "reason": f"Too few CVEs ({unique_cves})",
        }

    # Score at all granularities, pick best
    window = get_rolling_window()
    data_end = str(window["data_end"])
    best = None
    for gran in ["W", "M", "Q"]:
        result = _score_at_granularity(dates, gran, end_date=data_end)
        if best is None or result["score"] > best["score"]:
            best = result

    tier = assign_tier(best["score"])
    forecastable = tier != "NOT_FORECASTABLE"

    return {
        "forecastable": forecastable,
        "tier": tier,
        "score": best["score"],
        "recommended_granularity": best["granularity"] if forecastable else None,
        "total_cves": unique_cves,
        "reason": best.get("gate_reason", "") if not forecastable else "",
    }
