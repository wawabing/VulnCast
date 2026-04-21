"""
Configuration for the Yearly CVE Forecast Lambda.
"""
import os

# ── DynamoDB ──
DYNAMO_TABLE = os.environ.get("DYNAMO_TABLE", "forecast-cve-yearly")
DYNAMO_REGION = os.environ.get("AWS_REGION", "eu-west-2")

# ── NVD Data Source ──
NVD_URL = os.environ.get("NVD_URL", "https://nvd.handsonhacking.org/nvd.jsonl")
NVD_LOCAL_PATH = "/tmp/nvd.jsonl"

# ── S3 Cache (shared with CPE forecast) ──
NVD_S3_BUCKET = os.environ.get("NVD_S3_BUCKET", "cpe-forecast-nvd-cache")
NVD_S3_KEY = os.environ.get("NVD_S3_KEY", "nvd.jsonl")
NVD_CACHE_TTL_SEC = int(os.environ.get("NVD_CACHE_TTL_SEC", "86400"))

# ── Forecast Settings ──
START_YEAR = 2017
TARGET_YEAR = int(os.environ.get("TARGET_YEAR", "2026"))

# ── XGBoost params (exact match to original) ──
XGB_PARAMS = {
    "n_estimators": 120,
    "max_depth": 3,
    "learning_rate": 0.05,
    "subsample": 0.65,
    "colsample_bytree": 0.7,
    "reg_alpha": 0.2,
    "reg_lambda": 1.5,
    "min_child_weight": 4,
}

# ── Ensemble settings ──
# Blend XGBoost (monthly precision) with growth-rate projection (trend strength).
# 0.0 = pure XGBoost, 1.0 = pure growth-rate. Default 0.55 = slight growth lean.
ENSEMBLE_GROWTH_WEIGHT = float(os.environ.get("ENSEMBLE_GROWTH_WEIGHT", "0.55"))
# Number of recent years to average for growth-rate projection (3 = smoother)
GROWTH_RATE_YEARS = int(os.environ.get("GROWTH_RATE_YEARS", "3"))
