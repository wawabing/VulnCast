# Yearly CVE Forecast Service

Serverless Lambda that predicts the total number of CVEs that will be published in a given calendar year (defaulting to the current year). Triggered daily by EventBridge, it downloads NVD data, fits an XGBoost ensemble with adaptive bias correction, and writes a forecast record to DynamoDB for the VulnCast web app to consume.

This is a sibling to [`../forecast-service`](../forecast-service/README.md). Both services share the same S3 NVD cache — the raw NVD JSONL is downloaded at most once per day across both.

## Pipeline

```
EventBridge (daily)
       │
       ▼
┌──────────────┐      ┌──────────────────────────┐
│   Lambda     │─────▶│  S3 cache (shared)       │  (nvd.jsonl, TTL 24h)
│  (handler)   │      └──────────────────────────┘
│              │
│  1. Download │───▶ parse CVEs, filter rejected, build monthly series from 2017
│  2. Features │───▶ lag(1,2,3,6,12,24), rolling mean/std (3,6,12,24), trend, calendar
│  3. Train    │───▶ XGBoost (shallow, regularised, ~100 monthly rows)
│  4. Bias     │───▶ measure historical bias over prior 3 years, apply correction
│  5. Blend    │───▶ ensemble with per-calendar-month growth-rate projection
│  6. Recal    │───▶ swap completed months for actuals, dampen future by observed error
│  7. Backtest │───▶ independent bias correction for prior year, report MAPE/Diff%
│  8. Save     │───▶ ┌──────────────────────────┐
│              │     │  forecast-cve-yearly     │  (DynamoDB, PK = year)
└──────────────┘     └──────────────────────────┘
```

## Key techniques

- **Adaptive bias learning.** XGBoost systematically underpredicts because it cannot model unmeasurable CVE-growth drivers (AI-assisted vulnerability discovery, new attack surfaces, regulatory change, disclosure policy shifts). The service measures the model's historical bias by running retrospective one-year forecasts over each of the three years prior to the target, computing percentage error, and averaging. That bias is then applied forward to correct the target-year prediction.
- **Ensemble blending.** The final forecast is a weighted blend of XGBoost's monthly output and a per-calendar-month year-over-year growth-rate projection (January growth is computed independently from July growth). Default weight is 0.55 growth-rate / 0.45 XGBoost, configurable via `ENSEMBLE_GROWTH_WEIGHT`.
- **Live recalibration.** As months of the target year complete, completed-month actuals replace predictions and a recalibration factor is computed from observed error on those months. The correction is applied to remaining months, damped by `n / (n+1)` so a single outlier does not distort the rest of the year.
- **Honest backtesting.** The prior year gets its own independent bias correction (computed from *its* prior three years), so reported MAPE/Diff% is not contaminated by target-year information.

Deeper methodology notes live in [`summary-service-year.txt`](summary-service-year.txt).

## Deployment

No SAM template is shipped for this service — it is deployed via CodeBuild + ECR. A minimal flow:

```powershell
# Build + push the container image via CodeBuild (see buildspec.yml)
aws codebuild start-build --project-name forecast-yearly-service-build

# Point the Lambda at the new image, or create the Lambda the first time:
aws lambda create-function \
  --function-name forecast-yearly-service \
  --package-type Image \
  --code ImageUri=<ecr-uri>:latest \
  --role <lambda-exec-role-arn> \
  --timeout 900 --memory-size 3008

# Schedule it daily with EventBridge
aws events put-rule --name forecast-yearly-daily --schedule-expression "rate(1 day)"
aws events put-targets --rule forecast-yearly-daily \
  --targets "Id=1,Arn=<lambda-arn>"
```

Grant the Lambda's execution role:

- `dynamodb:PutItem` on the `forecast-cve-yearly` table
- `s3:GetObject` + `s3:PutObject` on the shared NVD cache bucket
- `logs:*` on its own CloudWatch log group

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DYNAMO_TABLE` | `forecast-cve-yearly` | Output table name |
| `AWS_REGION` | `eu-west-2` | AWS region (also used for DynamoDB client) |
| `NVD_URL` | `https://nvd.handsonhacking.org/nvd.jsonl` | Bulk NVD JSONL URL |
| `NVD_S3_BUCKET` | `cpe-forecast-nvd-cache` | Shared S3 bucket for the NVD cache |
| `NVD_S3_KEY` | `nvd.jsonl` | Object key within the bucket |
| `NVD_CACHE_TTL_SEC` | `86400` | Re-download the NVD file if older than this |
| `TARGET_YEAR` | current year | Year to forecast; override via event payload for backtests |
| `ENSEMBLE_GROWTH_WEIGHT` | `0.55` | Growth-rate weight in the XGBoost / growth ensemble |
| `GROWTH_RATE_YEARS` | `3` | Number of recent years to average for the growth projection |
| `LOG_LEVEL` | `INFO` | Python logging level |

## DynamoDB output

Table `forecast-cve-yearly`, PK = `year` (string).

| Field | Description |
|-------|-------------|
| `year` | Target year (e.g. `"2026"`) |
| `last_forecast_epoch` / `last_forecast_iso` | When this record was written |
| `status` | `success` or `failed` |
| `forecast_total` | Predicted CVE count for the whole target year |
| `actual_months_count` / `actual_months_total` | Completed months + their real CVE counts |
| `forecasted_months_count` / `forecasted_months_total` | Remaining months and their predictions |
| `forecast_monthly` | List of `{month, predicted, actual}` entries |
| `bias_correction_pct` | Percentage correction applied to raw XGBoost output |
| `ensemble` | `{xgb_total, growth_total, weight}` blend diagnostic |
| `backtest` | `{target_year, predicted, actual, diff_pct, mape}` for the prior year |
| `historical_yearly` / `historical_monthly` | Raw CVE counts for trend display |
| `projected_growth_pct` | Growth-rate projection used in the ensemble |
| `accuracy` | Per-month prediction-vs-actual once the target year starts filling in |
| `error` | Only set when `status == "failed"` |

## Local testing

```powershell
# Full pipeline (needs AWS credentials + a reachable S3 cache / NVD source):
python handler.py

# Specific year:
python handler.py --year 2025

# Skip the download and point at a local NVD file:
python handler.py --year 2025 --local-nvd ./nvd.jsonl
```

## Files

| File | Purpose |
|------|---------|
| `handler.py` | Lambda entry point + DynamoDB writer |
| `forecast_engine.py` | Feature engineering, XGBoost training, bias correction, ensemble, recalibration |
| `nvd_downloader.py` | S3-cached NVD download with TTL |
| `config.py` | Env-var-driven configuration |
| `Dockerfile` | Container image for Lambda |
| `buildspec.yml` | CodeBuild steps to build + push to ECR |
| `requirements.txt` | Python dependencies |
| `summary-service-year.txt` | Dissertation-style methodology write-up |
