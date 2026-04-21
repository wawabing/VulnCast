# CPE Forecast Service

Serverless service that runs every 30 minutes via EventBridge, reads CPEs from DynamoDB, downloads fresh NVD data (cached daily in S3), runs ARIMA forecasts, and saves results for the frontend.

## Architecture

```
EventBridge (every 30 min)
        │
        ▼
  ┌──────────────┐      ┌──────────────────┐
  │   Lambda     │─────▶│  forecast-cpes   │  (DynamoDB - input)
  │  (handler)   │      │  PK: cpe         │
  │              │      └──────────────────┘
  │  1. Read CPEs│
  │  2. Get NVD  │─────▶┌──────────────────┐
  │     data     │      │  S3 cache        │  (nvd.jsonl — refreshed 1x/day)
  │              │      │  └─ if stale ──▶ https://nvd.handsonhacking.org/nvd.jsonl
  │  3. Forecast │      └──────────────────┘
  │  4. Save     │─────▶┌──────────────────────┐
  │              │      │ cpe-forecast-results  │  (DynamoDB - output)
  └──────────────┘      │ PK: cpe              │
                        └──────────────────────┘
```

**NVD data** is downloaded from the source URL at most **once per day** and cached in S3.
Every 30-minute invocation pulls from S3 (~5 seconds) instead of the full download.

---

## Step-by-Step Setup Guide

### Prerequisites

Install these on your machine:

1. **AWS CLI** — https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
2. **AWS SAM CLI** — https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html
3. **Docker Desktop** — https://www.docker.com/products/docker-desktop/ (must be running)
4. **AWS credentials configured** with permissions for Lambda, DynamoDB, S3, ECR, CloudFormation, IAM

### Step 1: Configure AWS CLI

```powershell
# If you haven't configured AWS CLI yet:
aws configure
# Enter your Access Key ID, Secret Access Key, region (eu-west-2), output format (json)

# Verify it works:
aws sts get-caller-identity
```

### Step 2: Deploy with SAM (one command)

```powershell
cd forecast-service

# First-time deploy (interactive — walks you through options):
sam build; sam deploy --guided

# It will ask:
#   Stack Name:              cpe-forecast-service-prod
#   AWS Region:              eu-west-2
#   Confirm changes:         Y
#   Allow SAM CLI IAM:       Y
#   Save arguments:          Y  (saves to samconfig.toml for next time)
```

**Or use the deploy script:**

```powershell
.\deploy.ps1                        # dev environment
.\deploy.ps1 -Environment prod      # production
.\deploy.ps1 -Guided                # first-time guided setup
```

### Step 3: Verify it's working

```powershell
# Check the Lambda was created:
aws lambda get-function --function-name cpe-forecast-service-prod --query "Configuration.{Name:FunctionName,State:State,Timeout:Timeout,Memory:MemorySize}"

# Check the EventBridge rule was created (the 30-min schedule):
aws events list-rules --name-prefix cpe-forecast

# Check the DynamoDB tables exist:
aws dynamodb list-tables --query "TableNames[?contains(@, 'forecast')]"

# Check the S3 bucket:
aws s3 ls | Select-String "cpe-forecast-nvd-cache"
```

### Step 4: Add CPEs to the input table

Your main application should write CPEs to the `forecast-cpes` table. To add them manually for testing:

```powershell
# Add a single CPE:
aws dynamodb put-item --table-name forecast-cpes --item '{"cpe": {"S": "cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:*:*"}}'

# Add a few more:
aws dynamodb put-item --table-name forecast-cpes --item '{"cpe": {"S": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"}}'
aws dynamodb put-item --table-name forecast-cpes --item '{"cpe": {"S": "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*"}}'

# Verify:
aws dynamodb scan --table-name forecast-cpes --select COUNT
```

### Step 5: Trigger a test run (don't wait for the schedule)

```powershell
# Invoke the Lambda manually:
aws lambda invoke --function-name cpe-forecast-service-prod --payload '{"source": "manual-test"}' output.json; Get-Content output.json

# Watch the logs in real-time:
sam logs --name cpe-forecast-service-prod --tail
```

### Step 6: Check forecast results

```powershell
# See all forecast results:
aws dynamodb scan --table-name cpe-forecast-results --query "Items[].{cpe: cpe.S, status: status.S, annual_pred: annual_predicted_total.N, diff_pct: annual_diff_pct.N}" --output table

# Get a specific CPE result:
aws dynamodb get-item --table-name cpe-forecast-results --key '{"cpe": {"S": "cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:*:*"}}' --output json
```

---

## What the template creates

| Resource | Type | Purpose |
|----------|------|---------|
| `ForecastFunction` | Lambda (container) | Runs the forecast pipeline |
| EventBridge Rule | Schedule | Triggers Lambda every 30 minutes |
| `forecast-cpes` | DynamoDB | Input: unique CPEs across all users |
| `cpe-forecast-results` | DynamoDB | Output: forecast data for the frontend |
| S3 Bucket | S3 | NVD data cache (refreshed once/day) |
| CloudWatch Alarms | Alarms | Error rate + duration monitoring |
| IAM Policies | IAM | Lambda access to DynamoDB + S3 |

All created automatically by `sam deploy`. All deleted cleanly by `sam delete`.

---

## DynamoDB Tables

### `forecast-cpes` (input)

Holds the unique list of CPEs across all users. Populated by the main application when users upload Intune exports.

| Field | Type | Description |
|-------|------|-------------|
| `cpe` (PK) | String | Full CPE 2.3 string, e.g. `cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:*:*` |

### `cpe-forecast-results` (output)

Forecast results consumed by the frontend.

| Field | Type | Description |
|-------|------|-------------|
| `cpe` (PK) | String | Full CPE 2.3 string |
| `last_forecast_epoch` | Number | Unix epoch of last forecast |
| `last_forecast_iso` | String | ISO 8601 timestamp |
| `status` | String | `success` or `failed` |
| `model` | String | Model used (`arima`) |
| `granularity` | String | `weekly`, `monthly`, or `quarterly` |
| `vendor` | String | Vendor from CPE |
| `product` | String | Product from CPE |
| `annual_predicted_total` | Number | Diff%-optimised forecast (annual CVE count) |
| `annual_actual_total` | Number | Actual CVE count (test year) |
| `annual_diff_pct` | Number | (pred-actual)/actual x 100 |
| `shortterm_predicted_total` | Number | MAPE-optimised forecast total |
| `shortterm_mape` | Number | Per-period MAPE (%) |
| `shortterm_diff_pct` | Number | Short-term diff% |
| `annual_periods` | List | `[{date, predicted, actual}, ...]` Diff%-optimised per-period |
| `shortterm_periods` | List | `[{date, predicted, actual}, ...]` MAPE-optimised per-period |
| `mae` | Number | Mean Absolute Error |
| `rmse` | Number | Root Mean Square Error |
| `train_periods` | Number | Number of training periods |
| `test_periods` | Number | Number of test periods |
| `error` | String | Error message (if `status=failed`) |

## Dual Optimisation

Each CPE is forecast twice using ARIMA:

1. **Diff%-optimised (annual/long-term)**: Minimises `|sum(pred) - sum(actual)| / sum(actual)`. Best for "how many CVEs will affect this product this year?"

2. **MAPE-optimised (short-term)**: Minimises per-period MAPE with seasonal features (month, Patch Tuesday). Best for "when will CVEs spike?"

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DYNAMO_TABLE_CPES` | `forecast-cpes` | Input DynamoDB table name |
| `DYNAMO_TABLE_RESULTS` | `cpe-forecast-results` | Output DynamoDB table name |
| `NVD_URL` | `https://nvd.handsonhacking.org/nvd.jsonl` | NVD data download URL |
| `NVD_S3_BUCKET` | `cpe-forecast-nvd-cache` | S3 bucket for daily NVD cache |
| `NVD_CACHE_TTL_SEC` | `86400` | Re-download NVD interval. 86400 = 24h |
| `DEFAULT_MODEL` | `arima` | Forecast model to use |
| `FORECAST_TTL_SEC` | `86400` | Re-forecast interval per CPE. 86400 = 24h |
| `LAMBDA_BUDGET_SEC` | `840` | Max seconds for forecasting (reserves 60s for setup) |
| `PER_CPE_TIMEOUT_SEC` | `120` | Max seconds per individual CPE forecast |

## Local Testing

```powershell
# Test with a single CPE (uses local NVD file, skips DynamoDB):
python handler.py --cpe "cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:*:*" --local-nvd ../nvd.jsonl --skip-dynamo

# Full pipeline (requires AWS credentials + DynamoDB tables):
python handler.py
```

## How it handles time limits

Lambda has a 15-minute max timeout. The service:

1. Sets aside 60s for startup (NVD download/parse) and teardown
2. Processes CPEs one at a time, checking elapsed time before each
3. When the budget is nearly exhausted, stops gracefully
4. Unfinished CPEs are picked up on the next 30-minute invocation
5. CPEs with recent forecasts (within `FORECAST_TTL_SEC`) are skipped

## Frontend Integration

```javascript
// Fetch forecast for a specific CPE
const result = await dynamodb.get({
  TableName: 'cpe-forecast-results',
  Key: { cpe: 'cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:*:*' }
}).promise();

// result.Item:
// - annual_predicted_total: 1234
// - annual_diff_pct: -2.3
// - shortterm_periods: [{date: "2025-01-01", predicted: 45.2, actual: 48}, ...]
// - shortterm_mape: 15.6
```

## Tear down

```powershell
sam delete --stack-name cpe-forecast-service-prod
```
