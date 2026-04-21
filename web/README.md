# VulnCast — Web Application

The customer-facing component of VulnCast. Users sign in with AWS Cognito, upload a Microsoft Intune CSV export of their device/application inventory, optionally upload SBOMs, and see an enriched risk dashboard backed by NVD (CVEs), FIRST (EPSS), OSV.dev (supply chain), and endoflife.date.

This is one of three components in the VulnCast repository. For the overall architecture see the [top-level README](../README.md).

## Features

- CSV upload + parsing for both Intune Raw (13 columns) and Intune Aggregate (7 columns) formats
- Automatic CPE discovery against the NVD CPE API, with publisher-aware search and dual API-key rotation on rate limit
- CVE enrichment with CVSS severity, EPSS exploit probability, and reference URLs
- End-of-life detection with recommended-replacement tracking via endoflife.date
- SBOM ingestion (SPDX / CycloneDX / SWID) with live OSV.dev scanning streamed over Server-Sent Events
- Forecast dashboard showing per-CPE predicted CVE counts and an aggregate yearly forecast, sourced from the two Lambda services
- Risk scoring on the executive dashboard combining CVSS × EPSS × blast-radius per installation

## Tech stack

- Node.js (ES modules) with Express 5
- EJS server-side templating
- AWS Cognito via OpenID Connect (`openid-client` + `express-session`)
- AWS SDK v3 for S3 (schemas, SBOMs), DynamoDB (forecast lookups), Lambda (on-demand forecast trigger)
- Multer for multipart uploads, `csv-parser` for streaming CSV parsing
- Vanilla JS + Chart.js on the frontend

## Prerequisites

- Node.js 20 or later
- An AWS account with:
  - A Cognito User Pool + App Client configured for OAuth2 code flow
  - An S3 bucket for schema/SBOM storage
  - DynamoDB tables created by `../forecast-service` (run that deploy first)
  - An IAM user or role with `s3:*` on the bucket, `dynamodb:Query/GetItem/Scan` on the forecast tables, and `lambda:InvokeFunction` on the per-CPE forecast function

## Setup

```bash
cd web/backend
npm install
cp .env.example .env
# edit .env with your real values (see "Environment variables" below)
npm start
```

The server listens on `http://localhost:3000`. The root route redirects to the Cognito hosted UI; after successful sign-in you land on the onboarding page if no data has been uploaded, otherwise on the dashboard.

## Environment variables

All configuration lives in `backend/.env` (git-ignored). `backend/.env.example` is the canonical template — copy it and fill in real values.

| Variable | Purpose |
|----------|---------|
| `PORT` | HTTP port (default `3000`) |
| `NVD_API_KEYS` | Comma-separated list of NVD API keys for rotation on rate limit. Falls back to `NVD_API_KEY` for a single key. |
| `COGNITO_ISSUER` | Cognito User Pool issuer URL |
| `COGNITO_APP_CLIENT_ID` / `COGNITO_APP_CLIENT_SECRET` | Cognito App Client credentials |
| `COGNITO_CALLBACK_URL` / `COGNITO_LOGOUT_URL` / `COGNITO_DOMAIN` | OIDC callback, logout, and hosted-UI domain |
| `SESSION_SECRET` | Express session signing secret. Generate with `openssl rand -hex 32`. |
| `AWS_REGION` / `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | AWS credentials for S3 + DynamoDB + Lambda |
| `S3_BUCKET_NAME` | Bucket holding per-user enriched schemas and SBOM manifests |
| `FORECAST_LAMBDA_NAME` | Name of the deployed Lambda from `../forecast-service` |

## Usage

1. Sign in at `/` — redirects to Cognito hosted UI.
2. On first login you are sent to onboarding; upload an Intune CSV (drag-drop or file picker).
3. The app parses the CSV into a structured schema, uploads to S3, and starts async enrichment. The processing page polls progress over SSE.
4. Once enrichment completes you are redirected to the dashboard — devices, users, applications, vulnerabilities, forecasts, and supply-chain coverage pages are all linked in the sidebar.
5. Upload SBOMs from the supply-chain page modal. OSV scans stream results live.
6. Forecasts appear once the two Lambda services have processed the CPEs produced by your upload (typically within one scheduling cycle).

## Project layout

```
web/
├── backend/
│   ├── controllers/        # HTTP handlers (upload, SBOM, forecast, EOL)
│   ├── routes/             # Express route wiring
│   ├── services/           # NVD, EPSS, OSV, EOL, S3, DynamoDB, Lambda clients
│   ├── middlewares/        # Cognito OIDC auth
│   ├── utils/              # CSV type detection, SBOM parsing
│   ├── server.js           # Express app entry point
│   ├── package.json
│   └── .env.example        # Template — copy to .env
├── frontend/
│   ├── css/styles.css
│   └── js/                 # Per-page modules (dashboard, forecast, etc.)
├── views/
│   ├── *.ejs               # Page templates
│   └── partials/           # Shared layout + sidebar
├── schema.json             # Example of the enriched-schema shape
├── EOL_finder.py           # Legacy reference Python script for EOL lookups
└── README.md
```

## API endpoints

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/api/upload` | Multipart CSV upload, returns parsed schema |
| `POST` | `/api/start-enrichment` | Kicks off async CPE/CVE enrichment |
| `GET`  | `/api/enrichment-progress` | SSE stream of enrichment progress |
| `GET`  | `/api/latest-schema` | Latest enriched schema for the signed-in user |
| `POST` | `/api/sbom/upload` | SBOM upload with SSE progress |
| `POST` | `/api/trigger-forecast` | Manually invoke the per-CPE forecast Lambda |
| `GET`  | `/api/forecasts` | All per-CPE forecasts for this tenant + summary |
| `GET`  | `/api/forecasts/:cpe` | Single CPE forecast |
| `GET`  | `/api/forecasts/yearly/:year` | Yearly aggregate forecast |

Plus the page routes (`/dashboard`, `/devices`, `/users`, `/applications`, `/vulnerabilities`, `/forecast`, `/supply-chain`, `/profile`) and Cognito auth routes (`/login`, `/auth/callback`, `/logout`).

## NVD rate-limit handling

- Without an NVD API key: 5 requests per 30 seconds
- With an API key: 50 requests per 30 seconds
- The app rotates between multiple keys when it sees HTTP 429 or 403, then exponential-backs-off if all keys are throttled

For larger inventories (500+ apps) enrichment can still take tens of minutes. A production build would move this to a worker queue.

## CVE severity buckets

- Critical: CVSS 9.0 – 10.0
- High: CVSS 7.0 – 8.9
- Medium: CVSS 4.0 – 6.9
- Low: CVSS 0.1 – 3.9
