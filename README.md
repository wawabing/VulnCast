# VulnCast

A vulnerability assessment platform that ingests an organisation's software inventory, maps each installation to Common Platform Enumeration (CPE) identifiers, enriches it with CVE and EPSS exploit-probability data, analyses supply-chain risk via Software Bill of Materials (SBOMs), and forecasts future vulnerability counts using time-series modelling.

VulnCast is a dissertation artefact. It explores whether a pragmatic combination of NVD-backed enrichment, per-CPE ARIMA forecasting with a hierarchical version → product → vendor fallback, and an ensemble XGBoost model for annual totals can give a small-to-medium organisation a useful forward view of their vulnerability exposure.

## Repository layout

This repository is a monorepo containing three deployable components:

| Folder | What it is | Runtime |
|--------|------------|---------|
| [`web/`](web/README.md) | Customer-facing web app — CSV ingest, CPE mapping, SBOM scan, dashboard, risk scoring | Node.js / Express, EJS views, AWS Cognito auth, S3 + DynamoDB backend |
| [`forecast-service/`](forecast-service/README.md) | Per-CPE vulnerability forecasting — dual-optimised ARIMA with version/product/vendor fallback | Containerised AWS Lambda (Python 3.12), EventBridge every 30 minutes |
| [`forecast-yearly-service/`](forecast-yearly-service/README.md) | Annual CVE-total forecasting — XGBoost ensemble with adaptive bias correction | Containerised AWS Lambda (Python 3.12), EventBridge daily |

Each component has its own README covering deployment and internals.

## End-to-end data flow

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         VulnCast web application                         │
│                                                                          │
│   Intune CSV ──►  parser ──►  CPE mapper ──►  CVE / EPSS enrichment      │
│                                │                        │                │
│                                ▼                        ▼                │
│                        writes CPEs to          stores enriched schema    │
│                        forecast-cpes (DDB)     in S3 per tenant          │
│                                                                          │
│   SBOM upload ──►  parser (SPDX/CycloneDX/SWID) ──►  OSV.dev scan        │
│                                                                          │
│   Dashboard reads enriched schema + forecast tables via backend API      │
└──────────────────────────────────────────────────────────────────────────┘
                │                            ▲
                │ writes CPEs                │ reads forecasts
                ▼                            │
┌────────────────────────────┐   ┌───────────────────────────────────┐
│  forecast-service (Lambda) │   │ forecast-yearly-service (Lambda)  │
│                            │   │                                   │
│  Reads CPEs from DynamoDB, │   │ Downloads NVD, builds monthly     │
│  downloads NVD (S3 cache), │   │ CVE series, trains XGBoost with   │
│  runs dual ARIMA           │   │ adaptive bias correction and      │
│  (annual + short-term),    │   │ growth-rate ensemble, writes      │
│  writes cpe-forecast-      │   │ forecast-cve-yearly table.        │
│  results table.            │   │                                   │
│                            │   │ Hierarchical version→product→     │
│  Every 30 minutes.         │   │ vendor fallback lives here too    │
└────────────────────────────┘   │ for the per-CPE pipeline.         │
                                 └───────────────────────────────────┘
                │                               │
                └───────── shared S3 NVD cache ─┘
                            (refreshed 1x / day)
```

## Tech stack

- **Web**: Node.js 20+, Express 5, EJS, vanilla JavaScript frontend, Chart.js
- **Auth**: AWS Cognito via OpenID Connect (`openid-client`)
- **Storage**: AWS S3 (per-tenant schemas + SBOMs), DynamoDB (CPE + forecast tables)
- **Forecasting**: Python 3.12, statsmodels (ARIMA), XGBoost, pandas, numpy
- **Infra**: AWS Lambda (container images), EventBridge schedules, CodeBuild + ECR for CI, SAM / CloudFormation for IaC
- **External data**: NVD CVE/CPE APIs, FIRST.org EPSS, OSV.dev, endoflife.date

## Getting started

Run the web app locally first — it is the entry point for end users. The two Lambda services need to be deployed to AWS before their forecast data becomes visible in the dashboard.

1. Web app — see [`web/README.md`](web/README.md) for install, `.env` setup, and local run instructions (`npm install && npm start`, serves on `http://localhost:3000`).
2. Per-CPE forecasting Lambda — see [`forecast-service/README.md`](forecast-service/README.md) for `sam deploy --guided`.
3. Yearly forecasting Lambda — see [`forecast-yearly-service/README.md`](forecast-yearly-service/README.md) for the equivalent.

The two Lambda services share a single S3 NVD cache (`cpe-forecast-nvd-cache`) so the raw NVD JSONL is downloaded at most once per day across both.

## Security notes

- No secrets are checked in. Every component reads its configuration from environment variables at runtime.
- Each component ships a `.env.example` (web app) or documents its variables in the component README (Lambdas).
- AWS permissions are granted via IAM roles at deploy time; no long-lived AWS keys live in the Lambdas.
- The web app uses AWS Cognito hosted UI for authentication — no passwords touch the application.
- NVD API keys are optional but recommended; without a key, the NVD rate limit is 5 requests per 30 seconds which makes enrichment very slow.

## Dissertation context

Core research contributions:

1. **Hierarchical forecast fallback** — when a specific application version has too few CVEs to fit a model, forecasts cascade to the product level, then to the vendor level, with a forecastability score (ACF1, approximate entropy, trend/seasonal strength, ADF, naive MAPE) deciding which level is viable.
2. **Dual-objective ARIMA** — each forecastable entity is fit twice: once to minimise annual-total Diff%, once to minimise per-period MAPE. The first answers "how many CVEs will land this year?"; the second answers "when?".
3. **Adaptive-bias XGBoost for annual totals** — because unmeasurable drivers (AI-assisted discovery, new attack surfaces, regulatory change) systematically inflate CVE counts, the yearly model measures its own historical bias and corrects forward, then blends with a per-calendar-month growth-rate projection.
4. **Live recalibration** — as months of the target year complete, the model swaps in real counts and damps its future predictions against the observed error, weighted by how many months of evidence it has.

Deeper methodology sits in [`forecast-service/service-overview.txt`](forecast-service/service-overview.txt) and [`forecast-yearly-service/summary-service-year.txt`](forecast-yearly-service/summary-service-year.txt).

## Status

This is a dissertation submission, not a production service. Known limitations are tracked in the web-app TODO file (kept out of version control) and include: no automated test coverage yet, hardcoded NVD rate-limit constants on the client, and server-rendered pages without pagination for very large inventories.

## Acknowledgements

- [National Vulnerability Database (NVD)](https://nvd.nist.gov/) — CPE and CVE data
- [FIRST EPSS](https://www.first.org/epss/) — exploit probability scoring
- [OSV.dev](https://osv.dev/) — open-source vulnerability database for SBOM scanning
- [endoflife.date](https://endoflife.date/) — product end-of-life dates
- NVD mirror at [handsonhacking.org](https://nvd.handsonhacking.org/nvd.jsonl) — bulk NVD JSONL for the forecasting Lambdas
