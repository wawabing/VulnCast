import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  ScanCommand,
  GetCommand,
  BatchWriteCommand,
} from "@aws-sdk/lib-dynamodb";
import { LambdaClient, InvokeCommand } from "@aws-sdk/client-lambda";

const dynamoClient = new DynamoDBClient({
  region: process.env.AWS_REGION || "eu-west-2",
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

const lambdaClient = new LambdaClient({
  region: process.env.AWS_REGION || "eu-west-2",
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

/**
 * Invoke the CPE forecast Lambda asynchronously (Event invocation type).
 * The Lambda will process CPEs from the forecast-cpes table in the background.
 */
export async function invokeForecastLambda() {
  const functionName = process.env.FORECAST_LAMBDA_NAME || "cpe-forecast-lambda";

  const command = new InvokeCommand({
    FunctionName: functionName,
    InvocationType: "Event",
    Payload: JSON.stringify({ source: "profile-upload" }),
  });

  const response = await lambdaClient.send(command);
  return { statusCode: response.StatusCode };
}

const docClient = DynamoDBDocumentClient.from(dynamoClient);

const TABLE_NAME = "cpe-forecast-results";
const YEARLY_TABLE = "forecast-cve-yearly";

/**
 * Get all forecast results (full table scan).
 * The table is small (one item per tracked CPE) so scans are fine.
 * @returns {Promise<Array<object>>}
 */
export async function getAllForecasts() {
  const items = [];
  let lastKey;

  do {
    const res = await docClient.send(
      new ScanCommand({
        TableName: TABLE_NAME,
        ExclusiveStartKey: lastKey,
      })
    );
    items.push(...(res.Items || []));
    lastKey = res.LastEvaluatedKey;
  } while (lastKey);

  return items;
}

/**
 * Delete all forecast results from the cpe-forecast-results table.
 * Called on re-upload to prevent stale data contamination.
 * @returns {Promise<number>} number deleted
 */
export async function deleteAllForecastResults() {
  const all = await getAllForecasts();
  if (!all.length) return 0;

  const chunks = [];
  for (let i = 0; i < all.length; i += 25) {
    chunks.push(all.slice(i, i + 25));
  }

  for (const chunk of chunks) {
    await docClient.send(new BatchWriteCommand({
      RequestItems: {
        [TABLE_NAME]: chunk.map(item => ({
          DeleteRequest: { Key: { cpe: item.cpe } },
        })),
      },
    }));
  }

  console.log(`Forecast: deleted ${all.length} results from ${TABLE_NAME}`);
  return all.length;
}

/**
 * Get a single CPE's forecast by its full CPE 2.3 string.
 * @param {string} cpe – e.g. "cpe:2.3:a:google:chrome:0.2.149.29:*:*:*:*:*:*:*"
 * @returns {Promise<object|null>}
 */
export async function getForecastByCpe(cpe) {
  const res = await docClient.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: { cpe },
    })
  );
  return res.Item || null;
}

/**
 * Convenience: split all forecasts into successful vs failed buckets
 * and compute aggregate stats.
 * @returns {Promise<object>}
 */
export async function getForecastSummary() {
  const all = await getAllForecasts();

  const successful = all.filter((i) => i.status === "success");
  const failed = all.filter((i) => i.status === "failed");
  const notForcastable = all.filter((i) => i.status === "not_forecastable");

  // Helper: extract backtest actual total from flat or nested structure
  const getBacktestActual = (i) =>
    i.backtest_actual_total ?? i.backtest?.actual_total ?? 0;

  // Aggregate predicted CVEs across all successful CPEs
  const totalPredicted = successful.reduce(
    (sum, i) => sum + (i.forecast_total || 0),
    0
  );

  // Aggregate actual CVEs from backtest
  const totalActual = successful.reduce(
    (sum, i) => sum + getBacktestActual(i),
    0
  );

  // Average MAPE across successful forecasts
  const avgMape =
    successful.length > 0
      ? successful.reduce((sum, i) => sum + (i.backtest_mape ?? i.backtest?.mape ?? 0), 0) /
        successful.length
      : null;

  // Average diff pct
  const avgDiffPct =
    successful.length > 0
      ? successful.reduce((sum, i) => sum + (Math.abs(i.backtest_diff_pct ?? i.backtest?.diff_pct ?? 0)), 0) /
        successful.length
      : null;

  // Derive forecast / backtest years from the first successful item
  const sample = successful[0];
  const forecastYear = sample?.forecast_start?.slice(0, 4) || String(new Date().getFullYear());
  const backtestYear = sample?.backtest_start?.slice(0, 4) || String(new Date().getFullYear() - 1);

  return {
    total: all.length,
    successCount: successful.length,
    failedCount: failed.length,
    notForecastableCount: notForcastable.length,
    totalPredicted: successful.length > 0 ? Math.round(totalPredicted) : null,
    totalActual: successful.length > 0 ? Math.round(totalActual) : null,
    forecastYear,
    backtestYear,
    avgMape: avgMape !== null ? Math.round(avgMape * 100) / 100 : null,
    avgDiffPct: avgDiffPct !== null ? Math.round(avgDiffPct * 100) / 100 : null,
    successful,
    failed,
    notForcastable,
  };
}

/**
 * Get the yearly total CVE forecast from the forecast-cve-yearly table.
 * Normalises the item so the front-end always has a consistent shape
 * regardless of minor schema revisions in DynamoDB.
 * @param {string} year – e.g. "2026"
 * @returns {Promise<object|null>}
 */
export async function getYearlyForecast(year) {
  const res = await docClient.send(
    new GetCommand({
      TableName: YEARLY_TABLE,
      Key: { year: String(year) },
    })
  );
  const item = res.Item;
  if (!item) return null;

  // ── Compute backtest.diff_pct if absent ──────────────────────
  if (item.backtest) {
    const bt = item.backtest;
    if (bt.diff_pct === undefined && bt.actual_total && bt.forecast_total) {
      bt.diff_pct =
        ((bt.forecast_total - bt.actual_total) / bt.actual_total) * 100;
    }
  }

  return item;
}
