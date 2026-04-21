import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand, ScanCommand, BatchWriteCommand } from "@aws-sdk/lib-dynamodb";

const dynamoClient = new DynamoDBClient({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

const docClient = DynamoDBDocumentClient.from(dynamoClient);

const TABLE_NAME = "forecast-cpes";

/**
 * Upsert a single CPE into the forecast-cpes table.
 * Each item is keyed by `cpe` (the CPE URI string).
 *
 * @param {object} item
 * @param {string} item.cpe            – e.g. "cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*"
 * @param {string} item.vendor         – e.g. "microsoft"
 * @param {string} item.product        – e.g. "edge_chromium"
 * @param {string} item.version        – e.g. "120.0.2210.91"
 * @param {string} [item.app_name]     – friendly application name
 * @param {string} [item.added_by]     – user sub / email who triggered the upload
 * @param {string} [item.added_at]     – ISO timestamp
 */
export async function putCpe(item) {
  await docClient.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: {
      cpe: item.cpe,
      vendor: item.vendor || "",
      product: item.product || "",
      version: item.version || "",
      app_name: item.app_name || "",
      added_by: item.added_by || "system",
      added_at: item.added_at || new Date().toISOString(),
      updated_at: new Date().toISOString(),
      // EOL fields
      eol_date: item.eol_date || null,
      is_eol: item.is_eol || false,
      days_to_eol: item.days_to_eol ?? null,
      eol_product_slug: item.eol_product_slug || "",
      eol_release_label: item.eol_release_label || "",
      eol_recommended: item.eol_recommended || null,
      eol_alternatives: item.eol_alternatives || [],
    },
  }));
}

/**
 * Batch-write CPEs (max 25 per call, handles chunking internally).
 * Duplicates are automatically overwritten (DynamoDB PutItem is idempotent on the key).
 *
 * @param {Array<object>} items – array of CPE items (same shape as putCpe)
 */
export async function batchPutCpes(items) {
  if (!items.length) return;

  // Deduplicate by CPE key — DynamoDB BatchWrite rejects duplicate keys in one batch
  const seen = new Map();
  for (const item of items) {
    if (item.cpe) seen.set(item.cpe, item);
  }
  const uniqueItems = Array.from(seen.values());

  const now = new Date().toISOString();
  const chunks = [];
  for (let i = 0; i < uniqueItems.length; i += 25) {
    chunks.push(uniqueItems.slice(i, i + 25));
  }

  for (const chunk of chunks) {
    const requests = chunk.map(item => ({
      PutRequest: {
        Item: {
          cpe: item.cpe,
          vendor: item.vendor || "",
          product: item.product || "",
          version: item.version || "",
          app_name: item.app_name || "",
          added_by: item.added_by || "system",
          added_at: item.added_at || now,
          updated_at: now,
          // EOL fields
          eol_date: item.eol_date || null,
          is_eol: item.is_eol || false,
          days_to_eol: item.days_to_eol ?? null,
          eol_product_slug: item.eol_product_slug || "",
          eol_release_label: item.eol_release_label || "",
          eol_recommended: item.eol_recommended || null,
          eol_alternatives: item.eol_alternatives || [],
        },
      },
    }));

    await docClient.send(new BatchWriteCommand({
      RequestItems: {
        [TABLE_NAME]: requests,
      },
    }));
  }

  console.log(`DynamoDB: wrote ${uniqueItems.length} unique CPEs to ${TABLE_NAME} (${items.length - uniqueItems.length} duplicates removed)`);
}

/**
 * Get all CPEs from the table (full scan – fine for a bounded set of CPEs).
 * @returns {Promise<Array<object>>}
 */
export async function getAllCpes() {
  const items = [];
  let lastKey;

  do {
    const res = await docClient.send(new ScanCommand({
      TableName: TABLE_NAME,
      ExclusiveStartKey: lastKey,
    }));
    items.push(...(res.Items || []));
    lastKey = res.LastEvaluatedKey;
  } while (lastKey);

  return items;
}

/**
 * Delete all CPEs added by a specific user.
 * Scans for items where `added_by` matches, then batch-deletes them.
 * @param {string} userSub – the user's Cognito sub
 * @returns {Promise<number>} number of items deleted
 */
export async function deleteAllCpesForUser(userSub) {
  // First, scan for all CPEs belonging to this user
  const items = [];
  let lastKey;

  do {
    const res = await docClient.send(new ScanCommand({
      TableName: TABLE_NAME,
      FilterExpression: "added_by = :user",
      ExpressionAttributeValues: { ":user": userSub },
      ProjectionExpression: "cpe",
      ExclusiveStartKey: lastKey,
    }));
    items.push(...(res.Items || []));
    lastKey = res.LastEvaluatedKey;
  } while (lastKey);

  if (!items.length) return 0;

  // Batch delete (25 per call)
  const chunks = [];
  for (let i = 0; i < items.length; i += 25) {
    chunks.push(items.slice(i, i + 25));
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

  console.log(`DynamoDB: deleted ${items.length} CPEs for user ${userSub}`);
  return items.length;
}
