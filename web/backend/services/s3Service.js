import { S3Client, PutObjectCommand, GetObjectCommand, ListObjectsV2Command, DeleteObjectsCommand } from "@aws-sdk/client-s3";

const s3 = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

const BUCKET = process.env.S3_BUCKET_NAME;

/**
 * Upload a file buffer or string to S3.
 * @param {string} key   – S3 object key, e.g. "schemas/user123/abc.json"
 * @param {Buffer|string} body
 * @param {string} contentType
 */
export async function putObject(key, body, contentType = "application/octet-stream") {
  await s3.send(new PutObjectCommand({
    Bucket: BUCKET,
    Key: key,
    Body: body,
    ContentType: contentType,
  }));
  console.log(`S3 PUT → s3://${BUCKET}/${key}`);
  return key;
}

/**
 * Download an object from S3 as a string.
 * @param {string} key
 * @returns {Promise<string>}
 */
export async function getObject(key) {
  const res = await s3.send(new GetObjectCommand({
    Bucket: BUCKET,
    Key: key,
  }));
  return await res.Body.transformToString("utf-8");
}

/**
 * Download an object from S3 as a readable stream (for CSV piping).
 * @param {string} key
 * @returns {Promise<ReadableStream>}
 */
export async function getObjectStream(key) {
  const res = await s3.send(new GetObjectCommand({
    Bucket: BUCKET,
    Key: key,
  }));
  return res.Body;
}

/**
 * Get JSON from S3 (parse automatically).
 * @param {string} key
 * @returns {Promise<object>}
 */
export async function getJSON(key) {
  const raw = await getObject(key);
  return JSON.parse(raw);
}

/**
 * Put JSON to S3.
 * @param {string} key
 * @param {object} data
 */
export async function putJSON(key, data) {
  return putObject(key, JSON.stringify(data, null, 2), "application/json");
}

/**
 * List objects under a prefix.
 * @param {string} prefix – e.g. "schemas/user123/"
 * @returns {Promise<Array<{key: string, lastModified: Date, size: number}>>}
 */
export async function listObjects(prefix) {
  const res = await s3.send(new ListObjectsV2Command({
    Bucket: BUCKET,
    Prefix: prefix,
  }));
  if (!res.Contents) return [];
  return res.Contents.map(obj => ({
    key: obj.Key,
    lastModified: obj.LastModified,
    size: obj.Size,
  }));
}

/**
 * Find the latest schema JSON under a prefix.
 * Prefers the enriched version (-enriched.json) of the newest upload.
 * Falls back to the raw schema if the enriched version doesn't exist yet.
 * @param {string} prefix
 * @returns {Promise<string|null>} S3 key of latest file, or null
 */
export async function getLatestJsonKey(prefix) {
  const objects = await listObjects(prefix);
  const jsonFiles = objects.filter(o => o.key.endsWith(".json"));
  if (!jsonFiles.length) return null;

  // Extract timestamp from filename pattern: {timestamp}-{name}.csv.json or {timestamp}-{name}.csv-enriched.json
  // Group by base key (everything before -enriched.json or .json suffix)
  const groups = new Map();
  for (const f of jsonFiles) {
    const base = f.key.replace(/-enriched\.json$/, '.json');
    if (!groups.has(base)) groups.set(base, { raw: null, enriched: null });
    const g = groups.get(base);
    if (f.key.endsWith('-enriched.json')) {
      g.enriched = f;
    } else {
      g.raw = f;
    }
  }

  // Sort groups by the raw file's lastModified (or enriched if raw missing)
  const sorted = [...groups.entries()].sort((a, b) => {
    const aTime = (a[1].raw || a[1].enriched).lastModified;
    const bTime = (b[1].raw || b[1].enriched).lastModified;
    return bTime - aTime;
  });

  const latest = sorted[0][1];
  // Prefer enriched version if it exists
  return latest.enriched ? latest.enriched.key : latest.raw.key;
}

/**
 * Delete all objects under a prefix (e.g. all schemas for a user).
 * @param {string} prefix
 * @returns {Promise<number>} number of objects deleted
 */
export async function deleteObjectsByPrefix(prefix) {
  const objects = await listObjects(prefix);
  if (!objects.length) return 0;

  // DeleteObjectsCommand handles up to 1000 keys per call
  const chunks = [];
  for (let i = 0; i < objects.length; i += 1000) {
    chunks.push(objects.slice(i, i + 1000));
  }

  let deleted = 0;
  for (const chunk of chunks) {
    await s3.send(new DeleteObjectsCommand({
      Bucket: BUCKET,
      Delete: {
        Objects: chunk.map(o => ({ Key: o.key })),
        Quiet: true,
      },
    }));
    deleted += chunk.length;
  }

  console.log(`S3 DELETE → ${deleted} objects under ${prefix}`);
  return deleted;
}

export { BUCKET, s3 };
