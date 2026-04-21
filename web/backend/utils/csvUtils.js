import fs from "fs";
import csv from "csv-parser";
import { Readable } from "stream";

const INTUNE_AGGREGATE_HEADERS = [
  "ApplicationKey", "ApplicationName", "ApplicationPublisher",
  "ApplicationShortVersion", "ApplicationVersion", "DeviceCount", "Platform"
];

const INTUNE_RAW_HEADERS = [
  "ApplicationKey","ApplicationName","ApplicationPublisher","ApplicationShortVersion",
  "ApplicationVersion","DeviceID","DeviceName","OSDescription","OSVersion",
  "Platform","UserID","EmailAddress","UserName"
];

/**
 * Detect whether CSV is IntuneRaw, IntuneAggregate, or Unknown
 */
export function detectCsvType(filePath) {
  return new Promise((resolve, reject) => {
    let resolved = false;
    fs.createReadStream(filePath)
      .pipe(csv())
      .on("headers", (parsedHeaders) => {
        const headers = parsedHeaders.map(h => h.trim());
        const isAggregate = headers.length === INTUNE_AGGREGATE_HEADERS.length &&
                            headers.every((h,i) => h === INTUNE_AGGREGATE_HEADERS[i]);
        const isRaw = headers.length === INTUNE_RAW_HEADERS.length &&
                      headers.every((h,i) => h === INTUNE_RAW_HEADERS[i]);
        resolved = true;
        resolve(isAggregate ? "IntuneAggregate" : isRaw ? "IntuneRaw" : "Unknown");
      })
      .on("end", () => { if (!resolved) resolve("Unknown"); })
      .on("error", reject);
  });
}

/**
 * Build a structured JSON visual schema from CSV
 */
export function buildVisualSchema(filePath, fileType, orgName = "Imported Organization") {
  return new Promise((resolve, reject) => {
    const usersMap = new Map();
    const devicesMap = new Map();
    const appsMap = new Map();
    const platformMap = new Map(); // Track platform counts

    fs.createReadStream(filePath)
      .pipe(csv())
      .on("data", (row) => {

        // ---------- RAW DATA ----------
        if (fileType === "IntuneRaw") {
          // Users
          if (row.UserID && !usersMap.has(row.UserID)) {
            usersMap.set(row.UserID, {
              user_id: row.UserID,
              username: row.UserName || "Unknown",
              email_address: row.EmailAddress || "Unknown",
              org_id: "org-001"
            });
          }

          // Devices
          if (row.DeviceID && !devicesMap.has(row.DeviceID)) {
            devicesMap.set(row.DeviceID, {
              device_id: row.DeviceID,
              device_name: row.DeviceName || "Unknown",
              os_description: row.OSDescription || "Unknown",
              os_version: row.OSVersion || "Unknown",
              platform: row.Platform || "Unknown",
              user_id: row.UserID
            });
          }

          // Applications
          if (row.ApplicationKey) {
            if (!appsMap.has(row.ApplicationKey)) {
              appsMap.set(row.ApplicationKey, {
                application_key: row.ApplicationKey,
                application_name: row.ApplicationName,
                application_publisher: row.ApplicationPublisher,
                application_short_version: row.ApplicationShortVersion,
                application_version: row.ApplicationVersion,
                device_ids: row.DeviceID ? [row.DeviceID] : [],
                platforms: row.Platform ? [row.Platform] : []
              });
            } else {
              const app = appsMap.get(row.ApplicationKey);
              if (row.DeviceID && !app.device_ids.includes(row.DeviceID)) {
                app.device_ids.push(row.DeviceID);
              }
              if (row.Platform && !app.platforms.includes(row.Platform)) {
                app.platforms.push(row.Platform);
              }
            }
          }

          // Track platforms
          const platform = row.Platform || "Unknown";
          platformMap.set(platform, (platformMap.get(platform) || 0) + 1);

        // ---------- AGGREGATE DATA ----------
        } else if (fileType === "IntuneAggregate") {
          // Track platform device counts
          const platform = row.Platform || "Unknown";
          const count = parseInt(row.DeviceCount, 10) || 0;
          platformMap.set(platform, (platformMap.get(platform) || 0) + count);

          // Applications pointing to platforms
          if (row.ApplicationKey) {
            if (!appsMap.has(row.ApplicationKey)) {
              appsMap.set(row.ApplicationKey, {
                application_key: row.ApplicationKey,
                application_name: row.ApplicationName,
                application_publisher: row.ApplicationPublisher,
                application_short_version: row.ApplicationShortVersion,
                application_version: row.ApplicationVersion,
                platforms: [platform]
              });
            } else {
              const app = appsMap.get(row.ApplicationKey);
              if (!app.platforms.includes(platform)) app.platforms.push(platform);
            }
          }
        }

      })
      .on("end", () => {
        // Build final schema
        const schema = {
          type: fileType,
          org: { org_id: "org-001", org_name: orgName },
          users: Array.from(usersMap.values()),
          devices: Array.from(devicesMap.values()),
          applications: Array.from(appsMap.values()),
          Platforms: Array.from(platformMap.entries()).map(([platform_name, platform_device_count]) => ({
            platform_name,
            platform_device_count
          }))
        };

        resolve(schema);
      })
      .on("error", reject);
  });
}

/**
 * Detect CSV type from a readable stream (e.g. S3 body).
 * @param {ReadableStream} stream
 * @returns {Promise<string>}
 */
export function detectCsvTypeFromStream(stream) {
  return new Promise((resolve, reject) => {
    let resolved = false;
    const readable = stream instanceof Readable ? stream : Readable.from(stream);
    readable
      .pipe(csv())
      .on("headers", (parsedHeaders) => {
        const headers = parsedHeaders.map(h => h.trim());
        const isAggregate = headers.length === INTUNE_AGGREGATE_HEADERS.length &&
                            headers.every((h,i) => h === INTUNE_AGGREGATE_HEADERS[i]);
        const isRaw = headers.length === INTUNE_RAW_HEADERS.length &&
                      headers.every((h,i) => h === INTUNE_RAW_HEADERS[i]);
        resolved = true;
        resolve(isAggregate ? "IntuneAggregate" : isRaw ? "IntuneRaw" : "Unknown");
      })
      .on("end", () => { if (!resolved) resolve("Unknown"); })
      .on("error", reject);
  });
}

/**
 * Build visual schema from a readable stream (e.g. S3 body).
 * @param {ReadableStream} stream
 * @param {string} fileType
 * @param {string} orgName
 * @returns {Promise<object>}
 */
export function buildVisualSchemaFromStream(stream, fileType, orgName = "Imported Organization") {
  return new Promise((resolve, reject) => {
    const usersMap = new Map();
    const devicesMap = new Map();
    const appsMap = new Map();
    const platformMap = new Map();

    const readable = stream instanceof Readable ? stream : Readable.from(stream);
    readable
      .pipe(csv())
      .on("data", (row) => {
        if (fileType === "IntuneRaw") {
          if (row.UserID && !usersMap.has(row.UserID)) {
            usersMap.set(row.UserID, {
              user_id: row.UserID,
              username: row.UserName || "Unknown",
              email_address: row.EmailAddress || "Unknown",
              org_id: "org-001"
            });
          }
          if (row.DeviceID && !devicesMap.has(row.DeviceID)) {
            devicesMap.set(row.DeviceID, {
              device_id: row.DeviceID,
              device_name: row.DeviceName || "Unknown",
              os_description: row.OSDescription || "Unknown",
              os_version: row.OSVersion || "Unknown",
              platform: row.Platform || "Unknown",
              user_id: row.UserID
            });
          }
          if (row.ApplicationKey) {
            if (!appsMap.has(row.ApplicationKey)) {
              appsMap.set(row.ApplicationKey, {
                application_key: row.ApplicationKey,
                application_name: row.ApplicationName,
                application_publisher: row.ApplicationPublisher,
                application_short_version: row.ApplicationShortVersion,
                application_version: row.ApplicationVersion,
                device_ids: row.DeviceID ? [row.DeviceID] : [],
                platforms: row.Platform ? [row.Platform] : []
              });
            } else {
              const app = appsMap.get(row.ApplicationKey);
              if (row.DeviceID && !app.device_ids.includes(row.DeviceID)) app.device_ids.push(row.DeviceID);
              if (row.Platform && !app.platforms.includes(row.Platform)) app.platforms.push(row.Platform);
            }
          }
          const platform = row.Platform || "Unknown";
          platformMap.set(platform, (platformMap.get(platform) || 0) + 1);

        } else if (fileType === "IntuneAggregate") {
          const platform = row.Platform || "Unknown";
          const count = parseInt(row.DeviceCount, 10) || 0;
          platformMap.set(platform, (platformMap.get(platform) || 0) + count);
          if (row.ApplicationKey) {
            if (!appsMap.has(row.ApplicationKey)) {
              appsMap.set(row.ApplicationKey, {
                application_key: row.ApplicationKey,
                application_name: row.ApplicationName,
                application_publisher: row.ApplicationPublisher,
                application_short_version: row.ApplicationShortVersion,
                application_version: row.ApplicationVersion,
                platforms: [platform]
              });
            } else {
              const app = appsMap.get(row.ApplicationKey);
              if (!app.platforms.includes(platform)) app.platforms.push(platform);
            }
          }
        }
      })
      .on("end", () => {
        resolve({
          type: fileType,
          org: { org_id: "org-001", org_name: orgName },
          users: Array.from(usersMap.values()),
          devices: Array.from(devicesMap.values()),
          applications: Array.from(appsMap.values()),
          Platforms: Array.from(platformMap.entries()).map(([platform_name, platform_device_count]) => ({
            platform_name, platform_device_count
          }))
        });
      })
      .on("error", reject);
  });
}
