import path from "path";
import fs from "fs";
import { Readable } from "stream";
import { detectCsvType, buildVisualSchema, detectCsvTypeFromStream, buildVisualSchemaFromStream } from "../utils/csvUtils.js";
import { CveService } from "../services/cveService.js";
import { putObject, putJSON, getJSON, getObjectStream, deleteObjectsByPrefix } from "../services/s3Service.js";
import { batchPutCpes, deleteAllCpesForUser } from "../services/dynamoService.js";
import { deleteAllForecastResults } from "../services/forecastService.js";
import { fetchProductCatalog, enrichAppWithEol, enrichDeviceOsWithEol } from "../services/eolService.js";

const cveService = new CveService();

/**
 * Handle CSV upload → store in S3, parse into schema, store schema in S3.
 * The uploaded file arrives via Multer (in memory buffer via memoryStorage).
 */
export async function handleUpload(req, res) {
  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  try {
    const userSub = req.session?.userInfo?.sub || "anonymous";
    const timestamp = Date.now();
    const safeName = req.file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_");
    const csvKey = `uploads/${userSub}/${timestamp}-${safeName}`;

    // Clean up old data from previous uploads for this user
    await Promise.all([
      deleteObjectsByPrefix(`schemas/${userSub}/`),
      deleteObjectsByPrefix(`uploads/${userSub}/`),
      deleteAllCpesForUser(userSub),
      deleteAllForecastResults(),
    ]);

    // 1. Upload raw CSV to S3
    await putObject(csvKey, req.file.buffer, "text/csv");
    console.log(`Uploaded CSV to S3: ${csvKey}`);

    // 2. Detect CSV type from the buffer
    const stream1 = Readable.from(req.file.buffer);
    const fileType = await detectCsvTypeFromStream(stream1);
    console.log(`Uploaded file: ${req.file.originalname} → Detected type: ${fileType}`);

    // 3. Build JSON schema from the buffer
    const stream2 = Readable.from(req.file.buffer);
    const schema = await buildVisualSchemaFromStream(stream2, fileType);

    // 4. Store schema JSON in S3
    const schemaKey = `schemas/${userSub}/${timestamp}-${safeName}.json`;
    await putJSON(schemaKey, schema);

    res.json({
      message: "File uploaded successfully and schema generated",
      filename: `${timestamp}-${safeName}`,
      detectedType: fileType,
      schemaKey,
      csvKey,
      needsEnrichment: true
    });
  } catch (err) {
    console.error("Error processing CSV:", err);
    res.status(500).json({ error: "Failed to process CSV" });
  }
}

/**
 * Enrich a schema stored in S3 with CVE/CPE data, then:
 *   - Save the enriched schema back to S3
 *   - Push unique CPEs to the forecast-cpes DynamoDB table
 *
 * @param {string} schemaKey – S3 key of the schema JSON
 * @param {string} [userSub] – Cognito user sub for attribution
 * @returns {Promise<object>} enriched schema
 */
export async function enrichSchema(schemaKey, userSub = "system") {
  try {
    console.log(`Starting enrichment for S3 key: ${schemaKey}`);

    const schema = await getJSON(schemaKey);
    const applications = schema.applications || [];

    if (applications.length === 0) {
      console.log('No applications found to enrich');
      return schema;
    }

    console.log(`Starting CVE enrichment for ${applications.length} applications...`);

    const batchSize = 5;
    const enrichedApplications = [];

    for (let i = 0; i < applications.length; i += batchSize) {
      const batch = applications.slice(i, i + batchSize);

      console.log(`Processing batch ${Math.floor(i / batchSize) + 1}/${Math.ceil(applications.length / batchSize)}`);

      const batchPromises = batch.map(async (app) => {
        const cveData = await cveService.getCpeAndCvesForApplication(
          app.application_name,
          app.application_version,
          app.application_publisher
        );
        return { ...app, cve_data: cveData };
      });

      const batchResults = await Promise.all(batchPromises);
      enrichedApplications.push(...batchResults);

      const progress = Math.round((enrichedApplications.length / applications.length) * 100);
      console.log(`Progress: ${progress}% (${enrichedApplications.length}/${applications.length})`);
    }

    // ── EOL enrichment pass ──
    console.log('Starting EOL enrichment...');
    await fetchProductCatalog();

    // EOL for applications
    for (let i = 0; i < enrichedApplications.length; i += 5) {
      const batch = enrichedApplications.slice(i, i + 5);
      const eolResults = await Promise.all(
        batch.map(app => enrichAppWithEol(
          app.application_name,
          app.application_short_version || app.application_version || ""
        ))
      );
      batch.forEach((app, j) => { app.eol_data = eolResults[j]; });
    }

    // EOL for devices
    const devices = schema.devices || [];
    for (let i = 0; i < devices.length; i += 5) {
      const batch = devices.slice(i, i + 5);
      const eolResults = await Promise.all(
        batch.map(d => enrichDeviceOsWithEol(
          d.os_description || "",
          d.os_version || ""
        ))
      );
      batch.forEach((d, j) => { d.eol_data = eolResults[j]; });
    }
    console.log('EOL enrichment completed.');

    // Look up CPEs and CVE counts for EOL alternative products from NVD.
    // This lets the Lambda forecast alternatives so the dashboard uses real ARIMA data.
    const altTargets = [];
    for (const app of enrichedApplications) {
      if (!app.eol_data) continue;
      const eol = app.eol_data;
      const needsLookup = eol.is_eol || (typeof eol.days_to_eol === 'number' && eol.days_to_eol < 365);
      if (!needsLookup) continue;
      if (eol.recommended) altTargets.push({ alt: eol.recommended, parentApp: app.application_name });
      if (eol.alternatives) eol.alternatives.forEach(a => altTargets.push({ alt: a, parentApp: app.application_name }));
    }
    if (altTargets.length > 0) {
      console.log(`Looking up CPEs for ${altTargets.length} EOL alternatives...`);
      for (const { alt, parentApp } of altTargets) {
        const searchName = `${alt.label || ''} ${alt.release || ''}`.trim();
        if (!searchName) { alt.cve_count = 0; alt.cpe_name = null; continue; }
        try {
          const result = await cveService.getCpeAndCvesForApplication(searchName, alt.release || '', alt.label || '');
          if (result && result.cpe_name) {
            alt.cpe_name = result.cpe_name;
            alt.cve_count = result.totalCveCount || (result.cves || []).length;
            alt.vendor = result.vendor || '';
            alt.product = result.product || '';
            console.log(`  ${searchName}: CPE=${alt.cpe_name}, ${alt.cve_count} CVEs`);
          } else {
            alt.cpe_name = null;
            alt.cve_count = 0;
            console.log(`  ${searchName}: no CPE found`);
          }
          await new Promise(r => setTimeout(r, 800)); // NVD rate limit
        } catch (err) {
          console.error(`  ${searchName}: lookup failed:`, err.message);
          alt.cpe_name = null;
          alt.cve_count = 0;
        }
      }
      console.log('Alternative CPE lookup completed.');
    }

    // Create enriched schema
    const enrichedSchema = {
      ...schema,
      devices: devices,
      applications: enrichedApplications,
      enrichment_timestamp: new Date().toISOString()
    };

    // Save enriched schema to S3
    const enrichedKey = schemaKey.replace('.json', '-enriched.json');
    await putJSON(enrichedKey, enrichedSchema);
    console.log(`CVE enrichment completed. Saved to S3: ${enrichedKey}`);

    // Extract unique CPEs and push to DynamoDB forecast-cpes table (with EOL fields)
    const cpesToTrack = [];
    for (const app of enrichedApplications) {
      if (app.cve_data && app.cve_data.cpe_name) {
        const eol = app.eol_data || {};
        cpesToTrack.push({
          cpe: app.cve_data.cpe_name,
          vendor: app.cve_data.vendor || "",
          product: app.cve_data.product || "",
          version: app.application_version || "",
          app_name: app.application_name,
          added_by: userSub,
          eol_date: eol.eol_date || null,
          is_eol: eol.is_eol || false,
          days_to_eol: eol.days_to_eol ?? null,
          eol_product_slug: eol.product_slug || "",
          eol_release_label: eol.release_label || "",
          eol_recommended: eol.recommended || null,
          eol_alternatives: eol.alternatives || [],
        });
      }
    }

    if (cpesToTrack.length > 0) {
      await batchPutCpes(cpesToTrack);
      console.log(`Pushed ${cpesToTrack.length} unique CPEs to DynamoDB forecast-cpes`);
    }

    // Also push alternative product CPEs so the Lambda forecasts them too
    // Skip alts whose CPE matches an original — same CPE = same forecast, and
    // writing it again would overwrite the original's richer EOL metadata.
    const originalCpeSet = new Set(cpesToTrack.map(c => c.cpe));
    const altCpesToTrack = [];
    for (const { alt, parentApp } of altTargets) {
      if (alt.cpe_name && !originalCpeSet.has(alt.cpe_name)) {
        altCpesToTrack.push({
          cpe: alt.cpe_name,
          vendor: alt.vendor || "",
          product: alt.product || "",
          version: alt.release || "",
          app_name: `[ALT] ${alt.label || ''} ${alt.release || ''}`.trim(),
          added_by: userSub,
          is_alternative: true,
          parent_app: parentApp,
        });
        originalCpeSet.add(alt.cpe_name); // deduplicate across alts too
      }
    }
    if (altCpesToTrack.length > 0) {
      await batchPutCpes(altCpesToTrack);
      console.log(`Pushed ${altCpesToTrack.length} alternative CPEs to DynamoDB forecast-cpes`);
    }

    return enrichedSchema;

  } catch (error) {
    console.error('Error during enrichment:', error);
    throw error;
  }
}
