/**
 * SBOM Controller — handles upload, parsing, OSV analysis, and S3 persistence.
 *
 * S3 layout per user:
 *   sboms/{userSub}/manifest.json            — index of all SBOMs + coverage data
 *   sboms/{userSub}/results/{timestamp}.json  — individual scan results
 */

import { parseSbom, identifySbomFormat, extractSbomMetadata } from "../utils/parseSbom.js";
import { analyzeVulnerabilities } from "../services/osvService.js";
import { putJSON, getJSON, listObjects } from "../services/s3Service.js";

// ─── helpers ────────────────────────────────────────────────────────

function userPrefix(userSub) {
  return `sboms/${userSub}`;
}

async function getManifest(userSub) {
  try {
    return await getJSON(`${userPrefix(userSub)}/manifest.json`);
  } catch {
    return { scans: [], coverage: {} };
  }
}

async function saveManifest(userSub, manifest) {
  await putJSON(`${userPrefix(userSub)}/manifest.json`, manifest);
}

// ─── Upload + Analyse (one-shot) ────────────────────────────────────

/**
 * POST /api/sbom/upload
 * Accepts multipart file via Multer (memoryStorage).
 * Streams SSE progress events back to the client:
 *   { type: "status", message }    — parsing / saving phases
 *   { type: "parsed", format, components }
 *   { type: "start", totalComponents }
 *   { type: "progress", component, index, total, status, ... }
 *   { type: "complete", results: scan_metadata }
 *   { type: "done", success, scan, coverage }
 *   { type: "error", error }
 */
export async function uploadAndAnalyse(req, res) {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });

  const userSub = req.session?.userInfo?.sub || "anonymous";
  const applicationKey = req.body.applicationKey || null;
  const applicationName = req.body.applicationName || null;
  const buffer = req.file.buffer;
  const fileName = req.file.originalname;

  // Switch to Server-Sent Events
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  const send = (data) => {
    try { res.write(`data: ${JSON.stringify(data)}\n\n`); } catch { /* client gone */ }
  };

  try {
    // 1. Identify format + metadata
    send({ type: "status", message: "Parsing SBOM…" });
    const format = identifySbomFormat(buffer);
    const metadata = extractSbomMetadata(buffer, fileName);

    // 2. Parse components
    const components = parseSbom(buffer);
    send({ type: "parsed", format, components: components.length });
    console.log(`SBOM parsed: ${fileName} → ${format}, ${components.length} components`);

    // 3. OSV analysis — stream progress back
    const results = await analyzeVulnerabilities(components, metadata, (event) => {
      send(event);
    });

    // 4. Persist results to S3
    send({ type: "status", message: "Saving results…" });
    const ts = Date.now();
    const resultKey = `${userPrefix(userSub)}/results/${ts}-${fileName.replace(/[^a-zA-Z0-9._-]/g, "_")}.json`;
    await putJSON(resultKey, results);

    // 5. Update manifest
    const manifest = await getManifest(userSub);

    const scanEntry = {
      id: `scan-${ts}`,
      timestamp: new Date().toISOString(),
      fileName,
      format,
      applicationKey,
      applicationName: applicationName || metadata.application_name || fileName.replace(/\.[^.]+$/, ""),
      applicationVendor: metadata.application_vendor || null,
      applicationVersion: metadata.application_version || null,
      resultKey,
      totalComponents: results.scan_metadata.total_components_scanned,
      vulnerableComponents: results.scan_metadata.vulnerable_components_found,
      totalVulnerabilities: results.scan_metadata.total_vulnerabilities_found,
      skippedComponents: results.scan_metadata.skipped_components || 0,
    };

    manifest.scans.push(scanEntry);
    manifest.coverage = computeCoverage(manifest);
    await saveManifest(userSub, manifest);

    send({ type: "done", success: true, scan: scanEntry, coverage: manifest.coverage });
  } catch (err) {
    console.error("SBOM upload error:", err);
    send({ type: "error", error: err.message });
  }

  res.end();
}

// ─── Get manifest (all scans + coverage) ────────────────────────────

/**
 * GET /api/sbom/manifest
 */
export async function getManifestRoute(req, res) {
  try {
    const userSub = req.session?.userInfo?.sub || "anonymous";
    const manifest = await getManifest(userSub);
    res.json({ success: true, ...manifest });
  } catch (err) {
    console.error("Manifest error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
}

// ─── Get individual scan results ────────────────────────────────────

/**
 * GET /api/sbom/results/:scanId
 */
export async function getScanResults(req, res) {
  try {
    const userSub = req.session?.userInfo?.sub || "anonymous";
    const { scanId } = req.params;
    const manifest = await getManifest(userSub);
    const scan = manifest.scans.find((s) => s.id === scanId);
    if (!scan) return res.status(404).json({ success: false, error: "Scan not found" });

    const results = await getJSON(scan.resultKey);
    res.json({ success: true, scan, results });
  } catch (err) {
    console.error("Scan results error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
}

// ─── Delete a scan ──────────────────────────────────────────────────

/**
 * DELETE /api/sbom/scans/:scanId
 */
export async function deleteScan(req, res) {
  try {
    const userSub = req.session?.userInfo?.sub || "anonymous";
    const { scanId } = req.params;
    const manifest = await getManifest(userSub);
    manifest.scans = manifest.scans.filter((s) => s.id !== scanId);
    manifest.coverage = computeCoverage(manifest);
    await saveManifest(userSub, manifest);
    res.json({ success: true });
  } catch (err) {
    console.error("Delete scan error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
}

// ─── Coverage computation ───────────────────────────────────────────

/**
 * Coverage score = (apps that have an SBOM scan) / (total apps).
 * We match SBOM scans to the user's enriched schema applications.
 */
function computeCoverage(manifest) {
  const scannedAppKeys = new Set();
  const scannedNames = new Set();

  for (const scan of manifest.scans) {
    if (scan.applicationKey) scannedAppKeys.add(scan.applicationKey);
    if (scan.applicationName) scannedNames.add(scan.applicationName.toLowerCase());
  }

  // We store computed stats; the frontend will merge with schema data
  return {
    scannedAppKeys: [...scannedAppKeys],
    scannedAppNames: [...scannedNames],
    totalScans: manifest.scans.length,
    lastScanTimestamp: manifest.scans.length > 0 ? manifest.scans[manifest.scans.length - 1].timestamp : null,
  };
}
