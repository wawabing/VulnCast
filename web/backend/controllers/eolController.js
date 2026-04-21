import { fetchProductCatalog, enrichAppWithEol, enrichDeviceOsWithEol } from "../services/eolService.js";

/**
 * POST /api/eol
 * Body: { applications: [{ name, version }], devices: [{ os_description, os_version }] }
 * Returns EOL data for each item.
 */
export async function getEolForApps(req, res) {
  try {
    await fetchProductCatalog();

    const { applications = [], devices = [] } = req.body;
    const results = { applications: [], devices: [] };

    // Enrich apps in batches of 5
    for (let i = 0; i < applications.length; i += 5) {
      const batch = applications.slice(i, i + 5);
      const batchResults = await Promise.all(
        batch.map(app => enrichAppWithEol(app.name, app.version))
      );
      results.applications.push(...batchResults);
    }

    // Enrich devices in batches of 5
    for (let i = 0; i < devices.length; i += 5) {
      const batch = devices.slice(i, i + 5);
      const batchResults = await Promise.all(
        batch.map(d => enrichDeviceOsWithEol(d.os_description, d.os_version))
      );
      results.devices.push(...batchResults);
    }

    res.json({ success: true, eol: results });
  } catch (error) {
    console.error("EOL lookup error:", error);
    res.status(500).json({ success: false, error: error.message });
  }
}
