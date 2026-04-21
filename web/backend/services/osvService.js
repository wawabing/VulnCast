/**
 * OSV Service — queries https://api.osv.dev for open-source vulnerabilities.
 * Ported from application-v1 to ESM; uses native fetch (Node 18+).
 */

const OSV_API = "https://api.osv.dev/v1";
const TIMEOUT = 10_000;
const MAX_RETRIES = 3;

// ─── Low-level helpers ──────────────────────────────────────────────

async function osvPost(path, body, retries = 0) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT);

    const res = await fetch(`${OSV_API}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (!res.ok) throw new Error(`OSV ${res.status}`);
    return await res.json();
  } catch (err) {
    if (retries < MAX_RETRIES) {
      await new Promise((r) => setTimeout(r, 2 ** retries * 1000));
      return osvPost(path, body, retries + 1);
    }
    console.error(`OSV API failed after ${MAX_RETRIES} retries:`, err.message);
    return null;
  }
}

async function queryByVersion(name, version, ecosystem) {
  return osvPost("/query", { version, package: { name, ecosystem } });
}

async function queryByHash(hashValue) {
  return osvPost("/query", { commit: hashValue });
}

async function queryByPurl(purl) {
  return osvPost("/query", { package: { purl } });
}

// ─── Ecosystem mapper ───────────────────────────────────────────────

function getEcosystem(purl) {
  if (!purl) return null;
  const map = {
    "pkg:golang/": "Go",
    "pkg:pypi/": "PyPI",
    "pkg:npm/": "npm",
    "pkg:maven/": "Maven",
    "pkg:nuget/": "NuGet",
    "pkg:cargo/": "crates.io",
    "pkg:composer/": "Packagist",
    "pkg:gem/": "RubyGems",
    "pkg:hex/": "Hex",
    "pkg:pub/": "Pub",
    "pkg:swift/": "SwiftURL",
    "pkg:cocoapods/": "CocoaPods",
    "pkg:hackage/": "Hackage",
    "pkg:deb/": "Debian",
    "pkg:apk/": "Alpine",
    "pkg:rpm/": "Red Hat",
    "pkg:cran/": "CRAN",
    "pkg:bitnami/": "Bitnami",
    "pkg:chainguard/": "Chainguard",
    "pkg:wolfi/": "Wolfi",
  };
  for (const [prefix, eco] of Object.entries(map)) {
    if (purl.startsWith(prefix)) return eco;
  }
  return null;
}

// ─── Single component processing ────────────────────────────────────

async function processComponent(component, index, total, progressCb) {
  const core = component.core || {};
  const ctx = component.context || {};
  const name = core.name || "UNKNOWN";
  const version = core.version || "UNKNOWN";
  const purl = core.purl;
  const ecosystem = getEcosystem(purl);
  const sha256 = ctx.hashes?.["sha-256"] || ctx.hashes?.sha256;

  if (progressCb) progressCb({ type: "progress", component: name, index, total, status: "processing" });

  // If we have nothing to query with, skip
  if (!purl && !sha256 && !ecosystem) {
    if (progressCb) progressCb({ type: "progress", component: name, index, total, status: "skipped", reason: "No package URL, hash, or ecosystem" });
    return null;
  }

  let result = null;
  let method = "";

  try {
    // 1. PURL-based query (most reliable — OSV resolves ecosystem internally)
    if (purl) {
      result = await queryByPurl(purl);
      if (result?.vulns?.length) method = "purl";
    }

    // 2. Hash fallback
    if (!result?.vulns?.length && sha256) {
      result = await queryByHash(sha256);
      if (result?.vulns?.length) method = "hash";
    }

    // 3. Name + version + ecosystem fallback
    if (!result?.vulns?.length && ecosystem) {
      result = await queryByVersion(name, version, ecosystem);
      if (result?.vulns?.length) method = "version";
    }

    const count = result?.vulns?.length || 0;
    if (progressCb) progressCb({ type: "progress", component: name, index, total, status: count > 0 ? "vulnerable" : "clean", vulnerabilityCount: count });

    if (count > 0) {
      return {
        component_index: index,
        component,
        search_method: method,
        vulnerabilities: result.vulns,
        vulnerability_count: count,
      };
    }
  } catch (err) {
    console.error(`OSV error for ${name}:`, err.message);
    if (progressCb) progressCb({ type: "progress", component: name, index, total, status: "error", error: err.message });
  }

  return null;
}

// ─── Batch analysis ─────────────────────────────────────────────────

export async function analyzeVulnerabilities(components, metadata = {}, progressCb = null) {
  const start = Date.now();
  const vulnerablePackages = [];
  let totalVulns = 0;
  let skippedCount = 0;
  let errorCount = 0;

  // Wrap callback to track skips / errors
  const trackCb = progressCb
    ? (event) => {
        if (event.type === "progress") {
          if (event.status === "skipped") skippedCount++;
          if (event.status === "error") errorCount++;
        }
        progressCb(event);
      }
    : null;

  if (progressCb) progressCb({ type: "start", totalComponents: components.length });

  const CONCURRENCY = 10;
  for (let i = 0; i < components.length; i += CONCURRENCY) {
    const batch = components.slice(i, i + CONCURRENCY);
    const results = await Promise.all(
      batch.map((c, bi) => processComponent(c, i + bi, components.length, trackCb))
    );
    for (const r of results) {
      if (r) {
        vulnerablePackages.push(r);
        totalVulns += r.vulnerability_count;
      }
    }
  }

  const elapsed = (Date.now() - start) / 1000;

  const output = {
    sbom_origin: metadata,
    scan_metadata: {
      scan_timestamp: new Date().toISOString(),
      total_components_scanned: components.length,
      vulnerable_components_found: vulnerablePackages.length,
      total_vulnerabilities_found: totalVulns,
      skipped_components: skippedCount,
      error_components: errorCount,
      vulnerable_component_rate: `${((vulnerablePackages.length / Math.max(components.length, 1)) * 100).toFixed(1)}%`,
      processing_time_seconds: Math.round(elapsed * 100) / 100,
    },
    vulnerable_packages: vulnerablePackages,
  };

  if (progressCb) progressCb({ type: "complete", results: output.scan_metadata });

  return output;
}

export { getEcosystem };
