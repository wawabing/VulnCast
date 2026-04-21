/**
 * EOL (End-of-Life) Service
 * 
 * Queries https://endoflife.date/api/v1 to detect product EOL status,
 * recommend upgrades, and suggest alternatives.
 * 
 * Ported from EOL_finder.py — same matching logic, caching strategy,
 * and Windows edition handling.
 */

const BASE = "https://endoflife.date/api/v1";

// ── Caches ─────────────────────────────────────────────────
let productCatalog = [];       // full product list from API
const releaseCache  = {};      // product_slug -> releases array
const matchCache    = {};      // raw input string -> product_slug | null
const tagProducts   = {};      // tag -> [product dicts]
const latestCache   = {};      // product_slug -> latest non-EOL release

let catalogLoaded = false;

// ── Resilient fetch with retry ─────────────────────────────
async function resilientFetch(url, retries = 3, backoff = 1000) {
  for (let i = 0; i < retries; i++) {
    try {
      const res = await fetch(url, {
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(15000),
      });
      if (res.status === 429 || res.status >= 500) {
        if (i < retries - 1) {
          await new Promise(r => setTimeout(r, backoff * (i + 1)));
          continue;
        }
      }
      return res;
    } catch (err) {
      if (i < retries - 1) {
        await new Promise(r => setTimeout(r, backoff * (i + 1)));
        continue;
      }
      throw err;
    }
  }
}

// ── Normalise helper ───────────────────────────────────────
function normalize(text) {
  return text.toLowerCase().replace(/[^a-z0-9\s]/g, "").trim();
}

// ── Fetch product catalog ──────────────────────────────────
export async function fetchProductCatalog() {
  if (catalogLoaded && productCatalog.length > 0) return;
  try {
    const res = await resilientFetch(`${BASE}/products/`);
    if (!res.ok) throw new Error(`Catalog fetch failed: ${res.status}`);
    const data = await res.json();
    productCatalog = data.result || data;

    // Build tag → product index
    for (const p of productCatalog) {
      for (const t of p.tags || []) {
        if (!tagProducts[t]) tagProducts[t] = [];
        tagProducts[t].push(p);
      }
    }
    catalogLoaded = true;
    console.log(`EOL Service: loaded ${productCatalog.length} products from endoflife.date`);
  } catch (err) {
    console.error("EOL Service: failed to load product catalog:", err.message);
  }
}

// ── Dynamic product matcher ────────────────────────────────
export function findProduct(inputString) {
  if (!inputString) return null;
  if (matchCache[inputString] !== undefined) return matchCache[inputString];

  const normInput = normalize(inputString);
  let bestMatch = null;
  let bestScore = 0;

  for (const product of productCatalog) {
    const candidates = [product.label, product.name, ...(product.aliases || [])];

    for (const candidate of candidates) {
      const normCand = normalize(candidate);
      if (!normCand) continue;

      // Exact match
      if (normCand === normInput) {
        matchCache[inputString] = product.name;
        return product.name;
      }

      // Candidate is substring of input (word-boundary)
      if (normCand.length >= 3 && normInput.includes(normCand)) {
        const re = new RegExp("\\b" + normCand.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\b");
        if (re.test(normInput)) {
          const score = normCand.length / Math.max(normInput.length, 1) + 0.2;
          if (score > bestScore) {
            bestScore = score;
            bestMatch = product.name;
          }
        }
      }

      // Input is substring of candidate (word-boundary)
      if (normInput.length >= 3 && normCand.includes(normInput)) {
        const re = new RegExp("\\b" + normInput.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\b");
        if (re.test(normCand)) {
          const score = normInput.length / Math.max(normCand.length, 1) + 0.2;
          if (score > bestScore) {
            bestScore = score;
            bestMatch = product.name;
          }
        }
      }
    }
  }

  const result = bestScore >= 0.45 ? bestMatch : null;
  matchCache[inputString] = result;
  return result;
}

// ── Get product label ──────────────────────────────────────
function getProductLabel(slug) {
  for (const p of productCatalog) {
    if (p.name === slug) return p.label;
  }
  return slug;
}

// ── Get product tags ───────────────────────────────────────
function getProductTags(slug) {
  for (const p of productCatalog) {
    if (p.name === slug) return p.tags || [];
  }
  return [];
}

// ── Get product category ───────────────────────────────────
function getProductCategory(slug) {
  for (const p of productCatalog) {
    if (p.name === slug) return p.category || "";
  }
  return "";
}

// ── Fetch releases ─────────────────────────────────────────
export async function getReleases(productSlug) {
  if (releaseCache[productSlug]) return releaseCache[productSlug];
  try {
    const res = await resilientFetch(`${BASE}/products/${productSlug}`);
    if (!res.ok) {
      releaseCache[productSlug] = [];
      return [];
    }
    const data = await res.json();
    const releases = data.result?.releases || data.releases || [];
    releaseCache[productSlug] = releases;
    return releases;
  } catch (err) {
    console.error(`EOL Service: failed to fetch releases for ${productSlug}:`, err.message);
    releaseCache[productSlug] = [];
    return [];
  }
}

// ── Version → release matcher ──────────────────────────────
export async function matchRelease(productSlug, versionString, description = "") {
  const releases = await getReleases(productSlug);
  if (!releases.length) return null;

  // Windows-specific: pick edition (-e / -w) by description
  if (productSlug === "windows") {
    const isEnterprise = /Enterprise|Education/i.test(description);
    const suffix = isEnterprise ? "-e" : "-w";

    const matches = releases.filter(r => (r.latest?.name || "") === versionString);
    const edition = matches.filter(r => r.name.endsWith(suffix));
    if (edition.length) return edition[0];
    if (matches.length) return matches[0];

    for (const r of releases) {
      const ln = r.latest?.name || "";
      if (ln && versionString.startsWith(ln) && r.name.endsWith(suffix)) return r;
    }
    for (const r of releases) {
      const ln = r.latest?.name || "";
      if (ln && versionString.startsWith(ln)) return r;
    }
    return null;
  }

  // Generic matching
  for (const r of releases) {
    const latestName = r.latest?.name || "";
    if (versionString === (r.name || "") || versionString === latestName) return r;
  }

  for (const r of releases) {
    const cycle = r.name || "";
    if (cycle && (versionString.startsWith(cycle + ".") || versionString.startsWith(cycle + "-"))) {
      return r;
    }
  }

  const major = versionString ? versionString.split(".")[0] : "";
  if (major) {
    for (const r of releases) {
      if ((r.name || "") === major) return r;
    }
  }

  return null;
}

// ── Find best non-EOL release ──────────────────────────────
export async function getRecommendedRelease(productSlug, description = "") {
  const releases = await getReleases(productSlug);
  if (!releases.length) return null;

  if (productSlug === "windows") {
    const isEnterprise = /Enterprise|Education/i.test(description);
    const suffix = isEnterprise ? "-e" : "-w";
    for (const r of releases) {
      if (!r.isEol && r.name.endsWith(suffix)) return r;
    }
    for (const r of releases) {
      if (!r.isEol) return r;
    }
    return null;
  }

  for (const r of releases) {
    if (!r.isEol) return r;
  }
  return null;
}

// ── Format release recommendation ──────────────────────────
function formatReleaseRec(productSlug, release) {
  if (!release) return "";
  const label = getProductLabel(productSlug);
  const ver = release.label || release.name || "";
  const latestVer = release.latest?.name || "";
  const eolFrom = release.eolFrom || "";

  let text = `${label} ${ver}`;
  if (latestVer) text += ` (build ${latestVer})`;
  text += eolFrom ? ` | EOL: ${eolFrom}` : " | no EOL date set";
  return text;
}

// ── Find alternative products via shared tags ──────────────
const BROAD_TAGS = new Set([
  "app", "os", "framework", "lang", "server-app", "service",
  "database", "device", "standard",
  "microsoft", "google", "amazon", "alibaba", "apple", "red-hat",
  "oracle", "ibm", "cisco", "adobe", "meta", "intel", "nvidia",
  "atlassian", "elastic", "hashicorp", "jetbrains", "sap",
  "vmware", "hpe", "fortinet", "citrix", "gitlab", "herodevs",
  "bellsoft", "azul", "eclipse", "cncf", "linux-foundation",
  "progress", "sonarsource", "sony", "suse", "veeam", "veritas",
  "vercel", "zerto", "mondoo", "netapp", "stormshield",
  "mikrotik", "nutanix", "palo-alto-networks", "mozilla",
  "influxdata", "meilisearch", "motorola", "rust-foundation",
]);

export async function getAlternatives(productSlug, maxAlternatives = 3) {
  const tags = getProductTags(productSlug);
  const productCategory = getProductCategory(productSlug);
  const specificTags = tags.filter(t => !BROAD_TAGS.has(t));

  if (!specificTags.length) return [];

  const seen = new Set([productSlug]);
  const alternatives = [];

  for (const tag of specificTags) {
    for (const p of (tagProducts[tag] || [])) {
      const slug = p.name;
      if (seen.has(slug)) continue;
      if (productCategory && (p.category || "") !== productCategory) continue;
      seen.add(slug);

      const rec = await getRecommendedRelease(slug);
      if (!rec) continue;

      alternatives.push({
        product_slug: slug,
        label: p.label,
        release: rec.label || rec.name || "",
        latest_build: rec.latest?.name || "",
        eol_date: rec.eolFrom || "",
      });
      if (alternatives.length >= maxAlternatives) return alternatives;
    }
  }

  return alternatives;
}

// ── Days until EOL ─────────────────────────────────────────
function daysUntilEol(eolDateStr) {
  if (!eolDateStr) return null;
  try {
    const eolDate = new Date(eolDateStr);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    eolDate.setHours(0, 0, 0, 0);
    return Math.round((eolDate - today) / (1000 * 60 * 60 * 24));
  } catch {
    return null;
  }
}

// ── Build full EOL result for a product+version ────────────
export async function getEolResult(productSlug, version, description = "") {
  const empty = {
    product_slug: "", release_label: "", eol_date: null, is_eol: false,
    days_to_eol: null, recommended: null, alternatives: [],
  };

  if (!productSlug) return empty;

  const release = await matchRelease(productSlug, version, description);
  if (!release) {
    return { ...empty, product_slug: productSlug, release_label: "no match" };
  }

  const isEol = release.isEol === true;
  const eolFrom = release.eolFrom || null;
  const dToEol = daysUntilEol(eolFrom);

  // Build upgrade recommendation if EOL or approaching EOL (< 180 days)
  const needsUpgrade = isEol || (typeof dToEol === "number" && dToEol < 180);

  let recommended = null;
  let alternatives = [];

  if (needsUpgrade) {
    const recRelease = await getRecommendedRelease(productSlug, description);
    if (recRelease && recRelease.name !== release.name) {
      recommended = {
        product_slug: productSlug,
        label: getProductLabel(productSlug),
        release: recRelease.label || recRelease.name || "",
        latest_build: recRelease.latest?.name || "",
        eol_date: recRelease.eolFrom || null,
        formatted: formatReleaseRec(productSlug, recRelease),
      };
    }

    alternatives = await getAlternatives(productSlug);
  }

  return {
    product_slug: productSlug,
    release_label: release.label || release.name || "",
    eol_date: eolFrom,
    is_eol: isEol,
    days_to_eol: dToEol,
    recommended,
    alternatives,
  };
}

// ── Enrich a single application with EOL data ──────────────
export async function enrichAppWithEol(appName, appVersion, description = "") {
  if (!catalogLoaded) await fetchProductCatalog();

  const slug = findProduct(appName);
  return getEolResult(slug, appVersion, description);
}

// ── Enrich a single device OS with EOL data ────────────────
export async function enrichDeviceOsWithEol(osDescription, osVersion) {
  if (!catalogLoaded) await fetchProductCatalog();

  const slug = findProduct(osDescription);
  return getEolResult(slug, osVersion, osDescription);
}
