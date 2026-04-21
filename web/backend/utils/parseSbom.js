/**
 * SBOM Parser — ported from application-v1 to ES modules.
 * Parses CycloneDX (1.3–1.6), SPDX 2.2, and SPDX 3.0 JSON SBOMs.
 * Works with in-memory buffers (no filesystem) for S3/Multer integration.
 */

/**
 * Clean raw buffer/string, strip BOM, return parsed JSON + raw string.
 */
function cleanAndParse(input) {
  let str;
  if (Buffer.isBuffer(input)) {
    // UTF-16 LE BOM
    if (input.length >= 2 && input[0] === 0xff && input[1] === 0xfe) {
      str = input.slice(2).toString("utf16le");
    }
    // UTF-16 BE BOM
    else if (input.length >= 2 && input[0] === 0xfe && input[1] === 0xff) {
      str = input.slice(2).toString("utf16le"); // Node doesn't have utf16be natively
    }
    // UTF-8 BOM
    else if (input.length >= 3 && input[0] === 0xef && input[1] === 0xbb && input[2] === 0xbf) {
      str = input.slice(3).toString("utf8");
    } else {
      str = input.toString("utf8");
    }
  } else {
    str = String(input);
  }

  // Strip zero-width BOM character
  if (str.charCodeAt(0) === 0xfeff) str = str.substring(1);
  str = str.trim();

  return JSON.parse(str);
}

// ─── Format detection ───────────────────────────────────────────────

export function identifySbomFormat(input) {
  const sbom = cleanAndParse(input);

  if (sbom.bomFormat === "CycloneDX") {
    const v = sbom.specVersion || "";
    if (v.startsWith("1.6")) return "CycloneDX1.6";
    if (v.startsWith("1.5")) return "CycloneDX1.5";
    if (v.startsWith("1.4")) return "CycloneDX1.4";
    if (v.startsWith("1.3")) return "CycloneDX1.3";
    return "CycloneDX";
  }
  if (sbom.spdxVersion && sbom.spdxVersion.startsWith("SPDX-2.")) return "SPDX2.2";
  if (sbom["@context"] && Array.isArray(sbom["@graph"])) return "SPDX3.0";
  throw new Error("Unknown SBOM format");
}

// ─── Metadata extraction ────────────────────────────────────────────

export function extractSbomMetadata(input, fileName = "unknown") {
  const sbom = cleanAndParse(input);

  const meta = {
    sbom_file: fileName,
    sbom_format: null,
    application_name: null,
    application_version: null,
    application_vendor: null,
    application_description: null,
    application_url: null,
    sbom_generation_timestamp: null,
    sbom_tools: [],
    document_namespace: null,
  };

  // CycloneDX
  if (sbom.bomFormat === "CycloneDX") {
    meta.sbom_format = `CycloneDX ${sbom.specVersion || "unknown"}`;
    meta.sbom_generation_timestamp = sbom.metadata?.timestamp;

    const main = sbom.metadata?.component || {};
    meta.application_name = main.name || null;
    meta.application_version = main.version || null;
    if (main.supplier?.name) meta.application_vendor = main.supplier.name;
    else if (main.name?.startsWith("github.com/")) {
      const p = main.name.split("/");
      if (p.length >= 3) meta.application_vendor = p[1];
    }
    const refs = main.externalReferences || [];
    for (const r of refs) { if (r.type === "vcs") { meta.application_url = r.url; break; } }

    // Tools
    const tools = sbom.metadata?.tools;
    const arr = Array.isArray(tools) ? tools : tools?.components || [];
    for (const t of arr) {
      meta.sbom_tools.push(`${t.vendor || t.author || ""} ${t.name || "Unknown"} v${t.version || "?"}`.trim());
    }
  }
  // SPDX 2.2
  else if (sbom.spdxVersion?.startsWith("SPDX-2.")) {
    meta.sbom_format = "SPDX 2.2";
    meta.document_namespace = sbom.documentNamespace;
    meta.sbom_generation_timestamp = sbom.creationInfo?.created;
    if (sbom.name) meta.application_description = sbom.name;
    for (const c of sbom.creationInfo?.creators || []) {
      if (c.startsWith("Tool:")) meta.sbom_tools.push(c.replace("Tool: ", ""));
    }
    const pkgs = sbom.packages || [];
    const described = sbom.documentDescribes || [];
    let main = pkgs.find((p) => described.includes(p.SPDXID)) || pkgs[0];
    if (main) {
      meta.application_name = main.name;
      meta.application_version = main.versionInfo;
      meta.application_url = main.homepage;
      if (typeof main.supplier === "string" && main.supplier.startsWith("Organization:"))
        meta.application_vendor = main.supplier.replace("Organization: ", "");
    }
  }
  // SPDX 3.0
  else if (sbom["@context"] && Array.isArray(sbom["@graph"])) {
    meta.sbom_format = "SPDX 3.0";
    const graph = sbom["@graph"];
    for (const item of graph) {
      if (item.type === "CreationInfo") {
        meta.sbom_generation_timestamp = item.created;
        for (const tr of item.createdUsing || []) {
          const tool = graph.find((g) => g.spdxId === tr && g["@type"] === "Tool");
          if (tool) meta.sbom_tools.push(tool.name || "Unknown Tool");
        }
        break;
      }
    }
    let descId = null;
    for (const item of graph) {
      if (item.type === "Relationship" && item.relationshipType === "describes") {
        descId = Array.isArray(item.to) ? item.to[0] : item.to;
        break;
      }
    }
    if (descId) {
      const pkg = graph.find((g) => g.spdxId === descId && g["@type"] === "software_Package");
      if (pkg) {
        meta.application_name = pkg.name;
        meta.application_version = pkg.software_packageVersion || pkg.versionInfo;
        meta.application_url = pkg.homePage;
        meta.application_description = pkg.description || pkg.summary;
        for (const sid of pkg.supplier || []) {
          const agent = graph.find((g) => g.spdxId === sid && g["@type"] === "Agent");
          if (agent) { meta.application_vendor = agent.name; break; }
        }
      }
    }
  }

  return meta;
}

// ─── CycloneDX parser ───────────────────────────────────────────────

function parseCycloneDx(sbom) {
  const comps = Array.isArray(sbom.components) ? sbom.components : [];
  return comps.map((c) => {
    const core = {
      name: c.name || "UNKNOWN",
      version: c.version || "UNKNOWN",
      vendor: null,
      purl: c.purl || null,
      cpe: c.cpe || null,
    };
    if (!core.cpe && Array.isArray(c.properties)) {
      const p = c.properties.find((x) => x.name === "syft:cpe23");
      if (p) core.cpe = p.value;
    }
    if (c.supplier?.name) core.vendor = c.supplier.name;
    else if (c.purl) {
      const parts = c.purl.split("/");
      if (parts.length >= 3) core.vendor = parts[2].split("@")[0];
    }

    const context = { licenses: [], hashes: {}, downloadLocation: null, namespace: null };
    for (const lo of c.licenses || []) {
      const li = lo.license || {};
      if (li.id) context.licenses.push(li.id); else if (li.name) context.licenses.push(li.name);
    }
    for (const h of c.hashes || []) {
      if (h.alg && h.content) context.hashes[h.alg.toLowerCase()] = h.content;
    }
    for (const ref of c.externalReferences || []) {
      if (ref.type === "vcs" && ref.url) {
        context.downloadLocation = ref.url;
        const gh = ref.url.split("github.com/");
        if (gh.length > 1) context.namespace = gh[1].split("/")[0];
      }
    }
    return { core, context };
  });
}

// ─── SPDX 2.2 parser ───────────────────────────────────────────────

function parseSpdx22(sbom) {
  return (sbom.packages || []).map((pkg) => {
    const core = { name: pkg.name || "UNKNOWN", version: pkg.versionInfo || "UNKNOWN", vendor: null, purl: null, cpe: null };
    if (typeof pkg.supplier === "string" && pkg.supplier.startsWith("Organization: "))
      core.vendor = pkg.supplier.replace("Organization: ", "");
    // Extract PURL from external refs
    for (const ref of pkg.externalRefs || []) {
      if (ref.referenceType === "purl") core.purl = ref.referenceLocator;
    }

    const context = { licenses: [], hashes: {}, downloadLocation: pkg.downloadLocation };
    if (pkg.licenseConcluded && pkg.licenseConcluded !== "NOASSERTION") context.licenses.push(pkg.licenseConcluded);
    for (const cs of pkg.checksums || []) {
      if (cs.algorithm && cs.checksumValue) context.hashes[cs.algorithm.toLowerCase()] = cs.checksumValue;
    }
    return { core, context };
  });
}

// ─── SPDX 3.0 parser ───────────────────────────────────────────────

function parseSpdx30(sbom) {
  const graph = sbom["@graph"] || [];
  return graph
    .filter((item) => item["@type"] === "software_Package")
    .map((item) => {
      const core = {
        name: item.name || "UNKNOWN",
        version: item.software_packageVersion || item.versionInfo || "UNKNOWN",
        vendor: null, purl: null, cpe: null,
      };
      for (const sid of item.supplier || []) {
        const agent = graph.find((g) => g["@id"] === sid && g["@type"] === "Agent");
        if (agent) { core.vendor = agent.name; break; }
      }

      const context = { licenses: [], hashes: {}, downloadLocation: item.downloadLocation };
      if (item.licenseConcluded && item.licenseConcluded !== "NOASSERTION") {
        const lc = item.licenseConcluded;
        Array.isArray(lc) ? context.licenses.push(...lc) : context.licenses.push(lc);
      }
      for (const csId of item.checksum || []) {
        const cs = graph.find((g) => g["@id"] === csId);
        if (cs?.algorithm && cs.checksumValue) context.hashes[cs.algorithm.toLowerCase()] = cs.checksumValue;
      }
      return { core, context };
    });
}

// ─── Main parser ────────────────────────────────────────────────────

export function parseSbom(input) {
  const sbom = cleanAndParse(input);
  const fmt = identifySbomFormat(input);
  if (fmt.startsWith("CycloneDX")) return parseCycloneDx(sbom);
  if (fmt === "SPDX2.2") return parseSpdx22(sbom);
  if (fmt === "SPDX3.0") return parseSpdx30(sbom);
  throw new Error(`Unsupported SBOM format: ${fmt}`);
}
