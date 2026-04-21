/**
 * Supply Chain page — fetches SBOM manifest + schema, computes coverage,
 * renders summary stats, application coverage grid, and scan history.
 */
(function () {
  "use strict";

  // ─── State ──────────────────────────────────────────────────────
  let manifest = { scans: [], coverage: {} };
  let schema = null;
  let allApps = []; // merged list { key, name, version, publisher, covered, scanIds[] }
  let coveragePct = 0;

  // ─── DOM refs ───────────────────────────────────────────────────
  const $loading = document.getElementById("scLoading");
  const $error = document.getElementById("scError");
  const $errorMsg = document.getElementById("scErrorMsg");
  const $empty = document.getElementById("scEmpty");
  const $content = document.getElementById("scContent");
  const $refreshBtn = document.getElementById("refreshBtn");
  const $lastUpdated = document.getElementById("lastUpdated");

  // ─── Init ───────────────────────────────────────────────────────
  document.addEventListener("DOMContentLoaded", () => {
    load();
    $refreshBtn?.addEventListener("click", load);
    document.getElementById("appSearch")?.addEventListener("input", renderAppGrid);
    document.getElementById("appFilter")?.addEventListener("change", renderAppGrid);
  });

  async function load() {
    showState("loading");
    try {
      const [manifestRes, schemaRes] = await Promise.all([
        fetch("/api/sbom/manifest").then((r) => r.json()),
        fetch("/api/latest-schema").then((r) => r.json()),
      ]);

      manifest = { scans: manifestRes.scans || [], coverage: manifestRes.coverage || {} };
      schema = schemaRes.success ? schemaRes.schema : null;

      if (manifest.scans.length === 0) {
        showState("empty");
        return;
      }

      mergeApps();
      showState("content");
      renderSummary();
      renderAppGrid();
      renderScanList();
      $lastUpdated.textContent = manifest.coverage.lastScanTimestamp
        ? "Last scan: " + new Date(manifest.coverage.lastScanTimestamp).toLocaleString()
        : "";
    } catch (err) {
      $errorMsg.textContent = err.message;
      showState("error");
    }
  }

  // ─── Merge schema apps with SBOM coverage info ─────────────────
  function mergeApps() {
    const covKeys = new Set((manifest.coverage.scannedAppKeys || []).map((k) => k));
    const covNames = new Set((manifest.coverage.scannedAppNames || []).map((n) => n.toLowerCase()));

    allApps = [];

    // Pull apps from schema
    const apps = schema?.applications || [];
    for (const app of apps) {
      const key = app.application_key;
      const name = app.application_name || key;
      const covered = covKeys.has(key) || covNames.has(name.toLowerCase());
      // gather scan ids for this app
      const scanIds = manifest.scans
        .filter((s) => s.applicationKey === key || (s.applicationName && s.applicationName.toLowerCase() === name.toLowerCase()))
        .map((s) => s.id);
      allApps.push({
        key,
        name,
        version: app.application_version || "—",
        publisher: app.publisher || app.application_publisher || "—",
        deviceCount: app.device_count || (app.devices ? app.devices.length : 0),
        covered,
        scanIds,
      });
    }

    // Calculate coverage
    const total = allApps.length || 1;
    const covered = allApps.filter((a) => a.covered).length;
    coveragePct = Math.round((covered / total) * 100);
  }

  // ─── State switching ───────────────────────────────────────────
  function showState(state) {
    $loading.style.display = state === "loading" ? "" : "none";
    $error.style.display = state === "error" ? "" : "none";
    $empty.style.display = state === "empty" ? "" : "none";
    $content.style.display = state === "content" ? "" : "none";
  }

  // ─── Summary Cards + Coverage Ring ─────────────────────────────
  function renderSummary() {
    const covered = allApps.filter((a) => a.covered).length;
    const uncovered = allApps.length - covered;

    document.getElementById("coveragePct").textContent = coveragePct + "%";
    document.getElementById("coveredCount").textContent = covered;
    document.getElementById("uncoveredCount").textContent = uncovered;
    document.getElementById("totalScans").textContent = manifest.scans.length;
    document.getElementById("coverageDesc").textContent =
      `${covered} of ${allApps.length} applications have been analysed with an SBOM.`;

    // Aggregate stats across scans
    let comps = 0, vulns = 0, crit = 0;
    manifest.scans.forEach((s) => {
      comps += s.totalComponents || 0;
      vulns += s.totalVulnerabilities || 0;
      // we don't have critical counts in manifest; we'll show total vulns
    });
    document.getElementById("totalComponents").textContent = comps;
    document.getElementById("totalVulns").textContent = vulns;
    document.getElementById("criticalVulns").textContent = "—"; // will fill when detail is loaded

    drawCoverageRing(coveragePct);
  }

  function drawCoverageRing(pct) {
    const canvas = document.getElementById("coverageRing");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const cx = 70, cy = 70, r = 56, lw = 12;
    ctx.clearRect(0, 0, 140, 140);

    // Background ring
    ctx.beginPath();
    ctx.arc(cx, cy, r, 0, Math.PI * 2);
    ctx.strokeStyle = "rgba(255,255,255,0.08)";
    ctx.lineWidth = lw;
    ctx.stroke();

    // Foreground arc
    const angle = (pct / 100) * Math.PI * 2 - Math.PI / 2;
    ctx.beginPath();
    ctx.arc(cx, cy, r, -Math.PI / 2, angle);
    const color = pct >= 75 ? "#22c55e" : pct >= 40 ? "#ff6b35" : "#ef4444";
    ctx.strokeStyle = color;
    ctx.lineWidth = lw;
    ctx.lineCap = "round";
    ctx.stroke();
  }

  // ─── Application Coverage Grid ─────────────────────────────────
  function renderAppGrid() {
    const search = (document.getElementById("appSearch")?.value || "").toLowerCase();
    const filter = document.getElementById("appFilter")?.value || "all";
    const grid = document.getElementById("appGrid");

    let filtered = allApps;
    if (search) filtered = filtered.filter((a) => a.name.toLowerCase().includes(search) || a.publisher.toLowerCase().includes(search));
    if (filter === "covered") filtered = filtered.filter((a) => a.covered);
    if (filter === "uncovered") filtered = filtered.filter((a) => !a.covered);

    if (filtered.length === 0) {
      grid.innerHTML = `<div class="sc-app-empty"><i class="fas fa-search"></i> No matching applications</div>`;
      return;
    }

    grid.innerHTML = filtered
      .sort((a, b) => (a.covered === b.covered ? a.name.localeCompare(b.name) : a.covered ? -1 : 1))
      .map((app) => {
        const statusClass = app.covered ? "sc-app-covered" : "sc-app-uncovered";
        const icon = app.covered ? "fa-check-circle" : "fa-question-circle";
        const badge = app.covered
          ? `<span class="sc-badge sc-badge-ok"><i class="fas fa-shield-alt"></i> Scanned</span>`
          : `<span class="sc-badge sc-badge-unknown"><i class="fas fa-exclamation-circle"></i> Unknown</span>`;
        const scanAction = app.covered
          ? `<button class="sc-app-action" onclick="viewAppScans('${esc(app.key)}')"><i class="fas fa-eye"></i> View</button>`
          : `<button class="sc-app-action sc-app-action-upload" onclick="openSbomModal(event)"><i class="fas fa-upload"></i> Scan</button>`;
        return `
          <div class="sc-app-card ${statusClass}">
            <div class="sc-app-icon"><i class="fas ${icon}"></i></div>
            <div class="sc-app-info">
              <div class="sc-app-name">${esc(app.name)}</div>
              <div class="sc-app-meta">${esc(app.publisher)} · v${esc(app.version)}</div>
              <div class="sc-app-meta">${app.deviceCount} device${app.deviceCount !== 1 ? "s" : ""}</div>
            </div>
            <div class="sc-app-status">
              ${badge}
              ${scanAction}
            </div>
          </div>`;
      })
      .join("");
  }

  // ─── Scan History ──────────────────────────────────────────────
  function renderScanList() {
    const list = document.getElementById("scanList");
    if (manifest.scans.length === 0) {
      list.innerHTML = `<p class="sc-scan-empty">No scans yet.</p>`;
      return;
    }

    list.innerHTML = [...manifest.scans]
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .map((s) => {
        const d = new Date(s.timestamp);
        const vulnClass = s.totalVulnerabilities > 0 ? "sc-vulns-bad" : "sc-vulns-ok";
        return `
          <div class="sc-scan-card">
            <div class="sc-scan-main">
              <div class="sc-scan-file"><i class="fas fa-file-code"></i> ${esc(s.fileName)}</div>
              <div class="sc-scan-meta">
                ${esc(s.applicationName || "—")} · ${s.format || "?"} ·
                <time>${d.toLocaleDateString()} ${d.toLocaleTimeString()}</time>
              </div>
            </div>
            <div class="sc-scan-stats">
              <span class="sc-scan-chip"><i class="fas fa-puzzle-piece"></i> ${s.totalComponents}</span>
              <span class="sc-scan-chip ${vulnClass}"><i class="fas fa-bug"></i> ${s.totalVulnerabilities}</span>
            </div>
            <div class="sc-scan-actions">
              <button class="btn btn-sm" onclick="viewScanDetail('${esc(s.id)}')"><i class="fas fa-search"></i> Details</button>
              <button class="btn btn-sm btn-danger" onclick="removeScan('${esc(s.id)}')"><i class="fas fa-trash"></i></button>
            </div>
          </div>`;
      })
      .join("");
  }

  // ─── Scan Detail Modal ─────────────────────────────────────────
  window.viewScanDetail = async function (scanId) {
    const modal = document.getElementById("scanDetailModal");
    const body = document.getElementById("scanDetailBody");
    modal.classList.add("active");
    body.innerHTML = `<div class="sc-modal-loading"><div class="forecast-loading-spinner"></div><p>Loading scan results…</p></div>`;

    try {
      const res = await fetch(`/api/sbom/results/${scanId}`);
      const data = await res.json();
      if (!data.success) throw new Error(data.error);

      const r = data.results;
      const meta = r.scan_metadata;
      const vulns = r.vulnerable_packages || [];

      // Count severities — OSV severity is a CVSS array, need to extract level
      const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
      vulns.forEach((pkg) => {
        (pkg.vulnerabilities || []).forEach((v) => {
          const sev = extractSeverity(v);
          if (sevCounts[sev] !== undefined) sevCounts[sev]++;
          else sevCounts.UNKNOWN++;
        });
      });

      // Update the critical card on the main page
      const critCount = sevCounts.CRITICAL + sevCounts.HIGH;
      const critEl = document.getElementById("criticalVulns");
      if (critEl) critEl.textContent = critCount;

      body.innerHTML = `
        <div class="sc-detail">
          <div class="sc-detail-header">
            <h3>${esc(data.scan.fileName)}</h3>
            <p>${esc(data.scan.applicationName || "")} · ${data.scan.format || r.sbom_origin?.sbom_format || ""} · Scanned ${new Date(data.scan.timestamp).toLocaleString()}</p>
          </div>

          <div class="sc-detail-summary">
            <div class="sc-detail-stat"><strong>${meta.total_components_scanned}</strong><span>Components</span></div>
            <div class="sc-detail-stat"><strong>${meta.vulnerable_components_found}</strong><span>Vulnerable</span></div>
            <div class="sc-detail-stat"><strong>${meta.total_vulnerabilities_found}</strong><span>Total Vulns</span></div>
          </div>

          <div class="sc-severity-bar">
            ${sevBar(sevCounts)}
          </div>

          <h4>Vulnerable Components</h4>
          ${vulns.length === 0 ? '<p class="sc-no-vulns"><i class="fas fa-check-circle"></i> No vulnerabilities found.</p>' : vulnTable(vulns)}
        </div>
      `;
    } catch (err) {
      body.innerHTML = `<p class="sc-modal-error"><i class="fas fa-exclamation-triangle"></i> ${esc(err.message)}</p>`;
    }
  };

  function sevBar(counts) {
    const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;
    const colors = { CRITICAL: "#dc2626", HIGH: "#ef4444", MEDIUM: "#f59e0b", LOW: "#22c55e", UNKNOWN: "#64748b" };
    let html = '<div class="sc-sev-bar">';
    for (const [sev, count] of Object.entries(counts)) {
      if (count === 0) continue;
      const pct = (count / total) * 100;
      html += `<div class="sc-sev-segment" style="width:${pct}%;background:${colors[sev]}" title="${sev}: ${count}"></div>`;
    }
    html += "</div>";
    html += '<div class="sc-sev-legend">';
    for (const [sev, count] of Object.entries(counts)) {
      html += `<span style="color:${colors[sev]}"><i class="fas fa-circle"></i> ${sev} (${count})</span>`;
    }
    html += "</div>";
    return html;
  }

  function vulnTable(vulns) {
    let rows = "";
    for (const pkg of vulns) {
      const compName = pkg.component?.core?.name || pkg.component?.name || "—";
      const compVer = pkg.component?.core?.version || pkg.component?.version || "—";
      for (const v of pkg.vulnerabilities || []) {
        const sev = extractSeverity(v);
        const sevClass = `sc-sev-${sev.toLowerCase()}`;
        rows += `
          <tr>
            <td class="sc-comp-name">${esc(compName)}</td>
            <td>${esc(compVer)}</td>
            <td><a href="https://osv.dev/vulnerability/${esc(v.id)}" target="_blank" rel="noopener">${esc(v.id)}</a></td>
            <td><span class="sc-sev-badge ${sevClass}">${sev}</span></td>
            <td class="sc-vuln-summary">${esc(v.summary || v.details?.substring(0, 120) || "—")}</td>
          </tr>`;
      }
    }
    return `
      <div class="sc-vuln-table-wrap">
        <table class="sc-vuln-table">
          <thead><tr><th>Component</th><th>Version</th><th>Vuln ID</th><th>Severity</th><th>Summary</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  }

  /**
   * Extract severity level from an OSV vulnerability object.
   * OSV stores severity as: severity: [{ type: "CVSS_V3", score: "CVSS:3.1/..." }]
   * or sometimes in database_specific.severity as a string.
   */
  function extractSeverity(vuln) {
    // Check database_specific first (GitHub, etc. often set this)
    const dbSev = vuln.database_specific?.severity;
    if (typeof dbSev === "string") return dbSev.toUpperCase();

    // Parse from CVSS vector
    if (Array.isArray(vuln.severity)) {
      for (const s of vuln.severity) {
        const score = parseCvssScore(s.score);
        if (score !== null) return cvssToLevel(score);
      }
    }

    // Ecosystem-specific: some put it in affected[].ecosystem_specific
    if (Array.isArray(vuln.affected)) {
      for (const a of vuln.affected) {
        const es = a.ecosystem_specific?.severity;
        if (typeof es === "string") return es.toUpperCase();
      }
    }

    return "UNKNOWN";
  }

  function parseCvssScore(vector) {
    if (!vector || typeof vector !== "string") return null;
    // CVSS:3.x vectors don't always include a base score directly,
    // but some OSV entries might have just a numeric score
    const numMatch = vector.match(/^(\d+\.?\d*)$/);
    if (numMatch) return parseFloat(numMatch[1]);
    // Parse base score from full CVSS v3 vector if available
    // Fall back to extracting AV metric for rough estimation
    return null;
  }

  function cvssToLevel(score) {
    if (score >= 9.0) return "CRITICAL";
    if (score >= 7.0) return "HIGH";
    if (score >= 4.0) return "MEDIUM";
    if (score > 0) return "LOW";
    return "UNKNOWN";
  }

  window.closeScanModal = function () {
    document.getElementById("scanDetailModal").classList.remove("active");
  };

  // ─── View scans for a specific app ─────────────────────────────
  window.viewAppScans = function (appKey) {
    const app = allApps.find((a) => a.key === appKey);
    if (!app || app.scanIds.length === 0) return;
    // Open the most recent scan for this app
    viewScanDetail(app.scanIds[app.scanIds.length - 1]);
  };

  // ─── Delete scan ───────────────────────────────────────────────
  window.removeScan = async function (scanId) {
    if (!confirm("Remove this scan? The results will be deleted.")) return;
    try {
      const res = await fetch(`/api/sbom/scans/${scanId}`, { method: "DELETE" });
      const data = await res.json();
      if (data.success) load();
      else alert("Failed: " + (data.error || "Unknown"));
    } catch (err) {
      alert("Error: " + err.message);
    }
  };

  // ─── Util ──────────────────────────────────────────────────────
  function esc(str) {
    const d = document.createElement("div");
    d.textContent = String(str ?? "");
    return d.innerHTML;
  }
})();
