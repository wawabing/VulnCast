/**
 * VulnCast — Security Risk Dashboard
 * 
 * Risk Scoring Model:
 *   CVE_Risk  = CVSS × EPSS × 100 × BlastRadius
 *   App_Risk  = Σ(CVE_Risk)
 *   BlastRadius = 1 + ln(devices_affected) / ln(total_devices)   (1–2 range)
 *   Org_Risk  = normalised 0–100 from total weighted risk
 *
 * CVSS captures impact severity (0–10).
 * EPSS captures real-world exploit probability (0–1).
 * Multiplying them yields an "expected damage" metric that surfaces
 * high-severity + high-likelihood CVEs first — exactly what a Head of
 * Security needs to prioritise patching.
 */

// ───────── Constants ────────────────────────────────────────
const EPSS_DEFAULT     = 0.01;   // 1 % default when EPSS is unavailable
const EPSS_HIGH_THRESH = 0.10;   // 10 % = "exploit-likely"
const RISK_CAP         = 100;    // gauge max

// ───────── Main ─────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadDashboard();

  const refreshBtn = document.getElementById('refreshBtn');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => {
      refreshBtn.innerHTML = '<i class="fas fa-sync-alt fa-spin"></i>';
      loadDashboard();
    });
  }

  // Estate overview toggle
  const toggle = document.getElementById('estateToggle');
  if (toggle) {
    toggle.addEventListener('click', () => {
      const el = document.getElementById('estateOverview');
      const chev = document.getElementById('estateChevron');
      if (el.style.display === 'none') {
        el.style.display = '';
        chev.classList.replace('fa-chevron-down', 'fa-chevron-up');
      } else {
        el.style.display = 'none';
        chev.classList.replace('fa-chevron-up', 'fa-chevron-down');
      }
    });
  }
});

async function loadDashboard() {
  try {
    // Fetch schema + forecasts + SBOM manifest in parallel
    const [schemaRes, forecastRes, sbomRes] = await Promise.all([
      fetch('/api/latest-schema'),
      fetch('/api/forecasts').catch(() => null),
      fetch('/api/sbom/manifest').catch(() => null)
    ]);

    if (!schemaRes.ok) throw new Error('No data — upload a CSV first.');

    const schemaData = await schemaRes.json();
    if (!schemaData.success || !schemaData.schema) throw new Error('No schema data');

    let forecasts = null;
    if (forecastRes && forecastRes.ok) {
      const fj = await forecastRes.json();
      if (fj.success) forecasts = fj;
    }

    let sbomManifest = null;
    if (sbomRes && sbomRes.ok) {
      const sj = await sbomRes.json();
      if (sj.success !== false) sbomManifest = sj;
    }

    const schema = schemaData.schema;

    // ── Compute risk model ──
    const risk = computeRiskModel(schema, forecasts, sbomManifest);

    // ── Render everything ──
    renderHeroMetrics(risk);
    renderRiskGauge(risk.orgRiskScore);
    renderRiskBreakdown(risk);
    renderSeverityDonut(risk);
    renderRiskTrendChart(risk, forecasts);
    renderPatchRecommendations(risk);
    renderRiskByApp(risk);
    renderRiskByUser(risk);
    renderTopEpss(risk);
    renderEstateOverview(schema, risk);

    // Show content
    document.getElementById('dashLoading').style.display = 'none';
    document.getElementById('dashContent').style.display = '';
    document.getElementById('lastUpdated').textContent =
      `Last updated: ${new Date().toLocaleTimeString()}`;

    const refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) refreshBtn.innerHTML = '<i class="fas fa-sync-alt"></i>';

  } catch (err) {
    console.error('Dashboard error:', err);
    document.getElementById('dashLoading').innerHTML = `
      <i class="fas fa-exclamation-triangle" style="font-size:2rem;color:var(--danger);"></i>
      <p>${err.message}</p>`;
  }
}

// ═══════════════════════════════════════════════════════════
//  RISK MODEL COMPUTATION
// ═══════════════════════════════════════════════════════════

function computeRiskModel(schema, forecasts, sbomManifest) {
  const apps       = schema.applications || [];
  const devices    = schema.devices || [];
  const users      = schema.users || [];
  const totalDevices = devices.length || 1;

  // Build device→user lookup
  const deviceToUser = {};
  devices.forEach(d => { if (d.user_id) deviceToUser[d.device_id] = d.user_id; });

  // Per-CVE risk calculation
  const allCveRisks  = [];       // flat array of every CVE risk record
  const appRiskMap   = {};       // app_key → { name, riskScore, cves, deviceCount, ... }
  const userRiskMap  = {};       // user_id → { name, riskScore, apps }
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  let   totalRisk    = 0;
  let   exploitLikelyCount = 0;
  const affectedDeviceIds = new Set();

  users.forEach(u => {
    userRiskMap[u.user_id] = {
      name: u.username || u.email_address?.split('@')[0] || u.user_id,
      riskScore: 0,
      apps: new Set()
    };
  });

  apps.forEach(app => {
    const cves       = app.cve_data?.cves || [];
    const appDevices = app.device_ids || [];
    const deviceCount = appDevices.length;

    // Blast radius: logarithmic scaling relative to estate size
    const blastRadius = deviceCount > 0
      ? 1 + Math.log(deviceCount) / Math.log(Math.max(totalDevices, 2))
      : 1;

    let appRisk = 0;
    const cveDetails = [];

    cves.forEach(cve => {
      const cvss = cve.score || 0;
      const epss = cve.epss_score > 0 ? cve.epss_score : EPSS_DEFAULT;
      const sev  = (cve.severity || 'UNKNOWN').toUpperCase();

      // Core risk formula: expected exploit impact
      const cveRisk = cvss * epss * 100 * blastRadius;

      appRisk += cveRisk;
      totalRisk += cveRisk;

      // Severity counts
      const sevKey = sev.toLowerCase();
      if (severityCounts.hasOwnProperty(sevKey)) severityCounts[sevKey]++;
      else severityCounts.unknown++;

      // High EPSS
      if (epss >= EPSS_HIGH_THRESH) exploitLikelyCount++;

      // Track affected devices
      appDevices.forEach(d => affectedDeviceIds.add(d));

      const rec = {
        cve_id: cve.cve_id,
        description: cve.description,
        cvss, epss, severity: sev,
        riskScore: cveRisk,
        appName: app.application_name,
        appKey: app.application_key,
        deviceCount,
        blastRadius
      };
      allCveRisks.push(rec);
      cveDetails.push(rec);
    });

    appRiskMap[app.application_key] = {
      name: app.application_name,
      publisher: app.application_publisher,
      version: app.application_short_version,
      riskScore: appRisk,
      cveCount: app.cve_data?.totalCveCount || cves.length,
      deviceCount,
      blastRadius,
      cves: cveDetails,
      deviceIds: appDevices,
      cpe: app.cve_data?.cpe_name || null,
      vendor: app.cve_data?.vendor || null,
      product: app.cve_data?.product || null,
      eol_data: app.eol_data || null,
    };

    // Distribute risk to users
    const usersWithApp = new Set();
    appDevices.forEach(did => {
      const uid = deviceToUser[did];
      if (uid && userRiskMap[uid]) usersWithApp.add(uid);
    });
    usersWithApp.forEach(uid => {
      userRiskMap[uid].riskScore += appRisk / usersWithApp.size;
      userRiskMap[uid].apps.add(app.application_name);
    });
  });

  // Normalise org risk to 0–100 using a saturating exponential curve.
  const vulnRiskNorm = normalizeRisk(totalRisk, totalDevices);

  // Apps sorted by risk
  const appsSorted = Object.values(appRiskMap)
    .filter(a => a.riskScore > 0)
    .sort((a, b) => b.riskScore - a.riskScore);

  // Users sorted by risk
  const usersSorted = Object.values(userRiskMap)
    .filter(u => u.riskScore > 0)
    .sort((a, b) => b.riskScore - a.riskScore);

  // CVEs sorted by risk
  allCveRisks.sort((a, b) => b.riskScore - a.riskScore);

  // Vulnerable app count
  const vulnAppCount = apps.filter(a => a.cve_data?.cves?.length > 0).length;

  // ── Pillar 2: Forecast Exposure (0–100) ──────────────────
  // How much worse is it getting? Penalise orgs whose software
  // is trending upward in CVE volume.
  // Compute from per-CPE data (covers vendor/product/version levels)
  let forecastExposure = 0;
  let forecastGrowthPct = 0;
  const allSuccessful = forecasts?.successful || [];
  let sumPredicted = 0, sumActual = 0;
  allSuccessful.forEach(f => {
    if (f.status === 'success') {
      sumPredicted += f.forecast_total || 0;
      sumActual += f.backtest_actual_total ?? f.backtest?.actual_total ?? 0;
    }
  });
  // Fallback to aggregate totals if per-CPE data unavailable
  if (sumActual === 0 && forecasts?.totalActual) {
    sumActual = forecasts.totalActual;
    sumPredicted = forecasts.totalPredicted || sumActual;
  }
  if (sumActual > 0 && sumPredicted > 0) {
    forecastGrowthPct = ((sumPredicted - sumActual) / sumActual) * 100;
    // Clamp: 0 growth or declining = 0 penalty, cap at 100
    forecastExposure = Math.min(100, Math.max(0, forecastGrowthPct));
  }

  // ── Pillar 3: Coverage Gap (0–100) ───────────────────────
  // What percentage of the estate is NOT assessed?
  // Two components: CPE matches and SBOM scans.
  const appsWithCpe = apps.filter(a => a.cve_data?.cpe_name).length;
  const sbomScans   = sbomManifest?.scans || [];
  const sbomCoveredKeys = new Set(
    (sbomManifest?.coverage?.scannedAppKeys || []).map(k => k.toLowerCase())
  );
  // Also match by name for fuzzy coverage
  const sbomCoveredNames = new Set(
    (sbomManifest?.coverage?.scannedAppNames || []).map(n => n.toLowerCase())
  );
  const appsWithSbom = apps.filter(a =>
    sbomCoveredKeys.has((a.application_key || '').toLowerCase()) ||
    sbomCoveredNames.has((a.application_name || '').toLowerCase())
  ).length;
  // Combined coverage: unique apps that have either CPE enrichment or SBOM scan
  const appsCovered = apps.filter(a =>
    a.cve_data?.cpe_name ||
    sbomCoveredKeys.has((a.application_key || '').toLowerCase()) ||
    sbomCoveredNames.has((a.application_name || '').toLowerCase())
  ).length;
  const totalAppsCount = apps.length || 1;
  const coveragePct = (appsCovered / totalAppsCount) * 100;
  const coverageGap = 100 - coveragePct; // 0 = fully covered, 100 = blind

  // SBOM supply chain vulnerability count
  let sbomVulnCount = 0;
  sbomScans.forEach(s => { sbomVulnCount += s.totalVulnerabilities || 0; });

  // ── Composite Score ──────────────────────────────────────
  // Three pillars: current vulnerabilities, forecast trajectory, and coverage.
  const W_VULN = 0.55, W_FORECAST = 0.20, W_COVERAGE = 0.25;
  const orgRiskScore = Math.min(RISK_CAP,
    W_VULN * vulnRiskNorm +
    W_FORECAST * forecastExposure +
    W_COVERAGE * coverageGap
  );

  return {
    orgRiskScore: Math.round(orgRiskScore * 10) / 10,
    // Pillar scores for breakdown display
    pillarVuln: Math.round(vulnRiskNorm * 10) / 10,
    pillarForecast: Math.round(forecastExposure * 10) / 10,
    pillarCoverage: Math.round(coverageGap * 10) / 10,
    pillarWeights: { vuln: W_VULN, forecast: W_FORECAST, coverage: W_COVERAGE },
    forecastExposure,
    forecastGrowthPct: Math.round(forecastGrowthPct * 10) / 10,
    forecastPredicted: Math.round(sumPredicted),
    forecastActual: Math.round(sumActual),
    hasForecasts: allSuccessful.length > 0,
    coverageGap,
    coveragePct: Math.round(coveragePct),
    appsWithCpe,
    appsWithSbom,
    sbomVulnCount,
    sbomScanCount: sbomScans.length,
    totalRisk,
    vulnRiskNorm: Math.round(vulnRiskNorm * 10) / 10,
    totalDevices,
    totalUsers: users.length,
    totalApps: apps.length,
    totalPlatforms: schema.Platforms?.length || 0,
    totalCves: allCveRisks.length,
    severityCounts,
    exploitLikelyCount,
    assetsAtRisk: affectedDeviceIds.size,
    vulnAppCount,
    appsSorted,
    usersSorted,
    allCveRisks,
    appRiskMap,
    schema
  };
}

// ═══════════════════════════════════════════════════════════
//  RENDER: Hero Metrics
// ═══════════════════════════════════════════════════════════

function renderHeroMetrics(risk) {
  setText('criticalVulnCount', risk.severityCounts.critical);
  setText('exploitReadyCount', risk.exploitLikelyCount);

  // For elements with nested <small>, set innerHTML to preserve structure
  const assetsEl = document.getElementById('assetsAtRiskCount');
  if (assetsEl) assetsEl.innerHTML = `${risk.assetsAtRisk} <small id="assetsAtRiskTotal">/ ${risk.totalDevices}</small>`;

  const appsEl = document.getElementById('vulnAppCount');
  if (appsEl) appsEl.innerHTML = `${risk.vulnAppCount} <small id="vulnAppTotal">/ ${risk.totalApps}</small>`;

  // Risk score
  setText('riskScoreValue', risk.orgRiskScore.toFixed(1));
  const rating = getRiskRating(risk.orgRiskScore);
  const ratingEl = document.getElementById('riskScoreRating');
  if (!ratingEl) return;
  ratingEl.textContent = rating.label;
  ratingEl.style.color = rating.color;
}

function getRiskRating(score) {
  if (score >= 75) return { label: 'Critical', color: '#ef4444' };
  if (score >= 50) return { label: 'High',     color: '#f97316' };
  if (score >= 25) return { label: 'Medium',   color: '#f59e0b' };
  return                   { label: 'Low',      color: '#10b981' };
}

// ═══════════════════════════════════════════════════════════
//  RENDER: Risk Gauge (doughnut half-circle)
// ═══════════════════════════════════════════════════════════

let gaugeChart = null;
function renderRiskGauge(score) {
  const ctx = document.getElementById('riskGaugeChart');
  if (!ctx) return;

  const rating = getRiskRating(score);
  const remaining = RISK_CAP - score;

  if (gaugeChart) gaugeChart.destroy();

  gaugeChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      datasets: [{
        data: [score, remaining],
        backgroundColor: [rating.color, '#e5e7eb'],
        borderWidth: 0,
        circumference: 180,
        rotation: 270,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '78%',
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
    }
  });
}

// ═══════════════════════════════════════════════════════════
//  RENDER: Risk Breakdown Pillars
// ═══════════════════════════════════════════════════════════

function renderRiskBreakdown(risk) {
  const wrap = document.getElementById('riskBreakdown');
  if (!wrap) return;

  const pillars = [
    {
      label: 'Vulnerability',
      score: risk.pillarVuln,
      weight: risk.pillarWeights.vuln,
      weighted: (risk.pillarVuln * risk.pillarWeights.vuln).toFixed(1),
      color: '#ef4444',
      icon: 'fa-bug',
      detail: `${risk.totalCves} CVEs + ${risk.sbomVulnCount} supply chain`
    },
    {
      label: 'Forecast Outlook',
      score: risk.pillarForecast,
      weight: risk.pillarWeights.forecast,
      weighted: (risk.pillarForecast * risk.pillarWeights.forecast).toFixed(1),
      color: '#f97316',
      icon: 'fa-chart-line',
      detail: risk.forecastGrowthPct > 0
        ? `${risk.forecastGrowthPct.toFixed(0)}% predicted growth — ${risk.forecastPredicted} CVEs forecast`
        : risk.forecastGrowthPct < 0
        ? `${Math.abs(risk.forecastGrowthPct).toFixed(0)}% predicted decline — ${risk.forecastPredicted} vs ${risk.forecastActual} CVEs`
        : risk.hasForecasts ? 'Stable forecast — see trajectory' : 'No forecast data yet'
    },
    {
      label: 'Coverage Gap',
      score: risk.pillarCoverage,
      weight: risk.pillarWeights.coverage,
      weighted: (risk.pillarCoverage * risk.pillarWeights.coverage).toFixed(1),
      color: '#8b5cf6',
      icon: 'fa-eye-slash',
      detail: `${risk.coveragePct}% covered (${risk.appsWithCpe} CPE · ${risk.sbomScanCount} SBOMs)`
    }
  ];

  wrap.innerHTML = pillars.map(p => {
    const isInfoOnly = p.weight === 0;
    const scoreLabel = isInfoOnly
      ? `<span class="risk-pillar-score" style="opacity:0.6"><i class="fas fa-info-circle"></i> info</span>`
      : `<span class="risk-pillar-score">${p.weighted} <small>/ ${(p.weight * 100).toFixed(0)}</small></span>`;
    return `
    <div class="risk-pillar${isInfoOnly ? ' risk-pillar-info' : ''}">
      <div class="risk-pillar-header">
        <span class="risk-pillar-label"><i class="fas ${p.icon}" style="color:${p.color}"></i> ${p.label}</span>
        ${scoreLabel}
      </div>
      <div class="risk-pillar-bar">
        <div class="risk-pillar-fill" style="width:${Math.min(100, (p.score))}%;background:${p.color}${isInfoOnly ? ';opacity:0.45' : ''}"></div>
      </div>
      <span class="risk-pillar-detail">${p.detail}</span>
    </div>
  `;
  }).join('');
}

// ═══════════════════════════════════════════════════════════
//  RENDER: Severity Donut
// ═══════════════════════════════════════════════════════════

let severityChart = null;
function renderSeverityDonut(risk) {
  const ctx = document.getElementById('severityDonutChart');
  if (!ctx) return;
  const s = risk.severityCounts;

  if (severityChart) severityChart.destroy();

  severityChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data: [s.critical, s.high, s.medium, s.low],
        backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#10b981'],
        borderWidth: 2,
        borderColor: '#fff',
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '60%',
      plugins: {
        legend: { position: 'bottom', labels: { padding: 12, usePointStyle: true, font: { size: 11 } } },
        tooltip: {
          callbacks: {
            label: (ctx) => ` ${ctx.label}: ${ctx.raw} CVEs`
          }
        }
      }
    }
  });
}

// ═══════════════════════════════════════════════════════════
//  RENDER: Risk Trajectory — Stacked Area + What-If
// ═══════════════════════════════════════════════════════════

const APP_COLORS = [
  '#ef4444', '#f97316', '#f59e0b', '#8b5cf6',
  '#3b82f6', '#06b6d4', '#10b981', '#ec4899',
  '#6366f1', '#14b8a6', '#d946ef', '#84cc16',
];

// Stored globally so the what-if panel can re-render
let trendChart       = null;
let _trendLabels     = [];
let _appTraces       = [];
let _riskRef         = null;
let _currentMonth    = 0;
let _projectedTotals = [];
let _projectedNorm   = [];
let _currentRawTotal = 0;
let _eolAnnotations  = [];        // [{appName, monthIndex, color, eolDate}]
let _eolAlternatives = {};        // appName -> [{label, trace, eolDate, productSlug}]
let _activeEolToggles = new Map(); // appName -> selected alternative index (or null = "no change")

function renderRiskTrendChart(risk, forecasts) {
  const ctx = document.getElementById('riskTrendChart');
  if (!ctx) return;

  _riskRef = risk;
  const now        = new Date();
  _currentMonth    = now.getMonth();
  const currentYear = now.getFullYear();

  // 18 months
  const months = [];
  for (let m = 0; m < 12; m++) months.push({ m, y: currentYear });
  for (let m = 0; m < 6; m++)  months.push({ m, y: currentYear + 1 });
  _trendLabels = months.map(({ m, y }) => monthName(m) + ' ' + y);

  // Per-CPE forecast lookup
  const cpeForecasts = new Map();
  if (forecasts?.successful) {
    forecasts.successful.forEach(f => {
      if (f.cpe && f.status === 'success') cpeForecasts.set(f.cpe, f);
    });
  }
  const failedCpes = new Set();
  if (forecasts?.failed) {
    forecasts.failed.forEach(f => { if (f.cpe) failedCpes.add(f.cpe); });
  }

  const totalActual     = forecasts?.totalActual || 1;
  const totalPredicted  = forecasts?.totalPredicted || totalActual;
  const defaultGrowth   = Math.pow(Math.max(totalPredicted / totalActual, 1), 1 / 12) - 1;

  // Per-app traces
  const vulnApps = risk.appsSorted.filter(a => a.riskScore > 0);

  _appTraces = vulnApps.map(app => {
    const cpeForecast = app.cpe ? cpeForecasts.get(app.cpe) : null;
    const isFailed    = app.cpe ? failedCpes.has(app.cpe) : false;

    let growthMonthly = defaultGrowth;
    if (cpeForecast) {
      const actual   = cpeForecast.backtest_actual_total ?? cpeForecast.backtest?.actual_total ?? 0;
      const forecast = cpeForecast.forecast_total ?? actual;
      if (actual > 0) {
        growthMonthly = Math.pow(Math.max(forecast / actual, 0.5), 1 / 12) - 1;
      } else {
        // No historical data — use default or flat
        growthMonthly = forecast > 0 ? defaultGrowth : 0;
      }
    }

    const trace = _trendLabels.map((_, i) => {
      const ahead = i - _currentMonth;
      return ahead <= 0 ? app.cveCount : app.cveCount * Math.pow(1 + growthMonthly, ahead);
    });

    // ── EOL detection: compute month-index if EOL falls in the 18-month window ──
    let eolMonthIndex = null;
    let eolAlreadyPast = false;
    const eol = app.eol_data;
    if (eol?.eol_date || eol?.is_eol) {
      if (eol.eol_date) {
        const eolDate = new Date(eol.eol_date);
        const chartStart = new Date(currentYear, 0, 1);
        const chartEnd   = new Date(currentYear + 1, 5, 30); // Jun end of next year

        if (eolDate < chartStart) {
          // Already EOL (date in the past) — pin at month 0
          eolMonthIndex = 0;
          eolAlreadyPast = true;
        } else if (eolDate <= chartEnd) {
          // EOL falls within the chart window
          const eMonthOffset = eolDate.getFullYear() === currentYear
            ? eolDate.getMonth()
            : 12 + eolDate.getMonth();
          eolMonthIndex = eMonthOffset;
        }
        // else: EOL is beyond chart window — no line
      } else if (eol.is_eol) {
        // No explicit date but product is flagged EOL — pin at month 0
        eolMonthIndex = 0;
        eolAlreadyPast = true;
      }
    }

    return { name: app.name, cpe: app.cpe, hasForecast: !!cpeForecast, isFailed,
             baseRisk: app.riskScore, cveCount: app.cveCount, deviceCount: app.deviceCount,
             publisher: app.publisher, version: app.version, trace,
             eol_data: eol || null, eolMonthIndex, eolAlreadyPast };
  });

  // ── Build EOL annotations and alternative traces ──
  _eolAnnotations = [];
  _eolAlternatives = {};
  _activeEolToggles = new Map();

  _appTraces.forEach((app, idx) => {
    if (app.eolMonthIndex === null) return;
    const color = APP_COLORS[idx % APP_COLORS.length];
    const eolLabel = app.eolAlreadyPast
      ? `${truncate(app.name, 18)} — EOL`
      : `${truncate(app.name, 18)} EOL ${app.eol_data.eol_date}`;
    _eolAnnotations.push({
      appName: app.name,
      monthIndex: app.eolMonthIndex,
      color,
      eolDate: app.eol_data?.eol_date || 'past',
      label: eolLabel,
      alreadyPast: app.eolAlreadyPast,
    });

    // Build alternative traces: recommended upgrade + alternatives
    const alts = [];
    const eol = app.eol_data;

    // Recommended upgrade (new version of same product)
    if (eol.recommended) {
      alts.push({
        label: eol.recommended.formatted || `${eol.recommended.label} ${eol.recommended.release}`,
        productSlug: eol.recommended.product_slug,
        eolDate: eol.recommended.eol_date,
        cveCount: eol.recommended.cve_count ?? null,
        cpeName: eol.recommended.cpe_name || null,
        type: 'upgrade',
      });
    }

    // Alternative products
    if (eol.alternatives?.length) {
      eol.alternatives.forEach(alt => {
        let altLabel = `${alt.label} ${alt.release}`;
        if (alt.latest_build) altLabel += ` (${alt.latest_build})`;
        alts.push({
          label: altLabel,
          productSlug: alt.product_slug,
          eolDate: alt.eol_date,
          cveCount: alt.cve_count ?? null,
          cpeName: alt.cpe_name || null,
          type: 'alternative',
        });
      });
    }

    // For each alternative, build a CVE trace that forks from the EOL point.
    // Uses real ARIMA forecast from Lambda if CPE was forecasted, otherwise models a reduction.
    alts.forEach(alt => {
      const forkCves = app.trace[app.eolMonthIndex] || app.cveCount;

      // Use real CVE count if enrichment provided it from NVD
      let altBaseCves;
      if (alt.cveCount != null && alt.cveCount >= 0) {
        altBaseCves = alt.cveCount;
      } else {
        // Fallback: model reduction — upgrades inherit most CVE surface, alternatives less
        const reductionFactor = alt.type === 'upgrade' ? 0.75 : 0.55;
        altBaseCves = forkCves * reductionFactor;
      }

      // Use real ARIMA growth rate from Lambda forecast if available
      let altGrowth;
      const altForecast = alt.cpeName ? cpeForecasts.get(alt.cpeName) : null;
      if (altForecast) {
        const actual   = altForecast.backtest_actual_total ?? altForecast.backtest?.actual_total ?? 0;
        const forecast = altForecast.forecast_total ?? actual;
        if (actual > 0) {
          altGrowth = Math.pow(Math.max(forecast / actual, 0.5), 1 / 12) - 1;
        } else {
          altGrowth = forecast > 0 ? defaultGrowth : 0;
        }
        alt.hasForecast = true;
      } else {
        // Fallback: maintained products have near-zero organic growth
        altGrowth = alt.type === 'upgrade' ? 0.002 : 0.004;
        alt.hasForecast = false;
      }

      alt.trace = _trendLabels.map((_, i) => {
        if (i < app.eolMonthIndex) return null; // No data before fork
        const ahead = i - app.eolMonthIndex;
        return altBaseCves * Math.pow(1 + altGrowth, ahead);
      });
    });

    if (alts.length > 0) {
      _eolAlternatives[app.name] = alts;
    }
  });

  // Totals (CVE counts)
  _projectedTotals = _trendLabels.map((_, i) =>
    _appTraces.reduce((s, t) => s + t.trace[i], 0));
  _currentRawTotal = _projectedTotals[_currentMonth] || 1;

  // Keep normalised risk projection for what-if impact summary
  _projectedNorm = _trendLabels.map((_, i) => {
    const riskTot = _appTraces.reduce((s, t) => {
      if (t.cveCount === 0) return s;
      return s + t.trace[i] * (t.baseRisk / t.cveCount);
    }, 0);
    return Math.min(RISK_CAP, normalizeRisk(riskTot, risk.totalDevices));
  });

  // Initial what-if: nothing patched
  buildTrendChart(new Set());
  buildWhatIfPanel();
  buildEolPanel();
  updateWhatIfImpact(new Set());

  // Footnote
  const noForecast = _appTraces.filter(a => !a.hasForecast);
  const eolCount = _eolAnnotations.length;
  const fn = document.getElementById('trendChartFootnote');
  if (fn) {
    const parts = [];
    if (noForecast.length > 0) {
      parts.push(`<i class="fas fa-info-circle"></i> ` +
        noForecast.map(a => a.name + (a.isFailed ? ' (failed)' : ' (no data)')).join(', ') +
        ' — using aggregate growth rate');
    }
    if (eolCount > 0) {
      parts.push(`<i class="fas fa-calendar-times"></i> ${eolCount} product${eolCount > 1 ? 's' : ''} reach${eolCount === 1 ? 'es' : ''} EOL within the forecast window`);
    }
    if (parts.length) {
      fn.innerHTML = parts.join('<br>');
      fn.style.display = '';
    } else { fn.style.display = 'none'; }
  }
}

/* ─── Build / rebuild the chart with a given set of patched app names ─── */
function buildTrendChart(patchedNames) {
  const ctx = document.getElementById('riskTrendChart');
  if (!ctx || !_riskRef) return;

  const risk = _riskRef;
  const labels = _trendLabels;

  // Build effective traces: substitute alternative traces for EOL apps when toggled
  const effectiveTraces = _appTraces.map(app => {
    const altIdx = _activeEolToggles.get(app.name);
    const alts = _eolAlternatives[app.name];
    if (altIdx !== null && altIdx !== undefined && alts && alts[altIdx]) {
      const alt = alts[altIdx];
      const merged = app.trace.map((v, i) => {
        if (alt.trace[i] !== null && alt.trace[i] !== undefined) return alt.trace[i];
        return v;
      });
      return { ...app, trace: merged, altActive: true, altLabel: alt.label };
    }
    return { ...app, altActive: false };
  });

  // CVE count totals (no normalisation — chart shows raw counts)
  const effectiveTotals = labels.map((_, i) =>
    effectiveTraces.reduce((s, t) => s + (t.trace[i] || 0), 0));
  const currentTotal = effectiveTotals[_currentMonth] || 0;

  const patchedTotals = labels.map((_, i) =>
    effectiveTraces.filter(t => !patchedNames.has(t.name))
              .reduce((s, t) => s + (t.trace[i] || 0), 0));

  // Overlay lines — CVE counts
  const currentLine = labels.map((_, i) => i <= _currentMonth ? currentTotal : null);
  const projectedLine = effectiveTotals.map((v, i) => i >= _currentMonth ? v : null);
  const patchedLine = patchedTotals.map((v, i) => i >= _currentMonth ? v : null);

  // Stacked app datasets — raw CVE count per app
  const stackedDatasets = effectiveTraces.map((app, idx) => {
    const data = labels.map((_, i) => app.trace[i] || 0);
    const color = APP_COLORS[idx % APP_COLORS.length];
    const isPatched = patchedNames.has(app.name);

    return {
      label: app.altActive ? `${app.name} → ${app.altLabel}` : app.name,
      data,
      backgroundColor: isPatched ? color + '10' : (app.altActive ? color + '45' : color + '30'),
      borderColor: isPatched ? color + '40' : color,
      borderWidth: isPatched ? 0.5 : (app.altActive ? 2.5 : 1.5),
      borderDash: app.altActive ? [4, 2] : [],
      fill: idx === 0 ? 'origin' : '-1',
      tension: 0.3,
      pointRadius: 0,
      yAxisID: 'y',
      order: effectiveTraces.length - idx + 2,
    };
  });

  // Overlay lines (separate hidden axis to avoid stacking interference)
  const overlayDatasets = [
    { label: 'Current CVEs', data: currentLine, borderColor: '#1e293b',
      backgroundColor: 'transparent', fill: false, borderWidth: 3,
      pointRadius: 3, tension: 0.3, spanGaps: false, yAxisID: 'yOverlay', order: 1 },
    { label: 'Projected CVEs (no action)', data: projectedLine, borderColor: '#f97316',
      backgroundColor: 'transparent', fill: false, borderWidth: 2.5,
      borderDash: [6, 3], pointRadius: 2, tension: 0.3, spanGaps: false,
      yAxisID: 'yOverlay', order: 0 },
    { label: patchedNames.size > 0 ? 'After Patching Selected' : 'With Patching (select apps →)',
      data: patchedLine, borderColor: '#10b981', backgroundColor: 'transparent',
      fill: false, borderWidth: 2.5, borderDash: [4, 4], pointRadius: 2,
      tension: 0.3, spanGaps: false, yAxisID: 'yOverlay', order: 0 },
  ];

  // ── Build EOL annotation lines ──
  const annotations = {};
  // Track how many lines at each month to offset overlapping labels
  const monthLabelCount = {};
  _eolAnnotations.forEach((eol, i) => {
    const pos = eol.monthIndex;
    monthLabelCount[pos] = (monthLabelCount[pos] || 0);
    const yOffset = monthLabelCount[pos] * 22; // offset stacked labels
    monthLabelCount[pos]++;

    annotations[`eolLine_${i}`] = {
      type: 'line',
      xMin: pos,
      xMax: pos,
      borderColor: eol.color,
      borderWidth: 2,
      borderDash: [6, 4],
      label: {
        display: true,
        content: eol.label,
        position: eol.alreadyPast ? 'end' : 'start',
        yAdjust: yOffset,
        backgroundColor: eol.color + 'DD',
        color: '#fff',
        font: { size: 10, weight: 'bold' },
        padding: { top: 3, bottom: 3, left: 6, right: 6 },
        borderRadius: 4,
      },
    };
  });

  if (trendChart) trendChart.destroy();

  trendChart = new Chart(ctx, {
    type: 'line',
    data: { labels, datasets: [...stackedDatasets, ...overlayDatasets] },
    options: {
      responsive: true, maintainAspectRatio: false,
      interaction: { intersect: false, mode: 'index' },
      scales: {
        y: { stacked: true, beginAtZero: true,
             title: { display: true, text: 'Projected CVE Count', font: { size: 11 } },
             grid: { color: 'rgba(0,0,0,0.04)' },
             ticks: { precision: 0 } },
        yOverlay: { display: false, beginAtZero: true, stacked: false },
        x: { grid: { display: false }, ticks: { font: { size: 10 }, maxRotation: 45 } },
      },
      plugins: {
        annotation: {
          annotations,
        },
        legend: {
          position: 'bottom',
          labels: { usePointStyle: true, padding: 10, font: { size: 10 },
            filter: (item) => {
              return ['Current CVEs', 'Projected CVEs (no action)'].includes(item.text) ||
                     item.text.startsWith('After Patching') ||
                     item.text.startsWith('With Patching');
            }
          },
        },
        tooltip: {
          enabled: false,
          external: renderCustomTooltip,
        },
      },
    },
  });
}

/* ─── Custom HTML tooltip ─── */
function renderCustomTooltip(context) {
  const { chart, tooltip } = context;
  let el = document.getElementById('trendTooltip');
  if (!el) {
    el = document.createElement('div');
    el.id = 'trendTooltip';
    el.className = 'trend-tooltip';
    document.body.appendChild(el);
  }

  if (tooltip.opacity === 0) { el.style.opacity = 0; return; }

  const idx = tooltip.dataPoints?.[0]?.dataIndex;
  if (idx === undefined) return;

  // Gather values
  const month     = _trendLabels[idx];
  const projected = _projectedTotals[idx];
  const isFuture  = idx > _currentMonth;
  const currentCves = _projectedTotals[_currentMonth] || 0;

  // What-if currently selected
  const selected = getSelectedWhatIfApps();
  const patchedCves = _appTraces.filter(t => !selected.has(t.name))
    .reduce((s, t) => s + t.trace[idx], 0);

  // Per-app breakdown at this month (CVE counts)
  const appRows = _appTraces.map((a, i) => {
    const color = APP_COLORS[i % APP_COLORS.length];
    const isPatched = selected.has(a.name);
    const pastEol = a.eolMonthIndex !== null && idx >= a.eolMonthIndex;
    return { name: a.name, value: a.trace[idx] || 0, color, isPatched, pastEol, eol_data: a.eol_data };
  }).sort((a, b) => b.value - a.value);

  let html = `<div class="tt-header">${month}</div>`;
  html += `<div class="tt-scores">`;
  if (!isFuture) {
    html += `<div class="tt-score"><span class="tt-dot" style="background:#1e293b"></span>Current CVEs: <strong>${Math.round(currentCves)}</strong></div>`;
  }
  html += `<div class="tt-score"><span class="tt-dot" style="background:#f97316"></span>Projected CVEs: <strong>${Math.round(projected)}</strong></div>`;
  if (selected.size > 0) {
    const reduction = projected - patchedCves;
    html += `<div class="tt-score tt-patched"><span class="tt-dot" style="background:#10b981"></span>After Patching: <strong>${Math.round(patchedCves)}</strong> <span class="tt-reduction">▼${Math.round(reduction)} CVEs</span></div>`;
  }
  html += `</div>`;

  // App breakdown (top 5)
  html += `<div class="tt-breakdown">`;
  appRows.slice(0, 5).forEach(a => {
    const eolBadge = a.pastEol
      ? `<span class="tt-eol-badge">⚠ EOL ${a.eol_data?.eol_date || ''}</span>`
      : '';
    html += `<div class="tt-app ${a.isPatched ? 'tt-app-patched' : ''}">
      <span class="tt-dot" style="background:${a.color}"></span>
      <span class="tt-app-name">${escH(a.name)}${eolBadge}</span>
      <span class="tt-app-val">${Math.round(a.value)} CVEs</span>
    </div>`;
  });
  if (appRows.length > 5) html += `<div class="tt-app tt-more">+${appRows.length - 5} more</div>`;
  html += `</div>`;

  el.innerHTML = html;
  el.style.opacity = 1;

  // Position
  const pos = chart.canvas.getBoundingClientRect();
  const left = pos.left + window.scrollX + tooltip.caretX;
  const top  = pos.top + window.scrollY + tooltip.caretY;
  el.style.left = left + 12 + 'px';
  el.style.top  = top - 20 + 'px';

  // Keep in viewport
  requestAnimationFrame(() => {
    const rect = el.getBoundingClientRect();
    if (rect.right > window.innerWidth - 10) {
      el.style.left = (left - rect.width - 12) + 'px';
    }
    if (rect.bottom > window.innerHeight - 10) {
      el.style.top = (top - rect.height + 10) + 'px';
    }
  });
}

// Hide tooltip on mouseout
document.addEventListener('DOMContentLoaded', () => {
  document.addEventListener('mousemove', (e) => {
    const canvas = document.getElementById('riskTrendChart');
    const tt = document.getElementById('trendTooltip');
    if (!canvas || !tt) return;
    const rect = canvas.getBoundingClientRect();
    const over = e.clientX >= rect.left && e.clientX <= rect.right &&
                 e.clientY >= rect.top && e.clientY <= rect.bottom;
    if (!over) tt.style.opacity = 0;
  });
});

/* ─── What-If Panel ─── */
function buildWhatIfPanel() {
  const list = document.getElementById('whatifAppList');
  if (!list) return;

  const risk = _riskRef;
  list.innerHTML = _appTraces.map((app, idx) => {
    const color = APP_COLORS[idx % APP_COLORS.length];
    const pctOfTotal = risk.totalRisk > 0 ? (app.baseRisk / risk.totalRisk * 100).toFixed(1) : '0';
    const forecastTag = app.hasForecast
      ? '<span class="whatif-tag whatif-tag-ok"><i class="fas fa-chart-line"></i></span>'
      : app.isFailed
        ? '<span class="whatif-tag whatif-tag-fail" title="Forecast failed"><i class="fas fa-exclamation-triangle"></i></span>'
        : '<span class="whatif-tag whatif-tag-none" title="No forecast data"><i class="fas fa-question-circle"></i></span>';

    return `<label class="whatif-app-item" data-app="${escH(app.name)}">
      <input type="checkbox" class="whatif-check" value="${escH(app.name)}" />
      <span class="whatif-color" style="background:${color}"></span>
      <div class="whatif-app-info">
        <span class="whatif-app-name">${escH(app.name)}</span>
        <span class="whatif-app-meta">${app.cveCount} CVEs · ${app.deviceCount} devices · ${pctOfTotal}% of risk</span>
      </div>
      ${forecastTag}
    </label>`;
  }).join('');

  // Use event delegation on the list container — more robust than per-checkbox listeners
  // (Guards against DOM replacement / re-render race conditions)
  list.onchange = (e) => {
    if (!e.target.classList.contains('whatif-check')) return;
    const selected = getSelectedWhatIfApps();
    console.log('[What-If] selection changed:', [...selected]);
    try { buildTrendChart(selected); } catch(err) { console.error('[What-If] chart error:', err); }
    updateWhatIfImpact(selected);
  };

  // Action buttons — remove old listeners by cloning nodes
  const btnAll = document.getElementById('whatifSelectAll');
  const btnClr = document.getElementById('whatifClearAll');
  const btnTop = document.getElementById('whatifTop5');

  if (btnAll) {
    const fresh = btnAll.cloneNode(true);
    btnAll.parentNode.replaceChild(fresh, btnAll);
    fresh.addEventListener('click', () => {
      list.querySelectorAll('.whatif-check').forEach(cb => cb.checked = true);
      const selected = getSelectedWhatIfApps();
      buildTrendChart(selected); updateWhatIfImpact(selected);
    });
  }
  if (btnClr) {
    const fresh = btnClr.cloneNode(true);
    btnClr.parentNode.replaceChild(fresh, btnClr);
    fresh.addEventListener('click', () => {
      list.querySelectorAll('.whatif-check').forEach(cb => cb.checked = false);
      buildTrendChart(new Set()); updateWhatIfImpact(new Set());
    });
  }
  if (btnTop) {
    const fresh = btnTop.cloneNode(true);
    btnTop.parentNode.replaceChild(fresh, btnTop);
    fresh.addEventListener('click', () => {
      const top5 = new Set(_appTraces.slice(0, 5).map(a => a.name));
      list.querySelectorAll('.whatif-check').forEach(cb => {
        cb.checked = top5.has(cb.value);
      });
      buildTrendChart(top5); updateWhatIfImpact(top5);
    });
  }
}

function getSelectedWhatIfApps() {
  const set = new Set();
  document.querySelectorAll('#whatifAppList .whatif-check:checked').forEach(cb => set.add(cb.value));
  return set;
}

/* ─── EOL Alternatives Panel ─── */
function buildEolPanel() {
  const panel = document.getElementById('eolPanel');
  if (!panel) return;

  const appsWithEol = _appTraces.filter(a => a.eolMonthIndex !== null);
  if (appsWithEol.length === 0) {
    panel.style.display = 'none';
    return;
  }
  panel.style.display = 'block';

  const list = document.getElementById('eolAppList');
  if (!list) return;

  const EOL_ALT_COLORS = ['#22d3ee', '#a78bfa', '#fb923c', '#34d399'];

  list.innerHTML = appsWithEol.map((app, appIdx) => {
    const color = APP_COLORS[_appTraces.indexOf(app) % APP_COLORS.length];
    const eol = app.eol_data;
    const daysLabel = eol.days_to_eol !== null
      ? (eol.days_to_eol <= 0 ? `<span class="eol-past">EOL reached</span>` : `<span class="eol-approaching">${eol.days_to_eol} days</span>`)
      : '';

    const alts = _eolAlternatives[app.name] || [];

    let altHtml = '';
    if (alts.length > 0) {
      altHtml = `<div class="eol-alts">` +
        alts.map((alt, altIdx) => {
          const altColor = EOL_ALT_COLORS[altIdx % EOL_ALT_COLORS.length];
          const typeIcon = alt.type === 'upgrade' ? 'fa-arrow-up' : 'fa-exchange-alt';
          const typeLabel = alt.type === 'upgrade' ? 'Upgrade' : 'Alternative';
          const cveInfo = alt.cveCount != null ? `${alt.cveCount} CVEs` : '';
          const forecastBadge = alt.hasForecast
            ? ' · <span class="eol-arima-badge" title="Real ARIMA forecast from historical CVE data">ARIMA</span>'
            : ' · <span class="eol-modeled-badge" title="Growth estimated — not enough historical data for ARIMA">Modeled</span>';
          return `<label class="eol-alt-item" data-app="${escH(app.name)}" data-alt-idx="${altIdx}">
            <input type="radio" name="eol_${escH(app.name)}" class="eol-alt-radio" value="${altIdx}" />
            <span class="eol-alt-color" style="background:${altColor}"></span>
            <div class="eol-alt-info">
              <span class="eol-alt-name"><i class="fas ${typeIcon}"></i> ${typeLabel}: ${escH(alt.label)}</span>
              <span class="eol-alt-meta">${alt.eolDate ? `EOL: ${alt.eolDate}` : 'No EOL set'}${cveInfo ? ` · ${cveInfo}` : ''}${forecastBadge}</span>
            </div>
          </label>`;
        }).join('') +
        `<label class="eol-alt-item eol-alt-none" data-app="${escH(app.name)}">
          <input type="radio" name="eol_${escH(app.name)}" class="eol-alt-radio" value="none" checked />
          <span class="eol-alt-color" style="background:#94a3b8"></span>
          <span class="eol-alt-name">No change (keep current)</span>
        </label>` +
        `</div>`;
    } else {
      altHtml = `<div class="eol-alts"><span class="eol-no-alts">No upgrade paths found</span></div>`;
    }

    return `<div class="eol-app-group">
      <div class="eol-app-header">
        <span class="eol-app-dot" style="background:${color}"></span>
        <div class="eol-app-title">
          <strong>${escH(app.name)}</strong>
          <span class="eol-app-version">${escH(app.version || '')}</span>
        </div>
        <span class="eol-date-badge">
          <i class="fas fa-calendar-times"></i> ${eol.eol_date || 'Unknown'} ${daysLabel}
        </span>
      </div>
      ${altHtml}
    </div>`;
  }).join('');

  // Event listeners for radio toggles
  list.querySelectorAll('.eol-alt-radio').forEach(radio => {
    radio.addEventListener('change', () => {
      const appName = radio.closest('[data-app]').dataset.app;
      const val = radio.value;
      if (val === 'none') {
        _activeEolToggles.delete(appName);
      } else {
        _activeEolToggles.set(appName, parseInt(val, 10));
      }
      // Rebuild chart and update impact summary
      const selected = getSelectedWhatIfApps();
      buildTrendChart(selected);
      updateWhatIfImpact(selected);
    });
  });
}

function updateWhatIfImpact(selectedNames) {
  if (!_riskRef || _appTraces.length === 0) return;

  // Build effective traces that account for active EOL alternative toggles
  const effectiveTraces = _appTraces.map(app => {
    const altIdx = _activeEolToggles.get(app.name);
    const alts = _eolAlternatives[app.name];
    if (altIdx !== null && altIdx !== undefined && alts && alts[altIdx]) {
      const alt = alts[altIdx];
      const merged = app.trace.map((v, i) =>
        (alt.trace[i] !== null && alt.trace[i] !== undefined) ? alt.trace[i] : v);
      return { ...app, trace: merged };
    }
    return app;
  });

  // Current total CVEs (today — alternatives don't change this, they kick in at EOL date)
  const currentCves = _appTraces.reduce((s, t) => s + t.cveCount, 0);
  document.getElementById('whatifCurrent').textContent = Math.round(currentCves);

  const hasPatching = selectedNames.size > 0;
  const hasAlts = _activeEolToggles.size > 0;

  if (!hasPatching && !hasAlts) {
    document.getElementById('whatifAfter').textContent = Math.round(currentCves);
    document.getElementById('whatifReductionFill').style.width = '0%';
    document.getElementById('whatifReductionText').textContent = 'Select applications to see impact';
    document.getElementById('whatifAfter').className = 'whatif-value whatif-after';
    return;
  }

  // 12-month projected values
  const futureIdx = Math.min(_trendLabels.length - 1, _currentMonth + 12);
  const futureOriginal = _appTraces.reduce((s, t) => s + (t.trace[futureIdx] || 0), 0);

  // After patching: remove selected apps; remaining use effective (alt-aware) traces
  const afterCves = effectiveTraces.filter(t => !selectedNames.has(t.name))
    .reduce((s, t) => s + t.cveCount, 0);
  const immediateDelta = currentCves - afterCves;  // positive = reduction

  const futureAfter = effectiveTraces.filter(t => !selectedNames.has(t.name))
    .reduce((s, t) => s + (t.trace[futureIdx] || 0), 0);
  const futureDelta = futureOriginal - futureAfter; // positive = improvement

  // After value: for patching show immediate; for alts-only show projected
  const afterDisplay = hasPatching ? afterCves : Math.round(futureAfter);
  const afterLabel = hasPatching ? afterCves : futureAfter;

  document.getElementById('whatifAfter').textContent = Math.round(afterDisplay);

  // Colour: green if improved, red if worse
  const isImproved = hasPatching ? immediateDelta > 0 : futureDelta > 0;
  document.getElementById('whatifAfter').className =
    'whatif-value whatif-after' + (isImproved ? ' whatif-improved' : ' whatif-worse');

  // Reduction bar (0-100%, only for positive reductions)
  const barPct = immediateDelta > 0 && currentCves > 0
    ? Math.min(100, (immediateDelta / currentCves) * 100) : 0;
  document.getElementById('whatifReductionFill').style.width = barPct + '%';

  // Build description parts
  const parts = [];

  if (hasPatching) {
    const appCount = selectedNames.size;
    const appWord = appCount === 1 ? 'app' : 'apps';
    parts.push(`<strong>▼ ${Math.round(immediateDelta)} CVEs (${(immediateDelta / currentCves * 100).toFixed(0)}%)</strong> immediate · ${appCount} ${appWord} patched`);
  }

  // 12-month projection line
  if (futureDelta > 0) {
    parts.push(`<strong>▼ ${Math.round(futureDelta)} CVEs</strong> projected 12-month reduction${hasAlts ? ' (incl. alternatives)' : ''}`);
  } else if (futureDelta < 0) {
    parts.push(`<strong>▲ ${Math.round(Math.abs(futureDelta))} more CVEs</strong> projected 12-month${hasAlts ? ' — alternative has more vulnerabilities' : ''}`);
  } else {
    parts.push(`<strong>No change</strong> in projected 12-month CVEs`);
  }

  document.getElementById('whatifReductionText').innerHTML = parts.join(' · ');
}

// ═══════════════════════════════════════════════════════════
//  RENDER: Patching Recommendations
// ═══════════════════════════════════════════════════════════

function renderPatchRecommendations(risk) {
  const container = document.getElementById('patchRecommendations');
  if (!container) return;

  const top = risk.appsSorted.slice(0, 8);
  if (top.length === 0) {
    container.innerHTML = '<p>No vulnerable applications found. Your estate looks clean!</p>';
    return;
  }

  let cumulativeReduction = 0;

  let html = `<div class="patch-table-wrap"><table class="data-table patch-table">
    <thead><tr>
      <th>Priority</th>
      <th>Application</th>
      <th>CVEs</th>
      <th>Devices</th>
      <th>Risk Contribution</th>
      <th>Current Risk Reduction</th>
      <th>Projected Risk Reduction</th>
      <th>Cumulative</th>
    </tr></thead><tbody>`;

  // Composite normalization: vuln weight + coverage gap (no forecast in score)
  const vW   = risk.pillarWeights?.vuln ?? 0.75;
  const cgPen = (risk.coverageGap ?? 0) * (risk.pillarWeights?.coverage ?? 0.25);
  const compositeNorm = (raw) => vW * normalizeRisk(raw, risk.totalDevices) + cgPen;

  // Pre-compute normalised scores after removing each app cumulatively
  let cumulativeRemovedRisk = 0;

  top.forEach((app, i) => {
    // Current reduction: compare composite score before vs after removing this app
    const scoreBefore = compositeNorm(risk.totalRisk - cumulativeRemovedRisk);
    const scoreAfter  = compositeNorm(risk.totalRisk - cumulativeRemovedRisk - app.riskScore);
    const currentReductionPct = scoreBefore > 0
      ? ((scoreBefore - scoreAfter) / risk.orgRiskScore) * 100
      : 0;

    // Future reduction: patching also avoids 12 months of compounding on this app's risk
    const futureRawNoAction   = (risk.totalRisk - cumulativeRemovedRisk) * 1.15;
    const futureRawPatched    = (risk.totalRisk - cumulativeRemovedRisk - app.riskScore) * 1.15 * 0.85;
    const futureScoreBefore   = compositeNorm(futureRawNoAction);
    const futureScoreAfter    = compositeNorm(futureRawPatched);
    const futureReductionPct  = futureScoreBefore > 0
      ? ((futureScoreBefore - futureScoreAfter) / futureScoreBefore) * 100
      : 0;

    cumulativeRemovedRisk += app.riskScore;
    cumulativeReduction = risk.orgRiskScore > 0
      ? ((risk.orgRiskScore - compositeNorm(risk.totalRisk - cumulativeRemovedRisk)) / risk.orgRiskScore) * 100
      : 0;

    const priorityClass = i < 2 ? 'patch-priority-critical' :
                          i < 4 ? 'patch-priority-high' : 'patch-priority-medium';
    const priorityIcon  = i < 2 ? 'fa-fire' : i < 4 ? 'fa-exclamation-triangle' : 'fa-exclamation';

    html += `<tr class="${priorityClass}">
      <td><span class="patch-priority-badge"><i class="fas ${priorityIcon}"></i> #${i + 1}</span></td>
      <td>
        <strong>${escH(app.name)}</strong>
        <span class="patch-meta">${escH(app.publisher || '')} v${escH(app.version || '?')}</span>
      </td>
      <td>${app.cveCount}</td>
      <td>${app.deviceCount}</td>
      <td>
        <div class="risk-contrib">
          <span class="risk-contrib-pct">${(risk.totalRisk > 0 ? (app.riskScore / risk.totalRisk * 100) : 0).toFixed(1)}%</span>
          <div class="risk-contrib-bar"><div class="risk-contrib-fill" style="width:${Math.min(100, risk.totalRisk > 0 ? (app.riskScore / risk.totalRisk * 100) : 0)}%"></div></div>
        </div>
      </td>
      <td><span class="reduction-badge reduction-current">&#x25BC; ${currentReductionPct.toFixed(1)}%</span></td>
      <td><span class="reduction-badge reduction-future">&#x25BC; ${futureReductionPct.toFixed(1)}%</span></td>
      <td><span class="reduction-badge reduction-cumulative">&#x25BC; ${cumulativeReduction.toFixed(1)}%</span></td>
    </tr>`;
  });

  html += `</tbody></table></div>`;

  // Summary callout — use composite score comparison
  const top5RiskSum = risk.appsSorted.slice(0, Math.min(5, top.length)).reduce((s, a) => s + a.riskScore, 0);
  const scoreAfterTop5 = compositeNorm(risk.totalRisk - top5RiskSum);
  const top5CurrentReduction = risk.orgRiskScore > 0
    ? ((risk.orgRiskScore - scoreAfterTop5) / risk.orgRiskScore) * 100 : 0;
  const futureNoAction = compositeNorm(risk.totalRisk * 1.15);
  const futurePatched  = compositeNorm((risk.totalRisk - top5RiskSum) * 1.15 * 0.85);
  const top5FutureReduction = futureNoAction > 0
    ? ((futureNoAction - futurePatched) / futureNoAction) * 100 : 0;

  html += `<div class="patch-callout">
    <i class="fas fa-lightbulb"></i>
    <span>Patching the <strong>top ${Math.min(5, top.length)} applications</strong> would reduce your current risk score by
    <strong>${Math.min(100, top5CurrentReduction).toFixed(1)}%</strong>
    and projected future risk by approximately
    <strong>${Math.min(100, top5FutureReduction).toFixed(1)}%</strong>.</span>
  </div>`;

  container.innerHTML = html;
}

// ═══════════════════════════════════════════════════════════
//  RENDER: Risk by Application (horizontal bar)
// ═══════════════════════════════════════════════════════════

let appBarChart = null;
function renderRiskByApp(risk) {
  const ctx = document.getElementById('riskByAppChart');
  if (!ctx) return;

  const top = risk.appsSorted.slice(0, 10);
  const labels = top.map(a => truncate(a.name, 25));
  const data   = top.map(a => Math.round(a.riskScore * 10) / 10);
  const colors = top.map(a => {
    const pct = risk.totalRisk > 0 ? (a.riskScore / risk.totalRisk) * 100 : 0;
    if (pct > 20) return '#ef4444';
    if (pct > 10) return '#f97316';
    if (pct > 5)  return '#f59e0b';
    return '#3b82f6';
  });

  if (appBarChart) appBarChart.destroy();

  appBarChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Risk Score',
        data,
        backgroundColor: colors,
        borderRadius: 4,
        barThickness: 22,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: 'y',
      scales: {
        x: { beginAtZero: true, title: { display: true, text: 'Risk Score', font: { size: 10 } }, grid: { color: 'rgba(0,0,0,0.04)' } },
        y: { grid: { display: false }, ticks: { font: { size: 11 } } }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            afterLabel: (c) => {
              const app = risk.appsSorted[c.dataIndex];
              return `CVEs: ${app.cveCount} · Devices: ${app.deviceCount}\n% of total risk: ${(risk.totalRisk > 0 ? (app.riskScore / risk.totalRisk) * 100 : 0).toFixed(1)}%`;
            }
          }
        }
      }
    }
  });
}

// ═══════════════════════════════════════════════════════════
//  RENDER: Risk by User (horizontal bar)
// ═══════════════════════════════════════════════════════════

let userBarChart = null;
function renderRiskByUser(risk) {
  const ctx = document.getElementById('riskByUserChart');
  if (!ctx) return;

  const top = risk.usersSorted.slice(0, 10);
  const labels = top.map(u => truncate(u.name, 20));
  const data   = top.map(u => Math.round(u.riskScore * 10) / 10);
  const colors = top.map((_, i) => {
    if (i < 2) return '#ef4444';
    if (i < 5) return '#f97316';
    return '#f59e0b';
  });

  if (userBarChart) userBarChart.destroy();

  userBarChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Risk Score',
        data,
        backgroundColor: colors,
        borderRadius: 4,
        barThickness: 22,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: 'y',
      scales: {
        x: { beginAtZero: true, title: { display: true, text: 'Risk Score', font: { size: 10 } }, grid: { color: 'rgba(0,0,0,0.04)' } },
        y: { grid: { display: false }, ticks: { font: { size: 11 } } }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            afterLabel: (c) => {
              const user = risk.usersSorted[c.dataIndex];
              return `Vulnerable apps: ${user.apps.size}`;
            }
          }
        }
      }
    }
  });
}

// ═══════════════════════════════════════════════════════════
//  RENDER: Top EPSS Table
// ═══════════════════════════════════════════════════════════

function renderTopEpss(risk) {
  const tbody = document.getElementById('topEpssBody');
  if (!tbody) return;

  const top = [...risk.allCveRisks]
    .sort((a, b) => b.epss - a.epss)
    .slice(0, 15);

  if (top.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7">No vulnerability data available.</td></tr>';
    return;
  }

  tbody.innerHTML = top.map(cve => {
    const sevClass = `severity-${cve.severity.toLowerCase()}`;
    const epssBar = Math.min(100, cve.epss * 100);
    return `<tr>
      <td><a href="https://nvd.nist.gov/vuln/detail/${escH(cve.cve_id)}" target="_blank" rel="noopener">${escH(cve.cve_id)}</a></td>
      <td>${escH(cve.appName)}</td>
      <td><strong>${cve.cvss.toFixed(1)}</strong></td>
      <td>
        <div class="epss-bar-wrap">
          <div class="epss-bar" style="width:${epssBar}%;background:${epssColor(cve.epss)}"></div>
          <span class="epss-label">${(cve.epss * 100).toFixed(2)}%</span>
        </div>
      </td>
      <td><span class="risk-score-badge">${cve.riskScore.toFixed(1)}</span></td>
      <td>${cve.deviceCount}</td>
      <td><span class="status-badge ${sevClass}">${cve.severity}</span></td>
    </tr>`;
  }).join('');
}

// ═══════════════════════════════════════════════════════════
//  RENDER: Estate Overview (collapsible)
// ═══════════════════════════════════════════════════════════

function renderEstateOverview(schema, risk) {
  setText('devicesCount', risk.totalDevices);
  setText('usersCount', risk.totalUsers);
  setText('applicationsCount', risk.totalApps);
  setText('platformsCount', risk.totalPlatforms);
  setText('vulnerabilitiesCount', risk.totalCves);
}

// ═══════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════

/**
 * Normalise raw risk to 0–100 using a saturating exponential curve.
 * score = 100 × (1 − e^(−rawRisk / baseline))
 *
 * The baseline uses √(devices) scaling because blastRadius already
 * captures per-device exposure.  This means the same CVE count is
 * more alarming on a small estate and less on a large one.
 * Calibrated so 12 CVEs (real EPSS ~0.1%) on 50 devices ≈ 39,
 * and 50+ CVEs with moderate EPSS nears 90+.
 */
function normalizeRisk(rawRisk, totalDevices) {
  if (rawRisk <= 0) return 0;
  const baseline = 10 * Math.sqrt(Math.max(totalDevices, 1));
  return Math.min(RISK_CAP, 100 * (1 - Math.exp(-rawRisk / baseline)));
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function escH(s) {
  const d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML;
}

function truncate(s, n) {
  if (!s) return '';
  return s.length > n ? s.slice(0, n) + '…' : s;
}

function monthName(m) {
  return ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][m];
}

function epssColor(epss) {
  if (epss >= 0.5)  return '#ef4444';
  if (epss >= 0.1)  return '#f97316';
  if (epss >= 0.01) return '#f59e0b';
  return '#10b981';
}