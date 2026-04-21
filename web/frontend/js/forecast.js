// Forecast page — real DynamoDB ARIMA data integration
class ForecastManager {
  constructor() {
    this.data = null;           // full API response
    this.successful = [];       // successful forecasts
    this.failed = [];           // failed forecasts
    this.filtered = [];         // currently displayed
    this.activeFilter = 'all';
    this.modalCharts = {};      // chart instances in modal
    this.yearlyCharts = {};     // chart instances for yearly section
    this.yearly = null;         // yearly forecast data
    this.init();
  }

  async init() {
    try {
      // Load per-CPE + yearly in parallel
      await Promise.all([
        this.loadData(),
        this.loadYearly(),
      ]);
      this.updateLastUpdated();
      this.renderSummaryCards();
      this.renderGrid();
      this.renderFailedTable();
      this.setupEventListeners();
      document.getElementById('forecastLoading').style.display = 'none';
      document.getElementById('forecastContent').style.display = '';
    } catch (err) {
      console.error('Forecast init error:', err);
      document.getElementById('forecastLoading').style.display = 'none';
      document.getElementById('forecastErrorMsg').textContent = err.message || 'Failed to load forecast data.';
      document.getElementById('forecastError').style.display = 'flex';
    }
  }

  // ───────── Data loading ──────────────────────────────────────
  async loadData() {
    const res = await fetch('/api/forecasts');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const json = await res.json();
    if (!json.success) throw new Error(json.error || 'API error');

    this.data = json;
    this.successful = json.successful || [];
    this.failed = [...(json.failed || []), ...(json.notForcastable || [])];
    this.filtered = [...this.successful];
  }

  updateLastUpdated() {
    const el = document.getElementById('lastUpdated');
    if (!el) return;
    // Find the most recent forecast epoch across all items
    let newest = 0;
    this.successful.forEach(f => {
      if (f.last_forecast_epoch > newest) newest = f.last_forecast_epoch;
    });
    // Also consider the yearly forecast epoch
    if (this.yearly?.last_forecast_epoch > newest) {
      newest = this.yearly.last_forecast_epoch;
    }
    if (newest > 0) {
      const ago = this.timeAgo(newest);
      el.textContent = `Forecasts updated ${ago}`;
    } else {
      el.textContent = 'No forecast data';
    }
  }

  timeAgo(epoch) {
    const diff = Math.floor(Date.now() / 1000) - epoch;
    if (diff < 60) return 'just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  }

  // ───────── Yearly Total CVE Forecast ─────────────────────────
  async loadYearly() {
    const targetYear = new Date().getFullYear();
    try {
      const res = await fetch(`/api/forecasts/yearly/${targetYear}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      if (!json.success) throw new Error(json.error || 'API error');

      this.yearly = json.forecast;
      document.getElementById('yearlyLoading').style.display = 'none';

      if (this.yearly.status === 'failed') {
        document.getElementById('yearlyError').style.display = '';
        document.getElementById('yearlyErrorMsg').textContent =
          this.yearly.error || 'Forecast generation failed.';
        return;
      }

      document.getElementById('yearlyContent').style.display = '';
      this.renderYearly();
    } catch (err) {
      console.error('Yearly forecast error:', err);
      document.getElementById('yearlyLoading').style.display = 'none';
      document.getElementById('yearlyError').style.display = '';
      document.getElementById('yearlyErrorMsg').textContent = err.message;
    }
  }

  renderYearly() {
    const y = this.yearly;

    // Headline
    document.getElementById('yearlyTargetYear').textContent = y.target_year;
    document.getElementById('yearlyForecastTotal').textContent =
      Math.round(y.forecast_total).toLocaleString();

    // Growth badge
    if (y.projected_growth_pct !== null && y.projected_growth_pct !== undefined) {
      const badge = document.getElementById('yearlyGrowthBadge');
      const pct = y.projected_growth_pct;
      badge.style.display = '';
      badge.querySelector('i').className = pct >= 0 ? 'fas fa-arrow-up' : 'fas fa-arrow-down';
      badge.classList.toggle('yearly-growth-down', pct < 0);
      document.getElementById('yearlyGrowthPct').textContent = Math.abs(pct).toFixed(1);
    }

    // Sub text
    const bt = y.backtest;
    const lastYearTotal = bt?.actual_total || (y.historical_yearly?.slice(-1)[0]?.total);
    document.getElementById('yearlyHeroSub').textContent = lastYearTotal
      ? `Up from ${Math.round(lastYearTotal).toLocaleString()} in ${bt?.year || y.target_year - 1}`
      : '';

    // Backtest card
    if (bt) {
      document.getElementById('yearlyBtYear').textContent = bt.year;
      const btChartYearEl = document.getElementById('yearlyBtChartYear');
      if (btChartYearEl) btChartYearEl.textContent = bt.year;
      // diff_pct may be computed server-side; fall back to manual calc
      let diff = bt.diff_pct;
      if (diff === undefined && bt.actual_total && bt.forecast_total) {
        diff = ((bt.forecast_total - bt.actual_total) / bt.actual_total) * 100;
      }
      if (diff !== null && diff !== undefined) {
        document.getElementById('yearlyBtDiff').textContent =
          `${diff > 0 ? '+' : ''}${diff.toFixed(1)}% error`;
        document.getElementById('yearlyBtDiff').classList.toggle('yearly-bt-good', Math.abs(diff) < 5);
        document.getElementById('yearlyBtDiff').classList.toggle('yearly-bt-warn', Math.abs(diff) >= 5 && Math.abs(diff) < 15);
        document.getElementById('yearlyBtDiff').classList.toggle('yearly-bt-bad', Math.abs(diff) >= 15);
      }
      document.getElementById('yearlyBtSub').textContent =
        `Actual: ${bt.actual_total?.toLocaleString() || '—'} · Forecast: ${bt.forecast_total?.toLocaleString() || '—'}`;
    }

    // ── Year progress ──────────────────────────────────────────
    const progressWrap = document.getElementById('yearlyProgress');
    if (progressWrap) {
      const actualCt  = y.actual_months_count  || 0;
      const fcastCt   = y.forecasted_months_count || 0;
      const totalCt   = actualCt + fcastCt || 12;
      const pct       = Math.round((actualCt / totalCt) * 100);
      const actualTot = y.actual_months_total || 0;
      const fcastTot  = y.forecasted_months_total || 0;

      progressWrap.style.display = '';
      document.getElementById('yearlyProgressBar').style.width = `${pct}%`;
      document.getElementById('yearlyProgressLabel').textContent =
        `${actualCt} of ${totalCt} months actual`;
      const today = new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
      document.getElementById('yearlyProgressDetail').innerHTML =
        `<span>Actual YTD: <strong>${actualTot.toLocaleString()}</strong></span>` +
        `<span>Forecasted remaining: <strong>${fcastTot.toLocaleString()}</strong></span>` +
        `<span>Last data: <strong>${today}</strong></span>`;
    }

    // Metadata
    document.getElementById('yearlyUpdated').textContent =
      y.last_forecast_iso ? new Date(y.last_forecast_iso).toLocaleString() : '—';
    document.getElementById('yearlyModel').textContent = y.model || '—';
    document.getElementById('yearlyBias').textContent =
      y.bias_correction_pct !== null && y.bias_correction_pct !== undefined
        ? `${y.bias_correction_pct > 0 ? '+' : ''}${y.bias_correction_pct.toFixed(1)}%`
        : '—';

    // Charts
    this.renderYearlyBarChart();
    this.renderYearlyMonthlyChart();
    this.renderYearlyAccuracy();
  }

  renderYearlyBarChart() {
    const y = this.yearly;
    const ctx = document.getElementById('yearlyBarChart')?.getContext('2d');
    if (!ctx) return;

    const hist = (y.historical_yearly || []).sort((a, b) => a.year - b.year);
    const targetYear = y.target_year;

    // Filter out the target year from history to avoid duplicate bar
    const histFiltered = hist.filter(h => h.year !== targetYear);
    const labels = histFiltered.map(h => h.year);
    const data = histFiltered.map(h => h.total);

    // Append forecast year as the final bar
    labels.push(targetYear);
    data.push(Math.round(y.forecast_total));

    const bgColors = data.map((_, i) =>
      i === data.length - 1 ? 'rgba(255,107,53,0.75)' : 'rgba(59,130,246,0.6)');
    const borderColors = data.map((_, i) =>
      i === data.length - 1 ? '#ff6b35' : '#3b82f6');

    if (this.yearlyCharts.bar) this.yearlyCharts.bar.destroy();
    this.yearlyCharts.bar = new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: 'Total CVEs',
          data,
          backgroundColor: bgColors,
          borderColor: borderColors,
          borderWidth: 1,
          borderRadius: 4,
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              title: ctx => `Year ${ctx[0].label}`,
              label: ctx => {
                const idx = ctx.dataIndex;
                return idx === data.length - 1
                  ? `Forecast: ${ctx.parsed.y.toLocaleString()}`
                  : `Actual: ${ctx.parsed.y.toLocaleString()}`;
              }
            }
          }
        },
        scales: {
          x: { grid: { display: false } },
          y: { beginAtZero: false, grid: { color: 'rgba(0,0,0,0.05)' },
            ticks: { callback: v => v >= 1000 ? `${(v / 1000).toFixed(0)}k` : v } }
        }
      }
    });
  }

  renderYearlyMonthlyChart() {
    const y = this.yearly;
    const ctx = document.getElementById('yearlyMonthlyChart')?.getContext('2d');
    if (!ctx) return;

    // Historical monthly actuals
    const histMonthly = (y.historical_monthly || []).sort((a, b) => a.month.localeCompare(b.month));
    // Forecast monthly — new schema has is_actual flag
    const fcastMonthly = (y.forecast_monthly || []).sort((a, b) => a.month.localeCompare(b.month));

    // Only show last 36 months of history + forecast to keep it readable
    const recentHist = histMonthly.slice(-36);
    const allLabels = [
      ...recentHist.map(m => m.month),
      ...fcastMonthly.map(m => m.month),
    ];
    // Remove duplicates (in case partial year has both actual and forecast)
    const uniqueLabels = [...new Set(allLabels)].sort();

    // Build lookup maps
    const histMap = new Map(histMonthly.map(m => [m.month, m.actual]));
    // All forecast months (both completed and future) carry a predicted value
    const fcastPredMap = new Map(fcastMonthly.map(m => [m.month, m.predicted]));
    // Actual target-year months also have actual values
    const fcastActualMap = new Map(
      fcastMonthly.filter(m => m.is_actual).map(m => [m.month, m.actual])
    );

    // Actual line: history + target-year actuals (where available)
    const actualData = uniqueLabels.map(l => histMap.get(l) ?? fcastActualMap.get(l) ?? null);

    // Forecast line: predicted values for ALL forecast months (completed + future)
    const forecastData = uniqueLabels.map(l => fcastPredMap.get(l) ?? null);

    // Bridge: set the last historical month as the start of the forecast line
    // so the orange line visually connects from Dec to Jan
    const lastHistIdx = uniqueLabels.reduce((last, l, i) => histMap.has(l) ? i : last, -1);
    if (lastHistIdx >= 0 && forecastData[lastHistIdx] === null) {
      forecastData[lastHistIdx] = actualData[lastHistIdx];
    }

    const formatLabel = (m) => {
      const [yr, mo] = m.split('-');
      return new Date(yr, mo - 1).toLocaleDateString('en-GB', { month: 'short', year: '2-digit' });
    };

    if (this.yearlyCharts.monthly) this.yearlyCharts.monthly.destroy();
    this.yearlyCharts.monthly = new Chart(ctx, {
      type: 'line',
      data: {
        labels: uniqueLabels.map(formatLabel),
        datasets: [
          {
            label: 'Actual',
            data: actualData,
            borderColor: '#3b82f6',
            backgroundColor: 'rgba(59,130,246,0.08)',
            borderWidth: 2,
            fill: true,
            tension: 0.3,
            pointRadius: 0,
            spanGaps: false,
          },
          {
            label: 'Forecast',
            data: forecastData,
            borderColor: '#ff6b35',
            backgroundColor: 'rgba(255,107,53,0.08)',
            borderWidth: 2,
            borderDash: [6, 3],
            fill: true,
            tension: 0.3,
            pointRadius: 0,
            spanGaps: false,
          }
        ]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 11 } } },
          tooltip: {
            callbacks: {
              label: ctx => {
                const val = ctx.parsed.y;
                if (val === null || val === undefined) return null;
                return `${ctx.dataset.label}: ${Math.round(val).toLocaleString()}`;
              }
            }
          },
        },
        scales: {
          x: { grid: { display: false }, ticks: { maxTicksLimit: 12, font: { size: 10 } } },
          y: { beginAtZero: false, grid: { color: 'rgba(0,0,0,0.05)' },
            ticks: { callback: v => v >= 1000 ? `${(v / 1000).toFixed(1)}k` : v } }
        }
      }
    });
  }

  renderYearlyBacktestChart() {
    const y = this.yearly;
    const bt = y.backtest;
    if (!bt || !bt.monthly) return;

    const ctx = document.getElementById('yearlyBacktestChart')?.getContext('2d');
    if (!ctx) return;

    const months = (bt.monthly || []).sort((a, b) => a.month.localeCompare(b.month));
    const labels = months.map(m => {
      const [yr, mo] = m.month.split('-');
      return new Date(yr, mo - 1).toLocaleDateString('en-GB', { month: 'short' });
    });
    const actuals = months.map(m => m.actual ?? null);
    const predicted = months.map(m => m.predicted ?? null);

    if (this.yearlyCharts.backtest) this.yearlyCharts.backtest.destroy();
    this.yearlyCharts.backtest = new Chart(ctx, {
      type: 'line',
      data: {
        labels,
        datasets: [
          {
            label: 'Actual',
            data: actuals,
            borderColor: '#10b981',
            backgroundColor: 'rgba(16,185,129,0.12)',
            borderWidth: 2,
            fill: true,
            tension: 0.3,
            pointRadius: 4,
          },
          {
            label: 'Predicted',
            data: predicted,
            borderColor: '#ff6b35',
            borderWidth: 2,
            borderDash: [5, 3],
            fill: false,
            tension: 0.3,
            pointRadius: 4,
          }
        ]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 11 } } },
          title: {
            display: true,
            text: (() => {
              let d = bt.diff_pct;
              if (d === undefined && bt.actual_total && bt.forecast_total)
                d = ((bt.forecast_total - bt.actual_total) / bt.actual_total) * 100;
              return d !== null && d !== undefined
                ? `Model accuracy: ${Math.abs(d).toFixed(1)}% error`
                : 'Model accuracy: \u2014';
            })(),
            font: { size: 12, weight: 'normal' }, color: '#64748b',
          }
        },
        scales: {
          x: { grid: { display: false } },
          y: { beginAtZero: false, grid: { color: 'rgba(0,0,0,0.05)' },
            ticks: { callback: v => v >= 1000 ? `${(v / 1000).toFixed(1)}k` : v } }
        }
      }
    });
  }

  // ───────── Accuracy tracking for completed months ────────────
  renderYearlyAccuracy() {
    const y = this.yearly;
    const wrap = document.getElementById('yearlyAccuracySection');
    if (!wrap) return;

    // Use accuracy.per_month if available, else fall back to
    // forecast_monthly entries with is_actual === true
    let rows = [];
    if (y.accuracy && Array.isArray(y.accuracy.per_month) && y.accuracy.per_month.length) {
      rows = y.accuracy.per_month;
    } else if (Array.isArray(y.forecast_monthly)) {
      rows = y.forecast_monthly.filter(m => m.is_actual);
    }

    if (rows.length === 0) {
      wrap.style.display = 'none';
      return;
    }
    wrap.style.display = '';

    const sorted = [...rows].sort((a, b) => (a.month || '').localeCompare(b.month || ''));
    const tbody = sorted.map(r => {
      const lbl = r.month ? r.month : '\u2014';
      const actual = r.actual != null ? Math.round(r.actual).toLocaleString() : '\u2014';
      const pred   = r.predicted != null ? Math.round(r.predicted).toLocaleString() : '\u2014';
      const diff   = r.diff_pct != null ? r.diff_pct : null;
      let diffHtml = '\u2014';
      if (diff !== null) {
        const cls = Math.abs(diff) < 5 ? 'yearly-bt-good'
                  : Math.abs(diff) < 15 ? 'yearly-bt-warn' : 'yearly-bt-bad';
        diffHtml = `<span class="${cls}">${diff > 0 ? '+' : ''}${diff.toFixed(1)}%</span>`;
      }
      return `<tr><td>${lbl}</td><td>${actual}</td><td>${pred}</td><td>${diffHtml}</td></tr>`;
    }).join('');

    document.getElementById('yearlyAccuracyBody').innerHTML = tbody;
  }

  // ───────── Summary cards ─────────────────────────────────────
  renderSummaryCards() {
    const d = this.data;
    const fYear = d.forecastYear || String(new Date().getFullYear());
    const bYear = d.backtestYear || String(new Date().getFullYear() - 1);

    document.getElementById('totalCpes').textContent = d.total || 0;
    const parts = [];
    if (d.successCount) parts.push(`${d.successCount} success`);
    if (d.failedCount) parts.push(`${d.failedCount} failed`);
    if (d.notForecastableCount) parts.push(`${d.notForecastableCount} not forecastable`);
    document.getElementById('successFailCount').textContent =
      parts.length ? parts.join(' · ') : '0 results';

    document.getElementById('totalActualValue').textContent =
      this.formatNumber(d.totalActual);
    document.getElementById('totalActualLabel').textContent = `Actual CVEs ${bYear}`;

    document.getElementById('totalPredictedValue').textContent =
      this.formatNumber(d.totalPredicted);
    document.getElementById('totalPredictedLabel').textContent = `Predicted CVEs ${fYear}`;

    // Accuracy
    if (d.avgDiffPct !== null && d.avgDiffPct !== undefined) {
      document.getElementById('avgAccuracy').textContent = `${d.avgDiffPct.toFixed(1)}%`;
      document.getElementById('avgMapeLabel').textContent =
        `Avg MAPE: ${d.avgMape !== null ? d.avgMape.toFixed(1) + '%' : '-'}`;
    }
  }

  formatNumber(n) {
    if (n === null || n === undefined) return '-';
    return n.toLocaleString();
  }

  // ───────── CPE Forecast Cards Grid ───────────────────────────
  renderGrid() {
    const grid = document.getElementById('cpeForecastGrid');
    if (!grid) return;

    if (this.filtered.length === 0) {
      grid.innerHTML = `<div class="forecast-empty-state">
        <i class="fas fa-inbox"></i>
        <p>No forecasts match your filter.</p>
      </div>`;
      return;
    }

    grid.innerHTML = this.filtered.map(f => this.buildCpeCard(f)).join('');
  }

  buildCpeCard(f) {
    const vendor = this.capitalize(f.vendor || 'Unknown');
    const product = this.capitalize((f.product || 'unknown').replace(/_/g, ' '));
    const forecastTotal = Math.round(f.forecast_total || 0);
    const backtestActual = Math.round(f.backtest_actual_total || 0);
    const diffPct = f.backtest_diff_pct !== undefined ? f.backtest_diff_pct : null;
    const diffLabel = diffPct !== null ? `${Math.abs(diffPct).toFixed(1)}% error` : '';
    const growthPct = backtestActual > 0
      ? ((forecastTotal - backtestActual) / backtestActual * 100).toFixed(1)
      : null;
    const growthClass = growthPct !== null
      ? (parseFloat(growthPct) > 0 ? 'growth-up' : 'growth-down')
      : '';
    const growthIcon = growthPct !== null
      ? (parseFloat(growthPct) > 0 ? 'fa-arrow-up' : 'fa-arrow-down')
      : '';
    const granularity = f.granularity || 'unknown';
    const fYear = f.forecast_start?.slice(0, 4) || String(new Date().getFullYear());
    const bYear = f.backtest_start?.slice(0, 4) || String(new Date().getFullYear() - 1);

    // Version-level label
    const isVersionLevel = f.forecast_level === 'version' && f.version && f.version !== '*';
    const isVendorLevel = f.forecast_level === 'vendor';
    const versionBadge = isVersionLevel
      ? `<span class="cpe-version-badge">v${this.escapeHtml(f.version)}</span>`
      : '';

    // Forecast level badge for top-right
    const levelLabel = isVendorLevel ? 'Vendor' : isVersionLevel ? 'Version' : 'Product';
    const levelIcon = isVendorLevel ? 'fa-building' : isVersionLevel ? 'fa-code-branch' : 'fa-cube';
    const levelCls = isVendorLevel ? 'cpe-level-vendor' : isVersionLevel ? 'cpe-level-version' : 'cpe-level-product';

    return `
      <div class="cpe-forecast-card" data-cpe="${this.escapeAttr(f.cpe)}" tabindex="0" role="button">
        <div class="cpe-card-header">
          <div class="cpe-card-title">
            <span class="cpe-vendor">${this.escapeHtml(vendor)}</span>
            <span class="cpe-product">${this.escapeHtml(product)} ${versionBadge}</span>
          </div>
          <span class="cpe-level-badge ${levelCls}"><i class="fas ${levelIcon}"></i> ${levelLabel}</span>
        </div>
        <div class="cpe-card-body">
          <div class="cpe-stat-main">
            <span class="cpe-stat-value">${forecastTotal.toLocaleString()}</span>
            <span class="cpe-stat-label">Predicted CVEs ${fYear}</span>
          </div>
          <div class="cpe-stat-row">
            <div class="cpe-stat-mini">
              <span class="cpe-stat-mini-value">${backtestActual.toLocaleString()}</span>
              <span class="cpe-stat-mini-label">Actual ${bYear}</span>
            </div>
            ${growthPct !== null ? `
            <div class="cpe-stat-mini">
              <span class="cpe-stat-mini-value ${growthClass}">
                <i class="fas ${growthIcon}"></i> ${Math.abs(parseFloat(growthPct))}%
              </span>
              <span class="cpe-stat-mini-label">Change</span>
            </div>` : ''}
            <div class="cpe-stat-mini">
              <span class="cpe-stat-mini-value">${diffLabel || '-'}</span>
              <span class="cpe-stat-mini-label">Backtest</span>
            </div>
          </div>
        </div>
        <div class="cpe-card-footer">
          <span class="cpe-granularity"><i class="fas fa-clock"></i> ${granularity}</span>
          <span class="cpe-detail-link">View detail <i class="fas fa-chevron-right"></i></span>
        </div>
      </div>`;
  }

  getConfidence(mape) {
    if (mape === undefined || mape === null) return { label: 'N/A', cls: 'conf-na' };
    if (mape < 20) return { label: 'High', cls: 'conf-high' };
    if (mape < 50) return { label: 'Medium', cls: 'conf-med' };
    return { label: 'Low', cls: 'conf-low' };
  }

  // ───────── Failed table ──────────────────────────────────────
  renderFailedTable() {
    if (this.failed.length === 0) return;
    document.getElementById('failedSection').style.display = '';
    const tbody = document.getElementById('failedTableBody');
    tbody.innerHTML = this.failed.map(f => {
      const ago = f.last_forecast_epoch ? this.timeAgo(f.last_forecast_epoch) : '-';
      const reason = f.status === 'not_forecastable'
        ? (f.error || `Not forecastable (score: ${f.forecastability_score ?? '—'})`)
        : this.escapeHtml(f.error || 'Unknown error');
      return `<tr>
        <td class="cpe-cell" title="${this.escapeAttr(f.cpe)}">${this.truncateCpe(f.cpe)}</td>
        <td class="error-cell">${reason}</td>
        <td>${ago}</td>
      </tr>`;
    }).join('');
  }

  truncateCpe(cpe) {
    if (!cpe) return '-';
    // Show vendor:product portion
    const parts = cpe.split(':');
    if (parts.length >= 5) return `${parts[3]}:${parts[4]}`;
    return cpe.length > 40 ? cpe.substring(0, 40) + '…' : cpe;
  }

  // ───────── Modal ─────────────────────────────────────────────
  openModal(cpe) {
    const f = this.successful.find(i => i.cpe === cpe);
    if (!f) return;

    const modal = document.getElementById('forecastModal');
    modal.style.display = 'flex';
    document.body.style.overflow = 'hidden';

    const vendor = this.capitalize(f.vendor || 'Unknown');
    const product = this.capitalize((f.product || 'unknown').replace(/_/g, ' '));
    const isVersionLevel = f.forecast_level === 'version' && f.version && f.version !== '*';
    const isVendorLevel = f.forecast_level === 'vendor';
    const titleSuffix = isVersionLevel ? ` v${f.version}` : '';
    const levelLabel = isVendorLevel ? '(vendor-level)' : isVersionLevel ? '(version-level)' : '(all versions)';
    const fYear = f.forecast_start?.slice(0, 4) || String(new Date().getFullYear());

    document.getElementById('modalTitle').textContent = `${vendor} ${product}${titleSuffix}`;

    // Headline
    const headline = document.getElementById('modalHeadline');
    headline.innerHTML = `
      <div class="modal-headline-stat">
        <span class="modal-headline-value">${Math.round(f.forecast_total || 0).toLocaleString()}</span>
        <span class="modal-headline-label">Predicted CVEs in ${fYear} ${levelLabel}</span>
      </div>
      <div class="modal-headline-meta">
        <span><i class="fas fa-cogs"></i> Model: ${f.model || 'ARIMA'}</span>
        <span><i class="fas fa-clock"></i> Granularity: ${f.granularity || '-'}</span>
        <span><i class="fas fa-database"></i> Train: ${f.train_periods || '-'} periods</span>
        <span><i class="fas fa-vial"></i> Test: ${f.test_periods || '-'} periods</span>
      </div>`;

    // Metrics
    const metrics = document.getElementById('modalMetrics');
    metrics.innerHTML = `
      <div class="metric-pill"><span class="metric-label">MAE</span><span class="metric-value">${f.mae !== undefined ? f.mae.toFixed(2) : '-'}</span></div>
      <div class="metric-pill"><span class="metric-label">RMSE</span><span class="metric-value">${f.rmse !== undefined ? f.rmse.toFixed(2) : '-'}</span></div>
      <div class="metric-pill"><span class="metric-label">MAPE</span><span class="metric-value">${f.backtest_mape !== undefined ? f.backtest_mape.toFixed(1) + '%' : '-'}</span></div>
      <div class="metric-pill"><span class="metric-label">Diff%</span><span class="metric-value">${f.backtest_diff_pct !== undefined ? f.backtest_diff_pct.toFixed(1) + '%' : '-'}</span></div>`;

    // Destroy old charts
    Object.values(this.modalCharts).forEach(c => c.destroy());
    this.modalCharts = {};

    this.renderHistoricalChart(f);
    this.renderForecastPeriodsChart(f);
    this.renderBacktestChart(f);
  }

  closeModal() {
    document.getElementById('forecastModal').style.display = 'none';
    document.body.style.overflow = '';
    Object.values(this.modalCharts).forEach(c => c.destroy());
    this.modalCharts = {};
  }

  // Historical bar chart + forecast bar
  renderHistoricalChart(f) {
    const ctx = document.getElementById('modalHistoricalChart').getContext('2d');
    const hist = (f.historical_yearly || []).sort((a, b) => a.year - b.year);
    const fYear = parseInt(f.forecast_start?.slice(0, 4) || String(new Date().getFullYear()));

    // Filter out the forecast year from history (it may have partial actuals)
    const histFiltered = hist.filter(h => h.year !== fYear);
    const labels = histFiltered.map(h => h.year);
    const data = histFiltered.map(h => h.cve_count);

    // Append forecast year as the final bar
    labels.push(fYear);
    data.push(Math.round(f.forecast_total || 0));

    const bgColors = data.map((_, i) => i === data.length - 1 ? 'rgba(255,107,53,0.7)' : 'rgba(59,130,246,0.6)');
    const borderColors = data.map((_, i) => i === data.length - 1 ? '#ff6b35' : '#3b82f6');

    this.modalCharts.historical = new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: 'CVE Count',
          data,
          backgroundColor: bgColors,
          borderColor: borderColors,
          borderWidth: 1,
          borderRadius: 4,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              title: ctx => `Year ${ctx[0].label}`,
              label: ctx => {
                const idx = ctx.dataIndex;
                return idx === data.length - 1
                  ? `Forecast: ${ctx.parsed.y}`
                  : `Actual: ${ctx.parsed.y}`;
              }
            }
          }
        },
        scales: {
          x: { grid: { display: false } },
          y: { beginAtZero: true, grid: { color: 'rgba(0,0,0,0.05)' } }
        }
      }
    });
  }

  // Period forecast chart
  renderForecastPeriodsChart(f) {
    const ctx = document.getElementById('modalForecastChart').getContext('2d');
    const periods = f.forecast_periods || [];
    const periodsMape = f.forecast_periods_mape_optimised || [];

    const labels = periods.map(p => this.formatPeriodDate(p.date, f.granularity));
    const dataDiff = periods.map(p => Math.round(p.predicted * 10) / 10);
    const dataMape = periodsMape.map(p => Math.round(p.predicted * 10) / 10);

    const datasets = [{
      label: 'Diff%-optimised',
      data: dataDiff,
      borderColor: '#ff6b35',
      backgroundColor: 'rgba(255,107,53,0.1)',
      borderWidth: 2,
      fill: true,
      tension: 0.3,
      pointRadius: 4,
    }];
    if (dataMape.length) {
      datasets.push({
        label: 'MAPE-optimised',
        data: dataMape,
        borderColor: '#3b82f6',
        backgroundColor: 'rgba(59,130,246,0.08)',
        borderWidth: 2,
        borderDash: [5, 3],
        fill: false,
        tension: 0.3,
        pointRadius: 4,
      });
    }

    this.modalCharts.forecast = new Chart(ctx, {
      type: 'line',
      data: { labels, datasets },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 11 } } } },
        scales: {
          x: { grid: { display: false } },
          y: { beginAtZero: true, grid: { color: 'rgba(0,0,0,0.05)' } }
        }
      }
    });
  }

  // Backtest chart — predicted vs actual
  renderBacktestChart(f) {
    const ctx = document.getElementById('modalBacktestChart').getContext('2d');
    const periods = f.backtest_annual_periods || [];
    const periodsMape = f.backtest_shortterm_periods || [];

    const labels = periods.map(p => this.formatPeriodDate(p.date, f.granularity));
    const actuals = periods.map(p => p.actual);
    const predicted = periods.map(p => Math.round(p.predicted * 10) / 10);
    const predictedMape = periodsMape.map(p => Math.round(p.predicted * 10) / 10);

    const datasets = [
      {
        label: 'Actual',
        data: actuals,
        borderColor: '#10b981',
        backgroundColor: 'rgba(16,185,129,0.15)',
        borderWidth: 2,
        fill: true,
        tension: 0.3,
        pointRadius: 5,
      },
      {
        label: 'Predicted (Diff%)',
        data: predicted,
        borderColor: '#ff6b35',
        borderWidth: 2,
        borderDash: [5, 3],
        fill: false,
        tension: 0.3,
        pointRadius: 5,
      }
    ];
    if (predictedMape.length) {
      datasets.push({
        label: 'Predicted (MAPE)',
        data: predictedMape,
        borderColor: '#3b82f6',
        borderWidth: 2,
        borderDash: [2, 2],
        fill: false,
        tension: 0.3,
        pointRadius: 4,
      });
    }

    this.modalCharts.backtest = new Chart(ctx, {
      type: 'line',
      data: { labels, datasets },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 11 } } },
          title: {
            display: true,
            text: `Annual accuracy: ${f.backtest_diff_pct !== undefined ? Math.abs(f.backtest_diff_pct).toFixed(1) + '% error' : '-'}`,
            font: { size: 12, weight: 'normal' },
            color: '#64748b',
          }
        },
        scales: {
          x: { grid: { display: false } },
          y: { beginAtZero: true, grid: { color: 'rgba(0,0,0,0.05)' } }
        }
      }
    });
  }

  formatPeriodDate(dateStr, granularity) {
    if (!dateStr) return '-';
    const d = new Date(dateStr);
    if (granularity === 'weekly') return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' });
    if (granularity === 'quarterly') return `Q${Math.ceil((d.getMonth() + 1) / 3)} ${d.getFullYear()}`;
    return d.toLocaleDateString('en-GB', { month: 'short', year: 'numeric' });
  }

  // ───────── Filtering / Sorting ───────────────────────────────
  applyFilters() {
    const search = (document.getElementById('cpeSearch')?.value || '').toLowerCase().trim();
    const sort = document.getElementById('sortSelect')?.value || 'forecast_desc';

    let items = this.activeFilter === 'failed' ? [] : [...this.successful];

    // Text search
    if (search) {
      items = items.filter(f =>
        (f.vendor || '').toLowerCase().includes(search) ||
        (f.product || '').toLowerCase().includes(search) ||
        (f.cpe || '').toLowerCase().includes(search)
      );
    }

    // Sort
    switch (sort) {
      case 'forecast_asc':
        items.sort((a, b) => (a.forecast_total || 0) - (b.forecast_total || 0));
        break;
      case 'mape_asc':
        items.sort((a, b) => (a.backtest_mape || 999) - (b.backtest_mape || 999));
        break;
      case 'mape_desc':
        items.sort((a, b) => (b.backtest_mape || 0) - (a.backtest_mape || 0));
        break;
      case 'vendor_asc':
        items.sort((a, b) => (a.vendor || '').localeCompare(b.vendor || ''));
        break;
      default: // forecast_desc
        items.sort((a, b) => (b.forecast_total || 0) - (a.forecast_total || 0));
    }

    this.filtered = items;
    this.renderGrid();

    // Show/hide failed section
    const failedSection = document.getElementById('failedSection');
    if (this.activeFilter === 'failed' || this.activeFilter === 'all') {
      failedSection.style.display = this.failed.length > 0 ? '' : 'none';
    } else {
      failedSection.style.display = 'none';
    }
  }

  // ───────── Event listeners ───────────────────────────────────
  setupEventListeners() {
    // Refresh
    document.getElementById('refreshBtn')?.addEventListener('click', () => location.reload());

    // Search
    document.getElementById('cpeSearch')?.addEventListener('input', () => this.applyFilters());

    // Sort
    document.getElementById('sortSelect')?.addEventListener('change', () => this.applyFilters());

    // Filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        this.activeFilter = btn.dataset.filter;
        this.applyFilters();
      });
    });

    // Card clicks → open modal
    document.getElementById('cpeForecastGrid')?.addEventListener('click', e => {
      const card = e.target.closest('.cpe-forecast-card');
      if (card) this.openModal(card.dataset.cpe);
    });

    // Modal close
    document.getElementById('modalClose')?.addEventListener('click', () => this.closeModal());
    document.getElementById('forecastModal')?.addEventListener('click', e => {
      if (e.target === e.currentTarget) this.closeModal();
    });

    // Escape closes modal
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape') this.closeModal();
    });
  }

  // ───────── Helpers ───────────────────────────────────────────
  capitalize(s) {
    return s.charAt(0).toUpperCase() + s.slice(1);
  }

  escapeHtml(s) {
    const div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
  }

  escapeAttr(s) {
    return (s || '').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new ForecastManager();
});
