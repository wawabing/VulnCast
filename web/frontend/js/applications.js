// Applications page functionality
class ApplicationsManager {
  constructor() {
    this.schema = null;
    this.applications = [];
    this.init();
  }

  async init() {
    await this.loadData();
    this.renderApplications();
    this.setupEventListeners();
  }

  async loadData() {
    try {
      const response = await fetch('/api/latest-schema');
      const data = await response.json();
      
      if (data.success && data.schema) {
        this.schema = data.schema;
        this.applications = data.schema.applications || [];
        this.updateStats();
        this.updateLastUpdated();
      }
    } catch (error) {
      console.error('Error loading applications data:', error);
    }
  }

  updateStats() {
    const statsEl = document.getElementById('appStats');
    if (statsEl) {
      statsEl.innerHTML = `
        <span class="stat-badge">${this.applications.length} Total Applications</span>
      `;
    }
  }

  updateLastUpdated() {
    const lastUpdatedEl = document.getElementById('lastUpdated');
    if (lastUpdatedEl) {
      lastUpdatedEl.textContent = `Last updated: ${new Date().toLocaleString()}`;
    }
  }

  renderApplications() {
    const tbody = document.getElementById('applicationsTableBody');
    if (!tbody) return;

    if (this.applications.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="loading-row">No application data available</td></tr>';
      return;
    }

    tbody.innerHTML = this.applications.map(app => {
      const cpe = app.cve_data && app.cve_data.cpe_name ? app.cve_data.cpe_name : '<span class="cpe-none">none found</span>';
      return `
        <tr>
          <td>
            <strong>${app.application_name || 'Unknown Application'}</strong>
            <br>
            <span class="cpe-entry">
              <i class="fas fa-id-badge"></i>
              CPE: ${cpe}
            </span>
          </td>
          <td>${app.application_publisher || 'Unknown'}</td>
          <td>${app.application_version || 'N/A'}</td>
          <td>${app.device_ids ? app.device_ids.length : '0'}</td>
          <td>${this.renderCveCount(app.cve_data)}</td>
          <td>${this.renderCveSeverity(app.cve_data)}</td>
          <td>
            <span class="status-badge status-active">
              Active
            </span>
          </td>
        </tr>
      `;
    }).join('');
  }

  renderPlatforms(platforms) {
    if (!platforms) return 'N/A';
    
    if (Array.isArray(platforms)) {
      return `
        <div class="platform-badges">
          ${platforms.map(platform => `
            <span class="platform-badge">${platform}</span>
          `).join('')}
        </div>
      `;
    }
    
    return platforms;
  }

  getStatusClass(status) {
    if (!status) return 'status-active';
    const statusLower = status.toLowerCase();
    if (statusLower.includes('active') || statusLower.includes('installed')) return 'status-active';
    if (statusLower.includes('inactive') || statusLower.includes('uninstalled')) return 'status-inactive';
    if (statusLower.includes('outdated') || statusLower.includes('vulnerable')) return 'status-warning';
    return 'status-active';
  }

  renderCveCount(cveData) {
    if (!cveData || !cveData.cves) {
      return '<span class="cve-count">-</span>';
    }
    
    const count = cveData.cves.length;
    return `<span class="cve-count">${count}</span>`;
  }

  renderCveSeverity(cveData) {
    if (!cveData || !cveData.cves || cveData.cves.length === 0) {
      return '<span class="cve-badge cve-unknown">No CVEs</span>';
    }

    const severityCounts = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      UNKNOWN: 0
    };

    cveData.cves.forEach(cve => {
      const severity = (cve.severity || 'UNKNOWN').toUpperCase();
      if (severityCounts.hasOwnProperty(severity)) {
        severityCounts[severity]++;
      } else {
        severityCounts.UNKNOWN++;
      }
    });

    const badges = [];
    if (severityCounts.CRITICAL > 0) badges.push(`<span class="cve-badge cve-critical">C:${severityCounts.CRITICAL}</span>`);
    if (severityCounts.HIGH > 0) badges.push(`<span class="cve-badge cve-high">H:${severityCounts.HIGH}</span>`);
    if (severityCounts.MEDIUM > 0) badges.push(`<span class="cve-badge cve-medium">M:${severityCounts.MEDIUM}</span>`);
    if (severityCounts.LOW > 0) badges.push(`<span class="cve-badge cve-low">L:${severityCounts.LOW}</span>`);
    if (severityCounts.UNKNOWN > 0) badges.push(`<span class="cve-badge cve-unknown">U:${severityCounts.UNKNOWN}</span>`);

    return badges.join(' ') || '<span class="cve-badge cve-unknown">Unknown</span>';
  }

  async enrichWithCves() {
    const loadingOverlay = document.getElementById('loadingOverlay');
    const enrichBtn = document.getElementById('enrichBtn');
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');
    const loadingText = document.getElementById('loadingText');

    try {
      // Show loading overlay
      loadingOverlay.style.display = 'flex';
      enrichBtn.disabled = true;
      enrichBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Enriching...';

      // Start enrichment
      const response = await fetch('/api/enrich-cves', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();

      if (result.success) {
        // Update progress to 100%
        progressFill.style.width = '100%';
        progressText.textContent = '100%';
        loadingText.textContent = 'Enrichment completed successfully!';

        // Wait a moment then hide loading and refresh data
        setTimeout(() => {
          loadingOverlay.style.display = 'none';
          this.loadData(); // Refresh the table with new data
        }, 2000);
      } else {
        throw new Error(result.error || 'Enrichment failed');
      }

    } catch (error) {
      console.error('Error during CVE enrichment:', error);
      loadingText.textContent = 'Error occurred during enrichment. Please try again.';
      
      setTimeout(() => {
        loadingOverlay.style.display = 'none';
      }, 3000);
    } finally {
      enrichBtn.disabled = false;
      enrichBtn.innerHTML = '<i class="fas fa-shield-alt"></i> Enrich with CVEs';
    }
  }

  setupEventListeners() {
    const refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => {
        this.loadData();
      });
    }

    const enrichBtn = document.getElementById('enrichBtn');
    if (enrichBtn) {
      enrichBtn.addEventListener('click', () => {
        this.enrichWithCves();
      });
    }
  }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new ApplicationsManager();
});