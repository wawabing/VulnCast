// Vulnerabilities page functionality
class VulnerabilitiesManager {
  constructor() {
    this.schema = null;
    this.vulnerabilities = [];
    this.init();
  }

  async init() {
    await this.loadData();
    this.renderVulnerabilities();
    this.setupEventListeners();
  }

  async loadData() {
    try {
      const response = await fetch('/api/latest-schema');
      const data = await response.json();
      
      if (data.success && data.schema) {
        this.schema = data.schema;
        this.processVulnerabilities();
        this.updateStats();
        this.updateLastUpdated();
      }
    } catch (error) {
      console.error('Error loading vulnerabilities data:', error);
    }
  }

  processVulnerabilities() {
    this.vulnerabilities = [];
    
    if (!this.schema.applications) return;

    this.schema.applications.forEach(app => {
      if (app.cve_data && app.cve_data.cves) {
        app.cve_data.cves.forEach(cve => {
          this.vulnerabilities.push({
            ...cve,
            application_name: app.application_name,
            application_publisher: app.application_publisher,
            cpe_name: app.cve_data.cpe_name
          });
        });
      }
    });

    // Sort by severity (Critical -> High -> Medium -> Low)
    const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
    this.vulnerabilities.sort((a, b) => {
      const severityA = severityOrder[a.severity?.toUpperCase()] || 4;
      const severityB = severityOrder[b.severity?.toUpperCase()] || 4;
      return severityA - severityB;
    });
  }

  updateStats() {
    const stats = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      total: this.vulnerabilities.length
    };

    this.vulnerabilities.forEach(vuln => {
      const severity = (vuln.severity || 'unknown').toLowerCase();
      if (stats.hasOwnProperty(severity)) {
        stats[severity]++;
      }
    });

    // Update summary cards
    document.getElementById('criticalCount').textContent = stats.critical;
    document.getElementById('highCount').textContent = stats.high;
    document.getElementById('mediumCount').textContent = stats.medium;
    document.getElementById('lowCount').textContent = stats.low;

    // Update table stats
    const statsEl = document.getElementById('vulnerabilityStats');
    if (statsEl) {
      statsEl.innerHTML = `
        <span class="stat-badge">${stats.total} Total Vulnerabilities</span>
        <span class="stat-badge" style="background: #dc3545;">${stats.critical} Critical</span>
        <span class="stat-badge" style="background: #fd7e14;">${stats.high} High</span>
      `;
    }
  }

  updateLastUpdated() {
    const lastUpdatedEl = document.getElementById('lastUpdated');
    if (lastUpdatedEl) {
      lastUpdatedEl.textContent = `Last updated: ${new Date().toLocaleString()}`;
    }
  }

  renderVulnerabilities() {
    const tbody = document.getElementById('vulnerabilitiesTableBody');
    if (!tbody) return;

    if (this.vulnerabilities.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="loading-row">No vulnerability data available</td></tr>';
      return;
    }

    tbody.innerHTML = this.vulnerabilities.map(vuln => `
      <tr>
        <td>
          <a href="https://nvd.nist.gov/vuln/detail/${vuln.cve_id}" 
             target="_blank" 
             class="vulnerability-link">
            ${vuln.cve_id}
          </a>
        </td>
        <td><strong>${vuln.application_name}</strong><br>
            <small>${vuln.application_publisher}</small></td>
        <td>
          <span class="cve-badge cve-${(vuln.severity || 'unknown').toLowerCase()}">
            ${vuln.severity || 'Unknown'}
          </span>
        </td>
        <td>
          <span class="cvss-score cvss-${this.getCvssClass(vuln.score)}">
            ${vuln.score || 'N/A'}
          </span>
        </td>
        <td>
          <div class="epss-score">
            <span class="epss-value">${this.formatEpssScore(vuln.epss_score)}</span>
            <span class="epss-percentile">${this.formatEpssPercentile(vuln.epss_percentile)}</span>
          </div>
        </td>
        <td>
          <div class="description-cell" title="${vuln.description}">
            ${this.truncateDescription(vuln.description)}
          </div>
        </td>
        <td>
          <div class="action-buttons">
            <button class="action-btn view-btn" onclick="window.open('https://nvd.nist.gov/vuln/detail/${vuln.cve_id}', '_blank')">
              <i class="fas fa-external-link-alt"></i> View
            </button>
          </div>
        </td>
      </tr>
    `).join('');
  }

  getCvssClass(score) {
    if (!score || score === 'Unknown') return 'unknown';
    const numScore = parseFloat(score);
    if (numScore >= 9.0) return 'critical';
    if (numScore >= 7.0) return 'high';
    if (numScore >= 4.0) return 'medium';
    if (numScore >= 0.1) return 'low';
    return 'unknown';
  }

  formatEpssScore(score) {
    if (!score || score === 0) return '0.00%';
    return (score * 100).toFixed(2) + '%';
  }

  formatEpssPercentile(percentile) {
    if (!percentile || percentile === 0) return '0th percentile';
    return `${(percentile * 100).toFixed(1)}th percentile`;
  }

  truncateDescription(description) {
    if (!description) return 'No description available';
    return description.length > 100 ? description.substring(0, 100) + '...' : description;
  }

  setupEventListeners() {
    const refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => {
        this.loadData();
      });
    }
  }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new VulnerabilitiesManager();
});