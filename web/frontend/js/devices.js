// Devices page functionality
class DevicesManager {
  constructor() {
    this.schema = null;
    this.devices = [];
    this.init();
  }

  async init() {
    await this.loadData();
    this.renderDevices();
    this.setupEventListeners();
  }

  async loadData() {
    try {
      const response = await fetch('/api/latest-schema');
      const data = await response.json();
      
      if (data.success && data.schema) {
        this.schema = data.schema;
        this.devices = data.schema.devices || [];
        this.updateStats();
        this.updateLastUpdated();
      }
    } catch (error) {
      console.error('Error loading devices data:', error);
    }
  }

  updateStats() {
    const statsEl = document.getElementById('deviceStats');
    if (statsEl) {
      statsEl.innerHTML = `
        <span class="stat-badge">${this.devices.length} Total Devices</span>
      `;
    }
  }

  updateLastUpdated() {
    const lastUpdatedEl = document.getElementById('lastUpdated');
    if (lastUpdatedEl) {
      lastUpdatedEl.textContent = `Last updated: ${new Date().toLocaleString()}`;
    }
  }

  renderDevices() {
    const tbody = document.getElementById('devicesTableBody');
    if (!tbody) return;

    if (this.devices.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="loading-row">No device data available</td></tr>';
      return;
    }

    tbody.innerHTML = this.devices.map(device => {
      // Find the user for this device
      const deviceUser = this.schema.users?.find(user => user.user_id === device.user_id);
      
      return `
        <tr>
          <td><strong>${device.device_name || 'Unknown Device'}</strong></td>
          <td>${device.device_id || 'N/A'}</td>
          <td>${device.platform || 'Unknown'}</td>
          <td>${device.os_version || 'Unknown'}</td>
          <td>${deviceUser ? deviceUser.username : 'Unassigned'}</td>
          <td>
            <span class="status-badge status-active">
              Active
            </span>
          </td>
        </tr>
      `;
    }).join('');
  }

  getStatusClass(status) {
    if (!status) return 'status-warning';
    const statusLower = status.toLowerCase();
    if (statusLower.includes('active') || statusLower.includes('online')) return 'status-active';
    if (statusLower.includes('inactive') || statusLower.includes('offline')) return 'status-inactive';
    return 'status-warning';
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
  new DevicesManager();
});