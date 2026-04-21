// Users page functionality
class UsersManager {
  constructor() {
    this.schema = null;
    this.users = [];
    this.init();
  }

  async init() {
    await this.loadData();
    this.renderUsers();
    this.setupEventListeners();
  }

  async loadData() {
    try {
      const response = await fetch('/api/latest-schema');
      const data = await response.json();
      
      if (data.success && data.schema) {
        this.schema = data.schema;
        this.users = data.schema.users || [];
        this.updateStats();
        this.updateLastUpdated();
      }
    } catch (error) {
      console.error('Error loading users data:', error);
    }
  }

  updateStats() {
    const statsEl = document.getElementById('userStats');
    if (statsEl) {
      statsEl.innerHTML = `
        <span class="stat-badge">${this.users.length} Total Users</span>
      `;
    }
  }

  updateLastUpdated() {
    const lastUpdatedEl = document.getElementById('lastUpdated');
    if (lastUpdatedEl) {
      lastUpdatedEl.textContent = `Last updated: ${new Date().toLocaleString()}`;
    }
  }

  renderUsers() {
    const tbody = document.getElementById('usersTableBody');
    if (!tbody) return;

    if (this.users.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="loading-row">No user data available</td></tr>';
      return;
    }

    tbody.innerHTML = this.users.map(user => {
      // Count devices for this user
      const userDevices = this.schema.devices?.filter(device => device.user_id === user.user_id) || [];
      
      return `
        <tr>
          <td><strong>${user.username || 'Unknown User'}</strong></td>
          <td>${user.email_address || 'N/A'}</td>
          <td>${user.user_id || 'N/A'}</td>
          <td>${user.org_id || 'N/A'}</td>
          <td>${userDevices.length}</td>
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
    if (!status) return 'status-active';
    const statusLower = status.toLowerCase();
    if (statusLower.includes('active') || statusLower.includes('enabled')) return 'status-active';
    if (statusLower.includes('inactive') || statusLower.includes('disabled')) return 'status-inactive';
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
  new UsersManager();
});