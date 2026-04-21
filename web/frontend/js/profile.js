document.addEventListener('DOMContentLoaded', () => {
  const uploadZone = document.getElementById('profileUploadZone');
  const fileInput = document.getElementById('profileFileInput');
  const selectedFile = document.getElementById('profileSelectedFile');
  const actionsDiv = document.getElementById('profileUploadActions');
  const uploadBtn = document.getElementById('profileUploadBtn');
  const cancelBtn = document.getElementById('profileCancelBtn');
  const progressDiv = document.getElementById('profileUploadProgress');
  const progressFill = document.getElementById('profileProgressFill');
  const progressLabel = document.getElementById('profileProgressLabel');
  const statusEl = document.getElementById('profileUploadStatus');
  const dataInfo = document.getElementById('currentDataInfo');

  let chosenFile = null;

  // Load current data info
  loadCurrentData();

  // Drag & drop + click
  uploadZone.addEventListener('click', () => fileInput.click());

  uploadZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadZone.classList.add('dragover');
  });

  uploadZone.addEventListener('dragleave', () => {
    uploadZone.classList.remove('dragover');
  });

  uploadZone.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadZone.classList.remove('dragover');
    if (e.dataTransfer.files.length) {
      selectFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length) {
      selectFile(fileInput.files[0]);
    }
  });

  function selectFile(file) {
    if (!file.name.toLowerCase().endsWith('.csv')) {
      statusEl.className = 'profile-upload-status error';
      statusEl.textContent = 'Please select a CSV file.';
      return;
    }
    chosenFile = file;
    selectedFile.textContent = file.name;
    actionsDiv.style.display = '';
    statusEl.className = '';
    statusEl.textContent = '';
  }

  cancelBtn.addEventListener('click', () => {
    chosenFile = null;
    fileInput.value = '';
    selectedFile.textContent = '';
    actionsDiv.style.display = 'none';
    statusEl.className = '';
    statusEl.textContent = '';
  });

  uploadBtn.addEventListener('click', () => {
    if (!chosenFile) return;
    uploadFile(chosenFile);
  });

  async function loadCurrentData() {
    try {
      const res = await fetch('/api/latest-schema');
      const data = await res.json();
      if (data.success && data.schema) {
        const schema = data.schema;
        const appCount = schema.applications ? schema.applications.length : 0;
        const deviceCount = schema.devices ? schema.devices.length : 0;
        const userCount = schema.users ? schema.users.length : 0;
        const type = schema.type || 'Unknown';

        dataInfo.innerHTML = `
          <div class="profile-data-stats">
            <div class="profile-stat">
              <span class="profile-stat-value">${appCount}</span>
              <span class="profile-stat-label">Applications</span>
            </div>
            <div class="profile-stat">
              <span class="profile-stat-value">${deviceCount}</span>
              <span class="profile-stat-label">Devices</span>
            </div>
            <div class="profile-stat">
              <span class="profile-stat-value">${userCount}</span>
              <span class="profile-stat-label">Users</span>
            </div>
            <div class="profile-stat">
              <span class="profile-stat-value">${type}</span>
              <span class="profile-stat-label">CSV Type</span>
            </div>
          </div>
        `;
      } else {
        dataInfo.innerHTML = '<p class="profile-no-data">No data uploaded yet.</p>';
      }
    } catch {
      dataInfo.innerHTML = '<p class="profile-no-data">Could not load current data.</p>';
    }
  }

  async function uploadFile(file) {
    uploadBtn.disabled = true;
    actionsDiv.style.display = 'none';
    progressDiv.style.display = '';
    progressFill.style.width = '0%';
    progressLabel.textContent = 'Uploading...';
    statusEl.className = '';
    statusEl.textContent = '';

    const formData = new FormData();
    formData.append('file', file);

    try {
      // Step 1: Upload
      progressFill.style.width = '30%';
      progressLabel.textContent = 'Uploading CSV...';

      const uploadRes = await fetch('/api/upload', {
        method: 'POST',
        body: formData
      });
      const uploadData = await uploadRes.json();

      if (!uploadRes.ok || uploadData.error) {
        throw new Error(uploadData.error || 'Upload failed');
      }

      // Step 2: Start enrichment
      progressFill.style.width = '50%';
      progressLabel.textContent = 'Starting CVE enrichment...';

      const enrichRes = await fetch('/api/start-enrichment', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ schemaKey: uploadData.schemaKey })
      });
      const enrichData = await enrichRes.json();

      if (!enrichRes.ok || !enrichData.success) {
        throw new Error(enrichData.error || 'Enrichment failed to start');
      }

      // Step 3: Poll enrichment progress
      await pollEnrichment(uploadData.schemaKey);

    } catch (err) {
      progressDiv.style.display = 'none';
      statusEl.className = 'profile-upload-status error';
      statusEl.textContent = 'Error: ' + err.message;
      uploadBtn.disabled = false;
      actionsDiv.style.display = '';
    }
  }

  async function pollEnrichment(schemaKey) {
    const poll = async () => {
      try {
        const res = await fetch(`/api/enrichment-progress?schemaKey=${encodeURIComponent(schemaKey)}`);
        const data = await res.json();

        if (data.status === 'completed') {
          progressFill.style.width = '100%';
          progressLabel.textContent = 'Enrichment complete! Starting forecasts...';

          // Trigger the forecast Lambda
          triggerForecast();

          setTimeout(() => {
            progressDiv.style.display = 'none';
            statusEl.className = 'profile-upload-status success';
            statusEl.innerHTML = '<strong>Data updated successfully!</strong> Your new Intune export has been processed and enriched.' +
              '<br><br><i class="fas fa-chart-line"></i> <strong>Forecast generation has been triggered.</strong> ' +
              'The ARIMA forecast models are now running in the background — updated predictions will appear on the ' +
              '<a href="/forecast">Forecast</a> page shortly.';
            showForecastBanner();
            chosenFile = null;
            fileInput.value = '';
            selectedFile.textContent = '';
            uploadBtn.disabled = false;
            loadCurrentData();
          }, 800);
          return;
        }

        if (data.status === 'error') {
          progressDiv.style.display = 'none';
          statusEl.className = 'profile-upload-status error';
          statusEl.textContent = 'Enrichment error: ' + (data.error || 'Unknown error');
          uploadBtn.disabled = false;
          actionsDiv.style.display = '';
          return;
        }

        // Still processing
        const pct = Math.min(95, 50 + (data.progress || 0) * 0.45);
        progressFill.style.width = pct + '%';
        progressLabel.textContent = `Enriching... Step ${data.step || '?'} of 5`;

        setTimeout(poll, 2000);
      } catch {
        progressDiv.style.display = 'none';
        statusEl.className = 'profile-upload-status error';
        statusEl.textContent = 'Lost connection while checking progress.';
        uploadBtn.disabled = false;
        actionsDiv.style.display = '';
      }
    };

    setTimeout(poll, 2000);
  }

  async function triggerForecast() {
    try {
      await fetch('/api/trigger-forecast', { method: 'POST' });
    } catch (err) {
      console.error('Failed to trigger forecast Lambda:', err);
    }
  }

  function showForecastBanner() {
    const banner = document.getElementById('forecastBanner');
    if (banner) banner.style.display = '';
  }
});
