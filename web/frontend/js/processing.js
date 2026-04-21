// Processing page functionality
class ProcessingManager {
  constructor() {
    this.currentStep = 1;
    this.totalSteps = 5;
    this.checkInterval = null;
    this.init();
  }

  init() {
    // Get schemaKey from URL params
    const urlParams = new URLSearchParams(window.location.search);
    this.schemaKey = urlParams.get('schemaKey');
    
    if (!this.schemaKey) {
      this.showError('No file specified for processing');
      return;
    }

    // Start polling for progress (enrichment was already kicked off from the upload page)
    this.startProgressPolling();
  }

  startProgressPolling() {
    this.checkInterval = setInterval(async () => {
      try {
        const response = await fetch(`/api/enrichment-progress?schemaKey=${encodeURIComponent(this.schemaKey)}`);
        const data = await response.json();

        if (data.success) {
          this.updateProgress(data.status, data.progress, data.step);
          
          if (data.status === 'completed') {
            clearInterval(this.checkInterval);
            this.completeProcessing();
          } else if (data.status === 'error') {
            clearInterval(this.checkInterval);
            this.showError(data.error || 'Processing failed');
          }
        }
      } catch (error) {
        console.error('Error checking progress:', error);
      }
    }, 2000);
  }

  updateProgress(status, progress, step) {
    // Update progress bar
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');
    
    if (progressFill && progressText) {
      progressFill.style.width = `${progress}%`;
      progressText.textContent = `${Math.round(progress)}%`;
    }

    // Update active step
    if (step && step !== this.currentStep) {
      this.setActiveStep(step);
    }
  }

  setActiveStep(stepNumber) {
    // Mark all previous steps as completed (green)
    for (let i = 1; i < stepNumber; i++) {
      const stepEl = document.getElementById(`step${i}`);
      if (stepEl) {
        stepEl.classList.remove('active');
        stepEl.classList.add('completed');
      }
    }

    // Remove active from current step if we're moving forward
    if (stepNumber > this.currentStep) {
      const currentStepEl = document.getElementById(`step${this.currentStep}`);
      if (currentStepEl) {
        currentStepEl.classList.remove('active');
        currentStepEl.classList.add('completed');
      }
    }

    // Add active class to new step
    const newStepEl = document.getElementById(`step${stepNumber}`);
    if (newStepEl) {
      newStepEl.classList.add('active');
    }

    this.currentStep = stepNumber;
  }

  completeProcessing() {
    // Mark final step as completed
    this.setActiveStep(5);
    
    setTimeout(() => {
      const finalStep = document.getElementById('step5');
      if (finalStep) {
        finalStep.classList.remove('active');
        finalStep.classList.add('completed');
      }
    }, 1000);

    // Redirect to dashboard after a short delay
    setTimeout(() => {
      window.location.href = '/dashboard';
    }, 3000);
  }

  showError(message) {
    const container = document.querySelector('.processing-content');
    if (container) {
      container.innerHTML = `
        <div class="error-state">
          <i class="fas fa-exclamation-triangle" style="font-size: 3rem; color: #dc3545; margin-bottom: 1rem;"></i>
          <h3>Processing Failed</h3>
          <p>${message}</p>
          <button onclick="window.location.href='/'" class="enrich-btn" style="margin-top: 1rem;">
            <i class="fas fa-home"></i> Return to Home
          </button>
        </div>
      `;
    }
  }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new ProcessingManager();
});