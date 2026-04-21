document.addEventListener("DOMContentLoaded", () => {
  const uploadBtn = document.getElementById("uploadBtn");
  const fileInput = document.getElementById("fileInput");
  const fileNameDisplay = document.getElementById("fileName");

  uploadBtn.addEventListener("click", () => {
    fileInput.click();
  });

  fileInput.addEventListener("change", async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    if (file.type !== "text/csv") {
      alert("Please upload a CSV file.");
      return;
    }

    fileNameDisplay.textContent = `Uploading: ${file.name} ...`;

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch("/api/upload", {
        method: "POST",
        body: formData,
      });
      const data = await res.json();
      if (res.ok) {
        fileNameDisplay.textContent = `Uploaded: ${data.filename} (Type: ${data.detectedType || 'Unknown'})`;
        
        // Start enrichment and redirect to processing page
        if (data.schemaKey) {
          const enrichRes = await fetch('/api/start-enrichment', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ schemaKey: data.schemaKey }),
          });

          if (enrichRes.ok) {
            setTimeout(() => {
              window.location.href = `/processing?schemaKey=${encodeURIComponent(data.schemaKey)}`;
            }, 1000);
          } else {
            setTimeout(() => {
              window.location.href = '/dashboard';
            }, 1500);
          }
        } else {
          setTimeout(() => {
            window.location.href = '/dashboard';
          }, 1500);
        }
      } else {
        fileNameDisplay.textContent = `❌ Error: ${data.error}`;
      }
    } catch (err) {
      fileNameDisplay.textContent = "❌ Upload failed.";
      console.error(err);
    }
  });
});
