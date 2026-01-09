// Global state
let files = [];
let blockchain = [];

// Initialize app
document.addEventListener("DOMContentLoaded", () => {
  initializeUpload();
  loadStats();
  refreshFiles();
  refreshBlockchain();

  // Auto-refresh every 5 seconds
  setInterval(() => {
    loadStats();
    refreshFiles();
    refreshBlockchain();
  }, 5000);
});

// Upload functionality
function initializeUpload() {
  const uploadArea = document.getElementById("upload-area");
  const fileInput = document.getElementById("file-input");

  // Click to upload
  uploadArea.addEventListener("click", () => {
    fileInput.click();
  });

  // Drag and drop
  uploadArea.addEventListener("dragover", (e) => {
    e.preventDefault();
    uploadArea.classList.add("dragover");
  });

  uploadArea.addEventListener("dragleave", () => {
    uploadArea.classList.remove("dragover");
  });

  uploadArea.addEventListener("drop", (e) => {
    e.preventDefault();
    uploadArea.classList.remove("dragover");

    const files = e.dataTransfer.files;
    if (files.length > 0) {
      uploadFile(files[0]);
    }
  });

  fileInput.addEventListener("change", (e) => {
    if (e.target.files.length > 0) {
      uploadFile(e.target.files[0]);
    }
  });
}

async function uploadFile(file) {
  const formData = new FormData();
  formData.append("file", file);

  const progressBar = document.getElementById("upload-progress");
  const progressFill = document.getElementById("progress-fill");
  const messageDiv = document.getElementById("upload-message");

  progressBar.style.display = "block";
  progressFill.style.width = "0%";
  messageDiv.className = "message";
  messageDiv.style.display = "none";

  try {
    // Simulate progress
    let progress = 0;
    const progressInterval = setInterval(() => {
      progress += 10;
      if (progress <= 90) {
        progressFill.style.width = progress + "%";
      }
    }, 200);

    const response = await fetch("/api/upload", {
      method: "POST",
      body: formData,
    });

    clearInterval(progressInterval);
    progressFill.style.width = "100%";

    const data = await response.json();

    if (response.ok) {
      messageDiv.className = "message success";
      messageDiv.textContent = data.message || "File uploaded successfully!";
      messageDiv.style.display = "block";

      setTimeout(() => {
        refreshFiles();
        loadStats();
      }, 1000);
    } else {
      messageDiv.className = "message error";
      messageDiv.textContent = data.error || "Upload failed";
      messageDiv.style.display = "block";
    }

    setTimeout(() => {
      progressBar.style.display = "none";
    }, 2000);
  } catch (error) {
    progressBar.style.display = "none";
    messageDiv.className = "message error";
    messageDiv.textContent = "Error uploading file: " + error.message;
    messageDiv.style.display = "block";
  }
}

// File management
async function refreshFiles() {
  try {
    const response = await fetch("/api/files");
    const data = await response.json();

    if (response.ok) {
      files = data.files || [];
      renderFiles();
    }
  } catch (error) {
    console.error("Error loading files:", error);
  }
}

function renderFiles() {
  const tbody = document.getElementById("files-tbody");

  if (files.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="4" class="empty-state">No files uploaded yet</td></tr>';
    return;
  }

  tbody.innerHTML = files
    .map(
      (file) => `
        <tr>
            <td><strong>${escapeHtml(file.name)}</strong></td>
            <td>${file.blocks}</td>
            <td><span class="status-badge ${file.status}">${
        file.status
      }</span></td>
            <td>
                <button class="btn btn-success" onclick="auditFile('${escapeHtml(
                  file.name
                )}')">
                    <i class="fas fa-shield-alt"></i> Audit
                </button>
            </td>
        </tr>
    `
    )
    .join("");
}

async function auditFile(filename) {
  if (!confirm(`Audit file "${filename}"?`)) {
    return;
  }

  try {
    const response = await fetch("/api/audit", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ filename: filename }),
    });

    const data = await response.json();

    if (response.ok) {
      alert("Audit completed successfully!");
      refreshFiles();
      refreshBlockchain();
      loadStats();
    } else {
      alert("Audit failed: " + (data.error || "Unknown error"));
    }
  } catch (error) {
    alert("Error auditing file: " + error.message);
  }
}

// Blockchain functionality
async function refreshBlockchain() {
  try {
    const response = await fetch("/api/blockchain");
    const data = await response.json();

    if (response.ok) {
      blockchain = data.blocks || [];
      renderBlockchain();
    }
  } catch (error) {
    console.error("Error loading blockchain:", error);
  }
}

// ACT.json functionality
async function refreshACT() {
    try {
        const response = await fetch('/api/act');
        const data = await response.json();
        
        const actContent = document.getElementById('act-content');
        
        if (response.ok) {
            actContent.textContent = JSON.stringify(data.data, null, 2);
        } else {
            actContent.textContent = 'Error loading ACT.json: ' + (data.error || 'Unknown error');
        }
    } catch (error) {
        console.error('Error loading ACT:', error);
        document.getElementById('act-content').textContent = 'Error: ' + error.message;
    }
}

function downloadACT() {
    const actContent = document.getElementById('act-content').textContent;
    const blob = new Blob([actContent], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'act.json';
    a.click();
    URL.revokeObjectURL(url);
}

// Add to DOMContentLoaded
document.addEventListener('DOMContentLoaded', () => {
    // ... existing code ...
    refreshACT();
    
    // Update auto-refresh to include ACT
    setInterval(() => {
        loadStats();
        refreshFiles();
        refreshBlockchain();
        refreshACT();
    }, 5000);
});

function renderBlockchain() {
  const content = document.getElementById("blockchain-content");

  if (blockchain.length === 0) {
    content.innerHTML =
      '<div class="empty-state">No blocks in blockchain</div>';
    return;
  }

  content.innerHTML = blockchain
    .map(
      (block) => `
        <div class="block-item" onclick="viewBlockDetails(${block.height})">
            <h4>Block #${block.height}</h4>
            <p><strong>Hash:</strong> ${block.hash}</p>
            <p><strong>Previous:</strong> ${block.previous_hash}</p>
            <p><strong>Type:</strong> ${block.type}</p>
            <p><strong>Transactions:</strong> ${block.transactions}</p>
            <p><strong>Timestamp:</strong> ${new Date(
              block.timestamp * 1000
            ).toLocaleString()}</p>
        </div>
    `
    )
    .join("");
}

async function viewBlock() {
  const heightInput = document.getElementById("block-height-input");
  const height = parseInt(heightInput.value);

  if (isNaN(height) || height < 0) {
    alert("Please enter a valid block height");
    return;
  }

  await viewBlockDetails(height);
}

async function viewBlockDetails(height) {
  try {
    const response = await fetch(`/api/blockchain/${height}`);
    const data = await response.json();

    if (response.ok) {
      const modal = document.getElementById("block-modal");
      const details = document.getElementById("block-details");
      details.textContent = JSON.stringify(data.block, null, 2);
      modal.style.display = "block";
    } else {
      alert("Block not found: " + (data.error || "Unknown error"));
    }
  } catch (error) {
    alert("Error loading block: " + error.message);
  }
}

function closeModal() {
  document.getElementById("block-modal").style.display = "none";
}

// Close modal when clicking outside
window.onclick = function (event) {
  const modal = document.getElementById("block-modal");
  if (event.target === modal) {
    modal.style.display = "none";
  }
};

// Statistics
async function loadStats() {
  try {
    const response = await fetch("/api/stats");
    const data = await response.json();

    if (response.ok) {
      document.getElementById("file-count").textContent = data.files || 0;
      document.getElementById("block-count").textContent = data.blocks || 0;
      document.getElementById("tx-count").textContent = data.transactions || 0;
    }
  } catch (error) {
    console.error("Error loading stats:", error);
  }
}

// Utility functions
function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}
