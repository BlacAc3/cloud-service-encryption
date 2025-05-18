// Cloud Service Encryption - Cloud Storage JavaScript
document.addEventListener("DOMContentLoaded", function () {
  // Initialize UI components
  initializeFileManagement();
});

/**
 * Initialize file management functionality
 */
function initializeFileManagement() {
  // Set up button handlers
  document
    .getElementById("refresh-files")
    ?.addEventListener("click", refreshFiles);
  document
    .getElementById("refresh-shared-files")
    ?.addEventListener("click", refreshSharedFiles);
  document
    .getElementById("upload-form")
    ?.addEventListener("submit", uploadFile);
  document
    .getElementById("show-all-files")
    ?.addEventListener("change", refreshFiles);

  // Setup file sharing buttons
  document.addEventListener("click", function (e) {
    if (e.target.closest(".share-file-btn")) {
      const button = e.target.closest(".share-file-btn");
      const fileId = button.dataset.fileId || button.dataset.filename;
      const filename = button.dataset.filename || button.dataset.fileId;
      prepareShareModal(fileId, filename);
    } else if (e.target.closest(".share-shared-file-btn")) {
      const button = e.target.closest(".share-shared-file-btn");
      const fileId = button.dataset.fileId;
      const filename = button.dataset.filename;
      prepareShareModal(fileId, filename);
    }
  });

  // Setup share confirmation button
  document
    .getElementById("confirm-share-btn")
    ?.addEventListener("click", shareFile);

  // Setup key generation button
  document
    .getElementById("generate-keys-btn")
    ?.addEventListener("click", generateUserKeys);
  document
    .getElementById("show-generate-keys-btn")
    ?.addEventListener("click", function () {
      const modal = new bootstrap.Modal(
        document.getElementById("generateKeysModal"),
      );
      modal.show();
    });

  // Initial data load
  checkUserKeys();
  refreshFiles();
  refreshSharedFiles();
}

/**
 * Check if user has keys for sharing
 */
function checkUserKeys() {
  fetch("/api/get_key_info")
    .then((response) => response.json())
    .then((data) => {
      const canShare = document.body.dataset.canShareFiles === "true";
      if (!data.asymmetric_keys_exist && canShare) {
        // Show key generation reminder
        const alertContainer = document.querySelector(
          ".content-alert-container",
        );
        if (alertContainer) {
          const alert = document.createElement("div");
          alert.className =
            "alert alert-warning alert-dismissible fade show mb-4";
          alert.innerHTML = `
                        <i class="bi bi-key"></i> You need to generate keys to share files.
                        <button type="button" class="btn btn-sm btn-warning" id="show-generate-keys-btn">Generate Keys</button>
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    `;
          alertContainer.appendChild(alert);

          // Initialize the alert with Bootstrap
          new bootstrap.Alert(alert);

          // Setup the generate keys button
          alert
            .querySelector("#show-generate-keys-btn")
            .addEventListener("click", function () {
              // const modal = new bootstrap.Modal(
              //   document.getElementById("generate-keys"),
              // );
              // modal.show();
              generateKeysAndShowModal();
            });
        }
      }
    })
    .catch((error) => console.error("Error checking user keys:", error));
}

function generateKeysAndShowModal() {
  fetch("/api/generate_keys", {
    method: "POST",
    headers: {
      "X-CSRFToken": document
        .querySelector('meta[name="csrf-token"]')
        ?.getAttribute("content"),
    },
  })
    .then((response) => response.json())
    .then((data) => {
      if (data.success) {
        // Display success message
        showAlert("success", data.message);
      } else {
        // Display error message
        showAlert("danger", data.error || "Failed to generate keys.");
      }

      // Show the hardcoded key generation modal
      const modalHTML = `
      <div class="modal fade" id="generateKeysModal" tabindex="-1" aria-labelledby="generateKeysModalLabel" aria-hidden="true">
        <div class="modal-dialog">
          <div class="modal-content">
            <div class="modal-header">
              <h5 class="modal-title" id="generateKeysModalLabel">Key Generation</h5>
              <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
              <p>Keys have been generated.</p>
              <div class="mt-2">
                  <a href="#" class="btn btn-primary" download>
                      <i class="bi bi-download"></i> Download Private Key
                  </a>
              </div>
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
            </div>
          </div>
        </div>
      </div>
      `;

      // Create a temporary element to hold the modal HTML
      const tempDiv = document.createElement("div");
      tempDiv.innerHTML = modalHTML;

      // Append the modal to the body
      document.body.appendChild(tempDiv.firstChild); // Append the first child (the modal)

      // Initialize the modal
      // const modal = new bootstrap.Modal(
      //   document.getElementById("generateKeysModal"),
      // );
      // modal.show();
    })
    .catch((error) => {
      console.error("Error generating keys:", error);
      showAlert("danger", "Failed to generate keys: " + error.message);
    });
}

/**
 * Prepare the share modal for a file
 */
function prepareShareModal(fileId, filename) {
  // First check if user has keys
  fetch("/api/get_key_info")
    .then((response) => response.json())
    .then((data) => {
      if (!data.asymmetric_keys_exist) {
        generateKeysAndShowModal();
        return;
      }

      // Show sharing modal
      document.getElementById("share-file-id").value = fileId;
      console.log(fileId);
      // document.getElementById("share-file-name").value = filename;
      document.getElementById("share-result").innerHTML = "";

      // Uncheck all checkboxes
      document.querySelectorAll(".share-user-checkbox").forEach((cb) => {
        cb.checked = false;
      });

      const modal = new bootstrap.Modal(
        document.getElementById("shareFileModal"),
      );
      modal.show();
      populateUserList();
    })
    .catch((error) => {
      console.error("Error preparing share modal:", error);
      showAlert("danger", "Failed to prepare sharing: " + error.message);
    });
}

hideSecret = document.getElementById("file-list-secure");

// Show the content when the page finishes loading
document.addEventListener("DOMContentLoaded", function () {
  hideSecret.style.display = "block";
});

function populateUserList() {
  fetch("/api/list_users")
    .then((response) => {
      if (!response.ok) {
        throw new Error("Network response was not ok");
      }
      return response.json();
    })
    .then((data) => {
      const userList = document.getElementById("user-list");
      if (!userList) {
        console.error('Element with id "user-list" not found.');
        return;
      }

      userList.innerHTML = "";
      console.log(data);

      if (data.users && data.users.length > 0) {
        data.users.forEach((user) => {
          const div = document.createElement("div");
          div.className = "form-check";

          const input = document.createElement("input");
          input.className = "form-check-input share-user-checkbox";
          input.type = "checkbox";
          input.value = user;
          input.id = `recipient-${user}`;

          const label = document.createElement("label");
          label.className = "form-check-label";
          label.htmlFor = input.id;
          label.textContent = user;

          div.appendChild(input);
          div.appendChild(label);
          userList.appendChild(div);
        });
      } else {
        const p = document.createElement("p");
        p.textContent = "No users found.";
        userList.appendChild(p);
      }
    })
    .catch((error) => {
      console.error("Failed to load users:", error);
      const p = document.createElement("p");
      p.textContent = "Failed to load users.";
      const userList = document.getElementById("user-list");
      if (userList) {
        userList.appendChild(p);
      } else {
        console.error('Element with id "user-list" not found.');
      }
    });
}

/**
 * Share a file with selected users
 */
function shareFile() {
  const fileId = document.getElementById("share-file-id").value;
  const selectedUsers = Array.from(
    document.querySelectorAll(".share-user-checkbox:checked"),
  ).map((cb) => cb.value);

  if (selectedUsers.length === 0) {
    document.getElementById("share-result").innerHTML = `
            <div class="alert alert-warning">
                <i class="bi bi-exclamation-triangle"></i> Please select at least one user to share with.
            </div>
        `;
    return;
  }

  // Disable button and show loading indicator
  const shareBtn = document.getElementById("confirm-share-btn");
  shareBtn.disabled = true;
  shareBtn.innerHTML =
    '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Sharing...';

  fetch("/api/share_file", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRFToken": document
        .querySelector('meta[name="csrf-token"]')
        ?.getAttribute("content"),
    },
    body: JSON.stringify({
      file_id: fileId,
      recipients: selectedUsers,
    }),
  })
    .then((response) => response.json())
    .then((data) => {
      if (data.success) {
        document.getElementById("share-result").innerHTML = `
                <div class="alert alert-success">
                    <i class="bi bi-check-circle"></i> ${data.message}
                </div>
            `;

        // Close modal after delay
        setTimeout(function () {
          bootstrap.Modal.getInstance(
            document.getElementById("shareFileModal"),
          ).hide();
          refreshSharedFiles();
          refreshFiles();
        }, 2000);
      } else {
        let errorMsg = data.message || "Failed to share file";
        if (data.errors && data.errors.length > 0) {
          errorMsg += "<ul>";
          data.errors.forEach(function (err) {
            errorMsg += `<li>${err}</li>`;
          });
          errorMsg += "</ul>";
        }

        document.getElementById("share-result").innerHTML = `
                <div class="alert alert-danger">
                    <i class="bi bi-exclamation-triangle"></i> ${errorMsg}
                </div>
            `;
      }

      // Reset button
      shareBtn.disabled = false;
      shareBtn.textContent = "Share";
    })
    .catch((error) => {
      document.getElementById("share-result").innerHTML = `
            <div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle"></i> Failed to share file: ${error.message}
            </div>
        `;

      shareBtn.disabled = false;
      shareBtn.textContent = "Share";
    });
}

/**
 * Generate user keys for file sharing
 */
function generateUserKeys() {
  const generateBtn = document.getElementById("generate-keys-btn");
  generateBtn.disabled = true;
  generateBtn.innerHTML =
    '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Generating...';

  document.getElementById("key-generation-result").innerHTML = "";

  fetch("/api/generate_user_keys", {
    method: "POST",
    headers: {
      "X-CSRFToken": document
        .querySelector('meta[name="csrf-token"]')
        ?.getAttribute("content"),
    },
  })
    .then((response) => response.json())
    .then((data) => {
      document.getElementById("key-generation-result").innerHTML = `
            <div class="alert alert-success">
                <i class="bi bi-check-circle"></i> Keys generated successfully!
                <div class="mt-2">
                    <a href="${data.key_download_url}" class="btn btn-primary" download>
                        <i class="bi bi-download"></i> Download Private Key
                    </a>
                </div>
            </div>
        `;

      // Hide generate button after success
      generateBtn.style.display = "none";

      // Refresh file lists
      refreshFiles();
      refreshSharedFiles();
    })
    .catch((error) => {
      document.getElementById("key-generation-result").innerHTML = `
            <div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle"></i> Failed to generate keys: ${error.message}
            </div>
        `;

      generateBtn.disabled = false;
      generateBtn.textContent = "Generate Keys";
    });
}

/**
 * Refresh the files list
 */
function refreshFiles() {
  const refreshBtn = document.getElementById("refresh-files");
  if (refreshBtn) {
    refreshBtn.disabled = true;
    refreshBtn.innerHTML =
      '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
  }

  // Check for admin "show all" option
  const showAllFiles =
    document.getElementById("show-all-files")?.checked || false;
  const url = showAllFiles ? "/api/list_files?all=true" : "/api/list_files";

  fetch(url)
    .then((response) => response.json())
    .then((data) => {
      const tbody = document.querySelector("#files-table tbody");
      if (!tbody) return;
      console.log(data);

      tbody.innerHTML = "";

      if (data.files && data.files.length > 0) {
        data.files.forEach((file) => {
          const isAdmin = document.body.dataset.userRole === "admin";
          const canDownload = document.body.dataset.canDownload === "true";
          const canShare = document.body.dataset.canShareFiles === "true";

          console.log(document.body.dataset.canShareFiles);
          const actions = [];

          if (canDownload) {
            actions.push(`<a href="/api/download_file/${encodeURIComponent(file.name)}" class="btn btn-sm btn-success me-1" download>
                            <i class="bi bi-download"></i> Download
                        </a>`);
          }

          // Show share button if user is the owner or admin
          if (
            canShare &&
            (!file.owner ||
              file.owner === document.body.dataset.username ||
              isAdmin)
          ) {
            actions.push(`<button type="button" class="btn btn-sm btn-primary share-file-btn"
                            data-file-id="${file.file_id || file.name}"
                            data-filename="${file.name}">
                            <i class="bi bi-share"></i> Share
                        </button>`);
          }
          console.log("canShare:", canShare);

          const actionBtns =
            actions.length > 0
              ? `<div class="btn-group btn-group-sm">${actions.join("")}</div>`
              : '<span class="text-muted">No actions available</span>';

          // Format file size
          const fileSize = formatFileSize(file.size || 0);

          // Format date
          const fileDate = formatDate(file.date);

          // Create the row HTML
          let rowHtml = `
                        <tr>
                            <td>${file.name}</td>
                            <td>${fileSize}</td>
                            <td>${fileDate}</td>
                            <td>${actionBtns}</td>
                        </tr>
                    `;

          tbody.innerHTML += rowHtml;
        });
      } else {
        // No files found message
        tbody.innerHTML = `
                    <tr>
                        <td colspan="4" class="text-center">
                            <em>No files found in cloud storage</em>
                        </td>
                    </tr>
                `;
      }

      if (refreshBtn) {
        refreshBtn.disabled = false;
        refreshBtn.innerHTML = '<i class="bi bi-arrow-clockwise"></i> Refresh';
      }
    })
    .catch((error) => {
      console.error("Error refreshing files:", error);
      showAlert("danger", "Failed to refresh file list: " + error.message);

      if (refreshBtn) {
        refreshBtn.disabled = false;
        refreshBtn.innerHTML = '<i class="bi bi-arrow-clockwise"></i> Refresh';
      }
    });
}

/**
 * Refresh the shared files list
 */
function refreshSharedFiles() {
  const refreshBtn = document.getElementById("refresh-shared-files");
  if (refreshBtn) {
    refreshBtn.disabled = true;
    refreshBtn.innerHTML =
      '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
  }

  fetch("/api/shared_files")
    .then((response) => response.json())
    .then((data) => {
      const tbody = document.querySelector("#shared-files-table tbody");
      if (!tbody) return;

      tbody.innerHTML = "";

      if (data.shared_files && data.shared_files.length > 0) {
        data.shared_files.forEach((file) => {
          const canDownload = document.body.dataset.canDownload === "true";
          const canShare = document.body.dataset.canShareFiles === "true";

          const actions = [];

          if (canDownload) {
            actions.push(`<a href="/api/download_shared_file/${encodeURIComponent(file.file_id)}" class="btn btn-sm btn-success me-1" download>
                            <i class="bi bi-download"></i> Download
                        </a>`);
          }

          if (canShare && file.is_owner) {
            actions.push(`<button type="button" class="btn btn-sm btn-primary share-file-btn"
                                data-file-id="${file.file_id}"
                                data-filename="${file.original_filename || file.filename || "Unknown"}">
                            <i class="bi bi-share"></i> Share
                        </button>`);
          }

          const actionBtns =
            actions.length > 0
              ? `<div class="btn-group btn-group-sm">${actions.join("")}</div>`
              : '<span class="text-muted">No actions available</span>';

          // Format shared date
          const sharedDate = formatDate(file.date_shared);

          tbody.innerHTML += `
                        <tr>
                            <td>
                                <i class="bi bi-share-fill shared-icon"></i>
                                ${file.original_filename || file.filename || "Unknown"}
                            </td>
                            <td><span class="owner-tag">${file.owner || ""}</span></td>
                            <td>${sharedDate}</td>
                            <td>${actionBtns}</td>
                        </tr>
                    `;
        });
      } else {
        tbody.innerHTML = `
                    <tr>
                        <td colspan="4" class="text-center">
                            <em>No shared files found</em>
                        </td>
                    </tr>
                `;
      }

      if (refreshBtn) {
        refreshBtn.disabled = false;
        refreshBtn.innerHTML = '<i class="bi bi-arrow-clockwise"></i> Refresh';
      }
    })
    .catch((error) => {
      console.error("Error refreshing shared files:", error);
      showAlert("danger", "Failed to refresh shared files: " + error.message);

      if (refreshBtn) {
        refreshBtn.disabled = false;
        refreshBtn.innerHTML = '<i class="bi bi-arrow-clockwise"></i> Refresh';
      }
    });
}

/**
 * Handle file upload
 */
function uploadFile(e) {
  e.preventDefault();

  const fileInput = document.getElementById("file");
  if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
    showAlert("warning", "Please select a file to upload");
    return;
  }

  // Create FormData object
  const formData = new FormData();
  formData.append("file", fileInput.files[0]);

  // Check if it should be a shared upload
  const isShared = document.getElementById("shared-upload")?.checked || false;
  if (isShared) {
    formData.append("shared", "true");
  }

  // Get UI elements
  const progressContainer = document.getElementById(
    "upload-progress-container",
  );
  const progressBar = document.getElementById("upload-progress");
  const uploadBtn = document.getElementById("upload-btn");
  const resultDiv = document.getElementById("upload-result");

  // Show progress
  if (progressContainer) progressContainer.style.display = "block";
  if (progressBar) {
    progressBar.style.width = "0%";
    progressBar.textContent = "0%";
  }
  if (uploadBtn) {
    uploadBtn.disabled = true;
    uploadBtn.innerHTML =
      '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Uploading...';
  }

  // Create the XMLHttpRequest
  const xhr = new XMLHttpRequest();

  // Setup progress tracking
  xhr.upload.addEventListener("progress", function (e) {
    if (e.lengthComputable && progressBar) {
      const percent = Math.round((e.loaded / e.total) * 100);
      progressBar.style.width = percent + "%";
      progressBar.textContent = percent + "%";
    }
  });

  // Handle completion
  xhr.onload = function () {
    if (xhr.status >= 200 && xhr.status < 300) {
      // Success
      const data = JSON.parse(xhr.responseText);

      if (progressBar) {
        progressBar.style.width = "100%";
        progressBar.textContent = "100%";
      }

      showAlert("success", data.message);

      if (resultDiv) {
        resultDiv.innerHTML = `<div class="alert alert-success">
                    <i class="bi bi-check-circle"></i> ${data.message}
                </div>`;
      }

      // Reset form
      if (fileInput) fileInput.value = "";
      const sharedUploadCheckbox = document.getElementById("shared-upload");
      if (sharedUploadCheckbox) sharedUploadCheckbox.checked = false;

      // Refresh file lists
      if (data.shared) {
        refreshSharedFiles();
      } else {
        refreshFiles();
      }

      // Reset button
      if (uploadBtn) {
        uploadBtn.disabled = false;
        uploadBtn.innerHTML = '<i class="bi bi-upload"></i> Upload & Encrypt';
      }

      // Hide progress after a delay
      if (progressContainer) {
        setTimeout(function () {
          progressContainer.style.display = "none";
        }, 3000);
      }
    } else {
      // Error
      let errorMessage = "Upload failed";
      try {
        const response = JSON.parse(xhr.responseText);
        if (response.error) errorMessage = response.error;
      } catch (e) {
        // If parsing fails, use xhr.statusText
        errorMessage = xhr.statusText || errorMessage;
      }

      if (progressBar) {
        progressBar.classList.remove("bg-primary");
        progressBar.classList.add("bg-danger");
      }

      showAlert("danger", "Error: " + errorMessage);

      if (resultDiv) {
        resultDiv.innerHTML = `<div class="alert alert-danger">
                    <i class="bi bi-exclamation-triangle"></i> Upload failed: ${errorMessage}
                </div>`;
      }

      // Reset button
      if (uploadBtn) {
        uploadBtn.disabled = false;
        uploadBtn.innerHTML = '<i class="bi bi-upload"></i> Upload & Encrypt';
      }
    }
  };

  // Handle network errors
  xhr.onerror = function () {
    showAlert("danger", "Network error during upload");

    if (resultDiv) {
      resultDiv.innerHTML = `<div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle"></i> Network error during upload
            </div>`;
    }

    // Reset button
    if (uploadBtn) {
      uploadBtn.disabled = false;
      uploadBtn.innerHTML = '<i class="bi bi-upload"></i> Upload & Encrypt';
    }
  };

  // Setup and send the request
  xhr.open("POST", "/api/upload_file");

  // Add CSRF token if available
  const csrfToken = document
    .querySelector('meta[name="csrf-token"]')
    ?.getAttribute("content");
  if (csrfToken) {
    xhr.setRequestHeader("X-CSRFToken", csrfToken);
  }

  xhr.send(formData);
}

/**
 * Display an alert message
 */
function showAlert(type, message) {
  // Find or create alert container
  let alertContainer = document.querySelector(".content-alert-container");
  if (!alertContainer) {
    alertContainer = document.createElement("div");
    alertContainer.className = "content-alert-container";
    document.body.appendChild(alertContainer);
  }

  // Create alert element
  const alert = document.createElement("div");
  alert.className = `alert alert-${type} alert-dismissible fade show`;
  alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;

  // Add to container
  alertContainer.appendChild(alert);

  // Initialize Bootstrap alert if available
  if (typeof bootstrap !== "undefined") {
    const bsAlert = new bootstrap.Alert(alert);
    setTimeout(function () {
      bsAlert.close();
    }, 5000);
  } else {
    // Fallback for when Bootstrap JS is not available
    setTimeout(function () {
      alert.style.opacity = "0";
      setTimeout(function () {
        if (alert.parentNode) {
          alert.parentNode.removeChild(alert);
        }
      }, 500);
    }, 5000);
  }
}

/**
 * Format file size in human-readable format
 */
function formatFileSize(bytes) {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

/**
 * Format date for display
 */
function formatDate(timestamp) {
  if (!timestamp) return "Unknown";

  // Handle various timestamp formats
  let date;
  if (typeof timestamp === "number") {
    // Unix timestamp in seconds (convert to milliseconds)
    date = new Date(timestamp * 1000);
  } else if (typeof timestamp === "string" && /^\d+$/.test(timestamp)) {
    // String that contains only digits - likely a Unix timestamp
    date = new Date(parseInt(timestamp) * 1000);
  } else {
    // String date or already milliseconds timestamp
    date = new Date(timestamp);
  }

  // Check if the date is valid before formatting
  if (isNaN(date.getTime())) {
    return timestamp;
  }

  // Format the date
  return date.toLocaleString();
}
