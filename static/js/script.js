// Cloud Service Encryption - Main JavaScript file

// Initialize UI components when document is ready
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips and popovers if Bootstrap is used
    if (typeof bootstrap !== 'undefined') {
        var tooltips = document.querySelectorAll('[data-bs-toggle="tooltip"]');
        tooltips.forEach(function(tooltip) {
            new bootstrap.Tooltip(tooltip);
        });

        var popovers = document.querySelectorAll('[data-bs-toggle="popover"]');
        popovers.forEach(function(popover) {
            new bootstrap.Popover(popover);
        });
    }

    // Initialize alert container for notifications
    if (!document.querySelector('.content-alert-container')) {
        var alertContainer = document.createElement('div');
        alertContainer.className = 'content-alert-container';
        document.body.appendChild(alertContainer);
    }
});

/**
 * Show an alert message
 * @param {string} type - Alert type (success, danger, warning, info)
 * @param {string} message - Alert message
 * @param {number} [timeout=5000] - Auto-dismiss timeout in milliseconds
 */
function showAlert(type, message, timeout = 5000) {
    var alertContainer = document.querySelector('.content-alert-container');
    if (!alertContainer) {
        alertContainer = document.createElement('div');
        alertContainer.className = 'content-alert-container';
        document.body.appendChild(alertContainer);
    }

    var alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show`;
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    alertContainer.appendChild(alert);
    
    // Initialize Bootstrap alert
    if (typeof bootstrap !== 'undefined') {
        var bsAlert = new bootstrap.Alert(alert);
        if (timeout) {
            setTimeout(function() {
                bsAlert.close();
            }, timeout);
        }
    } else {
        // Fallback for when Bootstrap JS is not available
        if (timeout) {
            setTimeout(function() {
                alert.style.opacity = '0';
                setTimeout(function() {
                    alertContainer.removeChild(alert);
                }, 500);
            }, timeout);
        }
    }

    // Remove alert after it's closed
    alert.addEventListener('closed.bs.alert', function() {
        alertContainer.removeChild(alert);
    });
}

/**
 * Format file size in human-readable format
 * @param {number} bytes - Size in bytes
 * @returns {string} - Formatted size string
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Set up AJAX request with CSRF token for Flask
 */
function setupAjax() {
    // Try to get CSRF token
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
    
    if (csrfToken && typeof $.ajaxSetup === 'function') {
        $.ajaxSetup({
            beforeSend: function(xhr, settings) {
                if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type) && !this.crossDomain) {
                    xhr.setRequestHeader('X-CSRFToken', csrfToken);
                }
            }
        });
    }
}

/**
 * Create and show a modal confirmation dialog
 * @param {string} title - Dialog title
 * @param {string} message - Dialog message
 * @param {Function} onConfirm - Callback when confirmed
 * @param {string} [confirmText='Confirm'] - Text for confirm button
 * @param {string} [cancelText='Cancel'] - Text for cancel button
 */
function confirmDialog(title, message, onConfirm, confirmText = 'Confirm', cancelText = 'Cancel') {
    // Create modal elements
    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.id = 'confirmModal';
    modal.tabIndex = '-1';
    modal.setAttribute('aria-labelledby', 'confirmModalLabel');
    modal.setAttribute('aria-hidden', 'true');
    
    modal.innerHTML = `
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="confirmModalLabel">${title}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">${message}</div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">${cancelText}</button>
                    <button type="button" class="btn btn-primary" id="confirmBtn">${confirmText}</button>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    // Initialize and show modal
    const modalElement = new bootstrap.Modal(modal);
    modalElement.show();
    
    // Set up confirm button action
    document.getElementById('confirmBtn').addEventListener('click', function() {
        modalElement.hide();
        onConfirm();
        setTimeout(() => {
            document.body.removeChild(modal);
        }, 500);
    });
    
    // Remove modal from DOM when hidden
    modal.addEventListener('hidden.bs.modal', function() {
        document.body.removeChild(modal);
    });
}