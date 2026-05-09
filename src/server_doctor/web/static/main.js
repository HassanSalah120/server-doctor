// Shared utility functions for the ServerDoctor web UI

/**
 * Wrapper around fetch that parses JSON, handles non-OK responses,
 * and displays failures via toast alerts.
 *
 * Usage:
 *    const data = await apiFetch('/api/servers');
 */
async function apiFetch(url, options = {}) {
    try {
        const res = await fetch(url, options);
        let data = {};
        try {
            data = await res.json();
        } catch (_) {
            // non-JSON response
        }
        if (!res.ok) {
            const err = data.detail || res.statusText || 'Request failed';
            throw new Error(err);
        }
        return data;
    } catch (err) {
        showToast(err.message, 'danger');
        throw err;
    }
}

/**
 * Display a temporary toast message. Type is one of 'success','danger','info','warning'.
 */
function showToast(message, type = 'info') {
    const container = document.createElement('div');
    container.className = `alert alert-${type}`;
    container.style.position = 'fixed';
    container.style.bottom = '20px';
    container.style.right = '20px';
    container.style.zIndex = 1000;
    container.innerHTML = `<div class="alert-content">${message}</div>`;
    document.body.appendChild(container);
    setTimeout(() => {
        container.remove();
    }, 4000);
}

// helper to disable a button and show spinner
function setLoading(button, isLoading) {
    if (isLoading) {
        button.dataset.origText = button.innerHTML;
        button.innerHTML = '<span class="spinner"></span> ' + button.innerHTML;
        button.disabled = true;
    } else {
        if (button.dataset.origText) {
            button.innerHTML = button.dataset.origText;
            delete button.dataset.origText;
        }
        button.disabled = false;
    }
}
