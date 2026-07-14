import { apiPost, apiPut, apiDelete, AuthError } from './api.js';
import { showActionToast } from './ui.js';
import { DEV_MODE, mockDelay } from './dev-mocks.js';

/**
 * Shared helper to toggle an item's enabled state
 * @param {string} method - 'POST' or 'PUT'
 * @param {string} apiPath - The endpoint to hit
 * @param {object} payload - The request body (e.g. { command: name, enabled: true })
 * @param {string} itemName - Display name for toasts (e.g. '!hello' or 'Timer "discord"')
 * @param {boolean} enabled - The new enabled state
 * @param {HTMLInputElement} checkboxEl - The checkbox DOM element to toggle/revert
 */
export async function toggleItem(method, apiPath, payload, itemName, enabled, checkboxEl) {
    checkboxEl.disabled = true;

    if (DEV_MODE) {
        await mockDelay(500);
        showActionToast(`${itemName} ${enabled ? 'enabled' : 'disabled'} (dev mode).`, 'success');
        checkboxEl.disabled = false;
        return;
    }

    try {
        const res = method === 'POST' ? await apiPost(apiPath, payload) : await apiPut(apiPath, payload);
        const data = await res.json();

        if (data.success) {
            showActionToast(`${itemName} ${enabled ? 'enabled' : 'disabled'}.`, 'success');
        } else {
            showActionToast(data.message || `Error updating ${itemName}.`, 'danger');
            checkboxEl.checked = !enabled; // Revert on error
        }
    } catch (error) {
        if (error instanceof AuthError) {
            checkboxEl.checked = !enabled;
            return; // Toast is handled by apiFetch
        }
        console.error(`Error toggling ${itemName}:`, error);
        showActionToast(`Failed to update ${itemName}.`, 'danger');
        checkboxEl.checked = !enabled; // Revert on error
    } finally {
        checkboxEl.disabled = false;
    }
}

/**
 * Shared helper to delete an item
 * @param {string} apiPath - The endpoint to hit for deletion
 * @param {string} itemName - Display name for confirmation/toasts
 * @param {Function} onReload - Callback to reload the list on success
 */
export async function deleteItem(apiPath, itemName, onReload) {
    if (!confirm(`Delete ${itemName}?`)) return;

    if (DEV_MODE) {
        await mockDelay(300);
        await onReload();
        showActionToast(`${itemName} deleted (dev mode).`, 'success');
        return;
    }

    try {
        const res = await apiDelete(apiPath);
        const data = await res.json();
        
        if (data.success) {
            await onReload();
            // Note: some callers might want their own specific toast or no toast, 
            // but the original code had a reload and some had toasts. 
            // Wait, timers.js had no toast on success, custom-commands had no toast on success.
            // Oh, actually the original code only showed a toast on failure for both.
            // Let's just do reload on success.
        } else {
            showActionToast(data.message || `Failed to delete ${itemName}.`, 'danger');
        }
    } catch (error) {
        if (error instanceof AuthError) return;
        console.error(`Error deleting ${itemName}:`, error);
        showActionToast(`Error deleting ${itemName}.`, 'danger');
    }
}
