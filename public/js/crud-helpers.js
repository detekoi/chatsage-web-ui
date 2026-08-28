import { apiPost, apiPut, apiDelete, AuthError } from './api.js';
import { showActionToast } from './ui.js';
import { DEV_MODE, mockDelay } from './dev-mocks.js';
import { t } from './i18n.js';

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
        showActionToast(t(enabled ? 'toast.itemEnabledDev' : 'toast.itemDisabledDev', { item: itemName },
            `${itemName} ${enabled ? 'enabled' : 'disabled'} (dev mode).`), 'success');
        checkboxEl.disabled = false;
        return;
    }

    try {
        const res = method === 'POST' ? await apiPost(apiPath, payload) : await apiPut(apiPath, payload);
        const data = await res.json();

        if (data.success) {
            // Two whole sentences rather than a concatenated adjective: word order and
            // agreement around the item name differ by language.
            showActionToast(t(enabled ? 'toast.itemEnabled' : 'toast.itemDisabled', { item: itemName },
                `${itemName} ${enabled ? 'enabled' : 'disabled'}.`), 'success');
        } else {
            showActionToast(data.message || t('toast.updateFailed', { item: itemName }, `Failed to update ${itemName}.`), 'danger');
            checkboxEl.checked = !enabled; // Revert on error
        }
    } catch (error) {
        if (error instanceof AuthError) {
            checkboxEl.checked = !enabled;
            return; // Toast is handled by apiFetch
        }
        console.error(`Error toggling ${itemName}:`, error);
        showActionToast(t('toast.updateFailed', { item: itemName }, `Failed to update ${itemName}.`), 'danger');
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
    if (!confirm(t('confirm.deleteItem', { item: itemName }, `Delete ${itemName}?`))) return;

    if (DEV_MODE) {
        await mockDelay(300);
        await onReload();
        showActionToast(t('toast.itemDeletedDev', { item: itemName }, `${itemName} deleted (dev mode).`), 'success');
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
            showActionToast(data.message || t('toast.deleteFailed', { item: itemName }, `Failed to delete ${itemName}.`), 'danger');
        }
    } catch (error) {
        if (error instanceof AuthError) return;
        console.error(`Error deleting ${itemName}:`, error);
        showActionToast(t('toast.deleteFailed', { item: itemName }, `Failed to delete ${itemName}.`), 'danger');
    }
}
