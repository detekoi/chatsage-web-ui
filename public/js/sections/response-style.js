import { apiGet, apiPost, AuthError, readJson } from '../api.js';
import { debounce, setSuccessMessage, showActionToast } from '../ui.js';
import { DEV_MODE, mockDelay, mockResponseStyle } from '../dev-mocks.js';
import { t } from '../i18n.js';

// De-Slop card: one switch that tells the bot to write its AI text without the
// usual AI habits. One document per channel (/api/response-style). A change is
// saved on its own, debounced; the bot picks it up from Firestore. Moderators
// can change the same setting in chat with !deslop.

let loadingEl;
let enabledEl;
let statusEl;
let requestId = 0;        // id of the newest save, so a late response cannot overwrite it
let saveLater;

export function initResponseStyle() {
    loadingEl = document.getElementById('response-style-loading');
    enabledEl = document.getElementById('deslop-enabled');
    statusEl = document.getElementById('response-style-message');
    if (!enabledEl) return;

    saveLater = debounce(save, 600);
    enabledEl.addEventListener('change', saveLater);
}

export async function loadResponseStyle() {
    if (!enabledEl) return;
    if (loadingEl) loadingEl.hidden = false;
    const deslop = await fetchSetting();
    if (loadingEl) loadingEl.hidden = true;

    if (deslop === null) {
        showActionToast(t('toast.loadDeslopFailed', {}, 'The De-Slop setting did not load.'), 'danger');
        return;
    }
    enabledEl.checked = deslop;
}

async function fetchSetting() {
    if (DEV_MODE) {
        await mockDelay(500);
        return mockResponseStyle.deslop;
    }
    try {
        const res = await apiGet('/api/response-style');
        const data = await readJson(res);
        return data.success ? data.deslop === true : null;
    } catch (e) {
        if (!(e instanceof AuthError)) console.error('Error fetching the De-Slop setting:', e);
        return null;
    }
}

function setStatus(text, kind = 'muted') {
    if (kind === 'success') {
        setSuccessMessage(statusEl, text);
    } else {
        statusEl.textContent = text;
    }
    statusEl.className = `text-${kind} mb-0 response-style-status`;
}

async function save() {
    const deslop = enabledEl.checked;
    const id = ++requestId;
    const isCurrent = () => id === requestId;
    const savedMsg = t('toast.deslopSaved', {}, 'De-Slop setting saved.');
    setStatus(t('status.saving', {}, 'Saving…'));

    if (DEV_MODE) {
        await mockDelay(500);
        mockResponseStyle.deslop = deslop;
        if (isCurrent()) setStatus(t('status.savedDev', { message: savedMsg }, `${savedMsg} (dev mode).`), 'success');
        return;
    }

    try {
        const res = await apiPost('/api/response-style', { deslop });
        const data = await readJson(res);
        if (!isCurrent()) return;
        if (data.success) {
            setStatus(savedMsg, 'success');
        } else {
            setStatus(data.message || t('toast.saveSettingsFailed', {}, 'Failed to save settings.'), 'danger');
        }
    } catch (e) {
        if (e instanceof AuthError) return;
        console.error('Error saving the De-Slop setting:', e);
        if (isCurrent()) setStatus(t('toast.saveSettingsFailed', {}, 'Failed to save settings.'), 'danger');
    }
}
