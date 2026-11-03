import { apiGet, apiPost, AuthError, readJson } from '../api.js';
import { debounce, setSuccessMessage, showActionToast } from '../ui.js';
import { DEV_MODE, mockDelay, mockTimedGames } from '../dev-mocks.js';
import { t } from '../i18n.js';

// Timed Games card: chat games the bot starts on its own at a fixed interval
// while the stream is live. One document per channel (/api/timed-games). A
// changed setting is saved on its own, debounced; the bot picks the change up
// from Firestore. While timed games are off, the other settings are hidden.

const GAMES = ['trivia', 'geo', 'riddle'];

let loadingEl;
let enabledEl;
let intervalEl;
let gamesFieldset;
let statusEl;
let offNoteEl;
let settingRows = [];
const gameBoxes = {};     // game -> checkbox
let pending = {};         // setting -> value waiting for the debounced save
let requestId = 0;        // id of the newest save, so a late response cannot overwrite it
let saveLater;

export function initTimedGames() {
    loadingEl = document.getElementById('timed-games-loading');
    enabledEl = document.getElementById('timed-games-enabled');
    intervalEl = document.getElementById('timed-games-interval');
    gamesFieldset = document.getElementById('timed-games-games');
    statusEl = document.getElementById('timed-games-message');
    offNoteEl = document.getElementById('timed-games-off-note');
    settingRows = [...document.querySelectorAll('#timed-games-group [data-timed-setting]')];
    if (!enabledEl) return;

    for (const game of GAMES) {
        gameBoxes[game] = document.getElementById(`timed-games-game-${game}`);
        gameBoxes[game].addEventListener('change', onGamesChange);
    }
    saveLater = debounce(savePending, 600);

    enabledEl.addEventListener('change', () => {
        showSettings(enabledEl.checked);
        queue({ enabled: enabledEl.checked });
    });
    intervalEl.addEventListener('change', onIntervalChange);
    showSettings(false);
}

export async function loadTimedGames() {
    if (!enabledEl) return;
    if (loadingEl) loadingEl.hidden = false;
    const config = await fetchConfig();
    if (loadingEl) loadingEl.hidden = true;

    if (!config) {
        showActionToast(t('toast.loadTimedGamesFailed', {}, 'Timed games settings did not load.'), 'danger');
        return;
    }
    render(config);
}

async function fetchConfig() {
    if (DEV_MODE) {
        await mockDelay(500);
        return mockTimedGames;
    }
    try {
        const res = await apiGet('/api/timed-games');
        const data = await readJson(res);
        return data.success && data.config ? data.config : null;
    } catch (e) {
        if (!(e instanceof AuthError)) console.error('Error fetching timed games settings:', e);
        return null;
    }
}

function render(config) {
    enabledEl.checked = config.enabled === true;
    intervalEl.value = Number.isFinite(config.intervalMinutes) ? String(config.intervalMinutes) : '';
    intervalEl.removeAttribute('aria-invalid');
    for (const game of GAMES) {
        gameBoxes[game].checked = Array.isArray(config.games) && config.games.includes(game);
    }
    gamesFieldset.removeAttribute('aria-invalid');
    showSettings(enabledEl.checked);
}

function showSettings(enabled) {
    for (const row of settingRows) row.hidden = !enabled;
    if (offNoteEl) offNoteEl.hidden = enabled;
}

function setStatus(text, kind = 'muted') {
    if (kind === 'success') {
        setSuccessMessage(statusEl, text);
    } else {
        statusEl.textContent = text;
    }
    statusEl.className = `text-${kind} mb-0 timed-games-status`;
}

function onIntervalChange() {
    const min = Number(intervalEl.dataset.min);
    const max = Number(intervalEl.dataset.max);
    const raw = intervalEl.value.trim();
    const n = /^\d+$/.test(raw) ? Number(raw) : NaN;
    if (!Number.isInteger(n) || n < min || n > max) {
        intervalEl.setAttribute('aria-invalid', 'true');
        delete pending.intervalMinutes;
        setStatus(t('validation.gamesRange', { min, max }, `Enter a whole number from ${min} to ${max}.`), 'danger');
        return;
    }
    intervalEl.removeAttribute('aria-invalid');
    queue({ intervalMinutes: n });
}

function onGamesChange() {
    const games = GAMES.filter(game => gameBoxes[game].checked);
    if (games.length === 0) {
        gamesFieldset.setAttribute('aria-invalid', 'true');
        delete pending.games;
        setStatus(t('validation.timedGamesNone', {}, 'Select one or more games.'), 'danger');
        return;
    }
    gamesFieldset.removeAttribute('aria-invalid');
    queue({ games });
}

function queue(update) {
    Object.assign(pending, update);
    saveLater();
}

async function savePending() {
    const payload = pending;
    pending = {};
    if (Object.keys(payload).length === 0) return;

    const id = ++requestId;
    const isCurrent = () => id === requestId;
    const savedMsg = t('toast.timedGamesSaved', {}, 'Timed games settings saved.');
    setStatus(t('status.saving', {}, 'Saving…'));

    if (DEV_MODE) {
        await mockDelay(500);
        Object.assign(mockTimedGames, payload);
        if (isCurrent()) setStatus(t('status.savedDev', { message: savedMsg }, `${savedMsg} (dev mode).`), 'success');
        return;
    }

    try {
        const res = await apiPost('/api/timed-games', payload);
        const data = await readJson(res);
        if (!isCurrent()) return;
        if (data.success) {
            setStatus(savedMsg, 'success');
        } else {
            setStatus(data.message || t('toast.saveSettingsFailed', {}, 'Failed to save settings.'), 'danger');
        }
    } catch (e) {
        if (e instanceof AuthError) return;
        console.error('Error saving timed games settings:', e);
        if (isCurrent()) setStatus(t('toast.saveSettingsFailed', {}, 'Failed to save settings.'), 'danger');
    }
}
