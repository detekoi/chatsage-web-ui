import { apiGet, apiPost, AuthError, readJson } from '../api.js';
import { debounce, setSuccessMessage, showActionToast } from '../ui.js';
import { DEV_MODE, mockDelay, mockGameDefaults, mockGameSettings } from '../dev-mocks.js';
import { t } from '../i18n.js';
import { renderCommandRow } from './built-in-commands.js';

// Chat game settings (trivia, geo, riddle). Each control in dashboard.html
// names its game and field with data-game / data-field, so this module reads
// and writes them without a per-field table. A changed field is saved on its
// own, debounced per game; the bot picks the change up from Firestore.
// A game's on/off switch is its command switch, which Command Settings leaves
// to this card. While a game is off, its settings and reset rail are hidden.

const GAMES = ['trivia', 'geo', 'riddle'];

// GAME_LIST_MAX_ITEMS / GAME_LIST_MAX_LENGTH in functions/src/config/constants.ts.
const LIST_MAX_ITEMS = 20;
const LIST_MAX_LENGTH = 60;

let loadingEl;
const controls = {};      // game -> field -> element
const statusEls = {};     // game -> status <p>
const resetBtns = {};     // game -> reset button
const groupEls = {};      // game -> row stack
const actionsEls = {};    // game -> reset rail
const switchRows = {};    // game -> row holding the on/off switch
const pending = {};       // game -> { field: value } waiting for the debounced save
const saveLater = {};     // game -> debounced save
const requestIds = {};    // game -> id of the newest save, so a late response cannot overwrite it

function gameName(game) {
    switch (game) {
    case 'trivia': return t('page.games.trivia', {}, 'Trivia');
    case 'geo': return t('page.games.geo', {}, 'Geo-Game');
    default: return t('page.games.riddle', {}, 'Riddle');
    }
}

export function initGames() {
    loadingEl = document.getElementById('games-loading');

    for (const game of GAMES) {
        controls[game] = {};
        pending[game] = {};
        requestIds[game] = 0;
        statusEls[game] = document.getElementById(`games-${game}-message`);
        resetBtns[game] = document.getElementById(`games-${game}-reset`);
        groupEls[game] = document.getElementById(`games-${game}-group`);
        actionsEls[game] = document.getElementById(`games-${game}-actions`);
        saveLater[game] = debounce(() => savePending(game), 600);

        document.querySelectorAll(`[data-game="${game}"][data-field]`).forEach(el => {
            controls[game][el.dataset.field] = el;
            el.addEventListener('change', () => onFieldChange(game, el));
        });
        resetBtns[game].addEventListener('click', () => resetGame(game));
    }
}

export async function loadGames() {
    if (loadingEl) loadingEl.hidden = false;
    const games = await fetchGames();
    if (loadingEl) loadingEl.hidden = true;

    if (!games) {
        showActionToast(t('toast.loadGamesFailed', {}, 'Game settings did not load.'), 'danger');
        return;
    }
    for (const game of GAMES) {
        if (games[game]) renderGame(game, games[game]);
    }
}

/**
 * Puts each game's command switch under the game's title. Called with the
 * /api/commands list on every load of Command Settings.
 */
export function renderGameSwitches(commands) {
    for (const game of GAMES) {
        const cmd = commands.find(c => c.primaryName === game);
        if (!cmd) continue;

        const row = renderCommandRow(cmd, enabled => showSettings(game, enabled));
        const note = document.createElement('p');
        note.className = 'text-muted mb-0';
        note.dataset.offNote = '';
        note.textContent = t('page.games.offNote', {}, 'Turn on the game to see its settings.');
        row.querySelector('.col').appendChild(note);

        if (switchRows[game]) switchRows[game].replaceWith(row);
        else groupEls[game].querySelector('.wc-group-head').after(row);
        switchRows[game] = row;
        showSettings(game, cmd.enabled);
    }
}

function showSettings(game, enabled) {
    for (const item of groupEls[game].children) {
        if (item !== switchRows[game] && !item.classList.contains('wc-group-head')) item.hidden = !enabled;
    }
    actionsEls[game].hidden = !enabled;
    switchRows[game].querySelector('[data-off-note]').hidden = enabled;
}

async function fetchGames() {
    if (DEV_MODE) {
        await mockDelay(500);
        return mockGameSettings;
    }

    try {
        const res = await apiGet('/api/games');
        const data = await readJson(res);
        return data.success && data.games ? data.games : null;
    } catch (e) {
        if (!(e instanceof AuthError)) console.error('Error fetching game settings:', e);
        return null;
    }
}

function renderGame(game, config) {
    for (const [field, el] of Object.entries(controls[game])) {
        if (field in config) writeControl(el, config[field]);
        el.removeAttribute('aria-invalid');
    }
}

function writeControl(el, value) {
    if (el.type === 'checkbox') {
        el.checked = value === true;
    } else if ('list' in el.dataset) {
        el.value = Array.isArray(value) ? value.join(', ') : '';
    } else if (el.inputMode === 'numeric') {
        const scale = Number(el.dataset.scale) || 1;
        el.value = Number.isFinite(value) ? String(Math.round(value / scale)) : '';
    } else {
        el.value = value;
    }
}

/**
 * Reads a control into the value the API takes, or returns an error message.
 * @returns {{ value: unknown } | { error: string }}
 */
function readControl(el) {
    if (el.type === 'checkbox') return { value: el.checked };

    if ('list' in el.dataset) {
        const items = el.value.split(',').map(s => s.trim()).filter(Boolean);
        if (items.length > LIST_MAX_ITEMS || items.some(item => item.length > LIST_MAX_LENGTH)) {
            return {
                error: t('validation.gamesList', { maxItems: LIST_MAX_ITEMS, maxLength: LIST_MAX_LENGTH },
                    `Enter up to ${LIST_MAX_ITEMS} names. Each name can have up to ${LIST_MAX_LENGTH} characters.`),
            };
        }
        return { value: items };
    }

    if (el.inputMode === 'numeric') {
        const min = Number(el.dataset.min);
        const max = Number(el.dataset.max);
        const n = /^\d+$/.test(el.value.trim()) ? Number(el.value.trim()) : NaN;
        if (!Number.isInteger(n) || n < min || n > max) {
            return {
                error: t('validation.gamesRange', { min, max }, `Enter a whole number from ${min} to ${max}.`),
            };
        }
        return { value: n * (Number(el.dataset.scale) || 1) };
    }

    return { value: el.value };
}

function setStatus(game, text, kind = 'muted') {
    const el = statusEls[game];
    if (kind === 'success') {
        setSuccessMessage(el, text);
    } else {
        el.textContent = text;
    }
    el.className = `text-${kind} mb-0`;
}

function onFieldChange(game, el) {
    const field = el.dataset.field;
    const result = readControl(el);
    if ('error' in result) {
        el.setAttribute('aria-invalid', 'true');
        delete pending[game][field];
        setStatus(game, result.error, 'danger');
        return;
    }
    el.removeAttribute('aria-invalid');
    pending[game][field] = result.value;
    saveLater[game]();
}

async function savePending(game) {
    const payload = pending[game];
    pending[game] = {};
    if (Object.keys(payload).length === 0) return;

    const requestId = ++requestIds[game];
    const isCurrent = () => requestId === requestIds[game];
    const savedMsg = t('toast.gameSaved', { game: gameName(game) }, `${gameName(game)} settings saved.`);
    setStatus(game, t('status.saving', {}, 'Saving…'));

    if (DEV_MODE) {
        await mockDelay(500);
        Object.assign(mockGameSettings[game], payload);
        if (isCurrent()) {
            setStatus(game, t('status.savedDev', { message: savedMsg }, `${savedMsg} (dev mode).`), 'success');
        }
        return;
    }

    try {
        const res = await apiPost(`/api/games/${game}`, payload);
        const data = await readJson(res);
        if (!isCurrent()) return;

        if (data.success) {
            // Show the stored form of what was sent (a list comes back cleaned). Fields
            // changed again since then keep what the user typed.
            for (const field of Object.keys(payload)) {
                if (!(field in pending[game]) && data.config && field in data.config) {
                    writeControl(controls[game][field], data.config[field]);
                }
            }
            setStatus(game, savedMsg, 'success');
        } else {
            setStatus(game, data.message || t('toast.saveSettingsFailed', {}, 'Failed to save settings.'), 'danger');
        }
    } catch (e) {
        if (e instanceof AuthError) return;
        console.error(`Error saving ${game} settings:`, e);
        if (isCurrent()) setStatus(game, t('toast.saveSettingsFailed', {}, 'Failed to save settings.'), 'danger');
    }
}

async function resetGame(game) {
    const name = gameName(game);
    if (!window.confirm(t('confirm.resetGame', { game: name }, `Reset every ${name} setting to its default?`))) return;

    pending[game] = {};
    const requestId = ++requestIds[game];
    const resetMsg = t('toast.gameReset', { game: name }, `${name} settings are back to the defaults.`);
    resetBtns[game].disabled = true;
    setStatus(game, t('status.saving', {}, 'Saving…'));

    try {
        if (DEV_MODE) {
            await mockDelay(500);
            mockGameSettings[game] = structuredClone(mockGameDefaults[game]);
            renderGame(game, mockGameSettings[game]);
            setStatus(game, t('status.savedDev', { message: resetMsg }, `${resetMsg} (dev mode).`), 'success');
            return;
        }

        const res = await apiPost(`/api/games/${game}/reset`, {});
        const data = await readJson(res);
        if (requestId !== requestIds[game]) return;
        if (data.success && data.config) {
            renderGame(game, data.config);
            setStatus(game, resetMsg, 'success');
        } else {
            setStatus(game, data.message || t('toast.saveSettingsFailed', {}, 'Failed to save settings.'), 'danger');
        }
    } catch (e) {
        if (e instanceof AuthError) return;
        console.error(`Error resetting ${game} settings:`, e);
        if (requestId === requestIds[game]) {
            setStatus(game, t('toast.saveSettingsFailed', {}, 'Failed to save settings.'), 'danger');
        }
    } finally {
        resetBtns[game].disabled = false;
    }
}
