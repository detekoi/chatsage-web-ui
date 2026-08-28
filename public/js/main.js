import { apiGet, getToken, setToken } from './api.js';
import { t, initI18n } from './i18n.js';
import { showActionToast, setupNumericInputs } from './ui.js';
import { DEV_MODE, mockUser } from './dev-mocks.js';
import { initBotStatus, updateBotStatusUI } from './sections/bot-status.js';
import { initBuiltInCommands, loadCommandSettings } from './sections/built-in-commands.js';
import { initAutoChat, loadAndApplyAutoChatConfig } from './sections/auto-chat.js';
import { initCustomCommands, loadCustomCommands } from './sections/custom-commands.js';
import { initTimers, loadTimers } from './sections/timers.js';
import { initCheckin, loadCheckinSettings } from './sections/checkin.js';
import { initPersona, loadPersona } from './sections/persona.js';

let twitchUsernameEl;
let channelNameStatusEl;
let loggedInUser = null;

async function reloadAllConfigs() {
    await Promise.all([
        loadAndApplyAutoChatConfig(),
        loadCommandSettings(),
        loadCustomCommands(),
        loadTimers(),
        loadCheckinSettings(),
        loadPersona()
    ]);
}

async function initializeDashboard() {
    const userLoginFromStorage = localStorage.getItem('twitch_user_login');
    const userIdFromStorage = localStorage.getItem('twitch_user_id');

    // DEV MODE: Mock user data
    if (DEV_MODE) {
        loggedInUser = mockUser;
        setToken('dev_token');
        localStorage.setItem('twitch_user_login', loggedInUser.login);
        localStorage.setItem('twitch_user_id', loggedInUser.id);
        
        twitchUsernameEl.textContent = loggedInUser.displayName;
        channelNameStatusEl.textContent = loggedInUser.login;
        updateBotStatusUI(true);
        await reloadAllConfigs();
        return;
    }

    if (userLoginFromStorage && userIdFromStorage) {
        loggedInUser = { login: userLoginFromStorage, id: userIdFromStorage, displayName: userLoginFromStorage };
        twitchUsernameEl.textContent = loggedInUser.displayName;
        channelNameStatusEl.textContent = loggedInUser.login;

        if (!getToken()) {
            console.warn("No session token found, redirecting to login");
            showActionToast(t('toast.missingToken', {}, 'Authentication token is missing. Sign in again.'), 'danger', 0);
            setTimeout(() => window.location.href = 'index.html', 2000);
            return;
        }

        try {
            console.log("Dashboard: Fetching bot status and configs in parallel");
            const [statusRes] = await Promise.all([
                apiGet('/api/bot/status'),
                reloadAllConfigs()
            ]);

            if (!statusRes.ok) {
                if (statusRes.status === 401) {
                    showActionToast(t('toast.sessionExpired', {}, 'Your session expired or is not active. Sign in again.'), 'danger', 0);
                    return;
                }
                const errorData = await statusRes.json().catch(() => ({ message: statusRes.statusText }));
                throw new Error(t('toast.botStatusFailed', { message: errorData.message || statusRes.statusText },
                    `Failed to get bot status: ${errorData.message || statusRes.statusText}`));
            }
            const statusData = await statusRes.json();

            if (statusData.success) {
                updateBotStatusUI(statusData.isActive);
            } else {
                // statusData.message is server-authored and still English.
                showActionToast(t('toast.errorPrefix', { message: statusData.message }, `Error: ${statusData.message}`), 'danger', 0);
                const botStatusEl = document.getElementById('bot-status');
                if (botStatusEl) botStatusEl.textContent = t('common.error', {}, 'Error');
            }
        } catch (error) {
            console.error('Error fetching bot status:', error);
            showActionToast(t('toast.loadBotStatusFailed', { message: error.message },
                'Failed to load bot status. ' + error.message), 'danger', 0);
            const botStatusEl = document.getElementById('bot-status');
            if (botStatusEl) botStatusEl.textContent = t('common.error', {}, 'Error');
        }
    } else {
        // Not logged in or info missing, redirect to index.html
        window.location.href = 'index.html';
    }
}

document.addEventListener('DOMContentLoaded', async () => {
    // 0. Catalog first. Every section below renders text through t(), so the strings have to be
    //    available before the first paint rather than after it.
    await initI18n();

    // 1. Grab top-level DOM elements
    twitchUsernameEl = document.getElementById('twitch-username');
    channelNameStatusEl = document.getElementById('channel-name-status');

    // 2. Initialize all section modules
    initBotStatus({
        onBotAdded: async () => {
            await reloadAllConfigs();
        },
        onBotRemoved: async () => {
            await loadCommandSettings();
        },
        onLogout: () => {
            loggedInUser = null;
        }
    });

    initBuiltInCommands();
    initAutoChat();
    initCustomCommands();
    initTimers();
    initCheckin();
    initPersona();

    // Setup global UI listeners
    setupNumericInputs();

    // translatePage() only rewrites markup carrying data-i18n. The command, timer and custom
    // command lists are built in JS, so after a language switch they would keep the old language
    // until the next reload. Registered here, after the initial initI18n() above has already
    // dispatched once, so this only fires on an actual switch.
    document.addEventListener('i18n:changed', () => {
        if (!loggedInUser) return; // nothing rendered yet
        reloadAllConfigs().catch(err =>
            console.error('Failed to re-render sections after a language change:', err));
    });

    // 3. Start dashboard initialization
    initializeDashboard();
});
