import { apiGet, getToken, setToken } from './api.js';
import { showActionToast } from './ui.js';
import { DEV_MODE, mockUser } from './dev-mocks.js';
import { initBotStatus, updateBotStatusUI } from './sections/bot-status.js';
import { initBuiltInCommands, loadCommandSettings } from './sections/built-in-commands.js';
import { initAutoChat, loadAndApplyAutoChatConfig } from './sections/auto-chat.js';
import { initCustomCommands, loadCustomCommands } from './sections/custom-commands.js';
import { initTimers, loadTimers } from './sections/timers.js';
import { initCheckin, loadCheckinSettings } from './sections/checkin.js';

let twitchUsernameEl;
let channelNameStatusEl;
let loggedInUser = null;

async function reloadAllConfigs() {
    await Promise.all([
        loadAndApplyAutoChatConfig(),
        loadCommandSettings(),
        loadCustomCommands(),
        loadTimers(),
        loadCheckinSettings()
    ]);
}

async function initializeDashboard() {
    let appSessionToken = getToken();
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

        if (!appSessionToken) {
            console.warn("No session token found, redirecting to login");
            showActionToast("Authentication token missing. Please log in again.", 'danger', 0);
            setTimeout(() => window.location.href = 'index.html', 2000);
            return;
        }

        try {
            console.log("Dashboard: Sending request to /api/bot/status with Authorization header");
            const statusRes = await apiGet('/api/bot/status');

            if (!statusRes.ok) {
                if (statusRes.status === 401) {
                    showActionToast("Session potentially expired or not fully established. Try logging in again.", 'danger', 0);
                    return;
                }
                const errorData = await statusRes.json().catch(() => ({ message: statusRes.statusText }));
                throw new Error(`Failed to fetch status: ${errorData.message || statusRes.statusText}`);
            }
            const statusData = await statusRes.json();

            if (statusData.success) {
                updateBotStatusUI(statusData.isActive);
                // Load configs after bot status is loaded
                await reloadAllConfigs();
            } else {
                showActionToast(`Error: ${statusData.message}`, 'danger', 0);
                const botStatusEl = document.getElementById('bot-status');
                if (botStatusEl) botStatusEl.textContent = "Error";
            }
        } catch (error) {
            console.error('Error fetching bot status:', error);
            showActionToast('Failed to load bot status. ' + error.message, 'danger', 0);
            const botStatusEl = document.getElementById('bot-status');
            if (botStatusEl) botStatusEl.textContent = 'Error';
        }
    } else {
        // Not logged in or info missing, redirect to index.html
        window.location.href = 'index.html';
    }
}

document.addEventListener('DOMContentLoaded', () => {
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

    // 3. Start dashboard initialization
    initializeDashboard();
});
