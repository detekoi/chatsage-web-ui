import { apiGet, apiPost, AuthError } from '../api.js';
import { debounce, showActionToast } from '../ui.js';
import { DEV_MODE, mockAutoChatConfig, mockDelay } from '../dev-mocks.js';

let autoLoadingEl;
let autoModeEl;
let autoCatFactsEl;
let autoCatQuestionsEl;
let autoMsgEl;

let streamEventsLoadingEl;
let streamGreetingsToggleEl;
let streamFollowsToggleEl;
let streamSubscriptionsToggleEl;
let streamRaidsToggleEl;
let streamEventsMsgEl;

let adNotificationsLoadingEl;
let autoCatAdsEl;
let adNotificationsMsgEl;

export function initAutoChat() {
    autoLoadingEl = document.getElementById('auto-chat-loading');
    autoModeEl = document.getElementById('auto-mode');
    autoCatFactsEl = document.getElementById('auto-cat-facts');
    autoCatQuestionsEl = document.getElementById('auto-cat-questions');
    autoMsgEl = document.getElementById('auto-chat-message');

    streamEventsLoadingEl = document.getElementById('stream-events-loading');
    streamGreetingsToggleEl = document.getElementById('stream-greetings-toggle');
    streamFollowsToggleEl = document.getElementById('stream-follows-toggle');
    streamSubscriptionsToggleEl = document.getElementById('stream-subscriptions-toggle');
    streamRaidsToggleEl = document.getElementById('stream-raids-toggle');
    streamEventsMsgEl = document.getElementById('stream-events-message');

    adNotificationsLoadingEl = document.getElementById('ad-notifications-loading');
    autoCatAdsEl = document.getElementById('auto-cat-ads');
    adNotificationsMsgEl = document.getElementById('ad-notifications-message');

    // Debounced auto-save on any change to auto-chat controls
    const debouncedAutoSave = debounce(saveAutoChatSettings, 600);
    [autoModeEl, autoCatFactsEl, autoCatQuestionsEl].forEach(el => {
        el.addEventListener('change', debouncedAutoSave);
    });

    // Debounced auto-save for stream events
    const debouncedStreamEventsSave = debounce(saveStreamEventsSettings, 600);
    [streamGreetingsToggleEl, streamFollowsToggleEl, streamSubscriptionsToggleEl, streamRaidsToggleEl].forEach(el => {
        el.addEventListener('change', debouncedStreamEventsSave);
    });

    // Debounced auto-save for ad notifications
    const debouncedAdNotificationsSave = debounce(saveAdNotificationsSettings, 600);
    autoCatAdsEl.addEventListener('change', debouncedAdNotificationsSave);
}

export async function loadAndApplyAutoChatConfig() {
    if (autoLoadingEl) autoLoadingEl.style.display = 'block';
    if (adNotificationsLoadingEl) adNotificationsLoadingEl.style.display = 'block';
    if (streamEventsLoadingEl) streamEventsLoadingEl.style.display = 'block';
    
    const config = await fetchAutoChatConfig();
    applyAutoChatSettings(config);
    applyAdNotificationsSettings(config);
    applyStreamEventsSettings(config);
}

async function fetchAutoChatConfig() {

    if (DEV_MODE) {
        await mockDelay(500);
        return mockAutoChatConfig;
    }

    try {
        const res = await apiGet('/api/auto-chat');
        const data = await res.json();
        if (data.success && data.config) {
            return data.config;
        }
        return null;
    } catch (e) {
        console.error('Error fetching auto-chat config:', e);
        return null;
    }
}

function applyAutoChatSettings(config) {
    if (autoLoadingEl) autoLoadingEl.style.display = 'none';
    if (config) {
        autoModeEl.value = config.mode || 'off';
        autoCatFactsEl.checked = config.categories?.facts !== false;
        autoCatQuestionsEl.checked = config.categories?.questions !== false;
    } else {
        showActionToast('Failed to load auto-chat settings.', 'danger');
    }
}

function applyAdNotificationsSettings(config) {
    if (adNotificationsLoadingEl) adNotificationsLoadingEl.style.display = 'none';
    if (config) {
        autoCatAdsEl.checked = config.categories?.ads === true;
    } else {
        adNotificationsMsgEl.textContent = 'Failed to load ad notification settings.';
        adNotificationsMsgEl.style.color = '#ff6b6b';
    }
}

function applyStreamEventsSettings(config) {
    if (streamEventsLoadingEl) streamEventsLoadingEl.style.display = 'none';
    if (config) {
        streamGreetingsToggleEl.checked = config.categories?.greetings !== false;
        streamFollowsToggleEl.checked = config.categories?.follows !== false;
        streamSubscriptionsToggleEl.checked = config.categories?.subscriptions !== false;
        streamRaidsToggleEl.checked = config.categories?.raids !== false;
    } else {
        streamEventsMsgEl.textContent = 'Failed to load stream event settings.';
        streamEventsMsgEl.style.color = '#ff6b6b';
    }
}

const saveRequestIds = new Map();

async function saveSectionSettings(endpoint, payload, statusEl, successMsg) {
    const contextId = statusEl.id;
    const currentRequestId = (saveRequestIds.get(contextId) || 0) + 1;
    saveRequestIds.set(contextId, currentRequestId);

    statusEl.textContent = 'Saving...';
    statusEl.style.color = 'var(--text-muted, #6c757d)';

    if (DEV_MODE) {
        await mockDelay(500);
        if (currentRequestId === saveRequestIds.get(contextId)) {
            statusEl.textContent = `${successMsg} (dev mode).`;
            statusEl.style.color = '#4ecdc4';
        }
        return;
    }

    try {
        const res = await apiPost(endpoint, payload);
        const data = await res.json();
        
        if (currentRequestId === saveRequestIds.get(contextId)) {
            if (data.success) {
                statusEl.textContent = successMsg;
                statusEl.style.color = '#4ecdc4';
            } else {
                statusEl.textContent = data.message || 'Failed to save settings.';
                statusEl.style.color = '#ff6b6b';
            }
        }
    } catch (e) {
        if (e instanceof AuthError) return;
        console.error(`Error saving to ${endpoint}:`, e);
        if (currentRequestId === saveRequestIds.get(contextId)) {
            statusEl.textContent = 'Error saving settings.';
            statusEl.style.color = '#ff6b6b';
        }
    }
}

async function saveStreamEventsSettings() {
    const payload = {
        categories: {
            greetings: !!streamGreetingsToggleEl.checked,
            follows: !!streamFollowsToggleEl.checked,
            subscriptions: !!streamSubscriptionsToggleEl.checked,
            raids: !!streamRaidsToggleEl.checked,
        }
    };
    await saveSectionSettings('/api/auto-chat', payload, streamEventsMsgEl, 'Stream event settings saved.');
}

async function saveAutoChatSettings() {
    const payload = {
        mode: autoModeEl.value,
        categories: {
            facts: !!autoCatFactsEl.checked,
            questions: !!autoCatQuestionsEl.checked,
        }
    };
    await saveSectionSettings('/api/auto-chat', payload, autoMsgEl, 'Auto-chat settings saved.');
}

async function saveAdNotificationsSettings() {
    const payload = {
        categories: {
            ads: !!autoCatAdsEl.checked,
        }
    };
    await saveSectionSettings('/api/auto-chat', payload, adNotificationsMsgEl, 'Ad notification settings saved.');
}
