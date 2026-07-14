import { apiGet, apiPost, getToken } from '../api.js';
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
    autoLoadingEl.style.display = 'block';
    adNotificationsLoadingEl.style.display = 'block';
    streamEventsLoadingEl.style.display = 'block';
    
    const config = await fetchAutoChatConfig();
    applyAutoChatSettings(config);
    applyAdNotificationsSettings(config);
    applyStreamEventsSettings(config);
}

async function fetchAutoChatConfig() {
    if (!getToken()) return null;

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
    autoLoadingEl.style.display = 'none';
    if (config) {
        autoModeEl.value = config.mode || 'off';
        autoCatFactsEl.checked = config.categories?.facts !== false;
        autoCatQuestionsEl.checked = config.categories?.questions !== false;
    } else {
        showActionToast('Failed to load auto-chat settings.', 'danger');
    }
}

function applyAdNotificationsSettings(config) {
    adNotificationsLoadingEl.style.display = 'none';
    if (config) {
        autoCatAdsEl.checked = config.categories?.ads === true;
    } else {
        adNotificationsMsgEl.textContent = 'Failed to load ad notification settings.';
        adNotificationsMsgEl.style.color = '#ff6b6b';
    }
}

function applyStreamEventsSettings(config) {
    streamEventsLoadingEl.style.display = 'none';
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

let streamEventsSaveRequestId = 0;
async function saveStreamEventsSettings() {
    if (!getToken()) return;

    const currentRequestId = ++streamEventsSaveRequestId;
    streamEventsMsgEl.textContent = 'Saving...';

    if (DEV_MODE) {
        await mockDelay(500);
        if (currentRequestId === streamEventsSaveRequestId) {
            streamEventsMsgEl.textContent = 'Stream event settings saved (dev mode).';
            streamEventsMsgEl.style.color = '#4ecdc4';
        }
        return;
    }

    try {
        const res = await apiPost('/api/auto-chat', {
            categories: {
                greetings: !!streamGreetingsToggleEl.checked,
                follows: !!streamFollowsToggleEl.checked,
                subscriptions: !!streamSubscriptionsToggleEl.checked,
                raids: !!streamRaidsToggleEl.checked,
            }
        });
        const data = await res.json();
        
        if (currentRequestId === streamEventsSaveRequestId) {
            if (data.success) {
                streamEventsMsgEl.textContent = 'Stream event settings saved.';
                streamEventsMsgEl.style.color = '#4ecdc4';
            } else {
                streamEventsMsgEl.textContent = data.message || 'Failed to save stream event settings.';
                streamEventsMsgEl.style.color = '#ff6b6b';
            }
        }
    } catch (e) {
        console.error('Error saving stream events:', e);
        streamEventsMsgEl.textContent = 'Error saving stream event settings.';
        streamEventsMsgEl.style.color = '#ff6b6b';
    }
}

let autoSaveRequestId = 0;
async function saveAutoChatSettings() {
    if (!getToken()) return;

    const currentRequestId = ++autoSaveRequestId;
    autoMsgEl.textContent = 'Saving auto-chat...';

    if (DEV_MODE) {
        await mockDelay(500);
        if (currentRequestId === autoSaveRequestId) {
            autoMsgEl.textContent = 'Auto-chat settings saved (dev mode).';
            autoMsgEl.style.color = '#4ecdc4';
        }
        return;
    }

    try {
        const res = await apiPost('/api/auto-chat', {
            mode: autoModeEl.value,
            categories: {
                facts: !!autoCatFactsEl.checked,
                questions: !!autoCatQuestionsEl.checked,
            }
        });
        const data = await res.json();
        
        if (currentRequestId === autoSaveRequestId) {
            if (data.success) {
                autoMsgEl.textContent = 'Auto-chat settings saved.';
                autoMsgEl.style.color = '#4ecdc4';
            } else {
                autoMsgEl.textContent = data.message || 'Failed to save auto-chat settings.';
                autoMsgEl.style.color = '#ff6b6b';
            }
        }
    } catch (e) {
        console.error('Error saving auto-chat:', e);
        autoMsgEl.textContent = 'Error saving auto-chat settings.';
        autoMsgEl.style.color = '#ff6b6b';
    }
}

let adNotificationsSaveRequestId = 0;
async function saveAdNotificationsSettings() {
    if (!getToken()) return;

    const currentRequestId = ++adNotificationsSaveRequestId;
    adNotificationsMsgEl.textContent = 'Saving ad notifications...';

    if (DEV_MODE) {
        await mockDelay(500);
        if (currentRequestId === adNotificationsSaveRequestId) {
            adNotificationsMsgEl.textContent = 'Ad notification settings saved (dev mode).';
            adNotificationsMsgEl.style.color = '#4ecdc4';
        }
        return;
    }

    try {
        const res = await apiPost('/api/auto-chat', {
            categories: {
                ads: !!autoCatAdsEl.checked,
            }
        });
        const data = await res.json();
        
        if (currentRequestId === adNotificationsSaveRequestId) {
            if (data.success) {
                adNotificationsMsgEl.textContent = 'Ad notification settings saved.';
                adNotificationsMsgEl.style.color = '#4ecdc4';
            } else {
                adNotificationsMsgEl.textContent = data.message || 'Failed to save ad notification settings.';
                adNotificationsMsgEl.style.color = '#ff6b6b';
            }
        }
    } catch (e) {
        console.error('Error saving ad notifications:', e);
        adNotificationsMsgEl.textContent = 'Error saving ad notification settings.';
        adNotificationsMsgEl.style.color = '#ff6b6b';
    }
}
