import { apiPost, getToken, setToken, AuthError } from '../api.js';
import { showActionToast } from '../ui.js';
import { DEV_MODE, mockDelay } from '../dev-mocks.js';

let botStatusEl;
let addBotBtn;
let removeBotBtn;
let commandsSectionEl;
let streamEventsSectionEl;
let autoSectionEl;
let adNotificationsSectionEl;
let customCmdSectionEl;
let timersSectionEl;
let checkinSectionEl;
let actionMessageEl;

export function initBotStatus({ onBotAdded, onBotRemoved, onLogout }) {
    botStatusEl = document.getElementById('bot-status');
    addBotBtn = document.getElementById('add-bot-btn');
    removeBotBtn = document.getElementById('remove-bot-btn');
    commandsSectionEl = document.getElementById('commands-section');
    streamEventsSectionEl = document.getElementById('stream-events-section');
    autoSectionEl = document.getElementById('auto-chat-section');
    adNotificationsSectionEl = document.getElementById('ad-notifications-section');
    customCmdSectionEl = document.getElementById('custom-commands-section');
    timersSectionEl = document.getElementById('timers-section');
    checkinSectionEl = document.getElementById('checkin-section');
    actionMessageEl = document.getElementById('action-message');

    const logoutLink = document.getElementById('logout-link');

    addBotBtn.addEventListener('click', async () => {
        showActionToast('Requesting bot to join...', 'info', 0);
        
        if (DEV_MODE) {
            await mockDelay(500);
            showActionToast('Bot added (dev mode)', 'success');
            updateBotStatusUI(true);
            if (onBotAdded) await onBotAdded();
            return;
        }

        try {
            const res = await apiPost('/api/bot/add');
            const data = await res.json();
            showActionToast(data.message, data.success ? 'success' : 'danger');
            
            if (data.success) {
                updateBotStatusUI(true);
                if (onBotAdded) await onBotAdded();
            }
        } catch (error) {
            if (error instanceof AuthError) return;
            console.error('Error adding bot:', error);
            showActionToast('Failed to send request to add bot.', 'danger');
        }
    });

    removeBotBtn.addEventListener('click', async () => {
        showActionToast('Requesting bot to leave...', 'info', 0);

        if (DEV_MODE) {
            await mockDelay(500);
            showActionToast('Bot removed (dev mode)', 'success');
            updateBotStatusUI(false);
            if (onBotRemoved) await onBotRemoved();
            return;
        }

        try {
            const res = await apiPost('/api/bot/remove');
            const data = await res.json();
            showActionToast(data.message, data.success ? 'success' : 'danger');
            
            if (data.success) {
                updateBotStatusUI(false);
                if (onBotRemoved) await onBotRemoved();
            }
        } catch (error) {
            if (error instanceof AuthError) return;
            console.error('Error removing bot:', error);
            showActionToast('Failed to send request to remove bot.', 'danger');
        }
    });

    logoutLink.addEventListener('click', (e) => {
        e.preventDefault();

        // Clear localStorage
        localStorage.removeItem('twitch_user_login');
        localStorage.removeItem('twitch_user_id');
        setToken(null);

        if (onLogout) onLogout();
        
        // Redirect to login
        window.location.href = 'index.html';
    });
}

export function updateBotStatusUI(isActive) {
    if (!botStatusEl) return;
    
    if (isActive) {
        botStatusEl.textContent = 'Active';
        botStatusEl.classList.remove('text-danger');
        botStatusEl.classList.add('text-success');
        addBotBtn.style.display = 'none';
        removeBotBtn.style.display = 'inline-block';
    } else {
        botStatusEl.textContent = 'Inactive / Not Joined';
        botStatusEl.classList.remove('text-success');
        botStatusEl.classList.add('text-danger');
        addBotBtn.style.display = 'inline-block';
        removeBotBtn.style.display = 'none';
    }
    
    // Show settings sections regardless of bot status
    if (commandsSectionEl) commandsSectionEl.style.display = 'block';
    if (streamEventsSectionEl) streamEventsSectionEl.style.display = 'block';
    if (autoSectionEl) autoSectionEl.style.display = 'block';
    if (adNotificationsSectionEl) adNotificationsSectionEl.style.display = 'block';
    if (customCmdSectionEl) customCmdSectionEl.style.display = 'block';
    if (timersSectionEl) timersSectionEl.style.display = 'block';
    if (checkinSectionEl) checkinSectionEl.style.display = 'block';
    
    // Clear previous toast
    if (actionMessageEl) {
        actionMessageEl.style.display = 'none';
    }
}
