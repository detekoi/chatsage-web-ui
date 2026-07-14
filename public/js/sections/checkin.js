import { apiGet, apiPut, apiDelete, getToken } from '../api.js';
import { showActionToast, setSuccessMessage, setupChipInsertion } from '../ui.js';
import { DEV_MODE, mockDelay } from '../dev-mocks.js';

let checkinLoadingEl;
let checkinEnabledEl;
let checkinTitleEl;
let checkinCostEl;
let checkinResponseEl;
let checkinAiToggleEl;
let checkinAiPromptGroupEl;
let checkinAiPromptEl;
let checkinSaveBtn;
let checkinDeleteBtn;
let checkinMsgEl;
let checkinConfigFieldsEl;
let checkinResponseGroupEl;

export function initCheckin() {
    checkinLoadingEl = document.getElementById('checkin-loading');
    checkinEnabledEl = document.getElementById('checkin-enabled');
    checkinTitleEl = document.getElementById('checkin-title');
    checkinCostEl = document.getElementById('checkin-cost');
    checkinResponseEl = document.getElementById('checkin-response');
    checkinAiToggleEl = document.getElementById('checkin-ai-toggle');
    checkinAiPromptGroupEl = document.getElementById('checkin-ai-prompt-group');
    checkinAiPromptEl = document.getElementById('checkin-ai-prompt');
    checkinSaveBtn = document.getElementById('checkin-save-btn');
    checkinDeleteBtn = document.getElementById('checkin-delete-btn');
    checkinMsgEl = document.getElementById('checkin-msg');
    checkinConfigFieldsEl = document.getElementById('checkin-config-fields');
    checkinResponseGroupEl = document.getElementById('checkin-response-group');

    // Check-in AI toggle: show AI prompt OR response template (not both)
    checkinAiToggleEl.addEventListener('change', updateCheckinAiVisibility);

    // Check-in enable toggle: collapse/expand config fields
    checkinEnabledEl.addEventListener('change', updateCheckinConfigVisibility);

    // Wire up variable chip insertion
    setupChipInsertion('.checkin-chips', checkinResponseEl);
    setupChipInsertion('.checkin-ai-chips', checkinAiPromptEl);

    // Numeric fields logic (since this is specific to standardizing numbers across the whole app,
    // wait, we can just grab all numeric inputs here, or should we put it in ui.js? 
    // Putting it here specifically for check-in if there's only one. But there is a global query.
    // Let's do a global query here just like in the monolith, or put it in main.js. Let's do it in checkin.js since cost is numeric.)
    document.querySelectorAll('input[inputmode="numeric"]').forEach((input) => {
        input.addEventListener('input', () => {
            const digitsOnly = input.value.replace(/\D/g, '');
            if (input.value !== digitsOnly) {
                input.value = digitsOnly;
            }
        });
    });

    checkinSaveBtn.addEventListener('click', saveCheckinSettings);
    checkinDeleteBtn.addEventListener('click', deleteCheckinReward);
}

function updateCheckinAiVisibility() {
    const aiOn = checkinAiToggleEl.checked;
    checkinResponseGroupEl.style.display = aiOn ? 'none' : 'block';
    checkinAiPromptGroupEl.style.display = aiOn ? 'block' : 'none';
}

function updateCheckinConfigVisibility() {
    checkinConfigFieldsEl.style.display = checkinEnabledEl.checked ? 'block' : 'none';
}

function updateCheckinDeleteBtn(rewardId) {
    checkinDeleteBtn.style.display = rewardId ? 'inline-block' : 'none';
}

export async function loadCheckinSettings() {
    if (!getToken()) return;
    checkinLoadingEl.style.display = 'block';

    if (DEV_MODE) {
        await mockDelay(300);
        checkinLoadingEl.style.display = 'none';
        checkinEnabledEl.checked = false;
        checkinTitleEl.value = 'Daily Check-In';
        checkinCostEl.value = 100;
        checkinResponseEl.value = '$(user) checked in! Day #$(checkin_count) 🎉';
        checkinAiToggleEl.checked = false;
        checkinAiPromptEl.value = '';
        updateCheckinDeleteBtn(null);
        updateCheckinConfigVisibility();
        updateCheckinAiVisibility();
        return;
    }

    try {
        const res = await apiGet('/api/checkin');
        const data = await res.json();
        checkinLoadingEl.style.display = 'none';

        if (data.success && data.config) {
            checkinEnabledEl.checked = !!data.config.enabled;
            checkinTitleEl.value = data.config.title || 'Daily Check-In';
            checkinCostEl.value = data.config.cost || 100;
            checkinResponseEl.value = data.config.responseTemplate || '';
            checkinAiToggleEl.checked = !!data.config.useAi;
            checkinAiPromptEl.value = data.config.aiPrompt || '';
            updateCheckinAiVisibility();
            updateCheckinDeleteBtn(data.config.rewardId);
            updateCheckinConfigVisibility();
        }
    } catch (error) {
        console.error('Error loading check-in settings:', error);
        checkinLoadingEl.style.display = 'none';
    }
}

async function saveCheckinSettings() {
    if (!getToken()) return;

    const cost = parseInt(checkinCostEl.value, 10);
    if (isNaN(cost) || cost < 1 || cost > 999999) {
        checkinMsgEl.textContent = 'Cost must be between 1 and 999999 points.';
        checkinMsgEl.className = 'text-danger mt-2 mb-0';
        return;
    }

    checkinMsgEl.textContent = 'Saving...';
    checkinMsgEl.className = 'text-muted mt-2 mb-0';

    const body = {
        enabled: checkinEnabledEl.checked,
        title: checkinTitleEl.value.trim() || 'Daily Check-In',
        cost,
        responseTemplate: checkinResponseEl.value,
        useAi: checkinAiToggleEl.checked,
        aiPrompt: checkinAiPromptEl.value,
    };

    if (DEV_MODE) {
        await mockDelay(300);
        setSuccessMessage(checkinMsgEl, 'Saved (dev mode)');
        checkinMsgEl.className = 'text-success mt-2 mb-0';
        return;
    }

    try {
        const res = await apiPut('/api/checkin', body);
        const data = await res.json();

        if (data.success) {
            setSuccessMessage(checkinMsgEl, data.message || 'Check-in settings saved!');
            checkinMsgEl.className = 'text-success mt-2 mb-0';
            showActionToast(data.message || 'Daily check-in settings saved.', 'success');
            // Update delete button visibility from returned config
            if (data.config?.rewardId) updateCheckinDeleteBtn(data.config.rewardId);
        } else {
            checkinMsgEl.textContent = data.message || 'Error saving settings';
            checkinMsgEl.className = 'text-danger mt-2 mb-0';
            if (data.needsReauth) {
                showActionToast('Please log in again to manage Channel Point Rewards.', 'danger', 0);
            }
        }
    } catch (error) {
        console.error('Error saving check-in settings:', error);
        checkinMsgEl.textContent = 'Network error. Try again.';
        checkinMsgEl.className = 'text-danger mt-2 mb-0';
    }
}

async function deleteCheckinReward() {
    if (!getToken()) return;
    if (!confirm('Delete the Daily Check-In reward from your channel? This cannot be undone.')) return;

    checkinMsgEl.textContent = 'Deleting...';
    checkinMsgEl.className = 'text-muted mt-2 mb-0';

    if (DEV_MODE) {
        await mockDelay(300);
        setSuccessMessage(checkinMsgEl, 'Reward deleted (dev mode)');
        checkinMsgEl.className = 'text-success mt-2 mb-0';
        checkinEnabledEl.checked = false;
        updateCheckinDeleteBtn(null);
        showActionToast('Check-in reward deleted.', 'success');
        return;
    }

    try {
        const res = await apiDelete('/api/checkin');
        const data = await res.json();

        if (data.success) {
            setSuccessMessage(checkinMsgEl, data.message || 'Reward deleted');
            checkinMsgEl.className = 'text-success mt-2 mb-0';
            checkinEnabledEl.checked = false;
            updateCheckinDeleteBtn(null);
            showActionToast(data.message || 'Check-in reward deleted.', 'success');
        } else {
            checkinMsgEl.textContent = data.message || 'Error deleting reward';
            checkinMsgEl.className = 'text-danger mt-2 mb-0';
        }
    } catch (error) {
        console.error('Error deleting check-in reward:', error);
        checkinMsgEl.textContent = 'Network error. Try again.';
        checkinMsgEl.className = 'text-danger mt-2 mb-0';
    }
}
