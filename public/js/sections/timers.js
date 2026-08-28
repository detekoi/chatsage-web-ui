import { apiGet, apiPost, apiPut } from '../api.js';
import { showActionToast, setupChipInsertion } from '../ui.js';
import { DEV_MODE, mockTimers, mockDelay } from '../dev-mocks.js';
import { toggleItem, deleteItem } from '../crud-helpers.js';
import { t } from '../i18n.js';

let timerLoadingEl;
let timerListEl;
let timerEmptyEl;
let timerFormEl;
let timerAddBtn;
let timerSaveBtn;
let timerCancelBtn;
let timerNameEl;
let timerResponseEl;
let timerIntervalEl;
let timerLinesEl;
let timerFormMsgEl;
let timerTypeToggleEl;
let timerResponseLabelEl;

let timerEditingName = null;

export function initTimers() {
    timerLoadingEl = document.getElementById('timer-loading');
    timerListEl = document.getElementById('timer-list');
    timerEmptyEl = document.getElementById('timer-empty');
    timerFormEl = document.getElementById('timer-form');
    timerAddBtn = document.getElementById('timer-add-btn');
    timerSaveBtn = document.getElementById('timer-save-btn');
    timerCancelBtn = document.getElementById('timer-cancel-btn');
    timerNameEl = document.getElementById('timer-name');
    timerResponseEl = document.getElementById('timer-response');
    timerIntervalEl = document.getElementById('timer-interval');
    timerLinesEl = document.getElementById('timer-lines');
    timerFormMsgEl = document.getElementById('timer-form-msg');
    timerTypeToggleEl = document.getElementById('timer-type-toggle');
    timerResponseLabelEl = document.getElementById('timer-response-label');

    // Toggle label when timer AI mode changes
    timerTypeToggleEl.addEventListener('change', () => {
        if (timerTypeToggleEl.checked) {
            timerResponseLabelEl.textContent = t('page.timers.aiPromptLabel', {}, 'AI Prompt');
            timerResponseEl.placeholder = t('page.timers.aiPromptPlaceholder', {}, 'Remind chat about Discord for the current game.');
        } else {
            timerResponseLabelEl.textContent = t('page.timers.messageLabel', {}, 'Message');
            timerResponseEl.placeholder = t('page.timers.messagePlaceholder', {}, 'Enjoying the stream? Join the Discord!');
        }
    });

    // Wire up variable chip insertion
    setupChipInsertion('.timer-chips', timerResponseEl);

    // Wire up timer form buttons
    timerAddBtn.addEventListener('click', openTimerAddForm);
    timerSaveBtn.addEventListener('click', saveTimer);
    timerCancelBtn.addEventListener('click', closeTimerForm);
}

export async function loadTimers() {
    timerLoadingEl.style.display = 'block';
    timerEmptyEl.style.display = 'none';

    if (DEV_MODE) {
        await mockDelay(500);
        timerLoadingEl.style.display = 'none';
        renderTimersList(mockTimers);
        return;
    }

    try {
        const res = await apiGet('/api/timers');
        const data = await res.json();
        timerLoadingEl.style.display = 'none';

        if (data.success && data.timers) {
            renderTimersList(data.timers);
        } else {
            timerListEl.innerHTML = '<div class="alert alert-danger" role="alert">Failed to load timed messages.</div>';
        }
    } catch (error) {
        console.error('Error loading timers:', error);
        timerLoadingEl.style.display = 'none';
        timerListEl.innerHTML = '<div class="alert alert-danger" role="alert">Failed to load timed messages.</div>';
    }
}

function renderTimersList(timers) {
    timerListEl.innerHTML = '';

    if (!timers || timers.length === 0) {
        timerEmptyEl.style.display = 'block';
        return;
    }

    timerEmptyEl.style.display = 'none';

    timers.forEach(timer => {
        const item = document.createElement('div');
        item.className = 'list-group-item';

        const row = document.createElement('div');
        row.className = 'cmd-row';

        // Info column
        const info = document.createElement('div');
        info.className = 'cmd-info';

        const name = document.createElement('p');
        name.className = 'cmd-name';
        name.textContent = timer.name;

        const response = document.createElement('p');
        response.className = 'cmd-response';
        response.textContent = timer.response;

        const meta = document.createElement('div');
        meta.className = 'cmd-meta';

        const interval = document.createElement('span');
        interval.className = 'cmd-badge';
        interval.textContent = t('label.everyMinutes', { minutes: timer.intervalMinutes }, `every ${timer.intervalMinutes}m`);
        meta.appendChild(interval);

        if (timer.minChatLines > 0) {
            const lines = document.createElement('span');
            lines.className = 'cmd-cooldown';
            lines.textContent = t('label.chatLines', { count: timer.minChatLines }, `${timer.minChatLines} chat lines`);
            meta.appendChild(lines);
        }

        if (timer.type === 'prompt') {
            const aiBadge = document.createElement('span');
            aiBadge.className = 'cmd-badge';
            aiBadge.style.background = 'var(--bs-purple, #7c3aed)';
            aiBadge.style.color = '#fff';
            aiBadge.textContent = 'AI'; // product term, not translated
            meta.appendChild(aiBadge);
        }

        info.appendChild(name);
        info.appendChild(response);
        info.appendChild(meta);

        // Actions column: enabled toggle + edit/delete
        const actions = document.createElement('div');
        actions.className = 'cmd-actions';

        const switchDiv = document.createElement('div');
        switchDiv.className = 'form-check form-switch';
        switchDiv.style.cssText = 'min-height: 28px; display: flex; align-items: center;';

        const checkbox = document.createElement('input');
        checkbox.className = 'form-check-input';
        checkbox.type = 'checkbox';
        checkbox.id = `timer-enabled-${timer.name}`;
        checkbox.checked = timer.enabled !== false;
        checkbox.role = 'switch';
        checkbox.setAttribute('aria-label', t('label.enableTimer', { name: timer.name }, `Enable timer ${timer.name}`));
        checkbox.title = t('label.enableTimerTitle', {}, 'Enable or disable this timed message');
        checkbox.style.cssText = 'width: 44px; height: 24px; min-height: 24px; flex-shrink: 0;';
        checkbox.addEventListener('change', async function () {
            await toggleTimer(timer.name, this.checked, this);
        });
        switchDiv.appendChild(checkbox);

        const editBtn = document.createElement('button');
        editBtn.type = 'button';
        editBtn.className = 'btn btn-outline-primary btn-sm';
        editBtn.textContent = t('common.edit', {}, 'Edit');
        editBtn.setAttribute('aria-label', t('label.editTimer', { name: timer.name }, `Edit timer ${timer.name}`));
        editBtn.style.cssText = 'min-height: 28px; min-width: 44px; padding: 4px 10px; display: inline-flex; align-items: center; justify-content: center;';
        editBtn.addEventListener('click', () => openTimerEditForm(timer));

        const deleteBtn = document.createElement('button');
        deleteBtn.type = 'button';
        deleteBtn.className = 'btn btn-outline-danger btn-sm';
        deleteBtn.textContent = t('common.delete', {}, 'Del');
        deleteBtn.setAttribute('aria-label', t('label.deleteTimer', { name: timer.name }, `Delete timer ${timer.name}`));
        deleteBtn.style.cssText = 'min-height: 28px; min-width: 44px; padding: 4px 10px; display: inline-flex; align-items: center; justify-content: center;';
        deleteBtn.addEventListener('click', () => deleteTimer(timer.name));

        actions.appendChild(switchDiv);
        actions.appendChild(editBtn);
        actions.appendChild(deleteBtn);

        row.appendChild(info);
        row.appendChild(actions);
        item.appendChild(row);
        timerListEl.appendChild(item);
    });
}

async function toggleTimer(name, enabled, checkboxEl) {
    await toggleItem('PUT', `/api/timers/${encodeURIComponent(name)}`, { enabled }, `Timer "${name}"`, enabled, checkboxEl);
}

function openTimerAddForm() {
    timerEditingName = null;
    timerNameEl.value = '';
    timerNameEl.disabled = false;
    timerResponseEl.value = '';
    timerIntervalEl.value = '15';
    timerLinesEl.value = '5';
    timerTypeToggleEl.checked = false;
    timerResponseLabelEl.textContent = t('page.timers.messageLabel', {}, 'Message');
    timerResponseEl.placeholder = t('page.timers.messagePlaceholder', {}, 'Enjoying the stream? Join the Discord!');
    timerFormMsgEl.textContent = '';
    timerFormEl.style.display = 'block';
    timerNameEl.focus();
}

function openTimerEditForm(timer) {
    timerEditingName = timer.name;
    timerNameEl.value = timer.name;
    timerNameEl.disabled = true;
    timerResponseEl.value = timer.response;
    timerIntervalEl.value = String(timer.intervalMinutes || 15);
    timerLinesEl.value = String(timer.minChatLines ?? 5);
    timerTypeToggleEl.checked = timer.type === 'prompt';
    timerResponseLabelEl.textContent = timer.type === 'prompt'
        ? t('page.timers.aiPromptLabel', {}, 'AI Prompt')
        : t('page.timers.messageLabel', {}, 'Message');
    timerResponseEl.placeholder = timer.type === 'prompt'
        ? t('page.timers.aiPromptPlaceholder', {}, 'Remind chat about Discord for the current game.')
        : t('page.timers.messagePlaceholder', {}, 'Enjoying the stream? Join the Discord!');
    timerFormMsgEl.textContent = '';
    timerFormEl.style.display = 'block';
    timerResponseEl.focus();
}

function closeTimerForm() {
    timerFormEl.style.display = 'none';
    timerEditingName = null;
    timerFormMsgEl.textContent = '';
}

// Sanitize a user-typed timer name into a valid slug
function sanitizeTimerName(raw) {
    return raw
        .trim()
        .toLowerCase()
        .replace(/[\s\-]+/g, '_')       // spaces and hyphens → underscores
        .replace(/[^a-z0-9_]/g, '')     // strip anything else
        .replace(/_{2,}/g, '_')          // collapse multiple underscores
        .slice(0, 25)
        .replace(/^_|_$/g, '');          // trim leading/trailing underscores
}

async function saveTimer() {
    const name = sanitizeTimerName(timerNameEl.value);
    timerNameEl.value = name; // show the user what it became
    const response = timerResponseEl.value.trim();
    const intervalMinutes = parseInt(timerIntervalEl.value, 10);
    const minChatLines = parseInt(timerLinesEl.value, 10);

    if (!name) {
        timerFormMsgEl.textContent = t('validation.timerNameRequired', {}, 'Timer name is required.');
        timerFormMsgEl.style.color = 'var(--danger-primary)';
        return;
    }

    if (!response) {
        timerFormMsgEl.textContent = t('validation.messageRequired', {}, 'Message text is required.');
        timerFormMsgEl.style.color = 'var(--danger-primary)';
        return;
    }

    if (isNaN(intervalMinutes) || intervalMinutes < 2 || intervalMinutes > 1440) {
        timerFormMsgEl.textContent = t('validation.intervalRange', {}, 'Interval must be between 2 and 1440 minutes.');
        timerFormMsgEl.style.color = 'var(--danger-primary)';
        return;
    }

    if (isNaN(minChatLines) || minChatLines < 0 || minChatLines > 100) {
        timerFormMsgEl.textContent = t('validation.minLinesRange', {}, 'Minimum chat lines must be between 0 and 100.');
        timerFormMsgEl.style.color = 'var(--danger-primary)';
        return;
    }

    timerFormMsgEl.textContent = t('status.saving', {}, 'Saving…');
    timerFormMsgEl.style.color = 'var(--text-muted)';
    timerSaveBtn.disabled = true;

    if (DEV_MODE) {
        await mockDelay(500);
        timerFormMsgEl.textContent = t('toast.timerSavedDev', { name }, `Timer "${name}" saved (dev mode).`);
        timerFormMsgEl.style.color = '#4ecdc4';
        timerSaveBtn.disabled = false;
        closeTimerForm();
        loadTimers();
        return;
    }

    try {
        const isEditing = !!timerEditingName;
        const body = {
            response,
            intervalMinutes,
            minChatLines,
            type: timerTypeToggleEl.checked ? 'prompt' : 'text',
        };
        if (!isEditing) body.name = name;

        let res;
        if (isEditing) {
            res = await apiPut(`/api/timers/${encodeURIComponent(timerEditingName)}`, body);
        } else {
            res = await apiPost('/api/timers', body);
        }

        const data = await res.json();

        if (data.success) {
            closeTimerForm();
            await loadTimers();
        } else {
            timerFormMsgEl.textContent = data.message || t('toast.timerSaveFailed', {}, 'Failed to save timer.');
            timerFormMsgEl.style.color = 'var(--danger-primary)';
        }
    } catch (error) {
        console.error('Error saving timer:', error);
        timerFormMsgEl.textContent = t('toast.timerSaveFailed', {}, 'Failed to save timer.');
        timerFormMsgEl.style.color = 'var(--danger-primary)';
    } finally {
        timerSaveBtn.disabled = false;
    }
}

async function deleteTimer(name) {
    await deleteItem(`/api/timers/${encodeURIComponent(name)}`, `Timer "${name}"`, loadTimers);
}
