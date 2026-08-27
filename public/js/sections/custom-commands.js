import { apiGet, apiPost, apiPut } from '../api.js';
import { showActionToast, setupChipInsertion } from '../ui.js';
import { DEV_MODE, mockCustomCommands, mockDelay } from '../dev-mocks.js';
import { deleteItem } from '../crud-helpers.js';
import { t } from '../i18n.js';

let customCmdLoadingEl;
let customCmdListEl;
let customCmdEmptyEl;
let customCmdFormEl;
let customCmdAddBtn;
let customCmdSaveBtn;
let customCmdCancelBtn;
let customCmdNameEl;
let customCmdResponseEl;
let customCmdPermissionEl;
let customCmdCooldownEl;
let customCmdFormMsgEl;
let customCmdTypeToggleEl;
let customCmdResponseLabelEl;

let customCmdEditingName = null;

export function initCustomCommands() {
    customCmdLoadingEl = document.getElementById('custom-cmd-loading');
    customCmdListEl = document.getElementById('custom-cmd-list');
    customCmdEmptyEl = document.getElementById('custom-cmd-empty');
    customCmdFormEl = document.getElementById('custom-cmd-form');
    customCmdAddBtn = document.getElementById('custom-cmd-add-btn');
    customCmdSaveBtn = document.getElementById('custom-cmd-save-btn');
    customCmdCancelBtn = document.getElementById('custom-cmd-cancel-btn');
    customCmdNameEl = document.getElementById('custom-cmd-name');
    customCmdResponseEl = document.getElementById('custom-cmd-response');
    customCmdPermissionEl = document.getElementById('custom-cmd-permission');
    customCmdCooldownEl = document.getElementById('custom-cmd-cooldown');
    customCmdFormMsgEl = document.getElementById('custom-cmd-form-msg');
    customCmdTypeToggleEl = document.getElementById('custom-cmd-type-toggle');
    customCmdResponseLabelEl = document.getElementById('custom-cmd-response-label');

    // Toggle label when AI mode changes
    customCmdTypeToggleEl.addEventListener('change', () => {
        if (customCmdTypeToggleEl.checked) {
            customCmdResponseLabelEl.textContent = t('page.customCommands.aiPromptLabel', {}, 'AI Prompt');
            customCmdResponseEl.placeholder = 'Write a greeting for $(user) in one sentence.';
        } else {
            customCmdResponseLabelEl.textContent = t('page.customCommands.responseLabel', {}, 'Response');
            customCmdResponseEl.placeholder = 'Hello $(user), welcome to $(channel)!';
        }
    });

    // Wire up variable chip insertion
    setupChipInsertion('.variable-chips', customCmdResponseEl);

    // Wire up form buttons
    customCmdAddBtn.addEventListener('click', openAddForm);
    customCmdSaveBtn.addEventListener('click', saveCustomCommand);
    customCmdCancelBtn.addEventListener('click', closeForm);
}

export async function loadCustomCommands() {
    customCmdLoadingEl.style.display = 'block';
    customCmdEmptyEl.style.display = 'none';

    if (DEV_MODE) {
        await mockDelay(500);
        customCmdLoadingEl.style.display = 'none';
        renderCustomCommandsList(mockCustomCommands);
        return;
    }

    try {
        const res = await apiGet('/api/custom-commands');
        const data = await res.json();
        customCmdLoadingEl.style.display = 'none';

        if (data.success && data.commands) {
            renderCustomCommandsList(data.commands);
        } else {
            customCmdListEl.innerHTML = '<div class="alert alert-danger" role="alert">Failed to load custom commands.</div>';
        }
    } catch (error) {
        console.error('Error loading custom commands:', error);
        customCmdLoadingEl.style.display = 'none';
        customCmdListEl.innerHTML = '<div class="alert alert-danger" role="alert">Error loading custom commands.</div>';
    }
}

function renderCustomCommandsList(commands) {
    customCmdListEl.innerHTML = '';

    if (!commands || commands.length === 0) {
        customCmdEmptyEl.style.display = 'block';
        return;
    }

    customCmdEmptyEl.style.display = 'none';

    commands.forEach(cmd => {
        const item = document.createElement('div');
        item.className = 'list-group-item';

        const row = document.createElement('div');
        row.className = 'cmd-row';

        // Info column
        const info = document.createElement('div');
        info.className = 'cmd-info';

        const name = document.createElement('p');
        name.className = 'cmd-name';
        name.textContent = `!${cmd.name}`;

        const response = document.createElement('p');
        response.className = 'cmd-response';
        response.textContent = cmd.response;

        const meta = document.createElement('div');
        meta.className = 'cmd-meta';

        if (cmd.permission && cmd.permission !== 'everyone') {
            const badge = document.createElement('span');
            badge.className = 'cmd-badge';
            badge.textContent = cmd.permission;
            meta.appendChild(badge);
        }

        if (cmd.cooldownMs && cmd.cooldownMs > 0) {
            const cooldown = document.createElement('span');
            cooldown.className = 'cmd-cooldown';
            cooldown.textContent = t('label.cooldownSeconds', { seconds: cmd.cooldownMs / 1000 }, `${cmd.cooldownMs / 1000}s cooldown`);
            meta.appendChild(cooldown);
        }

        if (cmd.type === 'prompt') {
            const aiBadge = document.createElement('span');
            aiBadge.className = 'cmd-badge';
            aiBadge.style.background = 'var(--bs-purple, #7c3aed)';
            aiBadge.style.color = '#fff';
            aiBadge.textContent = 'AI'; // product term, not translated
            meta.appendChild(aiBadge);
        }

        info.appendChild(name);
        info.appendChild(response);
        if (meta.children.length > 0) info.appendChild(meta);

        // Actions column
        const actions = document.createElement('div');
        actions.className = 'cmd-actions';

        const editBtn = document.createElement('button');
        editBtn.type = 'button';
        editBtn.className = 'btn btn-outline-primary btn-sm';
        editBtn.textContent = t('common.edit', {}, 'Edit');
        editBtn.setAttribute('aria-label', `Edit command !${cmd.name}`);
        editBtn.style.cssText = 'min-height: 28px; min-width: 44px; padding: 4px 10px; display: inline-flex; align-items: center; justify-content: center;';
        editBtn.addEventListener('click', () => openEditForm(cmd));

        const deleteBtn = document.createElement('button');
        deleteBtn.type = 'button';
        deleteBtn.className = 'btn btn-outline-danger btn-sm';
        deleteBtn.textContent = t('common.delete', {}, 'Del');
        deleteBtn.setAttribute('aria-label', `Delete command !${cmd.name}`);
        deleteBtn.style.cssText = 'min-height: 28px; min-width: 44px; padding: 4px 10px; display: inline-flex; align-items: center; justify-content: center;';
        deleteBtn.addEventListener('click', () => deleteCustomCommand(cmd.name));

        actions.appendChild(editBtn);
        actions.appendChild(deleteBtn);

        row.appendChild(info);
        row.appendChild(actions);
        item.appendChild(row);
        customCmdListEl.appendChild(item);
    });
}

function openAddForm() {
    customCmdEditingName = null;
    customCmdNameEl.value = '';
    customCmdNameEl.disabled = false;
    customCmdResponseEl.value = '';
    customCmdPermissionEl.value = 'everyone';
    customCmdCooldownEl.value = '5';
    customCmdTypeToggleEl.checked = false;
    customCmdResponseLabelEl.textContent = t('page.customCommands.responseLabel', {}, 'Response');
    customCmdResponseEl.placeholder = 'Hello $(user), welcome to $(channel)!';
    customCmdFormMsgEl.textContent = '';
    customCmdFormEl.style.display = 'block';
    customCmdNameEl.focus();
}

function openEditForm(cmd) {
    customCmdEditingName = cmd.name;
    customCmdNameEl.value = cmd.name;
    customCmdNameEl.disabled = true;
    customCmdResponseEl.value = cmd.response;
    customCmdPermissionEl.value = cmd.permission || 'everyone';
    customCmdCooldownEl.value = String((cmd.cooldownMs || 5000) / 1000);
    customCmdTypeToggleEl.checked = cmd.type === 'prompt';
    customCmdResponseLabelEl.textContent = cmd.type === 'prompt' ? 'AI Prompt' : 'Response';
    customCmdResponseEl.placeholder = cmd.type === 'prompt'
        ? 'Write a greeting for $(user) in one sentence.'
        : 'Hello $(user), welcome to $(channel)!';
    customCmdFormMsgEl.textContent = '';
    customCmdFormEl.style.display = 'block';
    customCmdResponseEl.focus();
}

function closeForm() {
    customCmdFormEl.style.display = 'none';
    customCmdEditingName = null;
    customCmdFormMsgEl.textContent = '';
}

async function saveCustomCommand() {
    const commandName = customCmdNameEl.value.trim().toLowerCase();
    const response = customCmdResponseEl.value.trim();
    const permission = customCmdPermissionEl.value;
    const cooldownSec = parseInt(customCmdCooldownEl.value, 10);

    if (!commandName) {
        customCmdFormMsgEl.textContent = t('validation.commandNameRequired', {}, 'Command name is required.');
        customCmdFormMsgEl.style.color = 'var(--danger-primary)';
        return;
    }

    if (!response) {
        customCmdFormMsgEl.textContent = t('validation.responseRequired', {}, 'Response text is required.');
        customCmdFormMsgEl.style.color = 'var(--danger-primary)';
        return;
    }

    if (isNaN(cooldownSec) || cooldownSec < 0 || cooldownSec > 300) {
        customCmdFormMsgEl.textContent = t('validation.cooldownRange', {}, 'Cooldown must be between 0 and 300 seconds.');
        customCmdFormMsgEl.style.color = 'var(--danger-primary)';
        return;
    }

    customCmdFormMsgEl.textContent = t('status.saving', {}, 'Saving…');
    customCmdFormMsgEl.style.color = 'var(--text-muted)';
    customCmdSaveBtn.disabled = true;

    if (DEV_MODE) {
        await mockDelay(500);
        customCmdFormMsgEl.textContent = t('toast.commandSavedDev', { name: commandName }, `Command !${commandName} saved (dev mode).`);
        customCmdFormMsgEl.style.color = '#4ecdc4';
        customCmdSaveBtn.disabled = false;
        closeForm();
        loadCustomCommands();
        return;
    }

    try {
        const isEditing = !!customCmdEditingName;
        const body = {
            response,
            permission,
            cooldown: cooldownSec * 1000,
            type: customCmdTypeToggleEl.checked ? 'prompt' : 'text',
        };
        if (!isEditing) body.name = commandName;

        let res;
        if (isEditing) {
            res = await apiPut(`/api/custom-commands/${encodeURIComponent(customCmdEditingName)}`, body);
        } else {
            res = await apiPost('/api/custom-commands', body);
        }

        const data = await res.json();

        if (data.success) {
            closeForm();
            await loadCustomCommands();
        } else {
            customCmdFormMsgEl.textContent = data.message || 'Failed to save command.';
            customCmdFormMsgEl.style.color = 'var(--danger-primary)';
        }
    } catch (error) {
        console.error('Error saving custom command:', error);
        customCmdFormMsgEl.textContent = t('toast.commandSaveFailed', {}, 'Failed to save command.');
        customCmdFormMsgEl.style.color = 'var(--danger-primary)';
    } finally {
        customCmdSaveBtn.disabled = false;
    }
}

async function deleteCustomCommand(name) {
    await deleteItem(`/api/commands/custom/${encodeURIComponent(name)}`, `Command !${name}`, loadCustomCommands);
}
