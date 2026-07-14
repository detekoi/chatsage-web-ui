import { apiGet, apiPost, getToken } from '../api.js';
import { showActionToast } from '../ui.js';
import { DEV_MODE, mockCommands, mockDelay } from '../dev-mocks.js';

let commandsLoadingEl;
let commandsListEl;

export function initBuiltInCommands() {
    commandsLoadingEl = document.getElementById('commands-loading');
    commandsListEl = document.getElementById('commands-list');
}

export async function loadCommandSettings() {
    if (!getToken()) return;

    commandsLoadingEl.style.display = 'block';
    commandsListEl.innerHTML = '';

    if (DEV_MODE) {
        await mockDelay(500);
        commandsLoadingEl.style.display = 'none';
        renderCommandsList(mockCommands);
        return;
    }

    try {
        const res = await apiGet('/api/commands');
        const data = await res.json();
        commandsLoadingEl.style.display = 'none';

        if (data.success && data.commands) {
            renderCommandsList(data.commands);
        } else {
            commandsListEl.innerHTML = '<div class="alert alert-danger" role="alert">Failed to load command settings.</div>';
        }
    } catch (error) {
        console.error('Error loading command settings:', error);
        commandsLoadingEl.style.display = 'none';
        commandsListEl.innerHTML = '<div class="alert alert-danger" role="alert">Error loading command settings.</div>';
    }
}

function renderCommandsList(commands) {
    commandsListEl.innerHTML = '';

    commands.forEach(cmd => {
        const commandItem = document.createElement('div');
        commandItem.className = 'list-group-item';

        const row = document.createElement('div');
        row.className = 'row align-items-center';

        const col = document.createElement('div');
        col.className = 'col';

        const label = document.createElement('strong');
        label.textContent = `!${cmd.name}`;
        col.appendChild(label);

        const colAuto = document.createElement('div');
        colAuto.className = 'col-auto';

        const switchDiv = document.createElement('div');
        switchDiv.className = 'form-check form-switch';

        const checkbox = document.createElement('input');
        checkbox.className = 'form-check-input';
        checkbox.type = 'checkbox';
        checkbox.id = `cmd-${cmd.primaryName}`;
        checkbox.checked = cmd.enabled;
        checkbox.dataset.command = cmd.primaryName;
        checkbox.role = 'switch';

        checkbox.addEventListener('change', async function () {
            await toggleCommand(cmd.primaryName, this.checked, this);
        });

        switchDiv.appendChild(checkbox);
        colAuto.appendChild(switchDiv);

        row.appendChild(col);
        row.appendChild(colAuto);
        commandItem.appendChild(row);
        commandsListEl.appendChild(commandItem);
    });
}

async function toggleCommand(commandName, enabled, checkboxEl) {
    if (!getToken()) {
        showActionToast("Authentication token missing. Please log in again.", 'danger');
        checkboxEl.checked = !enabled;
        return;
    }

    checkboxEl.disabled = true; // Disable during request

    if (DEV_MODE) {
        await mockDelay(500);
        showActionToast(`Command !${commandName} ${enabled ? 'enabled' : 'disabled'} (dev mode).`, 'success');
        checkboxEl.disabled = false;
        return;
    }

    try {
        const res = await apiPost('/api/commands', {
            command: commandName,
            enabled: enabled
        });
        const data = await res.json();

        if (data.success) {
            showActionToast(`Command !${commandName} ${enabled ? 'enabled' : 'disabled'}.`, 'success');
        } else {
            showActionToast(data.message || 'Error updating command settings.', 'danger');
            checkboxEl.checked = !enabled; // Revert on error
        }
    } catch (error) {
        console.error('Error toggling command:', error);
        showActionToast('Failed to update command settings.', 'danger');
        checkboxEl.checked = !enabled; // Revert on error
    } finally {
        checkboxEl.disabled = false; // Re-enable checkbox
    }
}
