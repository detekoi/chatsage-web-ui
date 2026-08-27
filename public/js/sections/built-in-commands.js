import { apiGet } from '../api.js';
import { DEV_MODE, mockCommands, mockDelay } from '../dev-mocks.js';
import { toggleItem } from '../crud-helpers.js';
import { t } from '../i18n.js';

let commandsLoadingEl;
let commandsListEl;

export function initBuiltInCommands() {
    commandsLoadingEl = document.getElementById('commands-loading');
    commandsListEl = document.getElementById('commands-list');
}

export async function loadCommandSettings() {
    commandsLoadingEl.style.display = 'block';

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
        commandsListEl.innerHTML = '<div class="alert alert-danger" role="alert">Failed to load command settings.</div>';
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

        const label = document.createElement('label');
        label.htmlFor = `cmd-${cmd.primaryName}`;
        label.className = 'form-check-label';
        const strong = document.createElement('strong');
        strong.textContent = `!${cmd.name}`;
        label.appendChild(strong);
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
        checkbox.setAttribute('aria-label', `Enable command !${cmd.name}`);

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
    const payload = { command: commandName, enabled };
    await toggleItem('POST', '/api/commands', payload,
        t('label.commandNamed', { name: commandName }, `Command !${commandName}`), enabled, checkboxEl);
}
