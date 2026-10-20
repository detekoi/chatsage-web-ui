import { apiGet, readJson } from '../api.js';
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
        const data = await readJson(res);
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

// Grouped as docs.wildcat.chat/sage-commands groups them, except that the
// moderator-only commands sit together so the group note covers all of them.
// A command the API adds before this list knows it lands in General.
// Whether a command can be turned off comes from the API (`alwaysOn`).
const COMMAND_GROUPS = [
    { id: 'general', commands: ['ask', 'search', 'game', 'translate', 'help', 'lurk', 'quote', 'followage', 'ping'] },
    { id: 'games', commands: ['geo', 'riddle', 'trivia'] },
    { id: 'memory', commands: ['remember', 'forget', 'forgetme', 'memory'] },
    { id: 'moderators', commands: ['command', 'timer', 'botlang', 'auto', 'disable', 'enable'] },
];

// Literal t() calls, so verify-i18n.mjs sees every key.
function groupTitle(id) {
    switch (id) {
        case 'games': return t('page.commands.groupGames', {}, 'Games');
        case 'memory': return t('page.commands.groupMemory', {}, 'Channel Memory');
        case 'moderators': return t('page.commands.groupModerators', {}, 'Moderator commands');
        default: return t('page.commands.groupGeneral', {}, 'General');
    }
}

function groupNote(id) {
    switch (id) {
        case 'memory': return t('page.commands.memoryNote', {}, 'The bot remembers facts about your community from one stream to the next.');
        case 'moderators': return t('page.commands.moderatorsNote', {}, 'Only moderators and the broadcaster can use these commands.');
        default: return '';
    }
}

function commandDescription(name) {
    switch (name) {
        case 'ask': return t('page.commands.desc.ask', {}, 'Answers a question from a viewer. The bot can search the web to find the answer.');
        case 'search': return t('page.commands.desc.search', {}, 'Searches the web for a topic and posts the result in chat.');
        case 'game': return t('page.commands.desc.game', {}, 'Gives information about the game that you stream. With "analyze", the bot also looks at a recent image of the stream.');
        case 'translate': return t('page.commands.desc.translate', {}, 'Translates the chat messages of a viewer into a different language. Moderators can set this for other viewers.');
        case 'help': return t('page.commands.desc.help', {}, 'Posts a link to the list of bot commands.');
        case 'lurk': return t('page.commands.desc.lurk', {}, 'Tells chat that a viewer is lurking (watching without chatting). The viewer can add a reason.');
        case 'quote': return t('page.commands.desc.quote', {}, 'Shows, adds, and finds quotes for your channel. Moderators can also edit and delete quotes.');
        case 'followage': return t('page.commands.desc.followage', {}, 'Shows how long a viewer has followed your channel.');
        case 'ping': return t('page.commands.desc.ping', {}, 'The bot replies "Pong!" to show that it is in your chat.');
        case 'geo': return t('page.commands.desc.geo', {}, 'Starts a game in which viewers guess a place. The place is real or from the game that you stream.');
        case 'riddle': return t('page.commands.desc.riddle', {}, 'Starts a riddle game about a general topic, the game that you stream, or a subject that you give.');
        case 'trivia': return t('page.commands.desc.trivia', {}, 'Starts a trivia game about a general topic, a topic that you give, or the game that you stream.');
        case 'remember': return t('page.commands.desc.remember', {}, 'Moderators teach the bot a fact to remember.');
        case 'forget': return t('page.commands.desc.forget', {}, 'Moderators delete the memories that contain a phrase.');
        case 'forgetme': return t('page.commands.desc.forgetme', {}, 'Deletes the memories about the viewer who sends it. The bot then stores no new memories about that viewer.');
        case 'memory': return t('page.commands.desc.memory', {}, 'Moderators turn Channel Memory on or off. Channel Memory is on by default.');
        case 'command': return t('page.commands.desc.command', {}, 'Adds, edits, and deletes custom commands from chat. You can also do this in Custom Commands on this page.');
        case 'timer': return t('page.commands.desc.timer', {}, 'Adds, edits, and deletes timed messages from chat. You can also do this in Timed Messages on this page.');
        case 'botlang': return t('page.commands.desc.botlang', {}, 'Sets the language of the bot replies from chat. You can also do this in Bot Language on this page.');
        case 'auto': return t('page.commands.desc.auto', {}, 'Sets how often the bot posts automatic messages, and which types it posts. You can also do this in Auto-Chat Settings on this page.');
        case 'disable': return t('page.commands.desc.disable', {}, 'Turns off a command from chat.');
        case 'enable': return t('page.commands.desc.enable', {}, 'Turns a command back on from chat.');
        default: return '';
    }
}

function renderGroupHead(id) {
    const head = document.createElement('div');
    head.className = 'list-group-item cmd-group-head';

    const title = document.createElement('h3');
    title.className = 'cmd-group-title';
    title.textContent = groupTitle(id);
    head.appendChild(title);

    const note = groupNote(id);
    if (note) {
        const noteEl = document.createElement('p');
        noteEl.className = 'cmd-group-note';
        noteEl.textContent = note;
        head.appendChild(noteEl);
    }
    return head;
}

function renderCommandRow(cmd) {
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

    const alwaysOn = cmd.alwaysOn === true;
    const text = [commandDescription(cmd.primaryName),
        alwaysOn ? t('page.commands.alwaysOn', {}, 'You cannot turn off this command.') : '']
        .filter(Boolean).join(' ');
    let descId = '';
    if (text) {
        descId = `cmd-${cmd.primaryName}-desc`;
        const desc = document.createElement('p');
        desc.className = 'text-muted mb-0';
        desc.id = descId;
        desc.textContent = text;
        col.appendChild(desc);
    }

    const colAuto = document.createElement('div');
    colAuto.className = 'col-auto';

    const switchDiv = document.createElement('div');
    switchDiv.className = 'form-check form-switch';

    const checkbox = document.createElement('input');
    checkbox.className = 'form-check-input';
    checkbox.type = 'checkbox';
    checkbox.id = `cmd-${cmd.primaryName}`;
    checkbox.checked = alwaysOn || cmd.enabled;
    checkbox.disabled = alwaysOn;
    checkbox.dataset.command = cmd.primaryName;
    checkbox.role = 'switch';
    checkbox.setAttribute('aria-label', t('label.enableCommand', { name: cmd.name }, `Enable command !${cmd.name}`));
    if (descId) checkbox.setAttribute('aria-describedby', descId);

    checkbox.addEventListener('change', async function () {
        await toggleCommand(cmd.primaryName, this.checked, this);
    });

    switchDiv.appendChild(checkbox);
    colAuto.appendChild(switchDiv);

    row.appendChild(col);
    row.appendChild(colAuto);
    commandItem.appendChild(row);
    return commandItem;
}

function renderCommandsList(commands) {
    commandsListEl.innerHTML = '';

    const byName = new Map(commands.map(cmd => [cmd.primaryName, cmd]));
    const grouped = new Set(COMMAND_GROUPS.flatMap(group => group.commands));
    const ungrouped = commands.filter(cmd => !grouped.has(cmd.primaryName));

    COMMAND_GROUPS.forEach(group => {
        const rows = group.commands.map(name => byName.get(name)).filter(Boolean);
        if (group.id === 'general') rows.push(...ungrouped);
        if (!rows.length) return;
        commandsListEl.appendChild(renderGroupHead(group.id));
        rows.forEach(cmd => commandsListEl.appendChild(renderCommandRow(cmd)));
    });
}

async function toggleCommand(commandName, enabled, checkboxEl) {
    const payload = { command: commandName, enabled };
    await toggleItem('POST', '/api/commands', payload,
        t('label.commandNamed', { name: commandName }, `Command !${commandName}`), enabled, checkboxEl);
}
