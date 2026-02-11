document.addEventListener('DOMContentLoaded', () => {
    const twitchUsernameEl = document.getElementById('twitch-username');
    const channelNameStatusEl = document.getElementById('channel-name-status');
    const botStatusEl = document.getElementById('bot-status');
    const addBotBtn = document.getElementById('add-bot-btn');
    const removeBotBtn = document.getElementById('remove-bot-btn');
    const actionMessageEl = document.getElementById('action-message');
    const logoutLink = document.getElementById('logout-link');
    const commandsSectionEl = document.getElementById('commands-section');
    const commandsLoadingEl = document.getElementById('commands-loading');
    const commandsListEl = document.getElementById('commands-list');
    const autoSectionEl = document.getElementById('auto-chat-section');
    const autoLoadingEl = document.getElementById('auto-chat-loading');
    const autoModeEl = document.getElementById('auto-mode');
    const autoCatGreetingsEl = document.getElementById('auto-cat-greetings');
    const autoCatFactsEl = document.getElementById('auto-cat-facts');
    const autoCatQuestionsEl = document.getElementById('auto-cat-questions');
    const autoMsgEl = document.getElementById('auto-chat-message');
    const adNotificationsSectionEl = document.getElementById('ad-notifications-section');
    const adNotificationsLoadingEl = document.getElementById('ad-notifications-loading');
    const autoCatAdsEl = document.getElementById('auto-cat-ads');
    const adNotificationsMsgEl = document.getElementById('ad-notifications-message');

    // Custom commands elements
    const customCmdSectionEl = document.getElementById('custom-commands-section');
    const customCmdLoadingEl = document.getElementById('custom-cmd-loading');
    const customCmdListEl = document.getElementById('custom-cmd-list');
    const customCmdEmptyEl = document.getElementById('custom-cmd-empty');
    const customCmdFormEl = document.getElementById('custom-cmd-form');
    const customCmdAddBtn = document.getElementById('custom-cmd-add-btn');
    const customCmdSaveBtn = document.getElementById('custom-cmd-save-btn');
    const customCmdCancelBtn = document.getElementById('custom-cmd-cancel-btn');
    const customCmdNameEl = document.getElementById('custom-cmd-name');
    const customCmdResponseEl = document.getElementById('custom-cmd-response');
    const customCmdPermissionEl = document.getElementById('custom-cmd-permission');
    const customCmdCooldownEl = document.getElementById('custom-cmd-cooldown');
    const customCmdFormMsgEl = document.getElementById('custom-cmd-form-msg');
    let customCmdEditingName = null; // Track whether we're editing an existing command

    // Variable chip click → insert at cursor in response field
    document.querySelector('.variable-chips')?.addEventListener('click', (e) => {
        const chip = e.target.closest('.var-chip');
        if (!chip) return;
        const varText = chip.dataset.var;
        const input = customCmdResponseEl;
        const start = input.selectionStart ?? input.value.length;
        const end = input.selectionEnd ?? input.value.length;
        input.focus();
        input.setRangeText(varText, start, end, 'end');
    });

    // IMPORTANT: Configure this to your deployed Cloud Run Function URL
    const API_BASE_URL = 'https://api.wildcat.chat';
    let appSessionToken = null;
    let loggedInUser = null;

    // DEV MODE: Check for dev mode via URL parameter (?dev=true) or localStorage
    const urlParams = new URLSearchParams(window.location.search);
    const DEV_MODE = urlParams.get('dev') === 'true' || localStorage.getItem('dev_mode') === 'true';

    if (DEV_MODE) {
        console.log('🔧 DEV MODE ENABLED - Using mock data');
    }

    async function initializeDashboard() {
        appSessionToken = localStorage.getItem('app_session_token');
        const userLoginFromStorage = localStorage.getItem('twitch_user_login');
        const userIdFromStorage = localStorage.getItem('twitch_user_id');

        // DEV MODE: Mock user data
        if (DEV_MODE) {
            loggedInUser = { login: 'test_user', id: '12345', displayName: 'TestUser' };
            appSessionToken = 'dev_token';
            localStorage.setItem('twitch_user_login', loggedInUser.login);
            localStorage.setItem('twitch_user_id', loggedInUser.id);
            localStorage.setItem('app_session_token', appSessionToken);
            twitchUsernameEl.textContent = loggedInUser.displayName;
            channelNameStatusEl.textContent = loggedInUser.login;
            updateBotStatusUI(true);
            await Promise.all([loadCommandSettings(), loadAutoChatSettings(), loadAdNotificationsSettings(), loadCustomCommands()]);
            return;
        }

        if (userLoginFromStorage && userIdFromStorage) {
            loggedInUser = { login: userLoginFromStorage, id: userIdFromStorage, displayName: userLoginFromStorage };
            twitchUsernameEl.textContent = loggedInUser.displayName;
            channelNameStatusEl.textContent = loggedInUser.login;
            actionMessageEl.textContent = '';

            if (!appSessionToken) {
                console.warn("No session token found, redirecting to login");
                actionMessageEl.textContent = "Authentication token missing. Please log in again.";
                setTimeout(() => window.location.href = 'index.html', 2000);
                return;
            }

            try {
                console.log("Dashboard: Sending request to /api/bot/status with Authorization header");

                const statusRes = await fetch(`${API_BASE_URL}/api/bot/status`, {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${appSessionToken}`
                    }
                });

                if (!statusRes.ok) {
                    if (statusRes.status === 401) {
                        actionMessageEl.textContent = "Session potentially expired or not fully established. Try logging in again.";
                        return;
                    }
                    const errorData = await statusRes.json().catch(() => ({ message: statusRes.statusText }));
                    throw new Error(`Failed to fetch status: ${errorData.message || statusRes.statusText}`);
                }
                const statusData = await statusRes.json();

                if (statusData.success) {
                    updateBotStatusUI(statusData.isActive);
                    // Load command, auto-chat, and ad notifications settings after bot status is loaded
                    await Promise.all([loadCommandSettings(), loadAutoChatSettings(), loadAdNotificationsSettings(), loadCustomCommands()]);
                } else {
                    actionMessageEl.textContent = `Error: ${statusData.message}`;
                    botStatusEl.textContent = "Error";
                }
            } catch (error) {
                console.error('Error fetching bot status:', error);
                actionMessageEl.textContent = 'Failed to load bot status. ' + error.message;
                botStatusEl.textContent = 'Error';
            }
        } else {
            // Not logged in or info missing, redirect to index.html
            window.location.href = 'index.html';
        }
    }

    function updateBotStatusUI(isActive) {
        if (isActive) {
            botStatusEl.textContent = 'Active';
            botStatusEl.classList.remove('text-danger');
            botStatusEl.classList.add('text-success');
            addBotBtn.style.display = 'none';
            removeBotBtn.style.display = 'inline-block';
            // Show settings sections when bot is active
            commandsSectionEl.style.display = 'block';
            autoSectionEl.style.display = 'block';
            adNotificationsSectionEl.style.display = 'block';
            customCmdSectionEl.style.display = 'block';
        } else {
            botStatusEl.textContent = 'Inactive / Not Joined';
            botStatusEl.classList.remove('text-success');
            botStatusEl.classList.add('text-danger');
            addBotBtn.style.display = 'inline-block';
            removeBotBtn.style.display = 'none';
            // Show settings even when inactive for pre-configuration
            commandsSectionEl.style.display = 'block';
            autoSectionEl.style.display = 'block';
            adNotificationsSectionEl.style.display = 'block';
            customCmdSectionEl.style.display = 'block';
        }
        actionMessageEl.textContent = ''; // Clear previous messages
        actionMessageEl.style.display = 'none';
    }

    async function loadCommandSettings() {
        if (!appSessionToken) return;

        commandsLoadingEl.style.display = 'block';
        commandsListEl.innerHTML = '';

        // DEV MODE: Use mock data
        if (DEV_MODE) {
            setTimeout(() => {
                commandsLoadingEl.style.display = 'none';
                const mockCommands = [
                    { primaryName: 'help', name: 'help', enabled: true },
                    { primaryName: 'chatgpt', name: 'chatgpt', enabled: true },
                    { primaryName: 'dalle', name: 'dalle', enabled: true },
                    { primaryName: 'joke', name: 'joke', enabled: false },
                ];
                renderCommandsList(mockCommands);
            }, 500);
            return;
        }

        try {
            const res = await fetch(`${API_BASE_URL}/api/commands`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${appSessionToken}`
                }
            });

            if (!res.ok) {
                throw new Error(`Failed to fetch commands: ${res.statusText}`);
            }

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

    async function loadAutoChatSettings() {
        if (!appSessionToken) return;

        autoLoadingEl.style.display = 'block';

        // DEV MODE: Use mock data
        if (DEV_MODE) {
            setTimeout(() => {
                autoLoadingEl.style.display = 'none';
                autoModeEl.value = 'medium';
                autoCatGreetingsEl.checked = true;
                autoCatFactsEl.checked = true;
                autoCatQuestionsEl.checked = false;
            }, 500);
            return;
        }

        try {
            const res = await fetch(`${API_BASE_URL}/api/auto-chat`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${appSessionToken}`
                }
            });
            const data = await res.json();
            autoLoadingEl.style.display = 'none';
            if (data.success && data.config) {
                const cfg = data.config;
                autoModeEl.value = cfg.mode || 'off';
                autoCatGreetingsEl.checked = cfg.categories?.greetings !== false;
                autoCatFactsEl.checked = cfg.categories?.facts !== false;
                autoCatQuestionsEl.checked = cfg.categories?.questions !== false;
            } else {
                actionMessageEl.textContent = 'Failed to load auto-chat settings.';
                actionMessageEl.style.color = '#ff6b6b';
            }
        } catch (e) {
            console.error('Error loading auto-chat:', e);
            autoLoadingEl.style.display = 'none';
            actionMessageEl.textContent = 'Error loading auto-chat settings.';
            actionMessageEl.style.color = '#ff6b6b';
        }
    }

    async function loadAdNotificationsSettings() {
        if (!appSessionToken) return;

        adNotificationsLoadingEl.style.display = 'block';

        // DEV MODE: Use mock data
        if (DEV_MODE) {
            setTimeout(() => {
                adNotificationsLoadingEl.style.display = 'none';
                autoCatAdsEl.checked = true;
            }, 500);
            return;
        }

        try {
            const res = await fetch(`${API_BASE_URL}/api/auto-chat`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${appSessionToken}`
                }
            });
            const data = await res.json();
            adNotificationsLoadingEl.style.display = 'none';
            if (data.success && data.config) {
                autoCatAdsEl.checked = data.config.categories?.ads === true;
            } else {
                adNotificationsMsgEl.textContent = 'Failed to load ad notification settings.';
                adNotificationsMsgEl.style.color = '#ff6b6b';
            }
        } catch (e) {
            console.error('Error loading ad notifications:', e);
            adNotificationsLoadingEl.style.display = 'none';
            adNotificationsMsgEl.textContent = 'Error loading ad notification settings.';
            adNotificationsMsgEl.style.color = '#ff6b6b';
        }
    }

    let autoSaveRequestId = 0;
    async function saveAutoChatSettings() {
        if (!appSessionToken) return;

        const currentRequestId = ++autoSaveRequestId;
        autoMsgEl.textContent = 'Saving auto-chat...';

        // DEV MODE: Mock save
        if (DEV_MODE) {
            setTimeout(() => {
                if (currentRequestId === autoSaveRequestId) {
                    autoMsgEl.textContent = 'Auto-chat settings saved (dev mode).';
                    autoMsgEl.style.color = '#4ecdc4';
                }
            }, 500);
            return;
        }

        try {
            const body = {
                mode: autoModeEl.value,
                categories: {
                    greetings: !!autoCatGreetingsEl.checked,
                    facts: !!autoCatFactsEl.checked,
                    questions: !!autoCatQuestionsEl.checked,
                }
            };
            const res = await fetch(`${API_BASE_URL}/api/auto-chat`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${appSessionToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(body)
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
        if (!appSessionToken) return;

        const currentRequestId = ++adNotificationsSaveRequestId;
        adNotificationsMsgEl.textContent = 'Saving ad notifications...';

        // DEV MODE: Mock save
        if (DEV_MODE) {
            setTimeout(() => {
                if (currentRequestId === adNotificationsSaveRequestId) {
                    adNotificationsMsgEl.textContent = 'Ad notification settings saved (dev mode).';
                    adNotificationsMsgEl.style.color = '#4ecdc4';
                }
            }, 500);
            return;
        }

        try {
            const body = {
                categories: {
                    ads: !!autoCatAdsEl.checked,
                }
            };
            const res = await fetch(`${API_BASE_URL}/api/auto-chat`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${appSessionToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(body)
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

    // Debounced auto-save on any change to auto-chat controls
    function debounce(fn, delay) {
        let timerId;
        return (...args) => {
            if (timerId) clearTimeout(timerId);
            timerId = setTimeout(() => fn(...args), delay);
        };
    }
    const debouncedAutoSave = debounce(saveAutoChatSettings, 600);
    [autoModeEl, autoCatGreetingsEl, autoCatFactsEl, autoCatQuestionsEl].forEach(el => {
        el.addEventListener('change', debouncedAutoSave);
    });

    // Debounced auto-save for ad notifications
    const debouncedAdNotificationsSave = debounce(saveAdNotificationsSettings, 600);
    autoCatAdsEl.addEventListener('change', debouncedAdNotificationsSave);
    // No explicit save button; changes are auto-saved

    // ─── Custom Commands ─────────────────────────────────────────────────────

    async function loadCustomCommands() {
        if (!appSessionToken) return;

        customCmdLoadingEl.style.display = 'block';
        customCmdListEl.innerHTML = '';
        customCmdEmptyEl.style.display = 'none';

        // DEV MODE: Use mock data
        if (DEV_MODE) {
            setTimeout(() => {
                customCmdLoadingEl.style.display = 'none';
                const mockCmds = [
                    { name: 'hello', response: 'Hello $(user), welcome to $(channel)!', permission: 'everyone', cooldownMs: 5000 },
                    { name: 'discord', response: 'Join our Discord: https://discord.gg/example', permission: 'everyone', cooldownMs: 30000 },
                    { name: 'rank', response: '$(user) has used this command $(count) times!', permission: 'subscriber', cooldownMs: 10000 },
                ];
                renderCustomCommandsList(mockCmds);
            }, 500);
            return;
        }

        try {
            const res = await fetch(`${API_BASE_URL}/api/custom-commands`, {
                method: 'GET',
                headers: { 'Authorization': `Bearer ${appSessionToken}` }
            });
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
                cooldown.textContent = `${cmd.cooldownMs / 1000}s cooldown`;
                meta.appendChild(cooldown);
            }

            info.appendChild(name);
            info.appendChild(response);
            if (meta.children.length > 0) info.appendChild(meta);

            // Actions column
            const actions = document.createElement('div');
            actions.className = 'cmd-actions';

            const editBtn = document.createElement('button');
            editBtn.className = 'btn btn-outline-primary btn-sm';
            editBtn.textContent = 'Edit';
            editBtn.addEventListener('click', () => openEditForm(cmd));

            const deleteBtn = document.createElement('button');
            deleteBtn.className = 'btn btn-outline-danger btn-sm';
            deleteBtn.textContent = 'Del';
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
        if (!appSessionToken) return;

        const name = customCmdNameEl.value.trim().toLowerCase();
        const response = customCmdResponseEl.value.trim();
        const permission = customCmdPermissionEl.value;
        const cooldownSec = parseInt(customCmdCooldownEl.value, 10);

        if (!name) {
            customCmdFormMsgEl.textContent = 'Command name is required.';
            customCmdFormMsgEl.style.color = 'var(--danger-primary)';
            return;
        }

        if (!response) {
            customCmdFormMsgEl.textContent = 'Response text is required.';
            customCmdFormMsgEl.style.color = 'var(--danger-primary)';
            return;
        }

        customCmdFormMsgEl.textContent = 'Saving...';
        customCmdFormMsgEl.style.color = 'var(--text-muted)';
        customCmdSaveBtn.disabled = true;

        // DEV MODE: Mock save
        if (DEV_MODE) {
            setTimeout(() => {
                customCmdFormMsgEl.textContent = `Command !${name} saved (dev mode).`;
                customCmdFormMsgEl.style.color = '#4ecdc4';
                customCmdSaveBtn.disabled = false;
                closeForm();
                loadCustomCommands();
            }, 500);
            return;
        }

        try {
            const isEditing = !!customCmdEditingName;
            const url = isEditing
                ? `${API_BASE_URL}/api/custom-commands/${encodeURIComponent(customCmdEditingName)}`
                : `${API_BASE_URL}/api/custom-commands`;
            const method = isEditing ? 'PUT' : 'POST';

            const body = {
                response,
                permission,
                cooldown: (isNaN(cooldownSec) ? 5 : cooldownSec) * 1000,
            };
            if (!isEditing) body.name = name;

            const res = await fetch(url, {
                method,
                headers: {
                    'Authorization': `Bearer ${appSessionToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(body)
            });

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
            customCmdFormMsgEl.textContent = 'Error saving command.';
            customCmdFormMsgEl.style.color = 'var(--danger-primary)';
        } finally {
            customCmdSaveBtn.disabled = false;
        }
    }

    async function deleteCustomCommand(name) {
        if (!confirm(`Delete command !${name}?`)) return;
        if (!appSessionToken) return;

        // DEV MODE: Mock delete
        if (DEV_MODE) {
            setTimeout(() => loadCustomCommands(), 300);
            return;
        }

        try {
            const res = await fetch(`${API_BASE_URL}/api/custom-commands/${encodeURIComponent(name)}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${appSessionToken}` }
            });

            const data = await res.json();
            if (data.success) {
                await loadCustomCommands();
            } else {
                actionMessageEl.textContent = data.message || 'Failed to delete command.';
                actionMessageEl.className = 'alert alert-danger';
                actionMessageEl.style.display = 'block';
            }
        } catch (error) {
            console.error('Error deleting custom command:', error);
            actionMessageEl.textContent = 'Error deleting command.';
            actionMessageEl.className = 'alert alert-danger';
            actionMessageEl.style.display = 'block';
        }
    }

    // Wire up form buttons
    customCmdAddBtn.addEventListener('click', openAddForm);
    customCmdSaveBtn.addEventListener('click', saveCustomCommand);
    customCmdCancelBtn.addEventListener('click', closeForm);

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

            // Add disabled message for help command
            if (cmd.primaryName === 'help') {
                const helpText = document.createElement('p');
                helpText.className = 'text-muted mb-0';
                helpText.textContent = 'This command cannot be disabled';
                col.appendChild(helpText);
            }

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

            // Special handling for help command
            if (cmd.primaryName === 'help') {
                checkbox.disabled = true;
            }

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
        if (!appSessionToken) {
            actionMessageEl.textContent = "Authentication token missing. Please log in again.";
            checkboxEl.checked = !enabled;
            return;
        }

        const originalState = checkboxEl.checked;
        checkboxEl.disabled = true; // Disable during request

        // DEV MODE: Mock toggle
        if (DEV_MODE) {
            setTimeout(() => {
                actionMessageEl.textContent = `Command !${commandName} ${enabled ? 'enabled' : 'disabled'} (dev mode).`;
                actionMessageEl.style.color = '#4ecdc4';
                checkboxEl.disabled = false;
            }, 500);
            return;
        }

        try {
            const res = await fetch(`${API_BASE_URL}/api/commands`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${appSessionToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    command: commandName,
                    enabled: enabled
                })
            });

            const data = await res.json();

            if (data.success) {
                actionMessageEl.textContent = `Command !${commandName} ${enabled ? 'enabled' : 'disabled'}.`;
                actionMessageEl.className = 'alert alert-success';
                actionMessageEl.style.display = 'block';
            } else {
                actionMessageEl.textContent = data.message || 'Error updating command settings.';
                actionMessageEl.className = 'alert alert-danger';
                actionMessageEl.style.display = 'block';
                checkboxEl.checked = !enabled; // Revert on error
            }
        } catch (error) {
            console.error('Error toggling command:', error);
            actionMessageEl.textContent = 'Failed to update command settings.';
            actionMessageEl.className = 'alert alert-danger';
            actionMessageEl.style.display = 'block';
            checkboxEl.checked = !enabled; // Revert on error
        } finally {
            checkboxEl.disabled = false; // Re-enable checkbox
        }
    }

    addBotBtn.addEventListener('click', async () => {
        if (!appSessionToken) {
            actionMessageEl.textContent = "Authentication token missing. Please log in again.";
            actionMessageEl.className = 'alert alert-danger';
            actionMessageEl.style.display = 'block';
            return;
        }

        actionMessageEl.textContent = 'Requesting bot to join...';
        actionMessageEl.className = 'alert alert-info';
        actionMessageEl.style.display = 'block';
        try {
            const res = await fetch(`${API_BASE_URL}/api/bot/add`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${appSessionToken}`,
                    'Content-Type': 'application/json'
                }
            });
            const data = await res.json();
            actionMessageEl.textContent = data.message;
            if (data.success) {
                actionMessageEl.className = 'alert alert-success';
                updateBotStatusUI(true);
                await loadCommandSettings();
            } else {
                actionMessageEl.className = 'alert alert-danger';
            }
        } catch (error) {
            console.error('Error adding bot:', error);
            actionMessageEl.textContent = 'Failed to send request to add bot.';
            actionMessageEl.className = 'alert alert-danger';
        }
    });

    removeBotBtn.addEventListener('click', async () => {
        if (!appSessionToken) {
            actionMessageEl.textContent = "Authentication token missing. Please log in again.";
            actionMessageEl.className = 'alert alert-danger';
            actionMessageEl.style.display = 'block';
            return;
        }

        actionMessageEl.textContent = 'Requesting bot to leave...';
        actionMessageEl.className = 'alert alert-info';
        actionMessageEl.style.display = 'block';
        try {
            const res = await fetch(`${API_BASE_URL}/api/bot/remove`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${appSessionToken}`,
                    'Content-Type': 'application/json'
                }
            });
            const data = await res.json();
            actionMessageEl.textContent = data.message;
            if (data.success) {
                actionMessageEl.className = 'alert alert-success';
                updateBotStatusUI(false);
                await loadCommandSettings();
            } else {
                actionMessageEl.className = 'alert alert-danger';
            }
        } catch (error) {
            console.error('Error removing bot:', error);
            actionMessageEl.textContent = 'Failed to send request to remove bot.';
            actionMessageEl.className = 'alert alert-danger';
        }
    });

    logoutLink.addEventListener('click', (e) => {
        e.preventDefault();

        // Clear localStorage
        localStorage.removeItem('twitch_user_login');
        localStorage.removeItem('twitch_user_id');
        localStorage.removeItem('app_session_token');
        appSessionToken = null;

        // Redirect to login
        window.location.href = 'index.html';
    });

    initializeDashboard();
});