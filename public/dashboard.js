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
            await Promise.all([loadCommandSettings(), loadAutoChatSettings(), loadAdNotificationsSettings()]);
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
                    await Promise.all([loadCommandSettings(), loadAutoChatSettings(), loadAdNotificationsSettings()]);
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
            botStatusEl.className = 'status-active';
            addBotBtn.style.display = 'none';
            removeBotBtn.style.display = 'inline-block';
            // Show settings sections when bot is active
            commandsSectionEl.style.display = 'block';
            autoSectionEl.style.display = 'block';
            adNotificationsSectionEl.style.display = 'block';
        } else {
            botStatusEl.textContent = 'Inactive / Not Joined';
            botStatusEl.className = 'status-inactive';
            addBotBtn.style.display = 'inline-block';
            removeBotBtn.style.display = 'none';
            // Show settings even when inactive for pre-configuration
            commandsSectionEl.style.display = 'block';
            autoSectionEl.style.display = 'block';
            adNotificationsSectionEl.style.display = 'block';
        }
        actionMessageEl.textContent = ''; // Clear previous messages
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
                commandsListEl.innerHTML = '<p style="color: #ff6b6b;">Failed to load command settings.</p>';
            }
        } catch (error) {
            console.error('Error loading command settings:', error);
            commandsLoadingEl.style.display = 'none';
            commandsListEl.innerHTML = '<p style="color: #ff6b6b;">Error loading command settings.</p>';
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

    function renderCommandsList(commands) {
        commandsListEl.innerHTML = '';
        
        commands.forEach(cmd => {
            const commandDiv = document.createElement('div');
            commandDiv.className = 'command-item';
            
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.id = `cmd-${cmd.primaryName}`;
            checkbox.checked = cmd.enabled;
            checkbox.dataset.command = cmd.primaryName;
            
            // Special handling for help command
            if (cmd.primaryName === 'help') {
                checkbox.disabled = true;
                checkbox.title = 'The help command cannot be disabled';
            }
            
            const label = document.createElement('label');
            label.htmlFor = `cmd-${cmd.primaryName}`;
            label.textContent = `!${cmd.name}`;
            
            if (cmd.primaryName === 'help') {
                label.title = 'The help command cannot be disabled';
            }
            
            checkbox.addEventListener('change', async function() {
                await toggleCommand(cmd.primaryName, this.checked, this);
            });
            
            commandDiv.appendChild(checkbox);
            commandDiv.appendChild(label);
            commandsListEl.appendChild(commandDiv);
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
                actionMessageEl.style.color = '#4ecdc4';
            } else {
                actionMessageEl.textContent = data.message || 'Error updating command settings.';
                actionMessageEl.style.color = '#ff6b6b';
                checkboxEl.checked = !enabled; // Revert on error
            }
        } catch (error) {
            console.error('Error toggling command:', error);
            actionMessageEl.textContent = 'Failed to update command settings.';
            actionMessageEl.style.color = '#ff6b6b';
            checkboxEl.checked = !enabled; // Revert on error
        } finally {
            checkboxEl.disabled = false; // Re-enable checkbox
        }
    }

    addBotBtn.addEventListener('click', async () => {
        if (!appSessionToken) {
            actionMessageEl.textContent = "Authentication token missing. Please log in again.";
            return;
        }
        
        actionMessageEl.textContent = 'Requesting bot to join...';
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
                updateBotStatusUI(true);
                await loadCommandSettings();
            }
        } catch (error) {
            console.error('Error adding bot:', error);
            actionMessageEl.textContent = 'Failed to send request to add bot.';
        }
    });

    removeBotBtn.addEventListener('click', async () => {
        if (!appSessionToken) {
            actionMessageEl.textContent = "Authentication token missing. Please log in again.";
            return;
        }
        
        actionMessageEl.textContent = 'Requesting bot to leave...';
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
                updateBotStatusUI(false);
                await loadCommandSettings();
            }
        } catch (error) {
            console.error('Error removing bot:', error);
            actionMessageEl.textContent = 'Failed to send request to remove bot.';
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