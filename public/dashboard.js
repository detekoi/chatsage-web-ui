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

    // IMPORTANT: Configure this to your deployed Cloud Run Function URL
    const API_BASE_URL = 'https://webui-zpqjdsguqa-uc.a.run.app';
    let appSessionToken = null; // Variable to hold the token
    let loggedInUser = null;

    async function initializeDashboard() {
        appSessionToken = localStorage.getItem('app_session_token');
        console.log("Dashboard: Loaded app_session_token from localStorage:", appSessionToken); // Log what's loaded

        const userLoginFromStorage = localStorage.getItem('twitch_user_login');
        const userIdFromStorage = localStorage.getItem('twitch_user_id');

        if (userLoginFromStorage && userIdFromStorage) {
            loggedInUser = { login: userLoginFromStorage, id: userIdFromStorage, displayName: userLoginFromStorage };
            twitchUsernameEl.textContent = loggedInUser.displayName;
            channelNameStatusEl.textContent = loggedInUser.login;
            actionMessageEl.textContent = '';

            if (!appSessionToken) {
                console.warn("No session token found, API calls might fail authentication.");
                actionMessageEl.textContent = "Authentication token missing. Please log in again.";
                // Optionally redirect to login if token is essential
                // window.location.href = 'index.html';
                return;
            }

            try {
                const headers = {};
                if (appSessionToken) {
                    headers['Authorization'] = `Bearer ${appSessionToken}`;
                }
                console.log("Dashboard: Sending headers to /api/bot/status:", JSON.stringify(headers));

                const statusRes = await fetch(`${API_BASE_URL}/api/bot/status`, {
                    method: 'GET',
                    headers: headers
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
                    // Load command settings after bot status is loaded
                    await loadCommandSettings();
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
            // Show commands section when bot is active
            commandsSectionEl.style.display = 'block';
        } else {
            botStatusEl.textContent = 'Inactive / Not Joined';
            botStatusEl.className = 'status-inactive';
            addBotBtn.style.display = 'inline-block';
            removeBotBtn.style.display = 'none';
            // Show commands section even when inactive for pre-configuration
            commandsSectionEl.style.display = 'block';
        }
        actionMessageEl.textContent = ''; // Clear previous messages
    }

    async function loadCommandSettings() {
        if (!appSessionToken) {
            console.warn("No session token available for loading command settings");
            return;
        }

        commandsLoadingEl.style.display = 'block';
        commandsListEl.innerHTML = '';

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
            checkboxEl.checked = !enabled; // Revert checkbox
            return;
        }

        const originalState = checkboxEl.checked;
        checkboxEl.disabled = true; // Disable during request
        
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
        localStorage.removeItem('twitch_user_login');
        localStorage.removeItem('twitch_user_id');
        localStorage.removeItem('app_session_token'); // Clear JWT
        appSessionToken = null; // Clear in-memory token
        // Optionally call a backend /auth/logout endpoint
        window.location.href = 'index.html';
    });

    initializeDashboard();
});