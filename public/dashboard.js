document.addEventListener('DOMContentLoaded', () => {
    const twitchUsernameEl = document.getElementById('twitch-username');
    const channelNameStatusEl = document.getElementById('channel-name-status');
    const botStatusEl = document.getElementById('bot-status');
    const addBotBtn = document.getElementById('add-bot-btn');
    const removeBotBtn = document.getElementById('remove-bot-btn');
    const actionMessageEl = document.getElementById('action-message');
    const logoutLink = document.getElementById('logout-link');

    // IMPORTANT: Configure this to your deployed Cloud Function URL
    const API_BASE_URL = 'https://YOUR_REGION-YOUR_PROJECT_ID.cloudfunctions.net/webUi';

    let loggedInUser = null;

    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
        return null;
    }

    async function initializeDashboard() {
        const userLogin = getCookie('twitch_user_login');
        const userId = getCookie('twitch_user_id');

        if (!userLogin || !userId) {
            console.log("No user cookies found, redirecting to login initiation.");
            // If no user info, they need to log in.
            // You might redirect them to the main page or your auth redirect function.
            // Since this page is dashboard.html, if they land here without cookies,
            // it implies the callback redirect worked but maybe cookies weren't set or read yet.
            // For a robust solution, the callback should set a flag or redirect with a parameter
            // that this page can check.
            // For now, if cookies are missing, we assume they need to go through login.
            // This might cause a loop if cookies are blocked or not setting correctly.
            // window.location.href = `${API_BASE_URL}/auth/twitch/redirect`; // Careful with redirect loops
            twitchUsernameEl.textContent = "Not logged in";
            actionMessageEl.textContent = "Please login to manage the bot.";
            botStatusEl.textContent = "Unknown";
            return;
        }

        loggedInUser = { login: userLogin, id: userId, displayName: userLogin }; // Use login as display name
        twitchUsernameEl.textContent = loggedInUser.displayName;
        channelNameStatusEl.textContent = loggedInUser.login;
        actionMessageEl.textContent = '';

        try {
            const statusRes = await fetch(`${API_BASE_URL}/api/bot/status`, { credentials: 'include' }); // Send cookies

            if (!statusRes.ok) {
                if (statusRes.status === 401) {
                     actionMessageEl.textContent = "Session expired or invalid. Please login again.";
                    // Optionally redirect to login
                    // window.location.href = `${API_BASE_URL}/auth/twitch/redirect`;
                    return;
                }
                throw new Error(`Failed to fetch status: ${statusRes.statusText}`);
            }
            const statusData = await statusRes.json();

            if (statusData.success) {
                updateBotStatusUI(statusData.isActive);
            } else {
                actionMessageEl.textContent = `Error: ${statusData.message}`;
                botStatusEl.textContent = "Error";
            }
        } catch (error) {
            console.error('Error initializing dashboard:', error);
            actionMessageEl.textContent = 'Failed to load dashboard data. Refresh or try logging in again.';
            botStatusEl.textContent = 'Error';
        }
    }

    function updateBotStatusUI(isActive) {
        if (isActive) {
            botStatusEl.textContent = 'Active';
            botStatusEl.className = 'status-active';
            addBotBtn.style.display = 'none';
            removeBotBtn.style.display = 'inline-block';
        } else {
            botStatusEl.textContent = 'Inactive / Not Joined';
            botStatusEl.className = 'status-inactive';
            addBotBtn.style.display = 'inline-block';
            removeBotBtn.style.display = 'none';
        }
        actionMessageEl.textContent = ''; // Clear previous messages
    }

    addBotBtn.addEventListener('click', async () => {
        actionMessageEl.textContent = 'Requesting bot to join...';
        try {
            const res = await fetch(`${API_BASE_URL}/api/bot/add`, { method: 'POST', credentials: 'include' });
            const data = await res.json();
            actionMessageEl.textContent = data.message;
            if (data.success) {
                updateBotStatusUI(true);
            }
        } catch (error) {
            console.error('Error adding bot:', error);
            actionMessageEl.textContent = 'Failed to send request to add bot.';
        }
    });

    removeBotBtn.addEventListener('click', async () => {
        actionMessageEl.textContent = 'Requesting bot to leave...';
        try {
            const res = await fetch(`${API_BASE_URL}/api/bot/remove`, { method: 'POST', credentials: 'include' });
            const data = await res.json();
            actionMessageEl.textContent = data.message;
            if (data.success) {
                updateBotStatusUI(false);
            }
        } catch (error) {
            console.error('Error removing bot:', error);
            actionMessageEl.textContent = 'Failed to send request to remove bot.';
        }
    });

    logoutLink.addEventListener('click', async (e) => {
        e.preventDefault();
        actionMessageEl.textContent = 'Logging out...';
        try {
            // Call the backend logout to clear any server-side session if you implement one.
            // For cookie-based, just redirecting to the function that clears them is enough.
            window.location.href = `${API_BASE_URL}/auth/logout`;
        } catch (error) {
            console.error('Error logging out:', error);
            actionMessageEl.textContent = 'Logout failed.';
        }
    });

    initializeDashboard();
});