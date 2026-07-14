const urlParams = new URLSearchParams(window.location.search);
export const DEV_MODE = urlParams.get('dev') === 'true' || localStorage.getItem('dev_mode') === 'true';

if (DEV_MODE) {
    console.log('🔧 DEV MODE ENABLED - Using mock data');
}

export const mockUser = { login: 'test_user', id: '12345', displayName: 'TestUser' };

export const mockCommands = [
    { primaryName: 'help', name: 'help', enabled: true },
    { primaryName: 'chatgpt', name: 'chatgpt', enabled: true },
    { primaryName: 'dalle', name: 'dalle', enabled: true },
    { primaryName: 'joke', name: 'joke', enabled: false },
];

export const mockCustomCommands = [
    { name: 'hello', response: 'Hello $(user), welcome to $(channel)!', permission: 'everyone', cooldownMs: 5000, type: 'text' },
    { name: 'discord', response: 'Join our Discord: https://discord.gg/example', permission: 'everyone', cooldownMs: 30000, type: 'text' },
    { name: 'vibe', response: 'Tell $(user) what kind of vibe their message "$(args)" gives off in one sentence.', permission: 'everyone', cooldownMs: 10000, type: 'prompt' },
];

export const mockTimers = [
    { name: 'discord', response: 'Enjoying the stream? Join the Discord!', type: 'text', intervalMinutes: 30, minChatLines: 5, enabled: true },
    { name: 'hype', response: 'Write a short hype message about the current game that invites chat to share their opinion.', type: 'prompt', intervalMinutes: 20, minChatLines: 10, enabled: false },
];

export const mockAutoChatConfig = {
    mode: 'medium',
    categories: {
        facts: true,
        questions: false,
        ads: true,
        greetings: true,
        follows: true,
        subscriptions: true,
        raids: true,
    }
};

export function mockDelay(ms = 500) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
