const urlParams = new URLSearchParams(window.location.search);
export const DEV_MODE = urlParams.get('dev') === 'true' || localStorage.getItem('dev_mode') === 'true';

if (DEV_MODE) {
    console.log('🔧 DEV MODE ENABLED - Using mock data');
}

export const mockUser = { login: 'test_user', id: '12345', displayName: 'TestUser' };

// Same order as ALL_COMMANDS in functions/src/config/constants.ts.
export const mockCommands = [
    { primaryName: 'ask', name: 'ask', enabled: true },
    { primaryName: 'search', name: 'search', enabled: true },
    { primaryName: 'game', name: 'game', enabled: true },
    { primaryName: 'translate', name: 'translate', enabled: true },
    { primaryName: 'help', name: 'help', enabled: true },
    { primaryName: 'lurk', name: 'lurk', enabled: true },
    { primaryName: 'geo', name: 'geo', enabled: true },
    { primaryName: 'riddle', name: 'riddle', enabled: true },
    { primaryName: 'trivia', name: 'trivia', enabled: true },
    { primaryName: 'botlang', name: 'botlang', enabled: true },
    { primaryName: 'auto', name: 'auto', enabled: false },
    { primaryName: 'disable', name: 'disable', enabled: true, alwaysOn: true },
    { primaryName: 'enable', name: 'enable', enabled: true, alwaysOn: true },
    { primaryName: 'ping', name: 'ping', enabled: true },
    { primaryName: 'quote', name: 'quote', enabled: true },
    { primaryName: 'command', name: 'command', enabled: true },
    { primaryName: 'followage', name: 'followage', enabled: true },
    { primaryName: 'so', name: 'so', enabled: true, options: { aiMessage: true, twitchShoutout: true } },
    { primaryName: 'timer', name: 'timer', enabled: true },
    { primaryName: 'remember', name: 'remember', enabled: true },
    { primaryName: 'forget', name: 'forget', enabled: true },
    { primaryName: 'forgetme', name: 'forgetme', enabled: true, alwaysOn: true },
    { primaryName: 'memory', name: 'memory', enabled: true },
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

export const mockBotLanguage = {
    mode: 'auto',
    language: null,
    detected: 'spanish',
    available: [
        'english', 'spanish', 'french', 'german', 'italian', 'portuguese', 'japanese', 'russian',
        'chinese', 'korean', 'dutch', 'polish', 'turkish', 'arabic', 'hindi', 'vietnamese',
        'thai', 'swedish', 'danish', 'norwegian', 'finnish', 'greek', 'czech', 'hungarian', 'romanian',
    ],
};

// GET /api/games returns the stored values merged over these defaults.
export const mockGameDefaults = {
    trivia: {
        difficulty: 'normal', questionTimeSeconds: 45, pointsBase: 10,
        pointsTimeBonus: true, pointsDifficultyMultiplier: true, scoreTracking: true, topicPreferences: [],
    },
    geo: {
        difficulty: 'normal', clueIntervalSeconds: 45, roundDurationMinutes: 5, pointsBase: 15,
        pointsTimeBonus: true, pointsDifficultyMultiplier: true, scoreTracking: true,
        regionRestrictions: [], gameTitlePreferences: [],
    },
    riddle: {
        difficulty: 'normal', questionTimeSeconds: 45, pointsBase: 15,
        pointsTimeBonus: true, pointsDifficultyMultiplier: true, scoreTracking: true,
        maxRounds: 10, multiRoundDelayMs: 12000,
    },
};

export const mockGameSettings = {
    trivia: { ...mockGameDefaults.trivia, difficulty: 'hard', topicPreferences: ['Space', 'Pokémon'] },
    geo: { ...mockGameDefaults.geo, regionRestrictions: ['Europe'], gameTitlePreferences: ['Elden Ring'] },
    riddle: { ...mockGameDefaults.riddle, pointsTimeBonus: false },
};

export function mockDelay(ms = 500) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Dev-mode stand-in for POST /api/preview. Echoes the prompt back with the
 * sample variables filled in, so the panel can be exercised without the bot.
 */
export function mockPreview(kind, prompt, args = '') {
    const resolvedPrompt = prompt
        .replace(/\$\(user\)/gi, mockUser.displayName)
        .replace(/\$\(channel\)/gi, mockUser.login)
        .replace(/\$\(args\)/gi, args || 'example')
        .replace(/\$\((count|checkin_count)\)/gi, '1')
        .replace(/\$\(game\)/gi, 'Just Chatting')
        .replace(/\$\(uptime\)/gi, '1h 23m');
    const samples = {
        command: `@${mockUser.displayName} here's a sample AI reply for your command (dev mode).`,
        timer: 'Sample timed message from the AI (dev mode). Chat, what are you playing this weekend?',
        checkin: `Welcome back @${mockUser.displayName}, check-in #1 logged! (dev mode)`,
    };
    return { success: true, preview: { kind, resolvedPrompt, response: samples[kind] || samples.command, language: null } };
}
