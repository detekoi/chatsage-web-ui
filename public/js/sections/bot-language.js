import { apiGet, apiPost, AuthError } from '../api.js';
import { debounce } from '../ui.js';
import { DEV_MODE, mockBotLanguage, mockDelay } from '../dev-mocks.js';
import { t, getLanguage } from '../i18n.js';

// Language names are stored as lowercase English words, the way the bot's `!botlang` stores them.
// The codes are only for display: Intl.DisplayNames turns each one into the language's name in
// whatever language the dashboard is showing, so 25 names never enter the catalogs.
//
// Mirrors LANGUAGE_NAME_TO_CODE in the bot's src/lib/i18n.js. Keep the two in step.
const LANGUAGE_CODES = {
    english: 'en', spanish: 'es', french: 'fr', german: 'de', japanese: 'ja',
    portuguese: 'pt', italian: 'it', russian: 'ru', chinese: 'zh', korean: 'ko',
    dutch: 'nl', polish: 'pl', turkish: 'tr', arabic: 'ar', hindi: 'hi',
    vietnamese: 'vi', thai: 'th', swedish: 'sv', danish: 'da', norwegian: 'no',
    finnish: 'fi', greek: 'el', czech: 'cs', hungarian: 'hu', romanian: 'ro',
};

// The bot ships written translations for these, so their fixed messages post immediately and read
// the same every time. Every other language is translated message by message as the bot sends it.
// Same list as SUPPORTED_LOCALES in the bot's src/lib/i18n.js.
const WRITTEN_TRANSLATIONS = ['english', 'spanish', 'french', 'german', 'italian', 'portuguese', 'japanese', 'russian'];

let loadingEl;
let selectEl;
let helpEl;
let msgEl;

// Held so the select can be rebuilt in a new dashboard language, and so a save can be described
// without re-reading the server.
let state = { mode: 'auto', language: null, detected: null, available: [] };

export function initBotLanguage() {
    loadingEl = document.getElementById('bot-language-loading');
    selectEl = document.getElementById('bot-language-select');
    helpEl = document.getElementById('bot-language-help');
    msgEl = document.getElementById('bot-language-message');

    // Debounced like the other single-control sections: a click through the list should save the
    // language the user stopped on, not every one they passed.
    selectEl.addEventListener('change', debounce(saveBotLanguage, 600));
}

/** A language's name in the dashboard's current language, falling back to the English word. */
function displayName(name) {
    const code = LANGUAGE_CODES[name];
    if (!code) return name;
    try {
        return new Intl.DisplayNames([getLanguage()], { type: 'language' }).of(code) || name;
    } catch {
        return name;
    }
}

function addOption(parent, value, label) {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = label;
    parent.appendChild(option);
}

function addGroup(label) {
    const group = document.createElement('optgroup');
    group.label = label;
    selectEl.appendChild(group);
    return group;
}

/**
 * Rebuilds the list. The options carry language names rather than markup keys, so they are built
 * here rather than in the page — which also means this has to run again after a language change.
 */
function renderOptions() {
    const available = state.available.length ? state.available : Object.keys(LANGUAGE_CODES);
    selectEl.textContent = '';

    addOption(selectEl, 'auto', state.detected
        ? t('page.botLanguage.autoWith', { language: displayName(state.detected) },
            `Automatic (${displayName(state.detected)}, from Twitch)`)
        : t('page.botLanguage.auto', {}, 'Automatic (use my Twitch stream language)'));

    const written = addGroup(t('page.botLanguage.groupWritten', {}, 'Written in advance'));
    const translated = addGroup(t('page.botLanguage.groupTranslated', {}, 'Translated when sent'));

    for (const name of available) {
        addOption(WRITTEN_TRANSLATIONS.includes(name) ? written : translated, name, displayName(name));
    }

    // A moderator can set any language with `!botlang`, including one this list does not offer.
    // Showing it keeps the select honest and stops a save from quietly replacing that choice.
    if (state.mode === 'manual' && state.language && !available.includes(state.language)) {
        addOption(addGroup(t('page.botLanguage.groupInChat', {}, 'Set in chat')), state.language, state.language);
    }

    selectEl.value = state.mode === 'auto' ? 'auto' : (state.language || 'english');
}

/** One line saying what the channel does right now, since "automatic" alone does not say. */
function renderHelp() {
    if (state.mode === 'auto') {
        helpEl.textContent = state.detected
            ? t('page.botLanguage.autoDetected', { language: displayName(state.detected) },
                `Your Twitch stream language is ${displayName(state.detected)}. The bot speaks ${displayName(state.detected)}.`)
            : t('page.botLanguage.autoEnglish', {},
                'Your Twitch stream language is English, or you did not set it. The bot speaks English.');
        return;
    }
    const name = displayName(state.language || 'english');
    helpEl.textContent = t('page.botLanguage.manual', { language: name },
        `The bot speaks ${name}. Your Twitch stream language has no effect.`);
}

function applyBotLanguage(data) {
    if (loadingEl) loadingEl.style.display = 'none';

    if (!data) {
        msgEl.textContent = t('toast.loadBotLanguageFailed', {}, 'Failed to load the bot language setting.');
        msgEl.style.color = '#ff6b6b';
        return;
    }

    state = {
        mode: data.mode === 'manual' ? 'manual' : 'auto',
        language: data.language || null,
        detected: data.detected || null,
        available: Array.isArray(data.available) ? data.available : [],
    };

    renderOptions();
    renderHelp();
    msgEl.textContent = '';
}

export async function loadBotLanguage() {
    if (loadingEl) loadingEl.style.display = 'block';

    if (DEV_MODE) {
        await mockDelay(300);
        applyBotLanguage(mockBotLanguage);
        return;
    }

    try {
        const res = await apiGet('/api/language');
        const data = await res.json();
        applyBotLanguage(data.success ? data : null);
    } catch (e) {
        if (e instanceof AuthError) return;
        console.error('Error fetching bot language:', e);
        applyBotLanguage(null);
    }
}

let saveRequestId = 0;

async function saveBotLanguage() {
    const choice = selectEl.value;
    const payload = choice === 'auto' ? { mode: 'auto' } : { language: choice };
    const requestId = ++saveRequestId;

    msgEl.textContent = t('status.saving', {}, 'Saving…');
    msgEl.style.color = 'var(--text-muted, #6c757d)';

    if (DEV_MODE) {
        await mockDelay(400);
        if (requestId !== saveRequestId) return;
        state = { ...state, mode: choice === 'auto' ? 'auto' : 'manual', language: choice === 'auto' ? null : choice };
        renderHelp();
        msgEl.textContent = t('status.savedDev', { message: t('toast.botLanguageSaved', {}, 'Bot language saved.') },
            'Bot language saved. (dev mode).');
        msgEl.style.color = '#4ecdc4';
        return;
    }

    try {
        const res = await apiPost('/api/language', payload);
        const data = await res.json();
        if (requestId !== saveRequestId) return;

        if (data.success) {
            state = { ...state, mode: data.mode === 'manual' ? 'manual' : 'auto', language: data.language || null };
            renderHelp();
            msgEl.textContent = data.message || t('toast.botLanguageSaved', {}, 'Bot language saved.');
            msgEl.style.color = '#4ecdc4';
        } else {
            // The stored value did not change, so put the control back on it rather than leaving
            // it showing a language the channel is not set to.
            renderOptions();
            msgEl.textContent = data.message || t('toast.saveSettingsFailed', {}, 'Failed to save settings.');
            msgEl.style.color = '#ff6b6b';
        }
    } catch (e) {
        if (e instanceof AuthError) return;
        console.error('Error saving bot language:', e);
        if (requestId !== saveRequestId) return;
        renderOptions();
        msgEl.textContent = t('toast.saveSettingsFailed', {}, 'Failed to save settings.');
        msgEl.style.color = '#ff6b6b';
    }
}
