// public/js/i18n.js
//
// Client-side localization, adapted from wildcat-docs/src/scripts/i18n.js so the two sites behave
// identically: same locale set, same `?lang=` + localStorage + navigator.language resolution, same
// `data-i18n*` attribute vocabulary, same HTML sanitizer allowlist.
//
// Two things differ from the docs version:
//   1. `t(key, params, fallback)` is exported, because roughly a third of this app's strings are
//      produced in JS (toasts, confirm dialogs, rendered rows) rather than sitting in markup.
//   2. Applying translations fires an `i18n:changed` event, so sections that render their own DOM
//      can redraw. Markup-only pages can ignore it.

const AVAILABLE_LANGUAGES = {
    'en': 'English',
    'es': 'Español',
    'fr': 'Français',
    'de': 'Deutsch',
    'it': 'Italiano',
    'pt': 'Português',
    'ja': '日本語',
    'ru': 'Русский'
};

const LANGUAGE_ICONS = {
    'en': 'en', 'es': 'es', 'fr': 'fr', 'de': 'de',
    'it': 'it', 'pt': 'pt', 'ja': '日本', 'ru': 'ру'
};

const DEFAULT_LANGUAGE = 'en';

let currentLanguage = DEFAULT_LANGUAGE;
let translations = {};

// Guards against out-of-order responses when someone clicks through several languages quickly.
// The token is claimed inside loadTranslations() and re-checked once the fetches resolve, because
// that function mutates module state (translations, currentLanguage, localStorage, <html lang>,
// the URL). Checking only in the caller let a slow earlier response overwrite all of that after a
// faster later one had already rendered — leaving the page showing one language and every
// subsequent t() call returning another.
let loadToken = 0;

// Locale code -> merged catalog, for languages already fetched this session.
const catalogCache = new Map();

// --- sanitizer (defense-in-depth for translation values containing inline HTML) ---

const SAFE_TAGS = new Set(['a', 'br', 'code', 'em', 'i', 'small', 'span', 'strong']);
const SAFE_ATTRS = new Set(['href', 'class', 'target', 'rel']);

// Entities are decoded by the time an attribute value is read back, so a payload like
// `java&#x09;script:` arrives carrying a literal control character. Browsers strip those before
// resolving the scheme, so strip them here too and match on the scheme rather than the raw value.
const CONTROL_CHARS = /[\u0000-\u0020\u007f-\u009f]/g;

function sanitizeHTML(html) {
    const template = document.createElement('template');
    template.innerHTML = html;
    sanitizeNode(template.content);
    return template.innerHTML;
}

function sanitizeNode(node) {
    const toRemove = [];
    for (const child of node.childNodes) {
        if (child.nodeType !== Node.ELEMENT_NODE) continue;
        if (!SAFE_TAGS.has(child.tagName.toLowerCase())) {
            toRemove.push(child);
            continue;
        }
        for (const attr of [...child.attributes]) {
            if (!SAFE_ATTRS.has(attr.name.toLowerCase())) child.removeAttribute(attr.name);
        }
        if (child.hasAttribute('href')) {
            const href = child.getAttribute('href').replace(CONTROL_CHARS, '').toLowerCase();
            if (/^(?:javascript|data|vbscript):/.test(href)) child.removeAttribute('href');
        }
        sanitizeNode(child);
    }
    for (const el of toRemove) el.replaceWith(document.createTextNode(el.textContent));
}

// --- catalog loading ---

/**
 * Which page's catalog to load.
 *
 * Read from the document rather than the URL: Firebase Hosting serves 404.html at whatever path
 * was not found, so the URL of a 404 never contains "404". Matching on the path there fell through
 * to the index catalog, which shares the `page.lede` key — so a non-English 404 rendered the
 * sign-in page's text instead of the not-found text.
 */
function getCurrentPageId() {
    // Guarded: this module is also driven from a non-browser harness (scripts/test-i18n-race.mjs).
    const declared = document.documentElement?.getAttribute?.('data-i18n-page');
    if (declared) return declared;

    // Fallback for a page that has not been marked up yet.
    const path = window.location.pathname;
    if (path.includes('dashboard')) return 'dashboard';
    if (path.includes('auth-complete')) return 'auth-complete';
    if (path.includes('auth-error')) return 'auth-error';
    if (path.includes('404')) return '404';
    return 'index';
}

/** Commits a loaded catalog as the active language and syncs the document to it. */
function applyCatalog(merged, lang) {
    translations = merged;
    currentLanguage = lang;

    try {
        localStorage.setItem('preferredLanguage', lang);
    } catch { /* private mode or blocked storage: the choice just will not persist */ }

    document.documentElement.lang = lang;

    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('lang') !== lang) {
        urlParams.set('lang', lang);
        window.history.replaceState({}, '',
            window.location.pathname + '?' + urlParams.toString() + window.location.hash);
    }

    // Only the CJK locales this app actually ships; zh/ko are not in AVAILABLE_LANGUAGES, and
    // initI18n() rewrites anything unrecognized to English before it could reach here.
    document.body.classList.toggle('cjk-language', lang === 'ja');
}

/** Deep merge, so shared `common` branches are not wholesale-replaced by the page catalog. */
function mergeTranslations(base, override) {
    const isPlainObject = v => v !== null && typeof v === 'object' && !Array.isArray(v);
    const out = { ...base };
    for (const [key, value] of Object.entries(override)) {
        out[key] = (isPlainObject(value) && isPlainObject(out[key]))
            ? mergeTranslations(out[key], value)
            : value;
    }
    return out;
}

async function loadTranslations(lang) {
    const token = ++loadToken;
    try {
        const pageId = getCurrentPageId();

        const cached = catalogCache.get(lang);
        if (cached) {
            applyCatalog(cached, lang);
            return true;
        }

        const [commonResponse, pageResponse] = await Promise.all([
            fetch(`./i18n/common-${lang}.json`),
            fetch(`./i18n/${pageId}-${lang}.json`)
        ]);

        if (!pageResponse.ok) throw new Error(`Failed to load translations for ${lang}`);
        const pageTranslations = await pageResponse.json();

        // The common file only carries chrome. If only it is missing the page is still usable,
        // so degrade rather than falling back to English wholesale.
        let commonTranslations = {};
        if (commonResponse.ok) commonTranslations = await commonResponse.json();
        else console.error(`Failed to load shared translations for ${lang}`);

        // A newer selection was made while these fetches were in flight — discard this result
        // rather than clobbering the newer language's state.
        if (token !== loadToken) return false;

        const merged = mergeTranslations(commonTranslations, pageTranslations);
        catalogCache.set(lang, merged);
        applyCatalog(merged, lang);
        return true;
    } catch (error) {
        console.error('Error loading translations:', error);
        // Only fall back if this is still the current request; otherwise a stale failure would
        // yank a newer, successful language back to English.
        if (lang !== DEFAULT_LANGUAGE && token === loadToken) {
            return await loadTranslations(DEFAULT_LANGUAGE);
        }
        return false;
    }
}

// --- lookup ---

function getTranslation(key, defaultValue = null) {
    let result = translations;
    for (const part of String(key).split('.')) {
        if (result && Object.prototype.hasOwnProperty.call(result, part)) result = result[part];
        else return defaultValue;
    }
    return typeof result === 'string' ? result : defaultValue;
}

/**
 * Looks up a string for use in JS, interpolating {placeholders}.
 *
 * Always pass the English text as `fallback` — it is what renders before the catalog loads, on a
 * failed fetch, and for any key not yet present in that locale.
 *
 * @param {string} key Dotted catalog key.
 * @param {object} [params={}] Values for {placeholders}.
 * @param {string} [fallback=''] English text.
 * @returns {string}
 */
export function t(key, params = {}, fallback = '') {
    const template = getTranslation(key, fallback);
    return String(template).replace(/\{(\w+)\}/g, (match, name) =>
        Object.prototype.hasOwnProperty.call(params, name) && params[name] != null
            ? String(params[name])
            : match);
}

/** The active locale code. */
export function getLanguage() {
    return currentLanguage;
}

/** Formats a number in the active locale. */
export function formatNumber(value) {
    try {
        return new Intl.NumberFormat(currentLanguage).format(value);
    } catch {
        return String(value);
    }
}

// --- applying to the DOM ---

function applyToElement(element, translation) {
    if (translation === null) return;
    if (translation.includes('<') && translation.includes('>')) {
        element.innerHTML = sanitizeHTML(translation);
    } else {
        element.textContent = translation;
    }
}

// Attributes must be written with setAttribute, never routed through innerHTML. A hardcoded
// aria-label also outranks translated text for the accessible name, so leaving these in English
// makes the control announce in English no matter the locale.
const TRANSLATED_ATTRIBUTES = {
    'data-i18n-aria-label': 'aria-label',
    'data-i18n-alt': 'alt',
    'data-i18n-title': 'title',
    'data-i18n-placeholder': 'placeholder'
};

export function translatePage() {
    // A container whose own key would overwrite nested keys is skipped, and the nested keys own
    // its content — the same rule as before, but the containers are identified in one ancestor
    // walk instead of a subtree querySelector per element.
    const targets = [...document.querySelectorAll('[data-i18n]')];
    const containers = new Set();
    for (const element of targets) {
        for (let parent = element.parentElement; parent; parent = parent.parentElement) {
            if (parent.hasAttribute('data-i18n')) containers.add(parent);
        }
    }
    for (const element of targets) {
        if (containers.has(element)) continue;
        applyToElement(element, getTranslation(element.getAttribute('data-i18n')));
    }

    Object.entries(TRANSLATED_ATTRIBUTES).forEach(([sourceAttr, targetAttr]) => {
        document.querySelectorAll(`[${sourceAttr}]`).forEach(element => {
            const translation = getTranslation(element.getAttribute(sourceAttr));
            if (translation !== null) element.setAttribute(targetAttr, translation);
        });
    });

    // The visual affordance for a new-tab link is a CSS arrow with no text equivalent, and every
    // pass above rewrites innerHTML, so this re-applies after each translation.
    document.querySelectorAll('a[target="_blank"]').forEach(link => {
        link.setAttribute('rel', 'noopener noreferrer');
        let hint = link.querySelector('.new-tab-hint');
        if (!hint) {
            hint = document.createElement('span');
            hint.className = 'visually-hidden new-tab-hint';
            link.appendChild(hint);
        }
        hint.textContent = ' ' + t('common.opensInNewTab', {}, '(opens in a new tab)');
    });

    const title = getTranslation('meta.title');
    if (title) document.title = title;

    if (typeof lucide !== 'undefined') lucide.createIcons();

    // Sections that build their own DOM redraw on this.
    document.dispatchEvent(new CustomEvent('i18n:changed', { detail: { lang: currentLanguage } }));
}

// --- language selector ---

function createLanguageSelector() {
    if (document.querySelector('.language-selector')) return;

    const selector = document.createElement('div');
    selector.className = 'language-selector';
    // Appended to <body>, outside every other landmark — label it so it stays discoverable.
    selector.setAttribute('role', 'region');

    const currentBtn = document.createElement('button');
    currentBtn.className = 'current-lang';
    currentBtn.type = 'button';
    currentBtn.setAttribute('aria-expanded', 'false');
    currentBtn.setAttribute('aria-haspopup', 'true');
    currentBtn.setAttribute('aria-controls', 'language-grid');
    currentBtn.textContent = LANGUAGE_ICONS[currentLanguage] || currentLanguage;
    selector.appendChild(currentBtn);

    const grid = document.createElement('div');
    grid.className = 'language-grid';
    grid.id = 'language-grid';

    // The whole page rewrites on selection with no other signal, so announce the change.
    const status = document.createElement('div');
    status.className = 'visually-hidden';
    status.setAttribute('role', 'status');
    status.setAttribute('aria-live', 'polite');

    function setOpen(open) {
        selector.classList.toggle('open', open);
        currentBtn.setAttribute('aria-expanded', String(open));
    }

    for (const code of Object.keys(AVAILABLE_LANGUAGES)) {
        const btn = document.createElement('button');
        btn.className = 'grid-item';
        btn.type = 'button';
        btn.dataset.lang = code;
        // The visible label is an abbreviation, sometimes in another script ("ру", "日本"):
        // `lang` gets it pronounced correctly, aria-label announces the full name.
        btn.lang = code;
        btn.setAttribute('aria-label', AVAILABLE_LANGUAGES[code]);
        btn.textContent = LANGUAGE_ICONS[code] || code;
        btn.addEventListener('click', async () => {
            setOpen(false);
            const loaded = await loadTranslations(code);
            // Superseded by a newer selection: that click owns the render, so do nothing here.
            if (!loaded && currentLanguage !== code) return;

            // currentLanguage is what actually got applied — loadTranslations() falls back to
            // English when a catalog cannot be fetched, so report that rather than what was asked.
            const applied = currentLanguage;
            translatePage();
            updateLanguageSelector(applied);
            currentBtn.focus(); // collapsing the grid would otherwise drop focus to <body>
            status.textContent = AVAILABLE_LANGUAGES[applied] || applied;
        });
        grid.appendChild(btn);
    }

    selector.appendChild(grid);
    selector.appendChild(status);

    currentBtn.addEventListener('click', () => setOpen(!selector.classList.contains('open')));
    document.addEventListener('click', e => { if (!selector.contains(e.target)) setOpen(false); });
    selector.addEventListener('keydown', e => {
        if (e.key === 'Escape' && selector.classList.contains('open')) {
            e.stopPropagation();
            setOpen(false);
            currentBtn.focus();
        }
    });

    document.body.appendChild(selector);
}

function updateLanguageSelector(lang) {
    const selector = document.querySelector('.language-selector');
    if (!selector) return;

    const label = t('common.languageSelector', {}, 'Language');
    selector.setAttribute('aria-label', label);

    const currentBtn = selector.querySelector('.current-lang');
    if (currentBtn) {
        currentBtn.textContent = LANGUAGE_ICONS[lang] || lang;
        currentBtn.setAttribute('aria-label', `${label}: ${AVAILABLE_LANGUAGES[lang] || lang}`);
    }

    selector.querySelectorAll('.grid-item').forEach(btn => {
        if (btn.dataset.lang === lang) btn.setAttribute('aria-current', 'true');
        else btn.removeAttribute('aria-current');
    });
}

// --- init ---

/**
 * Resolves the locale and applies it. Resolution order matches wildcat-docs:
 * ?lang= then localStorage then navigator.language then English.
 * @returns {Promise<string>} The locale that was applied.
 */
export async function initI18n() {
    const langParam = new URLSearchParams(window.location.search).get('lang');
    let storedLang = null;
    try {
        storedLang = localStorage.getItem('preferredLanguage');
    } catch { /* blocked storage: fall through to the browser language */ }
    const browserLang = (navigator.language || DEFAULT_LANGUAGE).split('-')[0];

    let targetLang = langParam || storedLang || browserLang || DEFAULT_LANGUAGE;
    if (!Object.prototype.hasOwnProperty.call(AVAILABLE_LANGUAGES, targetLang)) {
        targetLang = DEFAULT_LANGUAGE;
    }

    createLanguageSelector();
    const loaded = await loadTranslations(targetLang);
    if (!loaded && currentLanguage !== targetLang) return currentLanguage;

    const applied = currentLanguage;
    updateLanguageSelector(applied);
    translatePage();
    return applied;
}

// Pages that are pure markup can just include this module. Pages that render DOM in JS set
// data-i18n-manual on <html> and await initI18n() themselves before their first paint.
if (!document.documentElement.hasAttribute('data-i18n-manual')) {
    document.addEventListener('DOMContentLoaded', () => {
        initI18n().catch(error => console.error('Error initializing i18n:', error));
    });
}
