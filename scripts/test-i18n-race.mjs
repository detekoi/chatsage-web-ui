#!/usr/bin/env node
// scripts/test-i18n-race.mjs
//
// Regression test for language-switch ordering in public/js/i18n.js.
//
// loadTranslations() mutates module state: translations, currentLanguage, localStorage,
// <html lang> and the URL. If the request token is only checked by the caller, a slow earlier
// response can overwrite all of that after a faster later one has already rendered — leaving the
// page showing one language while every subsequent t() call returns another.
//
// This drives the real module through its exported initI18n() with two overlapping loads and
// resolves the earlier one last. Run: node scripts/test-i18n-race.mjs

const pending = {};
const catalogs = {
    es: { common: { languageSelector: 'Idioma' }, page: { title: 'Panel' } },
    ja: { common: { languageSelector: '言語' }, page: { title: 'ダッシュボード' } },
};

// --- minimal browser surface ---

globalThis.window = {
    location: { pathname: '/dashboard.html', search: '?lang=es', hash: '' },
    history: {
        replaceState(_a, _b, url) {
            window.location.search = url.includes('?') ? '?' + url.split('?')[1] : '';
        }
    },
};

const stubElement = () => ({
    setAttribute() {}, removeAttribute() {}, appendChild() {}, addEventListener() {}, focus() {},
    classList: { toggle() {}, add() {}, remove() {}, contains: () => false },
    style: {}, dataset: {}, querySelector: () => null, querySelectorAll: () => [],
});

const bodyClasses = new Set();
globalThis.document = {
    documentElement: {
        lang: 'en',
        hasAttribute: () => true,
        // The page id is read from this attribute now (the URL is unreliable: Firebase serves
        // 404.html at whatever path was not found), so the stub has to answer it.
        getAttribute: name => (name === 'data-i18n-page' ? 'dashboard' : null),
    },
    body: {
        classList: { toggle: (c, on) => (on ? bodyClasses.add(c) : bodyClasses.delete(c)) },
        appendChild() {},
    },
    addEventListener() {}, querySelector: () => null, querySelectorAll: () => [],
    createElement: stubElement, dispatchEvent() {}, title: '',
};

const store = {};
globalThis.localStorage = { getItem: k => store[k] ?? null, setItem: (k, v) => { store[k] = v; } };
Object.defineProperty(globalThis, 'navigator', { value: { language: 'en' }, configurable: true });
globalThis.CustomEvent = class { constructor(type, init) { Object.assign(this, { type }, init); } };
globalThis.Node = { ELEMENT_NODE: 1 };

// Every fetch parks until the test releases it, so response order is fully controlled.
globalThis.fetch = (url) => {
    const lang = url.match(/-([a-z]+)\.json$/)[1];
    const which = url.includes('common-') ? 'common' : 'page';
    return new Promise(resolve => {
        (pending[lang] ||= []).push(() =>
            resolve({ ok: true, json: async () => ({ [which]: catalogs[lang][which] }) }));
    });
};

const release = lang => (pending[lang] || []).splice(0).forEach(fn => fn());
const tick = () => new Promise(r => setImmediate(r));

// --- the scenario ---

const i18n = await import('../public/js/i18n.js');

// Selection 1: Spanish. Selection 2: Japanese, made before Spanish has come back.
const spanish = i18n.initI18n();
await tick();
window.location.search = '?lang=ja';
const japanese = i18n.initI18n();
await tick();

release('ja');                     // the later request resolves first and is applied
await japanese;
await tick();
const afterJapanese = {
    lang: document.documentElement.lang,
    stored: store.preferredLanguage,
    title: i18n.t('page.title', {}, 'FALLBACK'),
};

release('es');                     // the earlier request resolves last and must be discarded
await spanish;
await tick();
const afterSpanish = {
    lang: document.documentElement.lang,
    stored: store.preferredLanguage,
    title: i18n.t('page.title', {}, 'FALLBACK'),
};

console.log('after ja resolves:', JSON.stringify(afterJapanese));
console.log('after es resolves:', JSON.stringify(afterSpanish));

const consistent =
    afterSpanish.lang === 'ja' &&
    afterSpanish.stored === 'ja' &&
    afterSpanish.title === catalogs.ja.page.title;

if (consistent) {
    console.log('\nPASS - the stale response did not clobber the applied language.');
    process.exit(0);
}
console.error('\nFAIL - a stale response overwrote state; the DOM and t() now disagree.');
process.exit(1);
