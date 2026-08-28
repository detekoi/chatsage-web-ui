#!/usr/bin/env node
// scripts/verify-i18n.mjs
//
// Checks the dashboard catalogs the way the bot's tests/unit/lib/i18n.test.js checks its own:
//
//   1. Every data-i18n* key used in the markup, and every t() key used in JS, exists in English.
//   2. Every locale carries exactly the same key set as English — a partial catalog would render
//      half a page in one language and half in another.
//   3. Translations keep every {placeholder}, $(variable), !command literal and HTML tag, since
//      losing any of those breaks interpolation, variable expansion or markup at runtime.
//
// Usage: node scripts/verify-i18n.mjs

import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const I18N_DIR = join(ROOT, 'public', 'i18n');
const PUBLIC_DIR = join(ROOT, 'public');

const LOCALES = ['en', 'es', 'fr', 'de', 'it', 'pt', 'ja', 'ru'];
const PAGE_OF_FILE = {
    'index.html': 'index',
    'dashboard.html': 'dashboard',
    'auth-complete.html': 'auth-complete',
    'auth-error.html': 'auth-error',
    '404.html': '404',
};

const problems = [];
const fail = msg => problems.push(msg);

const flatten = (obj, prefix = '', out = {}) => {
    for (const [key, value] of Object.entries(obj)) {
        const path = prefix ? `${prefix}.${key}` : key;
        if (value && typeof value === 'object') flatten(value, path, out);
        else out[path] = value;
    }
    return out;
};

const readCatalog = (page, locale) => {
    try {
        return flatten(JSON.parse(readFileSync(join(I18N_DIR, `${page}-${locale}.json`), 'utf8')));
    } catch {
        return null;
    }
};

const placeholders = s => [...String(s).match(/\{\w+\}/g) || [], ...String(s).match(/\$\([^)]*\)/g) || []].sort().join();
const commands = s => (String(s).match(/![a-z]+/g) || []).sort().join();
const tags = s => (String(s).match(/<\/?([a-z]+)[^>]*>/g) || []).map(t => t.toLowerCase()).sort().join();

// --- 1. keys used vs. keys defined ---

const commonEn = readCatalog('common', 'en');
if (!commonEn) fail('common-en.json is missing or unreadable');

const KEY_ATTRS = /data-i18n(?:-aria-label|-alt|-title|-placeholder)?="([\w.]+)"/g;
const T_CALL = /\bt\(\s*['"]([\w.]+)['"]/g;

for (const [file, page] of Object.entries(PAGE_OF_FILE)) {
    const html = readFileSync(join(PUBLIC_DIR, file), 'utf8');
    const pageEn = readCatalog(page, 'en');
    if (!pageEn) { fail(`${page}-en.json is missing or unreadable`); continue; }

    const known = new Set([...Object.keys(pageEn), ...Object.keys(commonEn || {})]);
    const used = new Set([
        ...[...html.matchAll(KEY_ATTRS)].map(m => m[1]),
        ...[...html.matchAll(T_CALL)].map(m => m[1]),
    ]);
    // The dashboard's strings also come from the shared JS modules.
    if (page === 'dashboard') {
        const walk = dir => readdirSync(dir, { withFileTypes: true }).flatMap(e =>
            e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)]);
        for (const js of walk(join(PUBLIC_DIR, 'js'))) {
            if (!js.endsWith('.js') || js.endsWith('i18n.js')) continue;
            for (const m of readFileSync(js, 'utf8').matchAll(T_CALL)) used.add(m[1]);
        }
    }
    for (const key of used) {
        if (!known.has(key)) fail(`${file}: key "${key}" has no entry in ${page}-en.json or common-en.json`);
    }
}

// --- 2 & 3. parity and token preservation across locales ---

const pages = readdirSync(I18N_DIR)
    .filter(f => f.endsWith('-en.json'))
    .map(f => f.slice(0, -'-en.json'.length));

for (const page of pages) {
    const english = readCatalog(page, 'en');
    const englishKeys = Object.keys(english).sort();

    for (const locale of LOCALES.filter(l => l !== 'en')) {
        const catalog = readCatalog(page, locale);
        if (!catalog) { fail(`${page}-${locale}.json is missing or unreadable`); continue; }

        const keys = Object.keys(catalog).sort();
        if (keys.join() !== englishKeys.join()) {
            const missing = englishKeys.filter(k => !(k in catalog));
            const extra = keys.filter(k => !(k in english));
            fail(`${page}-${locale}.json key set differs from English` +
                (missing.length ? ` (missing: ${missing.slice(0, 5).join(', ')})` : '') +
                (extra.length ? ` (extra: ${extra.slice(0, 5).join(', ')})` : ''));
            continue;
        }
        for (const key of englishKeys) {
            const en = english[key], tr = catalog[key];
            if (!String(tr).trim()) fail(`${page}-${locale}.json: "${key}" is empty`);
            if (placeholders(tr) !== placeholders(en)) {
                fail(`${page}-${locale}.json: "${key}" placeholder drift — expected ${placeholders(en) || 'none'}, got ${placeholders(tr) || 'none'}`);
            }
            if (commands(tr) !== commands(en)) {
                fail(`${page}-${locale}.json: "${key}" command literal drift — expected ${commands(en) || 'none'}, got ${commands(tr) || 'none'}`);
            }
            if (tags(tr) !== tags(en)) {
                fail(`${page}-${locale}.json: "${key}" HTML tag drift — expected ${tags(en) || 'none'}, got ${tags(tr) || 'none'}`);
            }
        }
    }
}

if (problems.length) {
    console.error(`i18n verification FAILED with ${problems.length} problem(s):\n`);
    for (const p of problems) console.error('  - ' + p);
    process.exit(1);
}
console.log(`i18n verification passed: ${pages.length} catalogs x ${LOCALES.length} locales.`);
