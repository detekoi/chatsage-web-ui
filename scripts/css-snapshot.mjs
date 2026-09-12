#!/usr/bin/env node
/**
 * Computed-style snapshot harness for the static site in public/.
 *
 * Usage:
 *   node scripts/css-snapshot.mjs --save            write the baseline
 *   node scripts/css-snapshot.mjs --check           diff against it (exit 1 on differences)
 *   node scripts/css-snapshot.mjs --check --page dashboard   one page only
 *
 * For every page in scripts/css-snapshot.config.json, at every width and theme,
 * it serves public/ on a local port, loads the page in headless Chromium,
 * disables transitions, runs the configured clicks, and records
 * getComputedStyle() for a fixed list of properties on every element in <body>.
 * The baseline lives in .css-baseline/ (git-ignored). Workflow: run --save on a
 * clean checkout, make the CSS change, run --check, and expect zero differences
 * unless the change was meant to be visible. When markup changes on purpose,
 * re-save the baseline.
 *
 * This file is identical in chatsage-web-ui and chatvibes-web-ui; the per-repo
 * differences live in the config file next to it.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync, statSync, readdirSync } from 'node:fs';
import { createServer } from 'node:http';
import { join, extname, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';
import { chromium } from 'playwright';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const config = JSON.parse(readFileSync(join(root, 'scripts/css-snapshot.config.json'), 'utf8'));
const args = process.argv.slice(2);
const mode = args.includes('--save') ? 'save' : args.includes('--check') ? 'check' : null;
const onlyPage = args.includes('--page') ? args[args.indexOf('--page') + 1] : null;
if (!mode) {
  console.error('usage: css-snapshot.mjs --save | --check [--page <name>]');
  process.exit(2);
}

const PROPS = [
  'display', 'position', 'color', 'background-color', 'background-image', 'background-position',
  'border-top', 'border-bottom', 'border-left', 'border-right', 'border-radius', 'box-shadow',
  'font-family', 'font-size', 'font-weight', 'text-transform', 'letter-spacing', 'line-height',
  'text-align', 'white-space', 'overflow-wrap', 'margin', 'padding', 'opacity', 'cursor', 'appearance',
  'justify-content', 'align-items', 'flex-direction', 'flex-wrap', 'gap',
  'grid-template-columns', 'grid-area', 'width', 'height', 'min-height', 'min-width',
];

const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.mjs': 'text/javascript',
  '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.woff': 'font/woff', '.mp4': 'video/mp4', '.mp3': 'audio/mpeg',
  '.map': 'application/json', '.txt': 'text/plain',
};

function serve(dir) {
  return new Promise((ok) => {
    const server = createServer((req, res) => {
      let path = decodeURIComponent(new URL(req.url, 'http://x').pathname);
      if (path.endsWith('/')) path += 'index.html';
      const file = join(dir, path);
      if (!file.startsWith(dir) || !existsSync(file) || statSync(file).isDirectory()) {
        res.writeHead(404); res.end('not found'); return;
      }
      res.writeHead(200, { 'content-type': MIME[extname(file)] || 'application/octet-stream', 'cache-control': 'no-store' });
      res.end(readFileSync(file));
    });
    server.listen(0, '127.0.0.1', () => ok({ server, port: server.address().port }));
  });
}

// Runs inside the page. Keyed by a structural path so the same element gets the same key on every run.
function snapshotInPage(props) {
  const path = (el) => {
    const parts = [];
    while (el && el !== document.documentElement) {
      let s = el.tagName.toLowerCase();
      if (el.id) s += '#' + el.id;
      else if (typeof el.className === 'string' && el.className.trim()) s += '.' + el.className.trim().split(/\s+/).join('.');
      const p = el.parentElement;
      if (p) s += ':nth-child(' + ([...p.children].indexOf(el) + 1) + ')';
      parts.unshift(s); el = p;
    }
    return parts.join('>');
  };
  const out = {};
  document.querySelectorAll('body *').forEach((el) => {
    const cs = getComputedStyle(el); const o = {};
    for (const p of props) o[p] = cs.getPropertyValue(p);
    out[path(el)] = o;
  });
  return out;
}

function diff(base, now) {
  const groups = new Map(); let count = 0;
  for (const k of new Set([...Object.keys(base), ...Object.keys(now)])) {
    const a = base[k], b = now[k];
    const tail = k.split('>').slice(-2).join('>').slice(-90);
    if (!a || !b) { count++; add(groups, a ? 'REMOVED element' : 'ADDED element', tail); continue; }
    for (const p of PROPS) if (a[p] !== b[p]) { count++; add(groups, `${p}: ${a[p]} -> ${b[p]}`, tail); }
  }
  return { count, groups };
}
function add(groups, key, ex) {
  const g = groups.get(key) || { n: 0, ex: [] }; g.n++; if (g.ex.length < 3) g.ex.push(ex); groups.set(key, g);
}

async function main() {
  if (config.prepare && mode) {
    console.log(`> ${config.prepare}`);
    execSync(config.prepare, { cwd: root, stdio: 'inherit' });
  }
  const publicDir = resolve(root, config.publicDir || 'public');
  const baselineDir = join(root, config.baselineDir || '.css-baseline');
  mkdirSync(baselineDir, { recursive: true });
  const { server, port } = await serve(publicDir);
  const browser = await chromium.launch();
  let failures = 0, snapshots = 0;
  try {
    for (const page of config.pages) {
      if (onlyPage && page.name !== onlyPage) continue;
      for (const width of config.widths || [1100, 400]) {
        const ctx = await browser.newContext({ viewport: { width, height: config.height || 900 } });
        const tab = await ctx.newPage();
        await tab.goto(`http://127.0.0.1:${port}${page.path}`, { waitUntil: 'networkidle' });
        await tab.waitForTimeout(page.settleMs ?? 1500);
        // Transitions and animations would make snapshots depend on timing.
        await tab.addStyleTag({ content: '*, *::before, *::after { transition: none !important; animation: none !important; }' });
        for (const sel of page.click || []) {
          const el = await tab.$(sel);
          if (el) await el.click({ force: true });
        }
        if (page.click?.length) await tab.waitForTimeout(300);
        for (const theme of config.themes || ['light', 'dark']) {
          const attr = config.themeAttribute || 'data-theme';
          await tab.evaluate(([attr, theme]) => {
            if (theme === 'dark') document.documentElement.setAttribute(attr, 'dark');
            else document.documentElement.removeAttribute(attr);
          }, [attr, theme]);
          await tab.waitForTimeout(150);
          const snap = await tab.evaluate(snapshotInPage, PROPS);
          const key = `${page.name}-${width}-${theme}`;
          const file = join(baselineDir, key + '.json');
          snapshots++;
          if (mode === 'save') {
            writeFileSync(file, JSON.stringify(snap));
            console.log(`saved   ${key} (${Object.keys(snap).length} elements)`);
          } else {
            if (!existsSync(file)) { console.log(`missing ${key}: no baseline, run --save first`); failures++; continue; }
            const base = JSON.parse(readFileSync(file, 'utf8'));
            const { count, groups } = diff(base, snap);
            if (count === 0) { console.log(`ok      ${key}`); continue; }
            failures++;
            console.log(`DIFF    ${key}: ${count} change(s)`);
            for (const [k, g] of [...groups.entries()].sort((x, y) => y[1].n - x[1].n)) {
              console.log(`  ${String(g.n).padStart(4)}  ${k}`);
              for (const ex of g.ex) console.log(`          ${ex}`);
            }
          }
        }
        await ctx.close();
      }
    }
  } finally {
    await browser.close();
    server.close();
  }
  if (mode === 'save') console.log(`\n${snapshots} baseline snapshot(s) written to ${baselineDir}`);
  else if (failures) { console.log(`\n${failures} of ${snapshots} snapshot(s) differ from the baseline.`); process.exit(1); }
  else console.log(`\nAll ${snapshots} snapshot(s) match the baseline.`);
}

main().catch((e) => { console.error(e); process.exit(1); });
