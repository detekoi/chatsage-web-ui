# CLAUDE.md

## Project Overview

WildcatSage (ChatSage) bot management web UI. Static site in `public/` (plain
HTML + ES modules, no build step) with an Express app in `functions/` deployed
as a Cloud Function. Sister project: **chatvibes-web-ui** (WildcatTTS), which
shares the same design system and the same Post-Industrial theme.

- `public/*.html` pages: `index`, `dashboard`, `auth-complete`, `auth-error`, `404`
- `public/js/` ES modules; `dashboard.html?dev=true` renders with mock data
  (`js/dev-mocks.js`), no Twitch login needed
- `functions/` Node.js Cloud Function (`npm run build` / `npm run lint` there)

## CSS Architecture (shared with chatvibes-web-ui)

Bootstrap is **not loaded**. The `.btn`, `.card`, `.form-*`, `.row`, `.mb-*`
class names in the markup are Bootstrap naming only; every definition lives in
these files, loaded in this order:

| Layer | File | Role |
|-------|------|------|
| 1 | `public/styles/reset.css` | normalize; loaded first on every page |
| 2 | `public/styles/custom.css` | theme: tokens, Post-Industrial look, component re-theming |
| 3 | `public/styles/design-system.css` | **shared** Wildcat design system: `--wc-*` tokens, `wc-*` components, utility shim (section 14) |
| 4 | `public/styles/chatsage-specific.css` | app layer, dashboard only: Sage-only markup (command rows, persona form, toast) |

Rules:

- **`design-system.css` is a synced copy; its source is the sibling repo
  `../wildcat-design-system`.** Do not edit the copy here. Edit the source,
  then run `npm run sync:design-system` in this repo and in
  `../chatvibes-web-ui` (it also syncs `scripts/css-snapshot.mjs`), and verify
  each with `npm run css:check`. `npm run check` fails while a copy has
  drifted. Rules for markup only this app has go in `chatsage-specific.css`.
- `!important` is reserved for the utility shim, the `[hidden]` rule, the
  square-corner overrides in `custom.css`, and the colour rules in the shared
  file that must beat one of the shim's own `.text-*` or `.fw-*` utilities
  (the bot status readout and the row-description rules, all documented
  inline). Do not add more.
- Visible states are driven by classes and the `hidden` attribute, never by
  inline `style` attributes written from JS.
- Sharp corners are intentional: `custom.css` overrides the design system's
  `--wc-radius-card` on `.card`, `.btn`, `.form-control`, `.form-select`.

### Verifying CSS changes

There is no visual test suite; the check is a computed-style diff run by
`scripts/css-snapshot.mjs` (Playwright, root `package.json`, `npm install` once
and `npx playwright install chromium-headless-shell` on a fresh machine).

```bash
npm run css:baseline   # on a clean checkout, before the change
npm run css:check      # after the change; exit 1 on any difference
```

It serves `public/`, loads every page in `scripts/css-snapshot.config.json` at
1100px and 400px in both themes (the dashboard through `?dev=true` with the
add-forms opened), disables transitions, and records `getComputedStyle` for
every element. Expect zero differences unless the change is meant to be
visible; when markup changes on purpose, re-save the baseline. The baseline
lives in `.css-baseline/` and is not committed. The script is synced from
`../wildcat-design-system` like the stylesheet; only the config is local.

## Conventions

- Commit messages describe the code change only.
- `main` is the primary branch.
- Channel-scoped Firestore documents (timers, custom commands, command
  settings, auto-chat, language, check-in, personas) are keyed by the
  broadcaster's Twitch user ID via `channelDocKey(req.user)` in
  `functions/src/utils/channelKey.ts`, never by login. The login is stored on
  the parent document as `channelName` for readability only. The bot reads the
  same keys (`twitch-knowledge-bot/src/lib/channelKey.js`); change both
  together.
