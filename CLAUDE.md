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

- **`design-system.css` is identical to the copy in
  `../chatvibes-web-ui/public/css/design-system.css`**, section 14 included.
  `diff` the two files after any change; a change to the design system is made
  in both repos in the same session. Do not add rules there for markup only
  this app has; put them in `chatsage-specific.css`.
- `!important` is reserved for the utility shim, the `[hidden]` rule, the
  square-corner overrides in `custom.css`, and the colour rules in the shared
  file that must beat a Bootstrap `.text-*` utility in WildcatTTS (the bot
  status readout and the row-description rules, all documented inline). Do not
  add more.
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
lives in `.css-baseline/` and is not committed. The same script exists in
chatvibes-web-ui; keep the two copies identical, only the config differs.

## Conventions

- Commit messages describe the code change only.
- `main` is the primary branch.
