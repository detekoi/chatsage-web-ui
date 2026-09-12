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

- **`design-system.css` is meant to converge with the copy in
  `../chatvibes-web-ui/public/css/design-system.css`** and eventually be one
  shared file. Do not add rules there for markup only this app has; put them in
  `chatsage-specific.css`, which loads after it. Fixes to the design system are
  made in both repos. Known differences today: this copy carries section 14
  (the utility shim) and the fixes that went with dropping Bootstrap, the
  chatvibes copy carries the RTL logical-property work, and the
  `.form-check.form-switch` row selector differs (see the comment in the file).
- `!important` is reserved for the utility shim, the `[hidden]` rule, and the
  square-corner overrides in `custom.css` (documented inline). Do not add more.
- Visible states are driven by classes and the `hidden` attribute, never by
  inline `style` attributes written from JS.
- Sharp corners are intentional: `custom.css` overrides the design system's
  `--wc-radius-card` on `.card`, `.btn`, `.form-control`, `.form-select`.

### Verifying CSS changes

There is no visual test suite. The reliable check is a computed-style diff in
the browser: snapshot `getComputedStyle` for every element on `index.html` and
`dashboard.html?dev=true` (light and dark, 1100px and 400px) before the change,
repeat after, and expect zero differences unless a change is intended. Serve
`public/` with any static server (`python3 -m http.server --directory public`).
Browsers cache the module scripts and stylesheets aggressively; fetch each
changed file with `cache: 'reload'` before re-navigating.

## Conventions

- Commit messages describe the code change only.
- `main` is the primary branch.
