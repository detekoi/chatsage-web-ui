#!/usr/bin/env node
/**
 * Copies the shared files from the wildcat-design-system checkout into this
 * app, or with --check verifies the copies match and exits 1 if not.
 *
 *   node scripts/sync-design-system.mjs          copy
 *   node scripts/sync-design-system.mjs --check  verify (used by `npm run check`)
 *
 * The source is the sibling checkout ../wildcat-design-system, or the directory
 * in WILDCAT_DESIGN_SYSTEM_DIR. This file is identical in both apps.
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = resolve(process.env.WILDCAT_DESIGN_SYSTEM_DIR || join(root, "..", "wildcat-design-system"));
const stylesDir = existsSync(join(root, "public/styles")) ? "public/styles" : "public/css";
const files = {
  "design-system.css": join(stylesDir, "design-system.css"),
  "css-snapshot.mjs": "scripts/css-snapshot.mjs",
};
const check = process.argv.includes("--check");

if (!existsSync(join(source, "design-system.css"))) {
  if (check && process.env.CI) { console.log("sync-design-system: no source checkout in CI, skipping"); process.exit(0); }
  console.error(`sync-design-system: no checkout at ${source} (clone wildcat-design-system next to this repo, or set WILDCAT_DESIGN_SYSTEM_DIR)`);
  process.exit(2);
}
let drift = 0;
for (const [name, target] of Object.entries(files)) {
  const src = readFileSync(join(source, name), "utf8");
  const dst = join(root, target);
  const cur = existsSync(dst) ? readFileSync(dst, "utf8") : null;
  if (cur === src) { console.log(`ok       ${target}`); continue; }
  if (check) { drift++; console.log(`DRIFT    ${target} differs from wildcat-design-system/${name}; run npm run sync:design-system`); continue; }
  writeFileSync(dst, src); console.log(`synced   ${target} <- wildcat-design-system/${name}`);
}
if (drift) process.exit(1);
