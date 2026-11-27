#!/usr/bin/env node
// Every string passed to t("…") or tk("…") in src/ must have a Persian entry
// in src/i18n/fa.ts. `--missing` prints them as `"…": "",` lines to paste.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const files = [];
(function walk(d) {
  for (const n of readdirSync(d)) {
    const p = join(d, n);
    if (statSync(p).isDirectory()) walk(p);
    else if (/\.(tsx?|mts)$/.test(n) && !p.includes("/i18n/")) files.push(p);
  }
})(join(root, "src"));

// String literal: "…" with escapes, or `…` without ${}.
const lit = String.raw`"((?:[^"\\]|\\.)*)"|\x60([^\x60$\\]*)\x60`;
const call = new RegExp(String.raw`\bt[k]?\(\s*(?:${lit})`, "g");
const used = new Map();
for (const f of files) {
  const src = readFileSync(f, "utf8");
  for (const m of src.matchAll(call)) {
    const s = m[1] !== undefined ? JSON.parse(`"${m[1]}"`) : m[2];
    if (!used.has(s)) used.set(s, f.slice(root.length));
  }
}

const fa = readFileSync(join(root, "src/i18n/fa.ts"), "utf8");
const keys = new Set();
for (const m of fa.matchAll(/^\s*("(?:[^"\\]|\\.)*")\s*:/gm)) keys.add(JSON.parse(m[1]));

const missing = [...used.keys()].filter((k) => !keys.has(k));
const unused = [...keys].filter((k) => !used.has(k));
if (process.argv.includes("--missing")) {
  for (const k of missing) console.log(`  ${JSON.stringify(k)}: "",  // ${used.get(k)}`);
  process.exit(0);
}
if (unused.length) console.warn(`i18n: ${unused.length} Persian entries are no longer used:\n  ${unused.join("\n  ")}`);
if (missing.length) {
  console.error(`i18n: ${missing.length} strings have no Persian translation (run: node scripts/check-i18n.mjs --missing)`);
  for (const k of missing.slice(0, 20)) console.error(`  ${JSON.stringify(k)}  (${used.get(k)})`);
  process.exit(1);
}
console.log(`i18n: ${used.size} strings, all translated.`);
