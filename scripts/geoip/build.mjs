#!/usr/bin/env node
// Converts DB-IP's "IP to Country Lite" CSV into the compact table the app
// embeds (src-tauri/geoip/country.bin.gz). Run before a release:
//
//   node scripts/geoip/build.mjs            # downloads this month's file
//   node scripts/geoip/build.mjs file.csv.gz  # or converts one you have
//
// Data: https://db-ip.com/db/download/ip-to-country-lite (CC BY 4.0).
//
// Layout (gzipped), fixed-width integers little-endian:
//   "AGEO" u8 version=2
//   u16 nCodes, nCodes × 2 ASCII bytes          (index 0 is "ZZ", unknown)
//   u32 n4, n4 × LEB128 start delta, n4 × u8 code index
//   u32 n6, n6 × LEB128 start delta (upper 64 bits of the address), n6 × u8 code index
// Each range runs until the next start. Adjacent ranges with the same
// country are merged, and gaps become "ZZ" ranges. IPv6 keeps only the
// upper 64 bits: no allocation that differs by country is smaller than a /64.
import { createReadStream, existsSync, writeFileSync, mkdirSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { createGunzip, gzipSync } from "node:zlib";
import { createInterface } from "node:readline";
import { dirname, join } from "node:path";

const src = process.argv[2] ?? (await download());
if (!existsSync(src)) {
  console.error(`geoip: no such file: ${src}\nusage: build.mjs [dbip-country-lite-YYYY-MM.csv.gz]  (no argument: download the latest)`);
  process.exit(2);
}

// DB-IP publishes on the 1st of each month; early in a month the new file
// may not be up yet, so fall back to the previous month.
async function download() {
  const d = new Date();
  for (let back = 0; back < 2; back++) {
    const m = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() - back, 1));
    const name = `dbip-country-lite-${m.toISOString().slice(0, 7)}.csv.gz`;
    const url = `https://download.db-ip.com/free/${name}`;
    const res = await fetch(url);
    if (!res.ok) {
      console.warn(`geoip: ${url}: HTTP ${res.status}`);
      continue;
    }
    const file = join(mkdtempSync(join(tmpdir(), "alizy-geoip-")), name);
    writeFileSync(file, Buffer.from(await res.arrayBuffer()));
    console.log(`geoip: downloaded ${url}`);
    return file;
  }
  console.error("geoip: could not download the DB-IP file; pass a downloaded .csv.gz instead");
  process.exit(1);
}
const out = join(new URL("../..", import.meta.url).pathname, "src-tauri/geoip/country.bin.gz");

const codes = ["ZZ"];
const codeIdx = new Map([["ZZ", 0]]);
const idx = (cc) => {
  cc = /^[A-Z]{2}$/.test(cc) ? cc : "ZZ";
  if (!codeIdx.has(cc)) {
    codeIdx.set(cc, codes.length);
    codes.push(cc);
  }
  return codeIdx.get(cc);
};

function v4(s) {
  const p = s.split(".").map(Number);
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}
function v6(s) {
  let [head, tail] = s.split("::");
  const h = head ? head.split(":") : [];
  const t = tail !== undefined ? (tail ? tail.split(":") : []) : [];
  const groups = tail !== undefined ? [...h, ...Array(8 - h.length - t.length).fill("0"), ...t] : h;
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g || "0", 16)), 0n);
}

// [start, end, code] lists, then merged into start-only tables.
const r4 = [];
const r6 = [];
const input = createReadStream(src).pipe(src.endsWith(".gz") ? createGunzip() : new (await import("node:stream")).PassThrough());
for await (const line of createInterface({ input })) {
  const [a, b, cc] = line.split(",");
  if (!cc) continue;
  if (a.includes(":")) r6.push([v6(a) >> 64n, v6(b) >> 64n, idx(cc.trim())]);
  else r4.push([v4(a), v4(b), idx(cc.trim())]);
}

function compact(ranges, zero) {
  ranges.sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0));
  const starts = [];
  const cs = [];
  let next = zero; // first address not yet covered
  const push = (s, c) => {
    if (cs.length && cs[cs.length - 1] === c) return;
    if (starts.length && starts[starts.length - 1] === s) {
      cs[cs.length - 1] = c;
      return;
    }
    starts.push(s);
    cs.push(c);
  };
  for (const [s, e, c] of ranges) {
    if (e < next) continue; // fully inside a range already placed (sub-/64 IPv6 split)
    if (s > next) push(next, 0);
    push(s > next ? s : next, c);
    next = e + (typeof e === "bigint" ? 1n : 1);
  }
  return { starts, cs };
}

const a = compact(r4, 0);
const b = compact(r6, 0n);
// Starts are stored as LEB128 deltas from the previous start, which turns
// ~5.6 MB of fixed-width integers into about a third of that, and the whole
// table is gzipped on top.
const bytes = [];
const u = (n, w) => { for (let i = 0; i < w; i++) bytes.push(Number((BigInt(n) >> BigInt(8 * i)) & 0xffn)); };
const leb = (n) => { n = BigInt(n); do { let b = Number(n & 0x7fn); n >>= 7n; if (n) b |= 0x80; bytes.push(b); } while (n); };
for (const ch of "AGEO") bytes.push(ch.charCodeAt(0));
bytes.push(2);
u(codes.length, 2);
for (const c of codes) bytes.push(c.charCodeAt(0), c.charCodeAt(1));
for (const t of [a, b]) {
  u(t.starts.length, 4);
  let prev = 0n;
  for (const s of t.starts) { leb(BigInt(s) - prev); prev = BigInt(s); }
  for (const c of t.cs) bytes.push(c);
}
const buf = gzipSync(Buffer.from(bytes), { level: 9 });
const size = buf.length;
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, buf);
console.log(`geoip: ${codes.length} countries, ${a.starts.length} IPv4 + ${b.starts.length} IPv6 ranges, ${(size / 1048576).toFixed(2)} MB → ${out}`);
