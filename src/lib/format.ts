import type { ProfileSummary } from "./types";

// Formatting helpers. Backend timestamps are unix seconds; toSec() also
// tolerates millisecond values defensively.

export function toSec(ts: number): number {
  return ts > 1e12 ? Math.floor(ts / 1000) : ts;
}

export function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

const UNITS = ["B", "KB", "MB", "GB", "TB", "PB"];

export function formatBytes(n: number | null | undefined, digits = 1): string {
  if (n == null || !Number.isFinite(n) || n < 0) return "—";
  if (n < 1024) return `${Math.round(n)} B`;
  let v = n;
  let i = 0;
  while (v >= 1024 && i < UNITS.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 ? 0 : digits)} ${UNITS[i]}`;
}

export function formatRate(bytesPerSec: number | null | undefined): string {
  if (bytesPerSec == null || !Number.isFinite(bytesPerSec)) return "—";
  return `${formatBytes(Math.max(0, bytesPerSec))}/s`;
}

const pad = (n: number) => String(n).padStart(2, "0");

/** Clock style: 4:05 / 1:02:03 / 2d 03:04:05 */
export function formatClock(totalSec: number): string {
  const s = Math.max(0, Math.floor(totalSec));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const hms = h > 0 || d > 0 ? `${pad(h)}:${pad(m)}:${pad(sec)}` : `${pad(m)}:${pad(sec)}`;
  return d > 0 ? `${d}d ${hms}` : hms;
}

/** Human style: 45s / 12m 3s / 2h 5m / 3d 4h */
export function formatDuration(totalSec: number): string {
  const s = Math.max(0, Math.floor(totalSec));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${m % 60}m`;
  const d = Math.floor(h / 24);
  return `${d}d ${h % 24}h`;
}

export function relativeTime(ts: number | null | undefined, now = nowSec()): string {
  if (!ts) return "never";
  const diff = now - toSec(ts);
  if (diff < -5) return `in ${formatDuration(-diff)}`;
  if (diff < 5) return "just now";
  if (diff < 60) return `${diff} s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)} min ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} h ago`;
  if (diff < 86400 * 30) return `${Math.floor(diff / 86400)} d ago`;
  return formatDate(ts);
}

export function formatDateTime(ts: number | null | undefined): string {
  if (!ts) return "—";
  return new Date(toSec(ts) * 1000).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatDate(ts: number | null | undefined): string {
  if (!ts) return "—";
  return new Date(toSec(ts) * 1000).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

export function formatTime(ts: number | null | undefined): string {
  if (!ts) return "—";
  return new Date(toSec(ts) * 1000).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

/** Abbreviate a base64 key for display: "AbCdEfGh…wxyz=" */
export function shortKey(key: string, head = 8, tail = 5): string {
  if (key.length <= head + tail + 1) return key;
  return `${key.slice(0, head)}…${key.slice(-tail)}`;
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** "user@host:port" for SSH profiles (IPv6 hosts bracketed), else the WireGuard endpoint. */
export function endpointLabel(p: ProfileSummary): string | null {
  if (p.kind === "ssh" && p.ssh) {
    const h = p.ssh.host.includes(":") ? `[${p.ssh.host}]` : p.ssh.host;
    return `${p.ssh.username}@${h}:${p.ssh.port}`;
  }
  return p.endpoint;
}
