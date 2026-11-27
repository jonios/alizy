// Frontend-only input validation used for hints before the backend checks.
import { t } from "../i18n";

export function isIPv4(s: string): boolean {
  const parts = s.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255 && (p === "0" || !p.startsWith("0")));
}

export function isIPv6(s: string): boolean {
  if (!/^[0-9a-fA-F:.]+$/.test(s) || !s.includes(":")) return false;
  const dbl = s.split("::");
  if (dbl.length > 2) return false;
  const groups = (x: string) => (x === "" ? [] : x.split(":"));
  let parts = [...groups(dbl[0]), ...(dbl.length === 2 ? groups(dbl[1]) : [])];
  let max = 8;
  const last = parts[parts.length - 1];
  if (last && last.includes(".")) {
    if (!isIPv4(last)) return false;
    parts = parts.slice(0, -1);
    max = 6;
  }
  if (!parts.every((g) => /^[0-9a-fA-F]{1,4}$/.test(g))) return false;
  return dbl.length === 2 ? parts.length < max : parts.length === max;
}

export function isIP(s: string): boolean {
  return isIPv4(s) || isIPv6(s);
}

export type NetCheck = { ok: true; normalized: string; family: 4 | 6 } | { ok: false; error: string };

export function checkNet(input: string): NetCheck {
  const s = input.trim();
  if (!s) return { ok: false, error: t("Enter an IP address or CIDR range.") };
  const [addr, prefix, ...rest] = s.split("/");
  if (rest.length) return { ok: false, error: t("Too many “/” characters.") };
  const family = isIPv4(addr) ? 4 : isIPv6(addr) ? 6 : null;
  if (!family) return { ok: false, error: t("Not a valid IPv4 or IPv6 address.") };
  if (prefix !== undefined) {
    const max = family === 4 ? 32 : 128;
    if (!/^\d{1,3}$/.test(prefix) || Number(prefix) > max) {
      return { ok: false, error: t("Prefix length must be 0–{max} for IPv{family}.", { max, family }) };
    }
    if (Number(prefix) === 0) return { ok: false, error: t("A /0 rule would cover the whole internet.") };
  }
  return { ok: true, normalized: prefix !== undefined ? `${addr.toLowerCase()}/${prefix}` : addr.toLowerCase(), family };
}

export function prefixLen(net: string): number {
  const [addr, p] = net.split("/");
  if (p !== undefined && /^\d+$/.test(p)) return Number(p);
  return addr.includes(":") ? 128 : 32;
}

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

export type DomainCheck = { ok: true; domain: string; wildcard: boolean } | { ok: false; error: string };

export function checkDomain(input: string): DomainCheck {
  let s = input.trim().toLowerCase().replace(/\.$/, "");
  if (!s) return { ok: false, error: t("Enter a domain name.") };
  if (/^[a-z]+:\/\//.test(s)) return { ok: false, error: t("Enter just the host name, without http:// or a path.") };
  if (s.includes("/")) return { ok: false, error: t("Enter just the host name, without a path.") };
  let wildcard = false;
  if (s.startsWith("*.")) {
    wildcard = true;
    s = s.slice(2);
  }
  if (s.includes("*")) return { ok: false, error: t("A wildcard is only allowed as the leading “*.” label.") };
  if (isIP(s)) return { ok: false, error: t("That is an IP address — add it on the IP Addresses tab.") };
  const labels = s.split(".");
  if (labels.length < 2) return { ok: false, error: t("Use a fully-qualified name such as bank.example.com.") };
  if (s.length > 253 || !labels.every((l) => LABEL.test(l))) return { ok: false, error: t("Contains invalid characters or empty labels.") };
  return { ok: true, domain: s, wildcard };
}

// ─── SSH connection form ───

/** Expand an IPv6 literal to eight 16-bit groups, or null if it is not one. */
function ipv6Groups(s: string): number[] | null {
  if (!isIPv6(s)) return null;
  const dbl = s.split("::");
  const side = (x: string): number[] => {
    if (x === "") return [];
    const out: number[] = [];
    for (const g of x.split(":")) {
      if (g.includes(".")) {
        const o = g.split(".").map(Number);
        out.push((o[0] << 8) | o[1], (o[2] << 8) | o[3]);
      } else {
        out.push(parseInt(g, 16));
      }
    }
    return out;
  };
  const head = side(dbl[0]);
  if (dbl.length === 1) return head.length === 8 ? head : null;
  const tail = side(dbl[1]);
  const fill = 8 - head.length - tail.length;
  if (fill < 1) return null;
  return [...head, ...new Array<number>(fill).fill(0), ...tail];
}

/** The IPv4 address inside an IPv4-mapped IPv6 literal (`::ffff:a.b.c.d`), else null. */
export function ipv4FromMapped(raw: string): string | null {
  const g = ipv6Groups(raw.trim());
  if (!g || !g.slice(0, 5).every((x) => x === 0) || g[5] !== 0xffff) return null;
  return [g[6] >> 8, g[6] & 0xff, g[7] >> 8, g[7] & 0xff].join(".");
}

/**
 * Returns an error message for a host that is not an acceptable SSH server literal, else null.
 * IPv4-mapped IPv6 input is accepted and checked as the IPv4 address it carries: the backend
 * stores it in that IPv4 form (core validation rejects the mapped form itself).
 */
export function sshHostError(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed) return t("Enter the server's IP address.");
  const host = ipv4FromMapped(trimmed) ?? trimmed;
  if (isIPv4(host)) {
    const first = Number(host.split(".")[0]);
    if (host === "0.0.0.0") return t("0.0.0.0 is not a valid server address.");
    if (first === 127) return t("Loopback addresses (127.0.0.0/8) are not allowed.");
    if (first >= 224 && first <= 239) return t("Multicast addresses are not allowed.");
    return null;
  }
  const g = ipv6Groups(host);
  if (!g) return t("Enter a valid IPv4 or IPv6 address (host names are not supported).");
  if (g.every((x) => x === 0)) return t(":: is not a valid server address.");
  if (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return t("The loopback address ::1 is not allowed.");
  if ((g[0] & 0xff00) === 0xff00) return t("Multicast addresses are not allowed.");
  return null;
}

export interface SshFields {
  name: string;
  host: string;
  port: string;
  username: string;
  password: string;
}

/** Mirrors the core validation rules. Returns field -> message (empty when valid). */
export function validateSsh(f: SshFields, opts: { editing: boolean }): Partial<Record<keyof SshFields, string>> {
  const errors: Partial<Record<keyof SshFields, string>> = {};
  const name = f.name.trim();
  if (!name) errors.name = t("Enter a name.");
  else if ([...name].length > 64) errors.name = t("Use 64 characters or fewer.");

  const hostErr = sshHostError(f.host);
  if (hostErr) errors.host = hostErr;

  const port = f.port.trim();
  if (!/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535) errors.port = t("Port must be a whole number from 1 to 65535.");

  const u = f.username;
  if (!u) errors.username = t("Enter the username.");
  else if ([...u].length > 64) errors.username = t("Use 64 characters or fewer.");
  else if (/[\s\u0000-\u001f\u007f]/.test(u)) errors.username = t("The username can't contain spaces or control characters.");
  else if (u.startsWith("-")) errors.username = t("The username can't start with “-”.");
  else if (u.includes("@")) errors.username = t("The username can't contain “@”.");

  const p = f.password;
  if (!p) {
    if (!opts.editing) errors.password = t("Enter the password.");
  } else if (/[\u0000\r\n]/.test(p)) {
    errors.password = t("The password can't contain line breaks or NUL characters.");
  } else if (new TextEncoder().encode(p).length > 1024) {
    errors.password = t("The password is too long (1024 bytes at most).");
  }
  return errors;
}
