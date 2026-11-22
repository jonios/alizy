// Frontend-only input validation used for hints before the backend checks.

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
  if (!s) return { ok: false, error: "Enter an IP address or CIDR range." };
  const [addr, prefix, ...rest] = s.split("/");
  if (rest.length) return { ok: false, error: "Too many “/” characters." };
  const family = isIPv4(addr) ? 4 : isIPv6(addr) ? 6 : null;
  if (!family) return { ok: false, error: "Not a valid IPv4 or IPv6 address." };
  if (prefix !== undefined) {
    const max = family === 4 ? 32 : 128;
    if (!/^\d{1,3}$/.test(prefix) || Number(prefix) > max) {
      return { ok: false, error: `Prefix length must be 0–${max} for IPv${family}.` };
    }
    if (Number(prefix) === 0) return { ok: false, error: "A /0 rule would cover the whole internet." };
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
  if (!s) return { ok: false, error: "Enter a domain name." };
  if (/^[a-z]+:\/\//.test(s)) return { ok: false, error: "Enter just the host name, without http:// or a path." };
  if (s.includes("/")) return { ok: false, error: "Enter just the host name, without a path." };
  let wildcard = false;
  if (s.startsWith("*.")) {
    wildcard = true;
    s = s.slice(2);
  }
  if (s.includes("*")) return { ok: false, error: "A wildcard is only allowed as the leading “*.” label." };
  if (isIP(s)) return { ok: false, error: "That is an IP address — add it on the IP Addresses tab." };
  const labels = s.split(".");
  if (labels.length < 2) return { ok: false, error: "Use a fully-qualified name such as bank.example.com." };
  if (s.length > 253 || !labels.every((l) => LABEL.test(l))) return { ok: false, error: "Contains invalid characters or empty labels." };
  return { ok: true, domain: s, wildcard };
}
