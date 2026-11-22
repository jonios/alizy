import type { DomainMatch, SplitRule, SplitTarget, Tier } from "../../lib/types";
import { prefixLen } from "../../lib/validate";

export const DEFAULT_PRIORITY = 100;

export const MATCH_LABEL: Record<DomainMatch, string> = {
  exact: "Exact",
  wildcard: "Wildcard",
  parent: "Domain + subdomains",
};

export const MATCH_HELP: Record<DomainMatch, string> = {
  exact: "Only this exact name",
  wildcard: "Subdomains only (*.example.com), not the name itself",
  parent: "The name and all its subdomains",
};

export const TIER_LABEL: Record<Tier, string> = {
  ip: "IP / CIDR",
  exact_domain: "Exact domain",
  wildcard_domain: "Wildcard domain",
  app: "Application",
  default: "Default",
};

export function tierOf(t: SplitTarget): Tier {
  if (t.type === "ip") return "ip";
  if (t.type === "app") return "app";
  return t.mode === "exact" ? "exact_domain" : "wildcard_domain";
}

export function targetText(t: SplitTarget): string {
  if (t.type === "ip") return t.net;
  if (t.type === "app") return t.path;
  if (t.mode === "wildcard") return `*.${t.domain}`;
  return t.domain;
}

export function targetKey(t: SplitTarget): string {
  if (t.type === "ip") return `ip:${t.net.toLowerCase()}`;
  if (t.type === "app") return `app:${t.path}`;
  return `domain:${t.mode}:${t.domain.toLowerCase()}`;
}

const TIER_RANK: Record<Tier, number> = { ip: 0, exact_domain: 1, wildcard_domain: 2, app: 3, default: 4 };

/** Precedence order: IP rules (longest prefix first), exact domains, wildcard/parent domains. */
export function precedenceSort(rules: SplitRule[]): SplitRule[] {
  return [...rules].sort((a, b) => {
    const ta = TIER_RANK[tierOf(a.target)];
    const tb = TIER_RANK[tierOf(b.target)];
    if (ta !== tb) return ta - tb;
    if (a.target.type === "ip" && b.target.type === "ip") {
      const d = prefixLen(b.target.net) - prefixLen(a.target.net);
      if (d) return d;
    }
    if (a.target.type === "domain" && b.target.type === "domain") {
      // more specific (more labels) names first
      const d = b.target.domain.split(".").length - a.target.domain.split(".").length;
      if (a.priority === b.priority && d) return d;
    }
    return a.priority - b.priority || targetText(a.target).localeCompare(targetText(b.target));
  });
}

/** Strip a leading "*." and decide the match mode from user input. */
export function parseDomainInput(raw: string, mode: DomainMatch): { domain: string; mode: DomainMatch } {
  const s = raw.trim().toLowerCase().replace(/\.$/, "");
  if (s.startsWith("*.")) return { domain: s.slice(2), mode: mode === "exact" ? "wildcard" : mode };
  return { domain: s, mode };
}
