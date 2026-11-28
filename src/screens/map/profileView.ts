import type { ProfileSummary } from "../../lib/types";

/** Server address without the port, as shown under a config's country. */
export function serverHost(p: ProfileSummary): string | null {
  if (p.kind === "ssh" && p.ssh) return p.ssh.host;
  const ep = p.endpoint;
  if (!ep) return null;
  const v6 = ep.match(/^\[(.+)\]:\d+$/);
  return v6 ? v6[1] : ep.replace(/:\d+$/, "");
}

export function serverPort(p: ProfileSummary): number | null {
  if (p.kind === "ssh" && p.ssh) return p.ssh.port;
  const m = p.endpoint?.match(/:(\d+)$/);
  return m ? Number(m[1]) : null;
}

export const protocolLabel = (p: ProfileSummary) => (p.kind === "ssh" ? "SSH" : "WireGuard");
