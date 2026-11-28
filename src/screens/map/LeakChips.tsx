import { CircleCheck, CircleSlash, TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";
import { Tooltip } from "../../components/ui/tooltip";
import { cn } from "../../lib/utils";
import { useStatus } from "../../store/status";
import { t } from "../../i18n";

/** IPv4 / IPv6 / DNS: how each traffic family is handled right now. */
export function LeakChips() {
  const status = useStatus((s) => s.status);
  const p = status?.policy;
  const cfg = status?.tunnel_config;
  const up = status?.state === "connected";
  const v6InTunnel = !!cfg?.peers.some((peer) => peer.allowed_ips.some((a) => a.includes(":")));
  const v4InTunnel = !!cfg?.peers.some((peer) => peer.allowed_ips.some((a) => a.includes(".")));
  // Derived from the verified kernel state, never from the policy toggles alone.
  const ksOn = !!status?.kill_switch.enabled;
  const ksVerified = ksOn && !!status?.kill_switch.firewall_verified;

  const family = (enabled: boolean, inTunnel: boolean): [ChipState, string] => {
    if (!enabled) return [status?.kill_switch.firewall_verified ? "blocked" : "warn", t("Disabled: blocked at the OS firewall")];
    if (up && inTunnel) return ["ok", t("Routed through the tunnel")];
    if (ksOn && !ksVerified) return ["warn", t("Kill switch is on but the firewall is not verified")];
    if (up) return ksVerified ? ["blocked", t("Not carried by this profile; blocked by the kill switch")] : ["exposed", t("Not carried by this profile: bypasses the VPN")];
    return ksVerified ? ["blocked", t("VPN not connected; blocked by the kill switch")] : ["exposed", t("VPN not connected: traffic uses your normal connection")];
  };
  const [v4State, v4Detail] = family(!!p?.ipv4_enabled, v4InTunnel);
  const [v6State, v6Detail] = family(!!p?.ipv6_enabled, v6InTunnel);
  const [dnsState, dnsDetail]: [ChipState, string] = up
    ? p?.dns_leak_protection
      ? ["ok", t("DNS can only leave through the tunnel")]
      : ["warn", t("DNS leak protection off: queries may bypass the tunnel")]
    : ksVerified
      ? ["blocked", t("VPN not connected; DNS blocked by the kill switch")]
      : ["exposed", t("VPN not connected: DNS uses your normal resolver")];

  if (!p) return null;
  return (
    <div className="flex gap-1.5">
      <Chip state={v4State} label="IPv4" detail={v4Detail} />
      <Chip state={v6State} label="IPv6" detail={v6Detail} />
      <Chip state={dnsState} label="DNS" detail={dnsDetail} />
    </div>
  );
}

type ChipState = "ok" | "warn" | "blocked" | "exposed";

function Chip({ state, label, detail }: { state: ChipState; label: string; detail: string }) {
  const map: Record<typeof state, { cls: string; icon: ReactNode; word: string }> = {
    ok: { cls: "border-success/25 bg-success/10 text-success", icon: <CircleCheck />, word: t("Protected") },
    warn: { cls: "border-warning/30 bg-warning/10 text-warning", icon: <TriangleAlert />, word: t("Check") },
    blocked: { cls: "border-border bg-surface-3 text-muted", icon: <CircleSlash />, word: t("Blocked") },
    exposed: { cls: "border-danger/30 bg-danger/10 text-danger", icon: <TriangleAlert />, word: t("Exposed") },
  };
  const m = map[state];
  return (
    <Tooltip content={detail}>
      <span
        tabIndex={0}
        className={cn("inline-flex h-6 flex-1 items-center justify-center gap-1 rounded-full border px-2 text-[11px] font-medium [&_svg]:size-3", m.cls)}
        aria-label={`${label}: ${m.word}. ${detail}`}
      >
        {m.icon}
        {label}
      </span>
    </Tooltip>
  );
}
