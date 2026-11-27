import { ShieldAlert, ShieldCheck, ShieldOff, Waypoints } from "lucide-react";
import { Card } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { useStatus } from "../../store/status";
import { useNav } from "../../store/nav";
import { cn } from "../../lib/utils";
import { t } from "../../i18n";

type Tone = "neutral" | "success" | "warning";

/** Kill switch state in tunnel mode; the local proxy's state in proxy mode. */
export function KillSwitchCard() {
  const ks = useStatus((s) => s.status?.kill_switch ?? null);
  const mode = useStatus((s) => s.status?.policy.mode ?? "tunnel");
  const local = useStatus((s) => s.status?.local_proxy ?? null);
  const connected = useStatus((s) => s.status?.state === "connected");
  const go = useNav((s) => s.go);

  const view: { Icon: typeof ShieldOff; tone: Tone; label: string; title: string; text: string; tag: string } =
    mode === "proxy"
      ? {
          Icon: Waypoints,
          tone: local?.error ? "warning" : connected ? "success" : "neutral",
          label: t("Proxy mode"),
          title: local?.error ? t("Not running") : connected ? t("Ready") : t("Waiting for the VPN"),
          text: local?.error
            ? local.error
            : t("Apps set to use the local proxy go through the VPN; everything else connects directly. The kill switch is not used in this mode."),
          tag: local ? `SOCKS5 127.0.0.1:${local.socks_port} · HTTP 127.0.0.1:${local.http_port}` : "",
        }
      : !ks
        ? {
            Icon: ShieldOff,
            tone: "neutral",
            label: t("Kill switch"),
            title: t("Unknown"),
            text: t("Kill switch status is unavailable while the service is unreachable."),
            tag: "",
          }
        : !ks.enabled
          ? {
              Icon: ShieldOff,
              tone: "neutral",
              label: t("Kill switch"),
              title: t("Off"),
              text: t("If the VPN drops, traffic may leave through your normal connection."),
              tag: ks.firewall_tag ?? "",
            }
          : ks.firewall_verified
            ? {
                Icon: ShieldCheck,
                tone: "success",
                label: t("Kill switch"),
                title: t("On · verified"),
                text: t("Firewall rules are in place and verified. Non-VPN traffic is blocked."),
                tag: ks.firewall_tag ?? "",
              }
            : {
                Icon: ShieldAlert,
                tone: "warning",
                label: t("Kill switch"),
                title: t("On · NOT verified"),
                text: t("The kill switch is enabled but its firewall rules could not be verified. Traffic may leak."),
                tag: ks.firewall_tag ?? "",
              };

  const toneCls = {
    neutral: "bg-surface-2 text-muted",
    success: "bg-success/12 text-success",
    warning: "bg-warning/12 text-warning",
  }[view.tone];

  return (
    <Card className={cn("p-5", view.tone === "warning" && "border-warning/40")}>
      <div className="flex items-start gap-3">
        <div className={cn("flex size-10 shrink-0 items-center justify-center rounded-xl", toneCls)}>
          <view.Icon className="size-5" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-xs text-muted">{view.label}</div>
          <div className={cn("text-[15px] font-semibold", view.tone === "warning" ? "text-warning" : "text-fg")}>{view.title}</div>
        </div>
      </div>
      <p className="mt-3 text-[13px] leading-relaxed text-muted">{view.text}</p>
      <div className="mt-2 flex items-center justify-between gap-2">
        <span dir="ltr" className="selectable truncate font-mono text-[11px] text-faint" title={view.tag || undefined}>
          {view.tag}
        </span>
        <Button variant="link" size="xs" onClick={() => go("network")}>
          {t("Configure")}
        </Button>
      </div>
    </Card>
  );
}
