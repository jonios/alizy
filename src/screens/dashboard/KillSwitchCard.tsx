import { ShieldAlert, ShieldCheck, ShieldOff } from "lucide-react";
import { Card } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { useStatus } from "../../store/status";
import { useNav } from "../../store/nav";
import { cn } from "../../lib/utils";

export function KillSwitchCard() {
  const ks = useStatus((s) => s.status?.kill_switch ?? null);
  const go = useNav((s) => s.go);

  const view = !ks
    ? { Icon: ShieldOff, tone: "neutral", title: "Unknown", text: "Kill switch status is unavailable while the service is unreachable." }
    : !ks.enabled
      ? { Icon: ShieldOff, tone: "neutral", title: "Off", text: "If the VPN drops, traffic may leave through your normal connection." }
      : ks.firewall_verified
        ? { Icon: ShieldCheck, tone: "success", title: "On · verified", text: "Firewall rules are in place and verified. Non-VPN traffic is blocked." }
        : {
            Icon: ShieldAlert,
            tone: "warning",
            title: "On · NOT verified",
            text: "The kill switch is enabled but its firewall rules could not be verified. Traffic may leak.",
          };

  const toneCls = {
    neutral: "bg-surface-2 text-muted",
    success: "bg-success/12 text-success",
    warning: "bg-warning/12 text-warning",
  }[view.tone as "neutral" | "success" | "warning"];

  return (
    <Card className={cn("p-5", view.tone === "warning" && "border-warning/40")}>
      <div className="flex items-start gap-3">
        <div className={cn("flex size-10 shrink-0 items-center justify-center rounded-xl", toneCls)}>
          <view.Icon className="size-5" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-xs text-muted">Kill switch</div>
          <div className={cn("text-[15px] font-semibold", view.tone === "warning" ? "text-warning" : "text-fg")}>{view.title}</div>
        </div>
      </div>
      <p className="mt-3 text-[13px] leading-relaxed text-muted">{view.text}</p>
      <div className="mt-2 flex items-center justify-between gap-2">
        <span className="truncate font-mono text-[11px] text-faint" title={ks?.firewall_tag ?? undefined}>
          {ks?.firewall_tag ?? ""}
        </span>
        <Button variant="link" size="xs" onClick={() => go("network")}>
          Configure
        </Button>
      </div>
    </Card>
  );
}
