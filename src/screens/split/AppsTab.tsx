import { AppWindow, Boxes, CircleCheck, Layers } from "lucide-react";
import { Card } from "../../components/ui/card";
import { Badge } from "../../components/ui/badge";
import type { ReactNode } from "react";
import { useRules } from "./store";

export function AppsTab() {
  const appRules = useRules().filter((r) => r.target.type === "app");
  return (
    <Card className="overflow-hidden">
      <div className="relative px-8 py-10">
        <div className="pointer-events-none absolute -top-20 -right-20 size-64 rounded-full bg-primary/10 blur-3xl" aria-hidden />
        <div className="relative flex max-w-2xl flex-col gap-5">
          <div className="flex items-center gap-3">
            <div className="flex size-12 items-center justify-center rounded-2xl bg-primary/12 text-primary ring-1 ring-primary/20">
              <AppWindow className="size-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-semibold text-fg">Per-application routing</h3>
                <Badge tone="primary">Planned</Badge>
              </div>
              <p className="text-[13px] text-muted">Not available on Linux in this build</p>
            </div>
          </div>
          <p className="text-[13px] leading-relaxed text-muted">
            On Linux, the kernel routes packets by address, not by the program that sent them. Reliable per-app routing requires starting
            each application inside a dedicated control group (cgroup) that the firewall can recognise — and doing that safely needs a
            launcher integration Alizy doesn’t ship yet. Rather than offer controls that might silently leak traffic, app rules are
            disabled here.
          </p>
          <div className="grid gap-3 @xl:grid-cols-3">
            <Point icon={<Layers />} title="How it will work" text="Launch an app through Alizy and it’s placed in a cgroup with its own routing mark." />
            <Point icon={<Boxes />} title="Today’s alternative" text="Use domain or IP rules for the services that app talks to." />
            <Point icon={<CircleCheck />} title="Fails safe" text="Anything not matched by a rule always stays inside the VPN." />
          </div>
          {appRules.length > 0 && (
            <p className="text-xs text-warning">
              Your configuration contains {appRules.length} application rule{appRules.length === 1 ? "" : "s"} (e.g. from an import). They
              are kept but have no effect on this platform.
            </p>
          )}
        </div>
      </div>
    </Card>
  );
}

function Point({ icon, title, text }: { icon: ReactNode; title: string; text: string }) {
  return (
    <div className="rounded-xl border border-border bg-surface-2/50 p-3.5">
      <div className="flex items-center gap-2 text-[13px] font-medium text-fg [&_svg]:size-4 [&_svg]:text-primary">
        {icon}
        {title}
      </div>
      <p className="mt-1 text-xs leading-relaxed text-muted">{text}</p>
    </div>
  );
}
