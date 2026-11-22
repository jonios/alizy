import {
  FileCode2,
  LayoutDashboard,
  Network,
  ScrollText,
  Settings,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Split,
  type LucideIcon,
} from "lucide-react";
import { useNav, type Screen } from "../store/nav";
import { useStatus } from "../store/status";
import { useProfiles } from "../store/profiles";
import { cn } from "../lib/utils";
import { useMediaQuery } from "../lib/hooks";
import { STATE_LABEL, STATE_TONE, TONE_BG, TONE_TEXT, isBusyState } from "../lib/constants";
import { Dot } from "./ui/badge";
import { Tooltip } from "./ui/tooltip";
import { LogoMark } from "./Logo";

const NAV: { id: Screen; label: string; icon: LucideIcon }[] = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "configurations", label: "Configurations", icon: FileCode2 },
  { id: "split", label: "Split Tunneling", icon: Split },
  { id: "network", label: "Network", icon: Network },
  { id: "general", label: "Settings", icon: Settings },
  { id: "logs", label: "Logs", icon: ScrollText },
];

/** Below this window width the sidebar collapses to an icon rail. */
const RAIL_QUERY = "(max-width: 959px)";

export function Sidebar() {
  const screen = useNav((s) => s.screen);
  const go = useNav((s) => s.go);
  const profileCount = useProfiles((s) => s.profiles.length);
  const rail = useMediaQuery(RAIL_QUERY);

  return (
    <aside
      className={cn(
        "flex shrink-0 flex-col overflow-hidden whitespace-nowrap border-r border-border bg-sidebar transition-[width] duration-200",
        rail ? "w-16" : "w-[232px]",
      )}
    >
      <div className={cn("flex h-16 items-center gap-2.5", rail ? "justify-center" : "px-5")}>
        <LogoMark className="size-8 shrink-0 drop-shadow-[0_4px_12px_rgb(37_99_235/0.35)]" />
        {!rail && (
          <div className="leading-tight">
            <div className="text-[15px] font-semibold tracking-tight text-fg">Alizy</div>
            <div className="text-[11px] text-faint">WireGuard client</div>
          </div>
        )}
      </div>

      <nav className={cn("flex flex-1 flex-col gap-0.5 pt-2", rail ? "px-2" : "px-3")} aria-label="Main">
        {NAV.map(({ id, label, icon: Icon }) => {
          const active = screen === id;
          const button = (
            <button
              key={id}
              type="button"
              onClick={() => go(id)}
              aria-current={active ? "page" : undefined}
              aria-label={rail ? label : undefined}
              className={cn(
                "group relative flex h-9 items-center gap-3 rounded-lg text-[13px] font-medium transition-colors duration-150",
                "focus-visible:outline-2 focus-visible:outline-ring",
                rail ? "justify-center" : "px-3",
                active ? "bg-surface text-fg shadow-soft" : "text-muted hover:bg-surface/60 hover:text-fg",
              )}
            >
              {active && <span className="absolute top-2 bottom-2 left-0 w-[3px] rounded-r-full bg-primary" aria-hidden />}
              <Icon className={cn("size-[17px] shrink-0", active ? "text-primary" : "text-faint group-hover:text-muted")} />
              {!rail && <span className="flex-1 text-left">{label}</span>}
              {!rail && id === "configurations" && profileCount > 0 && (
                <span className="text-[11px] text-faint tabular">{profileCount}</span>
              )}
            </button>
          );
          return rail ? (
            <Tooltip key={id} content={label} side="right">
              {button}
            </Tooltip>
          ) : (
            button
          );
        })}
      </nav>

      <div className={rail ? "p-2" : "p-3"}>
        <ConnectionPill rail={rail} />
      </div>
    </aside>
  );
}

function ConnectionPill({ rail }: { rail: boolean }) {
  const status = useStatus((s) => s.status);
  const daemonError = useStatus((s) => s.daemonError);
  const received = useStatus((s) => s.received);
  const go = useNav((s) => s.go);

  let label = "Starting…";
  let sub = "Waiting for status";
  let dotCls = "bg-faint";
  let pulse = false;
  let textCls = "text-muted";

  if (received && daemonError) {
    label = "Service unavailable";
    sub = "alizyd not reachable";
    dotCls = "bg-danger";
    textCls = "text-danger";
  } else if (status) {
    const tone = STATE_TONE[status.state];
    label = STATE_LABEL[status.state];
    sub = status.profile_name ?? (status.state === "disconnected" ? "No active profile" : "—");
    dotCls = TONE_BG[tone];
    textCls = TONE_TEXT[tone];
    pulse = isBusyState(status.state) || status.state === "connected";
  } else if (received) {
    label = "No status";
    sub = "Service returned nothing";
  }

  const ks = status?.kill_switch;
  const shield = !ks
    ? null
    : !ks.enabled
      ? { Icon: ShieldOff, cls: "text-faint", tip: "Kill switch off" }
      : ks.firewall_verified
        ? { Icon: ShieldCheck, cls: "text-success", tip: "Kill switch on — verified in the firewall" }
        : { Icon: ShieldAlert, cls: "text-warning", tip: "Kill switch on — NOT verified in the firewall" };

  if (rail) {
    const tip = shield ? `${label} — ${sub}. ${shield.tip}` : `${label} — ${sub}`;
    return (
      <Tooltip content={tip} side="right">
        <button
          type="button"
          onClick={() => go("dashboard")}
          className="flex h-11 w-full items-center justify-center gap-1.5 rounded-xl border border-border bg-surface shadow-soft focus-visible:outline-2 focus-visible:outline-ring"
          aria-label={`Connection: ${label}. Open dashboard`}
        >
          <Dot className={dotCls} pulse={pulse} />
          {shield && <shield.Icon className={cn("size-3.5", shield.cls)} aria-hidden />}
        </button>
      </Tooltip>
    );
  }

  return (
    <div className="flex items-center gap-2 rounded-xl border border-border bg-surface p-2.5 shadow-soft">
      <button
        type="button"
        onClick={() => go("dashboard")}
        className="flex min-w-0 flex-1 items-center gap-2.5 rounded-lg text-left focus-visible:outline-2 focus-visible:outline-ring"
        aria-label={`Connection: ${label}. Open dashboard`}
      >
        <Dot className={dotCls} pulse={pulse} />
        <div className="min-w-0">
          <div className={cn("truncate text-[13px] font-medium", textCls)}>{label}</div>
          <div className="truncate text-[11px] text-faint">{sub}</div>
        </div>
      </button>
      {shield && (
        <Tooltip content={shield.tip} side="top">
          <span
            className={cn("flex size-7 items-center justify-center rounded-lg bg-surface-2", shield.cls)}
            role="img"
            aria-label={shield.tip}
            tabIndex={0}
          >
            <shield.Icon className="size-4" />
          </span>
        </Tooltip>
      )}
    </div>
  );
}
