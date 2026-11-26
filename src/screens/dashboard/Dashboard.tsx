import { ChevronDown, CircleAlert, FileCode2, Star } from "lucide-react";
import { useMemo, useState } from "react";
import { ScreenBody, ScreenHeader } from "../../components/ScreenHeader";
import { Alert } from "../../components/ui/alert";
import { Card } from "../../components/ui/card";
import { Skeleton } from "../../components/ui/skeleton";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuTrigger,
} from "../../components/ui/dropdown-menu";
import { STATE_DESCRIPTION, STATE_LABEL, STATE_TONE, TONE_TEXT } from "../../lib/constants";
import { formatClock } from "../../lib/format";
import { useNow } from "../../lib/hooks";
import type { ConnectionState } from "../../lib/types";
import { cn } from "../../lib/utils";
import { useProfiles } from "../../store/profiles";
import { useSettings } from "../../store/settings";
import { useStatus } from "../../store/status";
import { useNav } from "../../store/nav";
import { ConnectControl } from "./ConnectControl";
import { DaemonBanner } from "./DaemonBanner";
import { KillSwitchCard } from "./KillSwitchCard";
import { LeakCard } from "./LeakCard";
import { PublicIpCard } from "./PublicIpCard";
import { QuickSwitcher, quickOrder } from "./QuickSwitcher";
import { TrafficCard } from "./TrafficCard";
import { TunnelCard } from "./TunnelCard";

export function Dashboard() {
  const { status, daemonError, received, pending, connect, disconnect } = useStatus();
  const profiles = useProfiles((s) => s.profiles);
  const settings = useSettings((s) => s.settings);
  const appVersion = useSettings((s) => s.appInfo?.version ?? null);
  const go = useNav((s) => s.go);
  const [chosen, setChosen] = useState<string | null>(null);

  const state: ConnectionState = status?.state ?? "disconnected";
  const engaged = state === "connected" || state === "connecting" || state === "reconnecting";
  const active = state === "connected" || state === "reconnecting";

  // Which profile the big button connects to when idle.
  const ordered = useMemo(() => quickOrder(profiles), [profiles]);
  const target = useMemo(() => {
    const byId = (id: string | null | undefined) => (id ? profiles.find((p) => p.id === id) : undefined);
    return byId(chosen) ?? byId(status?.profile_id) ?? byId(settings?.auto_connect_profile_id) ?? ordered[0] ?? null;
  }, [chosen, profiles, status?.profile_id, settings?.auto_connect_profile_id, ordered]);

  const unavailable = !!daemonError || (received && !status);
  const onToggle = () => {
    if (engaged || state === "disconnecting") void disconnect();
    else if (target) void connect(target.id);
    else go("configurations");
  };

  const tone = STATE_TONE[state];
  const buttonLabel = engaged ? (state === "connected" ? "Disconnect" : "Cancel") : state === "disconnecting" ? "Stopping" : "Connect";

  return (
    <>
      <ScreenHeader title="Dashboard" description="Connection overview and live tunnel health" />
      <ScreenBody className="flex flex-col gap-5">
        {received && daemonError && <DaemonBanner error={daemonError} />}
        {appVersion && status?.daemon_version && status.daemon_version !== appVersion && (
          <Alert tone="warning" title="App and service versions differ">
            This app is v{appVersion}, the background service is v{status.daemon_version}. Run the matching{" "}
            <code className="font-mono">alizy-installer</code> from the release page to update both together.
          </Alert>
        )}

        {status?.last_error && (
          <Alert tone="danger" title="Last connection error">
            <span className="selectable">{status.last_error}</span>
          </Alert>
        )}

        <div className="grid grid-cols-1 gap-5 @3xl:grid-cols-[minmax(300px,5fr)_7fr]">
          {/* Hero */}
          <Card className="relative flex flex-col items-center justify-center overflow-hidden px-6 pt-8 pb-6">
            <div
              className={cn(
                "pointer-events-none absolute -top-24 left-1/2 size-[360px] -translate-x-1/2 rounded-full blur-3xl transition-colors duration-500",
                state === "connected"
                  ? "bg-success/15"
                  : state === "error"
                    ? "bg-danger/10"
                    : state === "protected" || state === "reconnecting"
                      ? "bg-warning/10"
                      : "bg-primary/10",
              )}
              aria-hidden
            />
            {!received ? (
              <div className="flex flex-col items-center gap-4 py-6">
                <Skeleton className="size-[180px] rounded-full" />
                <Skeleton className="h-5 w-32" />
                <Skeleton className="h-4 w-48" />
              </div>
            ) : (
              <>
                <ConnectControl
                  state={state}
                  pending={pending !== null}
                  disabled={unavailable || (!engaged && !target && state !== "disconnecting")}
                  onClick={onToggle}
                  label={buttonLabel}
                />
                <div className="relative mt-5 text-center">
                  <div className={cn("text-lg font-semibold tracking-tight", unavailable ? "text-danger" : TONE_TEXT[tone])} aria-live="polite">
                    {unavailable ? "Service unavailable" : STATE_LABEL[state]}
                  </div>
                  <p className="mt-1 max-w-[300px] text-[13px] leading-relaxed text-muted">
                    {unavailable ? "Start the Alizy service to connect." : STATE_DESCRIPTION[state]}
                  </p>
                </div>
                <Duration since={active ? (status?.connected_since ?? null) : null} />
                <div className="mt-5 w-full max-w-[320px]">
                  <ProfilePicker
                    targetName={engaged ? (status?.profile_name ?? target?.name ?? null) : (target?.name ?? null)}
                    locked={engaged || state === "disconnecting"}
                    onPick={setChosen}
                    ordered={ordered}
                  />
                </div>
              </>
            )}
          </Card>

          <div className="grid grid-cols-1 gap-5 @5xl:grid-cols-2">
            <div className="@5xl:col-span-2">
              <TrafficCard active={active} />
            </div>
            <TunnelCard active={active} />
            <div className="flex flex-col gap-5">
              <KillSwitchCard />
              {settings?.show_public_ip && <PublicIpCard />}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-5 @3xl:grid-cols-[1fr_minmax(280px,340px)]">
          <QuickSwitcher disabled={unavailable} />
          <LeakCard />
        </div>
      </ScreenBody>
    </>
  );
}

function Duration({ since }: { since: number | null }) {
  const now = useNow(1000);
  if (!since) return <div className="mt-3 h-7" aria-hidden />;
  return (
    <div className="mt-3 rounded-full border border-border bg-surface-2/70 px-3 py-1 font-mono text-[15px] font-medium text-fg tabular" aria-label="Connection duration">
      {formatClock(now - since)}
    </div>
  );
}

function ProfilePicker({
  targetName,
  locked,
  onPick,
  ordered,
}: {
  targetName: string | null;
  locked: boolean;
  onPick: (id: string) => void;
  ordered: ReturnType<typeof quickOrder>;
}) {
  if (ordered.length === 0) {
    return (
      <div className="flex items-center justify-center gap-2 rounded-xl border border-dashed border-border px-4 py-3 text-[13px] text-muted">
        <CircleAlert className="size-4 text-faint" />
        Import a configuration to connect
      </div>
    );
  }
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild disabled={locked}>
        <button
          type="button"
          className="flex w-full items-center gap-3 rounded-xl border border-border bg-surface-2/60 px-3.5 py-2.5 text-left transition-colors hover:border-border-strong disabled:cursor-default disabled:hover:border-border focus-visible:outline-2 focus-visible:outline-ring"
          aria-label="Choose profile"
        >
          <FileCode2 className="size-4 shrink-0 text-faint" />
          <div className="min-w-0 flex-1">
            <div className="text-[11px] text-faint">{locked ? "Active profile" : "Profile"}</div>
            <div className="truncate text-sm font-medium text-fg">{targetName ?? "Choose a profile"}</div>
          </div>
          {!locked && <ChevronDown className="size-4 text-faint" />}
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="center" className="max-h-80 w-[var(--radix-dropdown-menu-trigger-width)] overflow-y-auto">
        <DropdownMenuLabel>Connect with</DropdownMenuLabel>
        {ordered.map((p) => (
          <DropdownMenuItem key={p.id} onSelect={() => onPick(p.id)}>
            {p.favorite ? <Star className="fill-warning !text-warning" /> : <FileCode2 />}
            <span className="flex-1 truncate">{p.name}</span>
            <span className="text-[11px] text-faint">{p.endpoint?.replace(/:\d+$/, "")}</span>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
