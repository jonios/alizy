import { ChevronsRight, Loader2, Power, ShieldCheck, ShieldOff, X } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Flag } from "../../components/Flag";
import { KillSwitchConfirm } from "../../components/KillSwitchConfirm";
import { CopyButton } from "../../components/ui/copy-button";
import { Switch } from "../../components/ui/switch";
import { Tooltip } from "../../components/ui/tooltip";
import { HANDSHAKE_WARN_SEC, STATE_LABEL, isBusyState } from "../../lib/constants";
import { formatBytes, formatClock, formatRate, relativeTime } from "../../lib/format";
import { countryName, homeCountry } from "../../lib/geo/countries";
import { useNow } from "../../lib/hooks";
import type { ProfileSummary } from "../../lib/types";
import { cn } from "../../lib/utils";
import { useGeo } from "../../store/geo";
import { useNav } from "../../store/nav";
import { usePing } from "../../store/ping";
import { usePolicy } from "../../store/policy";
import { useStatus } from "../../store/status";
import { Sparkline } from "./Sparkline";
import { LeakChips } from "./LeakChips";
import { Bars } from "./ConfigList";
import { protocolLabel, serverHost, serverPort } from "./profileView";
import { t } from "../../i18n";

/** Everything about one config: connect, session, traffic, tunnel facts, kill switch. */
export function DetailPanel({ profile }: { profile: ProfileSummary }) {
  const select = useNav((s) => s.select);
  const cc = useGeo((s) => s.country[profile.id] ?? null);
  const { status, rates, pending, connect, disconnect, daemonError } = useStatus();
  const policy = usePolicy((s) => s.policy);
  const saving = usePolicy((s) => s.saving);
  const ms = usePing((s) => s.results[profile.id]?.ms ?? null);
  const now = useNow(1000);
  const [ks, setKs] = useState<"on" | "off" | null>(null);

  const state = status?.state ?? "disconnected";
  const mine = status?.profile_id === profile.id;
  const view = mine ? state : "disconnected"; // this config's own state
  const up = mine && (state === "connected" || state === "reconnecting");
  const busy = (mine && isBusyState(state)) || pending === profile.id || (mine && pending === "disconnect");
  const engagedElsewhere = !mine && !!status && status.state !== "disconnected" && !!status.profile_id;
  const stats = up ? status?.stats : null;
  const latest = rates[rates.length - 1];
  const tunnel = up ? status?.tunnel_config : null;
  const handshake = stats?.last_handshake || null;
  const proxyMode = (policy?.mode ?? status?.policy.mode) === "proxy";
  const ksOn = policy?.kill_switch ?? status?.kill_switch.enabled ?? false;
  const unavailable = !!daemonError || !status;

  const onPower = () => {
    if (mine && state !== "disconnected" && state !== "error" && state !== "protected") void disconnect();
    else void connect(profile.id);
  };
  const label = mine && (state === "connected" || isBusyState(state)) ? (state === "connected" ? t("Disconnect") : t("Cancel")) : t("Connect");

  return (
    <div className="flex h-full w-[330px] flex-col gap-3.5 overflow-y-auto px-[18px] pt-4 pb-[18px] [scrollbar-width:none]">
      {/* route */}
      <div className="flex items-center gap-1.5 text-[11px] text-muted">
        <span>{t("You")}</span>
        <Flag cc={homeCountry()} className="size-4" />
        <ChevronsRight className={cn("size-3.5 rtl:rotate-180", up ? "text-primary motion-safe:animate-pulse" : "text-faint")} />
        <Flag cc={cc} className="size-4" />
        <span className="truncate">{countryName(cc) ?? t("Unknown")}</span>
        <button
          type="button"
          onClick={() => select(null)}
          aria-label={t("Close")}
          className="ms-auto flex size-6 items-center justify-center rounded-md text-faint transition-colors hover:bg-surface-2 hover:text-fg"
        >
          <X className="size-4" />
        </button>
      </div>

      {/* hero */}
      <div className="relative overflow-hidden rounded-2xl border border-border bg-surface-2 p-4">
        <div
          className="pointer-events-none absolute -end-10 -top-10 size-[170px] opacity-20 blur-xl saturate-150 [mask-image:radial-gradient(circle,#000_35%,transparent_70%)]"
          aria-hidden
        >
          <Flag cc={cc} className="size-full ring-0" />
        </div>
        <div className="relative text-xl font-semibold tracking-tight text-fg">{countryName(cc) ?? t("Unknown")}</div>
        <div className="relative mt-0.5 flex items-center gap-1 font-mono text-xs text-muted" dir="ltr">
          <span className="selectable truncate">{serverHost(profile)}</span>
          {serverHost(profile) && <CopyButton text={serverHost(profile)!} className="size-6" />}
        </div>
        <div className="relative mt-3 flex flex-wrap gap-1.5 text-[11px]">
          <span className="truncate rounded-md bg-surface-3 px-2 py-0.5 text-muted">{profile.name}</span>
          <span className="rounded-md bg-primary/12 px-2 py-0.5 text-primary">{protocolLabel(profile)}</span>
          {serverPort(profile) !== null && (
            <span className="rounded-md bg-surface-3 px-2 py-0.5 font-mono text-muted" dir="ltr">
              :{serverPort(profile)}
            </span>
          )}
        </div>
      </div>

      {/* power */}
      <div className="relative grid place-items-center py-1">
        <svg className="pointer-events-none absolute size-[168px]" viewBox="0 0 168 168" aria-hidden>
          <defs>
            <linearGradient id="ring-grad" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0" stopColor="var(--primary)" />
              <stop offset="1" stopColor="var(--primary-hover)" />
            </linearGradient>
          </defs>
          <circle cx="84" cy="84" r="82" fill="none" stroke="var(--border)" strokeWidth="2" />
          <circle
            cx="84"
            cy="84"
            r="82"
            fill="none"
            stroke="url(#ring-grad)"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeDasharray={up ? "516 0" : "60 456"}
            className={cn("origin-center transition-opacity duration-300", busy ? "opacity-100 motion-safe:animate-spin" : up ? "opacity-100" : "opacity-0")}
            style={{ transform: busy ? undefined : "rotate(-90deg)" }}
          />
        </svg>
        <button
          type="button"
          onClick={onPower}
          disabled={unavailable || (busy && !mine)}
          aria-label={label}
          className={cn(
            "relative my-5 flex size-32 flex-col items-center justify-center gap-1 rounded-full border transition-all duration-300",
            "focus-visible:outline-3 focus-visible:outline-offset-4 focus-visible:outline-ring enabled:active:scale-[0.97] disabled:opacity-50",
            up
              ? "border-transparent bg-primary text-primary-fg shadow-[0_0_60px_-6px_color-mix(in_oklab,var(--primary)_55%,transparent)]"
              : "border-border bg-surface-2 text-muted enabled:hover:border-primary/60 enabled:hover:text-primary",
          )}
        >
          {busy ? <Loader2 className="size-8 animate-spin" /> : <Power className="size-8" strokeWidth={2.2} />}
          <span className="text-[11px] font-semibold tracking-[0.1em] uppercase">{label}</span>
        </button>
      </div>
      <div className="-mt-2 text-center text-xs" aria-live="polite">
        {unavailable ? (
          <span className="text-danger">{t("Service unavailable")}</span>
        ) : up ? (
          <span className="font-medium text-success">● {t(STATE_LABEL[state])}</span>
        ) : engagedElsewhere ? (
          <span className="text-muted">{t("Connected to {name}", { name: status?.profile_name ?? "" })}</span>
        ) : (
          <span className="text-muted">{t(STATE_LABEL[view])}</span>
        )}
      </div>

      {/* session */}
      <Card className="flex items-end justify-between">
        <div>
          <div className="text-[11px] text-faint">{t("Session")}</div>
          <div className="font-mono text-[26px] leading-tight font-semibold tracking-tight text-fg tabular" dir="ltr">
            {up && status?.connected_since ? formatClock(now - status.connected_since) : "00:00"}
          </div>
        </div>
        <div className="text-end text-[11px] text-faint">
          {up && status?.connected_since
            ? new Date(status.connected_since * 1000).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })
            : "—"}
        </div>
      </Card>

      {/* traffic */}
      <Card>
        <div className="flex items-baseline justify-between">
          <div className="text-[11px] text-faint">{t("Live")}</div>
          <div className="flex gap-3 text-[13px] font-semibold tabular">
            <span className="text-primary">↓ {formatRate(up ? (latest?.rx ?? 0) : 0)}</span>
            <span className="text-success">↑ {formatRate(up ? (latest?.tx ?? 0) : 0)}</span>
          </div>
        </div>
        <div className="mt-2 h-[52px]">
          <Sparkline points={up ? rates : []} height={52} />
        </div>
        <div className="mt-2.5 grid grid-cols-2 gap-2.5 border-t border-border pt-2.5">
          <Fact label={t("Downloaded")} value={formatBytes(stats?.rx_bytes ?? (up ? 0 : null))} big />
          <Fact label={t("Uploaded")} value={formatBytes(stats?.tx_bytes ?? (up ? 0 : null))} big />
        </div>
      </Card>

      {/* facts */}
      <div className="grid grid-cols-2 gap-px overflow-hidden rounded-2xl border border-border bg-border">
        <Cell label={t("Tunnel IP")} value={tunnel?.addresses[0]?.replace(/\/\d+$/, "") ?? "—"} />
        <Cell
          label={t("Latency")}
          value={
            <span className="flex items-center gap-1.5">
              {ms !== null ? `${ms} ms` : "—"} <Bars ms={ms} />
            </span>
          }
        />
        <Cell
          label={t("Handshake")}
          value={
            profile.kind === "ssh" ? (
              "—"
            ) : handshake ? (
              <span className={cn(now - handshake > HANDSHAKE_WARN_SEC && "text-warning")}>{relativeTime(handshake, now)}</span>
            ) : (
              "—"
            )
          }
        />
        <Cell label={t("DNS")} value={tunnel?.dns[0] ?? "—"} />
      </div>

      <LeakChips />

      {/* kill switch */}
      <Card className="mt-auto flex items-center gap-3">
        <div
          className={cn(
            "flex size-[34px] shrink-0 items-center justify-center rounded-[10px] transition-colors",
            ksOn && !proxyMode ? "bg-success/12 text-success" : "bg-surface-3 text-muted",
          )}
        >
          {ksOn && !proxyMode ? <ShieldCheck className="size-[18px]" /> : <ShieldOff className="size-[18px]" />}
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-[13px] font-semibold text-fg">{t("Full protection")}</div>
          <div className="truncate text-[11px] text-faint">{proxyMode ? t("Not used in proxy mode") : t("Kill switch")}</div>
        </div>
        {proxyMode ? (
          <Tooltip content={t("Not used in proxy mode")}>
            <span>
              <Switch checked={false} disabled aria-label={t("Kill switch")} />
            </span>
          </Tooltip>
        ) : (
          <Switch checked={ksOn} onCheckedChange={(v) => setKs(v ? "on" : "off")} disabled={!policy || saving} aria-label={t("Kill switch")} />
        )}
      </Card>
      <KillSwitchConfirm which={ks} onClose={() => setKs(null)} />
    </div>
  );
}

function Card({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cn("rounded-2xl border border-border bg-surface-2 px-3.5 py-3", className)}>{children}</div>;
}

function Fact({ label, value, big }: { label: string; value: string; big?: boolean }) {
  return (
    <div>
      <div className="text-[11px] text-faint">{label}</div>
      <div className={cn("font-semibold text-fg tabular", big ? "text-[15px]" : "text-[13px]")}>{value}</div>
    </div>
  );
}

function Cell({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="bg-surface-2 px-3 py-2.5">
      <div className="text-[11px] text-faint">{label}</div>
      <div className="mt-0.5 truncate font-mono text-[12.5px] text-fg" dir="ltr">
        {value}
      </div>
    </div>
  );
}
