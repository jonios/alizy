import { useEffect, useMemo, useState } from "react";
import { Dock } from "../../components/Dock";
import { Flag } from "../../components/Flag";
import { Alert } from "../../components/ui/alert";
import { Dot } from "../../components/ui/badge";
import { STATE_LABEL, STATE_TONE, TONE_BG, isBusyState } from "../../lib/constants";
import { countryName, homeCountry } from "../../lib/geo/countries";
import { cn } from "../../lib/utils";
import { useGeo } from "../../store/geo";
import { useNav } from "../../store/nav";
import { useProfiles } from "../../store/profiles";
import { useSettings } from "../../store/settings";
import { useStatus } from "../../store/status";
import { DaemonBanner } from "./DaemonBanner";
import { usePublicIp } from "./usePublicIp";
import { ConfigList } from "./ConfigList";
import { DetailPanel } from "./DetailPanel";
import { serverHost } from "./profileView";
import { WorldMap, type MapPin } from "./WorldMap";
import { t } from "../../i18n";

export function MapScreen() {
  const profiles = useProfiles((s) => s.profiles);
  const country = useGeo((s) => s.country);
  const { status, daemonError, received } = useStatus();
  const appVersion = useSettings((s) => s.appInfo?.version ?? null);
  const selectedId = useNav((s) => s.selectedId);
  const select = useNav((s) => s.select);
  const publicIp = usePublicIp();
  const [picker, setPicker] = useState<{ cc: string; x: number; y: number } | null>(null);

  const selected = profiles.find((p) => p.id === selectedId) ?? null;
  const state = status?.state ?? "disconnected";
  const liveId = state !== "disconnected" ? (status?.profile_id ?? null) : null;

  // Open on the active config, so the panel shows what is running.
  useEffect(() => {
    if (!useNav.getState().selectedId && liveId) select(liveId);
  }, [liveId, select]);
  // A deleted config closes its panel.
  useEffect(() => {
    if (selectedId && profiles.length && !profiles.some((p) => p.id === selectedId)) select(null);
  }, [profiles, selectedId, select]);

  const byCountry = useMemo(() => {
    const m = new Map<string, typeof profiles>();
    for (const p of profiles) {
      const cc = country[p.id];
      if (!cc) continue;
      m.set(cc, [...(m.get(cc) ?? []), p]);
    }
    return m;
  }, [profiles, country]);
  const pins: MapPin[] = useMemo(() => [...byCountry].map(([cc, list]) => ({ cc, count: list.length })), [byCountry]);

  const onPick = (cc: string, at: { x: number; y: number }) => {
    const list = byCountry.get(cc) ?? [];
    if (list.length === 1) {
      select(list[0].id);
      setPicker(null);
    } else if (list.length > 1) setPicker({ cc, ...at });
  };

  useEffect(() => {
    if (!picker) return;
    const close = (e: Event) => {
      if (e instanceof KeyboardEvent && e.key !== "Escape") return;
      setPicker(null);
    };
    window.addEventListener("pointerdown", close);
    window.addEventListener("keydown", close);
    return () => {
      window.removeEventListener("pointerdown", close);
      window.removeEventListener("keydown", close);
    };
  }, [picker]);

  const tone = STATE_TONE[state];
  const ksOn = status?.kill_switch.enabled && status.policy.mode !== "proxy";

  return (
    <div className="flex min-h-0 flex-1">
      <ConfigList />

      <section className="relative min-w-0 flex-1 overflow-hidden bg-[radial-gradient(800px_420px_at_55%_45%,color-mix(in_oklab,var(--primary)_7%,transparent),transparent_70%)]">
        <WorldMap
          pins={pins}
          selected={selected ? (country[selected.id] ?? null) : null}
          live={liveId ? (country[liveId] ?? null) : null}
          connected={state === "connected"}
          home={homeCountry()}
          onPick={onPick}
        />
        <Dock />

        {picker && (
          <div
            className="absolute z-20 min-w-[210px] animate-pop-in rounded-xl border border-border bg-surface/95 p-1.5 shadow-card backdrop-blur"
            style={{ left: picker.x + 10, top: picker.y + 10 }}
            onPointerDown={(e) => e.stopPropagation()}
          >
            <div className="flex items-center gap-2 px-2 pt-1 pb-2 text-[11px] tracking-wide text-muted uppercase">
              <Flag cc={picker.cc} className="size-4" />
              {countryName(picker.cc)}
            </div>
            {(byCountry.get(picker.cc) ?? []).map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => {
                  select(p.id);
                  setPicker(null);
                }}
                className="flex w-full items-center justify-between gap-4 rounded-lg px-2.5 py-2 text-start text-[13px] text-fg hover:bg-primary/12"
              >
                <span className="flex items-center gap-2 truncate">
                  {p.id === liveId && <Dot className="bg-success" pulse />}
                  {p.name}
                </span>
                <span dir="ltr" className="font-mono text-[11px] text-muted">
                  {serverHost(p)}
                </span>
              </button>
            ))}
          </div>
        )}

        {/* service problems float over the map's lower edge */}
        <div className="absolute inset-x-4 bottom-16 z-10 mx-auto flex max-w-[560px] flex-col gap-2">
          {received && daemonError && <DaemonBanner error={daemonError} />}
          {appVersion && status?.daemon_version && status.daemon_version !== appVersion && (
            <Alert tone="warning" title={t("App and service versions differ")}>
              {t(
                "This app is v{app}, the background service is v{service}. Run the matching alizy-installer from the release page to update both together.",
                { app: appVersion, service: status.daemon_version },
              )}
            </Alert>
          )}
          {status?.last_error && (
            <Alert tone="danger" title={t("Last connection error")}>
              <span className="selectable">{status.last_error}</span>
            </Alert>
          )}
        </div>

        <div className="absolute start-4 bottom-4 z-10 flex items-center gap-2.5 rounded-xl border border-border bg-surface/80 px-3 py-2 text-xs text-muted backdrop-blur">
          <Dot className={TONE_BG[tone]} pulse={state === "connected" || isBusyState(state)} />
          <b className="font-semibold text-fg">{daemonError ? t("Service unavailable") : t(STATE_LABEL[state])}</b>
          {liveId && status?.profile_name && (
            <>
              <span className="h-3.5 w-px bg-border" />
              <span className="truncate">{status.profile_name}</span>
            </>
          )}
          {publicIp.ip && (
            <>
              <span className="h-3.5 w-px bg-border" />
              <span dir="ltr" className="selectable font-mono text-[11px]" title={t("Public IP address")}>
                {publicIp.ip}
              </span>
            </>
          )}
          {ksOn && (
            <>
              <span className="h-3.5 w-px bg-border" />
              <span className="text-success">{t("Kill switch on")}</span>
            </>
          )}
        </div>
      </section>

      <aside
        className={cn(
          "shrink-0 overflow-hidden border-s bg-sidebar transition-[width] duration-300 ease-[cubic-bezier(0.3,0.7,0.2,1)]",
          selected ? "w-[330px] border-border" : "w-0 border-transparent",
        )}
        aria-hidden={!selected}
      >
        {selected && <DetailPanel key={selected.id} profile={selected} />}
      </aside>
    </div>
  );
}
