import { CircleCheck, CircleX, Info, LogOut, Monitor, Moon, Palette, Power, RefreshCw, Sun, TriangleAlert } from "lucide-react";
import { useEffect, useState } from "react";
import { ScreenBody, ScreenHeader } from "../../components/ScreenHeader";
import { Card, CardHeader, InfoRow } from "../../components/ui/card";
import { Switch } from "../../components/ui/switch";
import { Select } from "../../components/ui/select";
import { Button } from "../../components/ui/button";
import { Badge } from "../../components/ui/badge";
import { Alert } from "../../components/ui/alert";
import { Skeleton } from "../../components/ui/skeleton";
import { EmptyState } from "../../components/ui/empty-state";
import { ConfirmDialog } from "../../components/ui/dialog";
import { Divider, SettingRow } from "../../components/ui/misc";
import { api } from "../../lib/api";
import type { Theme, UpdateInfo } from "../../lib/types";
import { cn } from "../../lib/utils";
import { useSettings } from "../../store/settings";
import { useNav } from "../../store/nav";
import { useStatus } from "../../store/status";
import { toast } from "../../store/toast";
import { SystemCheck } from "./SystemCheck";
import { LANGS, t } from "../../i18n";

export function GeneralSettings() {
  const { settings, settingsError, update, loadSettings, saving } = useSettings();
  const focus = useNav((s) => s.focus);
  const clearFocus = useNav((s) => s.clearFocus);

  useEffect(() => {
    if (!focus) return;
    const timer = window.setTimeout(() => {
      document.getElementById(focus)?.scrollIntoView({ behavior: "smooth", block: "start" });
      clearFocus();
    }, 120);
    return () => window.clearTimeout(timer);
  }, [focus, clearFocus]);

  return (
    <>
      <ScreenHeader
        title={t("Settings")}
        description={t("Startup, appearance and app information.")}
        actions={
          saving ? (
            <span className="flex items-center gap-1.5 text-xs text-muted">
              <RefreshCw className="size-3.5 animate-spin" /> {t("Saving…")}
            </span>
          ) : null
        }
      />
      <ScreenBody narrow className="flex flex-col gap-5">
        {!settings ? (
          settingsError ? (
            <EmptyState
              tone="danger"
              icon={<CircleX />}
              title={t("Settings unavailable")}
              description={<span className="selectable">{settingsError}</span>}
              action={
                <Button size="sm" variant="secondary" onClick={() => void loadSettings()}>
                  <RefreshCw /> {t("Try again")}
                </Button>
              }
            />
          ) : (
            <Skeleton className="h-72 rounded-2xl" />
          )
        ) : (
          <>
            <StartupCard />
            <Card className="overflow-hidden">
              <CardHeader icon={<Palette />} title={t("Appearance & behaviour")} />
              <Divider />
              <SettingRow title={t("Theme")} description={t("Follow the system or pick a fixed look.")} control={<ThemePicker value={settings.theme} onChange={(theme) => void update({ theme })} />} />
              <Divider className="mx-5" />
              <SettingRow
                title={t("Language")}
                control={
                  <Select
                    value={settings.language}
                    onValueChange={(language) => void update({ language })}
                    aria-label={t("Language")}
                    className="w-40"
                    options={LANGS}
                  />
                }
                description={t("English is the default. Persian switches the interface to right-to-left.")}
              />
              <Divider className="mx-5" />
              <SettingRow
                htmlFor="notifications"
                title={t("Notifications")}
                description={t("Desktop notifications when the connection state changes or the kill switch engages.")}
                control={<Switch id="notifications" checked={settings.notifications} onCheckedChange={(v) => void update({ notifications: v })} />}
              />
              <Divider className="mx-5" />
              <SettingRow
                htmlFor="public-ip"
                title={t("Show public IP on the dashboard")}
                description={t("Looks up your public address by contacting api.ipify.org — an external service that will see your IP.")}
                control={<Switch id="public-ip" checked={settings.show_public_ip} onCheckedChange={(v) => void update({ show_public_ip: v })} />}
              />
              <Divider className="mx-5" />
              <SettingRow
                htmlFor="auto-updates"
                title={t("Automatic updates")}
                description={t("No update channel is configured for this build")}
                disabled
                control={<Switch id="auto-updates" checked={false} disabled aria-label={t("Automatic updates (unavailable)")} />}
              />
            </Card>
          </>
        )}

        <AboutCard />
        <SystemCheck />
        <QuitCard />
      </ScreenBody>
    </>
  );
}

function StartupCard() {
  const { settings, update } = useSettings();
  const appInfo = useSettings((s) => s.appInfo);
  if (!settings) return null;
  const trayOff = appInfo ? !appInfo.tray_available : false;
  return (
    <Card className="overflow-hidden">
      <CardHeader icon={<Power />} title={t("Startup & window")} />
      <Divider />
      <SettingRow
        htmlFor="launch-startup"
        title={t("Launch at startup")}
        description={t("Open Alizy when you log in.")}
        control={<Switch id="launch-startup" checked={settings.launch_at_startup} onCheckedChange={(v) => void update({ launch_at_startup: v })} />}
      />
      <Divider className="mx-5" />
      <SettingRow
        htmlFor="start-min"
        title={t("Start minimized")}
        description={t("Start hidden in the system tray instead of showing the window.")}
        disabled={trayOff}
        control={
          <Switch id="start-min" checked={settings.start_minimized && !trayOff} disabled={trayOff} onCheckedChange={(v) => void update({ start_minimized: v })} />
        }
      />
      <Divider className="mx-5" />
      <SettingRow
        htmlFor="close-tray"
        title={t("Minimize / close to system tray")}
        description={
          trayOff
            ? t("Unavailable: no system tray was detected on this desktop. Closing the window quits the UI (the protection service keeps running).")
            : t("Closing the window keeps Alizy running in the tray.")
        }
        disabled={trayOff}
        control={
          <Switch id="close-tray" checked={settings.close_to_tray && !trayOff} disabled={trayOff} onCheckedChange={(v) => void update({ close_to_tray: v })} />
        }
      />
    </Card>
  );
}

function ThemePicker({ value, onChange }: { value: Theme; onChange: (t: Theme) => void }) {
  const opts: { v: Theme; label: string; Icon: typeof Sun }[] = [
    { v: "light", label: t("Light"), Icon: Sun },
    { v: "dark", label: t("Dark"), Icon: Moon },
    { v: "system", label: t("System"), Icon: Monitor },
  ];
  return (
    <div role="radiogroup" aria-label={t("Theme")} className="inline-flex rounded-xl border border-border bg-surface-2/70 p-1">
      {opts.map(({ v, label, Icon }) => (
        <button
          key={v}
          type="button"
          role="radio"
          aria-checked={value === v}
          onClick={() => onChange(v)}
          className={cn(
            "inline-flex h-8 items-center gap-1.5 rounded-lg px-3 text-[13px] font-medium transition-colors focus-visible:outline-2 focus-visible:outline-ring",
            value === v ? "bg-surface text-fg shadow-soft" : "text-muted hover:text-fg",
          )}
        >
          <Icon className="size-4" /> {label}
        </button>
      ))}
    </div>
  );
}

function AboutCard() {
  const { appInfo, appInfoError, appInfoLoading, loadAppInfo } = useSettings();
  const daemonVersion = useStatus((s) => s.status?.daemon_version ?? null);
  return (
    <Card className="overflow-hidden">
      <CardHeader
        icon={<Info />}
        title={t("About")}
        action={
          <Button size="icon-sm" variant="ghost" onClick={() => void loadAppInfo()} aria-label={t("Refresh app information")} disabled={appInfoLoading}>
            <RefreshCw className={appInfoLoading ? "animate-spin" : ""} />
          </Button>
        }
      />
      {!appInfo ? (
        appInfoError ? (
          <div className="px-5 pb-5">
            <Alert tone="danger" title={t("App information unavailable")}>
              <span className="selectable">{appInfoError}</span>
            </Alert>
          </div>
        ) : (
          <div className="px-5 pb-5">
            <Skeleton className="h-28 rounded-xl" />
          </div>
        )
      ) : (
        <div className="flex flex-col gap-3 px-5 pb-5">
          <div className="divide-y divide-border rounded-xl border border-border px-4">
            <InfoRow label={t("Alizy version")}>
              <span dir="ltr" className="font-mono text-[12px]">{appInfo.version}</span>
            </InfoRow>
            <InfoRow label={t("Platform")}>{appInfo.platform}</InfoRow>
            <InfoRow label={t("Desktop environment")}>{appInfo.desktop ?? t("Unknown")}</InfoRow>
            <InfoRow label={t("Background service (alizyd)")}>
              {appInfo.daemon.reachable ? (
                <span className="inline-flex items-center gap-1.5 text-success">
                  <CircleCheck className="size-3.5" /> {t("Reachable")}
                  <span dir="ltr" className="font-mono text-[12px] text-muted">v{appInfo.daemon.version ?? daemonVersion ?? "?"}</span>
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 text-danger">
                  <CircleX className="size-3.5" /> {t("Not reachable")}
                </span>
              )}
            </InfoRow>
            <InfoRow label={t("Secret storage")}>
              {appInfo.secret_backend === "keyring" ? (
                <Badge tone="success">{t("System keyring (Secret Service)")}</Badge>
              ) : appInfo.secret_backend === "file" ? (
                <Badge tone="warning">{t("Protected file (0600)")}</Badge>
              ) : (
                <Badge>{appInfo.secret_backend}</Badge>
              )}
            </InfoRow>
            <InfoRow label={t("Country data")}>
              <span className="text-[12px] text-muted">
                {t("IP geolocation by")} <span dir="ltr">DB-IP (db-ip.com), CC BY 4.0</span>
              </span>
            </InfoRow>
          </div>
          {appInfo.daemon.reachable &&
            (appInfo.daemon.version ?? daemonVersion) !== null &&
            (appInfo.daemon.version ?? daemonVersion) !== appInfo.version && (
              <Alert tone="warning" icon={<TriangleAlert />} title={t("App and service versions differ")}>
                {t("This app is v{app}, the background service is v{service}. Run the matching alizy-installer from the release page to update both together.", {
                  app: appInfo.version,
                  service: appInfo.daemon.version ?? daemonVersion ?? "?",
                })}
              </Alert>
            )}
          <UpdateCheck />
          {!appInfo.daemon.reachable && appInfo.daemon.error && (
            <Alert tone="danger" title={t("Service error")}>
              <span className="selectable">{appInfo.daemon.error}</span>
            </Alert>
          )}
          {appInfo.secret_backend === "file" && (
            <Alert tone="warning" icon={<TriangleAlert />} title={t("Private keys are stored in a file")}>
              {t(
                "No Secret Service (e.g. GNOME Keyring or KWallet) was found, so private keys are kept in a file readable only by your user (permissions 0600). Install and unlock a keyring for stronger protection.",
              )}
            </Alert>
          )}
        </div>
      )}
    </Card>
  );
}

function UpdateCheck() {
  const [busy, setBusy] = useState(false);
  const [info, setInfo] = useState<UpdateInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const run = async () => {
    setBusy(true);
    setInfo(null);
    setError(null);
    try {
      setInfo(await api.checkUpdate());
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="flex flex-wrap items-center gap-3 rounded-xl border border-border px-4 py-3">
      <div className="min-w-0 flex-1 text-[13px]">
        {info ? (
          info.update_available ? (
            <span className="text-fg">{t("Alizy v{latest} is available (you have v{current}).", { latest: info.latest, current: info.current })}</span>
          ) : (
            <span className="text-muted">{t("You have the latest version (v{current}).", { current: info.current })}</span>
          )
        ) : error ? (
          <span className="selectable text-danger">{error}</span>
        ) : (
          <span className="text-muted">{t("Asks GitHub Releases for the newest version only when you press the button. Nothing is downloaded.")}</span>
        )}
      </div>
      {info?.update_available && (
        <Button size="sm" variant="primary" onClick={() => void api.openReleasesPage().catch((e) => toast.error(t("Could not open the browser"), e))}>
          {t("Open release page")}
        </Button>
      )}
      <Button size="sm" variant="secondary" onClick={() => void run()} disabled={busy}>
        <RefreshCw className={busy ? "animate-spin" : ""} />
        {t("Check for updates")}
      </Button>
    </div>
  );
}

function QuitCard() {
  const [open, setOpen] = useState(false);
  return (
    <Card className="flex items-center gap-4 p-5">
      <div className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-surface-2 text-muted">
        <LogOut className="size-5" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium text-fg">{t("Quit Alizy (UI only)")}</div>
        <p className="text-[13px] text-muted">
          {t(
            "Closes this window and the tray icon. The protection service keeps running — an active VPN connection and the kill switch stay in effect.",
          )}
        </p>
      </div>
      <Button variant="secondary" onClick={() => setOpen(true)}>
        {t("Quit UI")}
      </Button>
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        icon={<LogOut />}
        title={t("Quit the Alizy interface?")}
        description={t("The background service keeps your current connection and kill switch active. Open Alizy again any time to manage it.")}
        confirmLabel={t("Quit UI")}
        onConfirm={async () => {
          try {
            await api.quitUi();
          } catch (e) {
            toast.error(t("Could not quit"), e);
            return false;
          }
        }}
      />
    </Card>
  );
}

