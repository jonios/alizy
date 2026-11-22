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
import type { Theme } from "../../lib/types";
import { cn } from "../../lib/utils";
import { useSettings } from "../../store/settings";
import { useNav } from "../../store/nav";
import { useStatus } from "../../store/status";
import { toast } from "../../store/toast";
import { SystemCheck } from "./SystemCheck";

export function GeneralSettings() {
  const { settings, settingsError, update, loadSettings, saving } = useSettings();
  const focus = useNav((s) => s.focus);
  const clearFocus = useNav((s) => s.clearFocus);

  useEffect(() => {
    if (!focus) return;
    const t = window.setTimeout(() => {
      document.getElementById(focus)?.scrollIntoView({ behavior: "smooth", block: "start" });
      clearFocus();
    }, 120);
    return () => window.clearTimeout(t);
  }, [focus, clearFocus]);

  return (
    <>
      <ScreenHeader
        title="Settings"
        description="Startup, appearance and app information."
        actions={
          saving ? (
            <span className="flex items-center gap-1.5 text-xs text-muted">
              <RefreshCw className="size-3.5 animate-spin" /> Saving…
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
              title="Settings unavailable"
              description={<span className="selectable">{settingsError}</span>}
              action={
                <Button size="sm" variant="secondary" onClick={() => void loadSettings()}>
                  <RefreshCw /> Try again
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
              <CardHeader icon={<Palette />} title="Appearance & behaviour" />
              <Divider />
              <SettingRow title="Theme" description="Follow the system or pick a fixed look." control={<ThemePicker value={settings.theme} onChange={(theme) => void update({ theme })} />} />
              <Divider className="mx-5" />
              <SettingRow
                title="Language"
                control={
                  <Select value="en" onValueChange={() => {}} aria-label="Language" className="w-40" options={[{ value: "en", label: "English" }]} />
                }
                description="More languages may be added in future releases."
              />
              <Divider className="mx-5" />
              <SettingRow
                htmlFor="notifications"
                title="Notifications"
                description="Desktop notifications when the connection state changes or the kill switch engages."
                control={<Switch id="notifications" checked={settings.notifications} onCheckedChange={(v) => void update({ notifications: v })} />}
              />
              <Divider className="mx-5" />
              <SettingRow
                htmlFor="public-ip"
                title="Show public IP on the dashboard"
                description="Looks up your public address by contacting api.ipify.org — an external service that will see your IP."
                control={<Switch id="public-ip" checked={settings.show_public_ip} onCheckedChange={(v) => void update({ show_public_ip: v })} />}
              />
              <Divider className="mx-5" />
              <SettingRow
                htmlFor="auto-updates"
                title="Automatic updates"
                description="No update channel is configured for this build"
                disabled
                control={<Switch id="auto-updates" checked={false} disabled aria-label="Automatic updates (unavailable)" />}
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
      <CardHeader icon={<Power />} title="Startup & window" />
      <Divider />
      <SettingRow
        htmlFor="launch-startup"
        title="Launch at startup"
        description="Open Alizy when you log in."
        control={<Switch id="launch-startup" checked={settings.launch_at_startup} onCheckedChange={(v) => void update({ launch_at_startup: v })} />}
      />
      <Divider className="mx-5" />
      <SettingRow
        htmlFor="start-min"
        title="Start minimized"
        description="Start hidden in the system tray instead of showing the window."
        disabled={trayOff}
        control={
          <Switch id="start-min" checked={settings.start_minimized && !trayOff} disabled={trayOff} onCheckedChange={(v) => void update({ start_minimized: v })} />
        }
      />
      <Divider className="mx-5" />
      <SettingRow
        htmlFor="close-tray"
        title="Minimize / close to system tray"
        description={
          trayOff
            ? "Unavailable: no system tray was detected on this desktop. Closing the window quits the UI (the protection service keeps running)."
            : "Closing the window keeps Alizy running in the tray."
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
    { v: "light", label: "Light", Icon: Sun },
    { v: "dark", label: "Dark", Icon: Moon },
    { v: "system", label: "System", Icon: Monitor },
  ];
  return (
    <div role="radiogroup" aria-label="Theme" className="inline-flex rounded-xl border border-border bg-surface-2/70 p-1">
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
        title="About"
        action={
          <Button size="icon-sm" variant="ghost" onClick={() => void loadAppInfo()} aria-label="Refresh app information" disabled={appInfoLoading}>
            <RefreshCw className={appInfoLoading ? "animate-spin" : ""} />
          </Button>
        }
      />
      {!appInfo ? (
        appInfoError ? (
          <div className="px-5 pb-5">
            <Alert tone="danger" title="App information unavailable">
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
            <InfoRow label="Alizy version">
              <span className="font-mono text-[12px]">{appInfo.version}</span>
            </InfoRow>
            <InfoRow label="Platform">{appInfo.platform}</InfoRow>
            <InfoRow label="Desktop environment">{appInfo.desktop ?? "Unknown"}</InfoRow>
            <InfoRow label="Background service (alizyd)">
              {appInfo.daemon.reachable ? (
                <span className="inline-flex items-center gap-1.5 text-success">
                  <CircleCheck className="size-3.5" /> Reachable
                  <span className="font-mono text-[12px] text-muted">v{appInfo.daemon.version ?? daemonVersion ?? "?"}</span>
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 text-danger">
                  <CircleX className="size-3.5" /> Not reachable
                </span>
              )}
            </InfoRow>
            <InfoRow label="Secret storage">
              {appInfo.secret_backend === "keyring" ? (
                <Badge tone="success">System keyring (Secret Service)</Badge>
              ) : appInfo.secret_backend === "file" ? (
                <Badge tone="warning">Protected file (0600)</Badge>
              ) : (
                <Badge>{appInfo.secret_backend}</Badge>
              )}
            </InfoRow>
          </div>
          {!appInfo.daemon.reachable && appInfo.daemon.error && (
            <Alert tone="danger" title="Service error">
              <span className="selectable">{appInfo.daemon.error}</span>
            </Alert>
          )}
          {appInfo.secret_backend === "file" && (
            <Alert tone="warning" icon={<TriangleAlert />} title="Private keys are stored in a file">
              No Secret Service (e.g. GNOME Keyring or KWallet) was found, so private keys are kept in a file readable only by your user
              (permissions 0600). Install and unlock a keyring for stronger protection.
            </Alert>
          )}
        </div>
      )}
    </Card>
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
        <div className="text-sm font-medium text-fg">Quit Alizy (UI only)</div>
        <p className="text-[13px] text-muted">
          Closes this window and the tray icon. The protection service keeps running — an active VPN connection and the kill switch stay
          in effect.
        </p>
      </div>
      <Button variant="secondary" onClick={() => setOpen(true)}>
        Quit UI
      </Button>
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        icon={<LogOut />}
        title="Quit the Alizy interface?"
        description="The background service keeps your current connection and kill switch active. Open Alizy again any time to manage it."
        confirmLabel="Quit UI"
        onConfirm={async () => {
          try {
            await api.quitUi();
          } catch (e) {
            toast.error("Could not quit", e);
            return false;
          }
        }}
      />
    </Card>
  );
}

