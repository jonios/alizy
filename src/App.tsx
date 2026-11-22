import { useEffect } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { EVENTS } from "./lib/api";
import type { StatusEvent } from "./lib/types";
import { useStatus } from "./store/status";
import { useProfiles } from "./store/profiles";
import { useSettings } from "./store/settings";
import { usePolicy } from "./store/policy";
import { resolveScreen, useNav } from "./store/nav";
import { TooltipProvider } from "./components/ui/tooltip";
import { Toaster } from "./components/ui/toaster";
import { Sidebar } from "./components/Sidebar";
import { ImportReportDialog } from "./components/ImportReportDialog";
import { DropOverlay } from "./components/DropOverlay";
import { useTheme } from "./components/useTheme";
import { Dashboard } from "./screens/dashboard/Dashboard";
import { Configurations } from "./screens/configurations/Configurations";
import { SshFlowDialogs } from "./screens/configurations/HostKeyDialog";
import { ProfileDetailsSheet } from "./screens/configurations/ProfileDetails";
import { SplitTunneling } from "./screens/split/SplitTunneling";
import { NetworkSettings } from "./screens/network/NetworkSettings";
import { GeneralSettings } from "./screens/general/GeneralSettings";
import { Logs } from "./screens/logs/Logs";

function useBackendWiring() {
  useEffect(() => {
    const unlisteners: Promise<UnlistenFn>[] = [];
    const safe = (p: Promise<UnlistenFn>) => {
      p.catch((e) => console.warn("event listener unavailable:", e));
      unlisteners.push(p);
    };
    safe(listen<StatusEvent>(EVENTS.status, (e) => useStatus.getState().ingest(e.payload)));
    safe(listen(EVENTS.profilesChanged, () => void useProfiles.getState().load()));
    safe(
      listen<string>(EVENTS.navigate, (e) => {
        const target = typeof e.payload === "string" ? resolveScreen(e.payload) : null;
        if (target) useNav.getState().go(target, e.payload === "system-check" ? "system-check" : null);
      }),
    );

    void useStatus.getState().bootstrap();
    void useProfiles.getState().load();
    void useSettings.getState().loadSettings();
    void useSettings.getState().loadAppInfo();
    void usePolicy.getState().load();

    return () => {
      for (const p of unlisteners) p.then((un) => un()).catch(() => {});
    };
  }, []);
}

function CurrentScreen() {
  const screen = useNav((s) => s.screen);
  switch (screen) {
    case "dashboard":
      return <Dashboard />;
    case "configurations":
      return <Configurations />;
    case "split":
      return <SplitTunneling />;
    case "network":
      return <NetworkSettings />;
    case "general":
      return <GeneralSettings />;
    case "logs":
      return <Logs />;
  }
}

export default function App() {
  useBackendWiring();
  useTheme();
  const screen = useNav((s) => s.screen);

  return (
    <TooltipProvider delayDuration={350} skipDelayDuration={150}>
      <div className="flex h-full min-h-0 w-full bg-background text-fg">
        <Sidebar />
        {/* @container: screens size their grids against the space beside the sidebar, not the window. */}
        <main key={screen} className="@container relative flex min-w-0 flex-1 animate-fade-in flex-col overflow-hidden">
          <CurrentScreen />
        </main>
      </div>
      <ProfileDetailsSheet />
      <ImportReportDialog />
      <SshFlowDialogs />
      <DropOverlay />
      <Toaster />
    </TooltipProvider>
  );
}
