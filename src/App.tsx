import { Fragment, useEffect } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { EVENTS } from "./lib/api";
import type { StatusEvent } from "./lib/types";
import { useStatus } from "./store/status";
import { useProfiles } from "./store/profiles";
import { useGeo } from "./store/geo";
import { useSettings } from "./store/settings";
import { usePolicy } from "./store/policy";
import { resolveScreen, useNav } from "./store/nav";
import { TooltipProvider } from "./components/ui/tooltip";
import { Toaster } from "./components/ui/toaster";
import { Dock } from "./components/Dock";
import { ImportReportDialog } from "./components/ImportReportDialog";
import { DropOverlay } from "./components/DropOverlay";
import { useTheme } from "./components/useTheme";
import { MapScreen } from "./screens/map/MapScreen";
import { Configurations } from "./screens/configurations/Configurations";
import { SshFlowDialogs } from "./screens/configurations/HostKeyDialog";
import { ProfileDetailsSheet } from "./screens/configurations/ProfileDetails";
import { SplitTunneling } from "./screens/split/SplitTunneling";
import { NetworkSettings } from "./screens/network/NetworkSettings";
import { GeneralSettings } from "./screens/general/GeneralSettings";
import { Logs } from "./screens/logs/Logs";
import { setLang } from "./i18n";
import { cn } from "./lib/utils";

function useBackendWiring() {
  useEffect(() => {
    const unlisteners: Promise<UnlistenFn>[] = [];
    const safe = (p: Promise<UnlistenFn>) => {
      p.catch((e) => console.warn("event listener unavailable:", e));
      unlisteners.push(p);
    };
    safe(listen<StatusEvent>(EVENTS.status, (e) => useStatus.getState().ingest(e.payload)));
    safe(
      listen(EVENTS.profilesChanged, () => {
        void useProfiles.getState().load();
        void useGeo.getState().load();
      }),
    );
    safe(
      listen<string>(EVENTS.navigate, (e) => {
        const target = typeof e.payload === "string" ? resolveScreen(e.payload) : null;
        if (target) useNav.getState().go(target, e.payload === "system-check" ? "system-check" : null);
      }),
    );

    void useStatus.getState().bootstrap();
    void useProfiles.getState().load();
    void useGeo.getState().load();
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
      return <MapScreen />;
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
  const language = useSettings((s) => s.settings?.language ?? "en");
  // Set before the tree renders so every t() call sees it; the key remounts
  // the tree when the language (and with it the text direction) changes.
  setLang(language);

  return (
    <TooltipProvider delayDuration={350} skipDelayDuration={150}>
      <Fragment key={language}>
      <div className="relative flex h-full min-h-0 w-full bg-background text-fg">
        {/* The map screen places the dock over the map itself; other screens start below it. */}
        {screen !== "dashboard" && <Dock />}
        <main
          key={screen}
          className={cn("@container relative flex min-w-0 flex-1 animate-fade-in flex-col overflow-hidden", screen !== "dashboard" && "pt-14")}
        >
          <CurrentScreen />
        </main>
      </div>
      <ProfileDetailsSheet />
      <ImportReportDialog />
      <SshFlowDialogs />
      <DropOverlay />
      <Toaster />
      </Fragment>
    </TooltipProvider>
  );
}
