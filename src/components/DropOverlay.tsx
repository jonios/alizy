import { useEffect, useState } from "react";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { FileDown } from "lucide-react";
import { api } from "../lib/api";
import { useImportReport } from "../store/importReport";
import { useNav } from "../store/nav";
import { t } from "../i18n";

/** Full-window overlay for dragging .conf files or folders onto Alizy. */
export function DropOverlay() {
  const [over, setOver] = useState(false);

  useEffect(() => {
    let unlisten: (() => void) | null = null;
    let cancelled = false;
    try {
      getCurrentWebview()
        .onDragDropEvent((event) => {
          const p = event.payload;
          if (p.type === "enter" || p.type === "over") setOver(true);
          else if (p.type === "leave") setOver(false);
          else if (p.type === "drop") {
            setOver(false);
            if (p.paths.length) {
              useNav.getState().go("configurations");
              void useImportReport.getState().run(() => api.importPaths(p.paths), t("Imported from drag and drop"));
            }
          }
        })
        .then((un) => {
          if (cancelled) un();
          else unlisten = un;
        })
        .catch((e) => console.warn("drag-and-drop unavailable:", e));
    } catch (e) {
      console.warn("drag-and-drop unavailable:", e);
    }
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  if (!over) return null;
  return (
    <div className="pointer-events-none fixed inset-0 z-[90] flex animate-fade-in items-center justify-center bg-[var(--overlay)] p-6 backdrop-blur-sm">
      <div className="flex h-full w-full flex-col items-center justify-center rounded-3xl border-2 border-dashed border-primary/70 bg-primary/[0.06]">
        <div className="mb-5 flex size-16 items-center justify-center rounded-2xl bg-primary text-primary-fg shadow-pop">
          <FileDown className="size-8" />
        </div>
        <div className="text-lg font-semibold text-fg">{t("Drop to import")}</div>
        <div className="mt-1 text-sm text-muted">{t("WireGuard .conf files or folders containing them")}</div>
      </div>
    </div>
  );
}
