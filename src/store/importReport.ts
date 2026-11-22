import { create } from "zustand";
import type { ImportReport } from "../lib/types";
import { useProfiles } from "./profiles";
import { toast } from "./toast";

interface ImportReportState {
  report: ImportReport | null;
  title: string;
  busy: boolean;
  show: (report: ImportReport, title?: string) => void;
  close: () => void;
  /** Runs an import call, then shows the report and refreshes the profile list. */
  run: (fn: () => Promise<ImportReport>, title?: string) => Promise<ImportReport | null>;
}

export const useImportReport = create<ImportReportState>((set, get) => ({
  report: null,
  title: "Import report",
  busy: false,
  show: (report, title = "Import report") => set({ report, title }),
  close: () => set({ report: null }),
  run: async (fn, title) => {
    set({ busy: true });
    try {
      const report = await fn();
      get().show(report, title);
      void useProfiles.getState().load();
      return report;
    } catch (e) {
      toast.error("Import failed", e);
      return null;
    } finally {
      set({ busy: false });
    }
  },
}));
