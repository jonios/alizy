import { create } from "zustand";
import { api } from "../lib/api";
import type { AppInfo, AppSettings } from "../lib/types";
import { errMsg } from "../lib/utils";
import { toast } from "./toast";

interface SettingsState {
  settings: AppSettings | null;
  settingsError: string | null;
  saving: boolean;
  appInfo: AppInfo | null;
  appInfoError: string | null;
  appInfoLoading: boolean;
  loadSettings: () => Promise<void>;
  loadAppInfo: () => Promise<void>;
  /** optimistic: applies immediately, rolls back and toasts on failure */
  update: (patch: Partial<AppSettings>) => Promise<boolean>;
}

export const useSettings = create<SettingsState>((set, get) => ({
  settings: null,
  settingsError: null,
  saving: false,
  appInfo: null,
  appInfoError: null,
  appInfoLoading: false,

  loadSettings: async () => {
    try {
      set({ settings: await api.settingsGet(), settingsError: null });
    } catch (e) {
      set({ settingsError: errMsg(e) });
    }
  },

  loadAppInfo: async () => {
    set({ appInfoLoading: true });
    try {
      set({ appInfo: await api.appInfo(), appInfoError: null });
    } catch (e) {
      set({ appInfoError: errMsg(e) });
    } finally {
      set({ appInfoLoading: false });
    }
  },

  update: async (patch) => {
    const prev = get().settings;
    if (!prev) return false;
    const next = { ...prev, ...patch };
    set({ settings: next, saving: true });
    try {
      await api.settingsSet(next);
      return true;
    } catch (e) {
      set({ settings: prev });
      toast.error("Could not save settings", e);
      return false;
    } finally {
      set({ saving: false });
    }
  },
}));
