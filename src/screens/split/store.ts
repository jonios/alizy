import { create } from "zustand";
import { api } from "../../lib/api";
import type { SplitConfig, SplitRule, SplitStatus } from "../../lib/types";
import { errMsg } from "../../lib/utils";
import { toast } from "../../store/toast";
import { t } from "../../i18n";

interface SplitState {
  data: SplitStatus | null;
  loaded: boolean;
  error: string | null;
  saving: boolean;
  load: () => Promise<void>;
  /** Optimistically applies `fn` to the whole config and sends it with splitSet. */
  mutate: (fn: (c: SplitConfig) => SplitConfig, successMsg?: string) => Promise<boolean>;
}

let loadSeq = 0;

export const useSplit = create<SplitState>((set, get) => ({
  data: null,
  loaded: false,
  error: null,
  saving: false,

  load: async () => {
    const seq = ++loadSeq;
    try {
      const data = await api.splitGet();
      // ignore responses that raced with a save
      if (seq === loadSeq && !get().saving) set({ data, error: null, loaded: true });
    } catch (e) {
      if (seq === loadSeq) set({ error: errMsg(e), loaded: true });
    }
  },

  mutate: async (fn, successMsg) => {
    const prev = get().data;
    if (!prev) return false;
    const config = fn(structuredClone(prev.config));
    loadSeq++;
    set({ data: { ...prev, config }, saving: true });
    try {
      await api.splitSet(config);
      if (successMsg) toast.success(successMsg);
      set({ saving: false });
      await get().load();
      return true;
    } catch (e) {
      set({ data: prev, saving: false });
      toast.error(t("Could not save split tunneling rules"), e);
      return false;
    }
  },
}));

const EMPTY_RULES: SplitRule[] = [];
/** Stable selector for the rule list (avoids a fresh [] per render). */
export const useRules = (): SplitRule[] => useSplit((s) => s.data?.config.rules ?? EMPTY_RULES);
