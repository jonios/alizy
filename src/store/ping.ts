import { create } from "zustand";
import { api } from "../lib/api";
import type { PingResult } from "../lib/types";
import { errMsg } from "../lib/utils";
import { toast } from "./toast";
import { t } from "../i18n";

/** Last known probe of one profile's endpoint. */
export interface PingEntry {
  /** round-trip time in ms, null when the probe failed */
  ms: number | null;
  /** short reason when ms is null (timeout, blocked, DNS failure, …) */
  error: string | null;
  /** unix ms when this result was measured */
  at: number;
}

interface PingState {
  /** keyed by profile id; survives navigation so rows never go blank */
  results: Record<string, PingEntry>;
  /** a run is in flight */
  busy: boolean;
  /** set when the run itself failed (the command rejected) */
  error: string | null;
  /** probe every profile endpoint; concurrent runs are ignored */
  pingAll: () => Promise<void>;
}

export const usePing = create<PingState>((set, get) => ({
  results: {},
  busy: false,
  error: null,
  pingAll: async () => {
    if (get().busy) return;
    set({ busy: true, error: null });
    try {
      const list: PingResult[] = await api.profilesPing();
      const at = Date.now();
      const fresh: Record<string, PingEntry> = {};
      for (const r of list) fresh[r.profile_id] = { ms: r.latency_ms, error: r.error, at };
      // Merge: profiles imported after the last run keep whatever they had.
      set({ results: { ...get().results, ...fresh }, busy: false });
    } catch (e) {
      set({ error: errMsg(e), busy: false });
      toast.error(t("Couldn’t measure the pings"), e);
    }
  },
}));
