import { create } from "zustand";
import { api } from "../lib/api";
import type { DaemonStatus, StatusEvent } from "../lib/types";
import { toast } from "./toast";

export interface RatePoint {
  t: number;
  rx: number;
  tx: number;
}

const MAX_POINTS = 60;

interface Sample {
  t: number;
  rx: number;
  tx: number;
  key: string;
}

interface StatusState {
  status: DaemonStatus | null;
  daemonError: string | null;
  /** true after the first status (event or initial fetch) arrived */
  received: boolean;
  lastUpdate: number | null;
  rates: RatePoint[];
  last: Sample | null;
  /** connect/disconnect request in flight (profile id or "disconnect") */
  pending: string | null;
  ingest: (ev: StatusEvent) => void;
  bootstrap: () => Promise<void>;
  connect: (id: string) => Promise<void>;
  disconnect: () => Promise<void>;
}

export const useStatus = create<StatusState>((set, get) => ({
  status: null,
  daemonError: null,
  received: false,
  lastUpdate: null,
  rates: [],
  last: null,
  pending: null,

  ingest: (ev) => {
    const now = Date.now();
    const s = ev.status;
    let { rates, last } = get();
    if (s && s.stats && (s.state === "connected" || s.state === "reconnecting")) {
      const key = `${s.profile_id}|${s.interface}|${s.connected_since}`;
      const { rx_bytes: rx, tx_bytes: tx } = s.stats;
      if (last && last.key === key && rx >= last.rx && tx >= last.tx) {
        const dt = (now - last.t) / 1000;
        if (dt >= 0.25) {
          rates = [...rates, { t: now, rx: (rx - last.rx) / dt, tx: (tx - last.tx) / dt }].slice(-MAX_POINTS);
          last = { t: now, rx, tx, key };
        }
      } else {
        rates = [];
        last = { t: now, rx, tx, key };
      }
    } else {
      rates = [];
      last = null;
    }
    set({ status: s, daemonError: ev.daemon_error, received: true, lastUpdate: now, rates, last });
  },

  bootstrap: async () => {
    try {
      const status = await api.status();
      if (!get().received) get().ingest({ status, daemon_error: null });
    } catch (e) {
      if (!get().received) {
        set({ received: true, status: null, daemonError: typeof e === "string" ? e : String(e) });
      }
    }
  },

  connect: async (id) => {
    set({ pending: id });
    try {
      await api.connect(id);
    } catch (e) {
      toast.error("Could not connect", e);
    } finally {
      set({ pending: null });
    }
  },

  disconnect: async () => {
    set({ pending: "disconnect" });
    try {
      await api.disconnect();
    } catch (e) {
      toast.error("Could not disconnect", e);
    } finally {
      set({ pending: null });
    }
  },
}));
