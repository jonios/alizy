import { create } from "zustand";
import { api } from "../lib/api";
import type { NetworkPolicy } from "../lib/types";
import { errMsg } from "../lib/utils";
import { useStatus } from "./status";

interface PolicyState {
  policy: NetworkPolicy | null;
  loading: boolean;
  loadError: string | null;
  saving: boolean;
  saveError: string | null;
  load: () => Promise<void>;
  save: (policy: NetworkPolicy) => Promise<boolean>;
}

export const usePolicy = create<PolicyState>((set, get) => ({
  policy: null,
  loading: false,
  loadError: null,
  saving: false,
  saveError: null,

  load: async () => {
    set({ loading: true });
    try {
      set({ policy: await api.policyGet(), loadError: null });
    } catch (e) {
      set({ loadError: errMsg(e) });
    } finally {
      set({ loading: false });
    }
  },

  save: async (policy) => {
    const prev = get().policy;
    set({ policy, saving: true, saveError: null });
    try {
      await api.policySet(policy);
      return true;
    } catch (e) {
      set({ policy: prev, saveError: errMsg(e) });
      return false;
    } finally {
      set({ saving: false });
    }
  },
}));

// Follow the policy the service reports. Anything that changes it outside
// this window (the tray, a service restart, another client) shows up here.
// Only a *change* in the reported policy is applied, never while a save is in
// flight, so an optimistic edit isn't reverted by a status poll that predates it.
let reported: string | null = null;
useStatus.subscribe((s) => {
  const p = s.status?.policy;
  if (!p) return;
  const json = JSON.stringify(p);
  if (json === reported) return;
  reported = json;
  const st = usePolicy.getState();
  if (!st.saving && JSON.stringify(st.policy) !== json) usePolicy.setState({ policy: p });
});
