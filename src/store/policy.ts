import { create } from "zustand";
import { api } from "../lib/api";
import type { NetworkPolicy } from "../lib/types";
import { errMsg } from "../lib/utils";

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
