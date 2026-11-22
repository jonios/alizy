import { create } from "zustand";
import { api } from "../lib/api";
import type { ProfileSummary } from "../lib/types";
import { errMsg } from "../lib/utils";

interface ProfilesState {
  profiles: ProfileSummary[];
  loaded: boolean;
  loading: boolean;
  error: string | null;
  load: () => Promise<void>;
}

export const useProfiles = create<ProfilesState>((set, get) => ({
  profiles: [],
  loaded: false,
  loading: false,
  error: null,
  load: async () => {
    if (get().loading) return;
    set({ loading: true });
    try {
      const profiles = await api.profilesList();
      set({ profiles, loaded: true, error: null });
    } catch (e) {
      set({ error: errMsg(e), loaded: true });
    } finally {
      set({ loading: false });
    }
  },
}));
