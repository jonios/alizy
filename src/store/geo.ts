import { create } from "zustand";
import { api } from "../lib/api";
import { errMsg } from "../lib/utils";

interface GeoState {
  /** profile id → ISO alpha-2 country, null when unknown */
  country: Record<string, string | null>;
  loaded: boolean;
  error: string | null;
  load: () => Promise<void>;
}

let inflight: Promise<void> | null = null;
let again = false;

/** Server country of every profile, looked up offline by the app. */
export const useGeo = create<GeoState>((set) => ({
  country: {},
  loaded: false,
  error: null,
  load: () => {
    // A change while a lookup runs (an import, say) gets its own run after it.
    if (inflight) {
      again = true;
      return inflight;
    }
    inflight = api
      .profilesGeo()
      .then((list) => {
        const country: Record<string, string | null> = {};
        for (const r of list) country[r.profile_id] = r.country;
        set({ country, loaded: true, error: null });
      })
      .catch((e) => set({ loaded: true, error: errMsg(e) }))
      .finally(() => {
        inflight = null;
        if (again) {
          again = false;
          void useGeo.getState().load();
        }
      });
    return inflight;
  },
}));
