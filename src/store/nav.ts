import { create } from "zustand";

export type Screen = "dashboard" | "configurations" | "split" | "network" | "general" | "logs";

export const SCREENS: Screen[] = ["dashboard", "configurations", "split", "network", "general", "logs"];

const ALIASES: Record<string, Screen> = {
  home: "dashboard",
  profiles: "configurations",
  configs: "configurations",
  configuration: "configurations",
  "split-tunneling": "split",
  split_tunneling: "split",
  splittunneling: "split",
  network: "network",
  "network-settings": "network",
  settings: "general",
  "general-settings": "general",
  about: "general",
  "system-check": "general",
  log: "logs",
  history: "logs",
};

export function resolveScreen(id: string): Screen | null {
  const k = id.trim().toLowerCase();
  if ((SCREENS as string[]).includes(k)) return k as Screen;
  return ALIASES[k] ?? null;
}

interface NavState {
  screen: Screen;
  /** profile shown in the details slide-over */
  detailsId: string | null;
  /** a section id to scroll into view after navigation (e.g. "system-check") */
  focus: string | null;
  /** profile shown in the map's side panel */
  selectedId: string | null;
  select: (id: string | null) => void;
  go: (screen: Screen, focus?: string | null) => void;
  openDetails: (id: string) => void;
  closeDetails: () => void;
  clearFocus: () => void;
}

export const useNav = create<NavState>((set) => ({
  screen: "dashboard",
  detailsId: null,
  focus: null,
  selectedId: null,
  select: (selectedId) => set({ selectedId }),
  go: (screen, focus = null) => set({ screen, focus }),
  openDetails: (id) => set({ detailsId: id }),
  closeDetails: () => set({ detailsId: null }),
  clearFocus: () => set({ focus: null }),
}));
