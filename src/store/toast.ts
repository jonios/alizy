import { create } from "zustand";
import { errMsg } from "../lib/utils";

export type ToastKind = "success" | "error" | "warning" | "info";
export interface Toast {
  id: number;
  kind: ToastKind;
  title: string;
  description?: string;
  duration: number;
}

interface ToastState {
  toasts: Toast[];
  push: (t: Omit<Toast, "id" | "duration"> & { duration?: number }) => number;
  dismiss: (id: number) => void;
}

let seq = 1;

export const useToasts = create<ToastState>((set, get) => ({
  toasts: [],
  push: (t) => {
    const id = seq++;
    const duration = t.duration ?? (t.kind === "error" ? 8000 : 4000);
    set({ toasts: [...get().toasts.slice(-4), { ...t, id, duration }] });
    if (duration > 0) window.setTimeout(() => get().dismiss(id), duration);
    return id;
  },
  dismiss: (id) => set({ toasts: get().toasts.filter((x) => x.id !== id) }),
}));

export const toast = {
  success: (title: string, description?: string) => useToasts.getState().push({ kind: "success", title, description }),
  info: (title: string, description?: string) => useToasts.getState().push({ kind: "info", title, description }),
  warning: (title: string, description?: string) => useToasts.getState().push({ kind: "warning", title, description }),
  error: (title: string, err?: unknown) =>
    useToasts.getState().push({ kind: "error", title, description: err === undefined ? undefined : errMsg(err) }),
};
