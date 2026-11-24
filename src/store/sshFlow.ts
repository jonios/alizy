import { create } from "zustand";
import type { ConnectError, HostKey } from "../lib/types";

/** UI state for the SSH connect flow; dialogs are mounted once in <SshFlowDialogs />. */
export interface HostKeyPrompt {
  profileId: string;
  changed: boolean;
  hostKey: HostKey;
  fingerprint: string;
}

interface SshFlowState {
  hostKey: HostKeyPrompt | null;
  /** profile id whose password must be re-entered */
  passwordFor: string | null;
  openHostKey: (p: HostKeyPrompt) => void;
  closeHostKey: () => void;
  openPassword: (id: string) => void;
  closePassword: () => void;
}

export const useSshFlow = create<SshFlowState>((set) => ({
  hostKey: null,
  passwordFor: null,
  openHostKey: (hostKey) => set({ hostKey }),
  closeHostKey: () => set({ hostKey: null }),
  openPassword: (passwordFor) => set({ passwordFor }),
  closePassword: () => set({ passwordFor: null }),
}));

export function isConnectError(e: unknown): e is ConnectError {
  return !!e && typeof e === "object" && typeof (e as ConnectError).code === "string" && typeof (e as ConnectError).message === "string";
}
