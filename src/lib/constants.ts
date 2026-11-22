import type { ConnectionState } from "./types";

export const STATE_LABEL: Record<ConnectionState, string> = {
  disconnected: "Disconnected",
  connecting: "Connecting",
  connected: "Connected",
  disconnecting: "Disconnecting",
  reconnecting: "Reconnecting",
  error: "Connection error",
  protected: "Protected",
};

export type Tone = "neutral" | "primary" | "success" | "warning" | "danger";

export const STATE_TONE: Record<ConnectionState, Tone> = {
  disconnected: "neutral",
  connecting: "primary",
  connected: "success",
  disconnecting: "primary",
  reconnecting: "warning",
  error: "danger",
  protected: "warning",
};

export const STATE_DESCRIPTION: Record<ConnectionState, string> = {
  disconnected: "Your traffic is not protected by the VPN.",
  connecting: "Establishing a secure tunnel…",
  connected: "Your traffic is encrypted through the VPN.",
  disconnecting: "Tearing down the tunnel…",
  reconnecting: "Connection was interrupted. Restoring the tunnel…",
  error: "The tunnel could not be established.",
  protected: "Kill switch is blocking all traffic until the VPN is connected.",
};

export const isBusyState = (s: ConnectionState) => s === "connecting" || s === "disconnecting" || s === "reconnecting";
export const isUpState = (s: ConnectionState) => s === "connected";

export const TONE_TEXT: Record<Tone, string> = {
  neutral: "text-muted",
  primary: "text-primary",
  success: "text-success",
  warning: "text-warning",
  danger: "text-danger",
};
export const TONE_BG: Record<Tone, string> = {
  neutral: "bg-faint",
  primary: "bg-primary",
  success: "bg-success",
  warning: "bg-warning",
  danger: "bg-danger",
};

export const HANDSHAKE_WARN_SEC = 180;
