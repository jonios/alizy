import type { ConnectionState } from "./types";
import { tk } from "../i18n";

export const STATE_LABEL: Record<ConnectionState, string> = {
  disconnected: tk("Disconnected"),
  connecting: tk("Connecting"),
  connected: tk("Connected"),
  disconnecting: tk("Disconnecting"),
  reconnecting: tk("Reconnecting"),
  error: tk("Connection error"),
  protected: tk("Protected"),
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
  disconnected: tk("Your traffic is not protected by the VPN."),
  connecting: tk("Establishing a secure tunnel…"),
  connected: tk("Your traffic is encrypted through the VPN."),
  disconnecting: tk("Tearing down the tunnel…"),
  reconnecting: tk("Connection was interrupted. Restoring the tunnel…"),
  error: tk("The tunnel could not be established."),
  protected: tk("Kill switch is blocking all traffic until the VPN is connected."),
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
