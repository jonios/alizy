import { Loader2, Power } from "lucide-react";
import type { ConnectionState } from "../../lib/types";
import { cn } from "../../lib/utils";
import { isBusyState } from "../../lib/constants";

const RING: Record<ConnectionState, string> = {
  disconnected: "from-surface-3 to-surface-2 text-muted",
  connecting: "from-primary/30 to-primary/10 text-primary",
  connected: "from-success/30 to-success/10 text-success",
  disconnecting: "from-primary/25 to-primary/5 text-primary",
  reconnecting: "from-warning/30 to-warning/10 text-warning",
  error: "from-danger/30 to-danger/10 text-danger",
  protected: "from-warning/25 to-warning/5 text-warning",
};

const CORE: Record<ConnectionState, string> = {
  disconnected: "bg-surface border-border-strong text-muted hover:text-primary hover:border-primary/60",
  connecting: "bg-surface border-primary/50 text-primary",
  connected: "bg-success text-white border-transparent shadow-[0_12px_40px_-8px_color-mix(in_oklab,var(--success)_60%,transparent)]",
  disconnecting: "bg-surface border-primary/40 text-primary",
  reconnecting: "bg-surface border-warning/50 text-warning",
  error: "bg-surface border-danger/60 text-danger hover:border-danger",
  protected: "bg-surface border-warning/60 text-warning hover:border-warning",
};

const ORBIT: Partial<Record<ConnectionState, string>> = {
  connecting: "var(--primary)",
  disconnecting: "var(--primary)",
  reconnecting: "var(--warning)",
};

export function ConnectControl({
  state,
  pending,
  disabled,
  onClick,
  label,
}: {
  state: ConnectionState;
  pending: boolean;
  disabled?: boolean;
  onClick: () => void;
  label: string;
}) {
  const busy = isBusyState(state) || pending;
  const orbitColor = ORBIT[state] ?? (pending ? "var(--primary)" : null);
  return (
    <div className="relative flex size-[208px] items-center justify-center">
      {state === "connected" && (
        <span className="absolute inset-4 rounded-full bg-success/25 motion-safe:animate-ring-pulse" aria-hidden />
      )}
      {(state === "protected" || state === "error") && (
        <span
          className={cn("absolute inset-6 rounded-full motion-safe:animate-breathe", state === "error" ? "bg-danger/10" : "bg-warning/10")}
          aria-hidden
        />
      )}
      <div className={cn("absolute inset-0 rounded-full bg-linear-to-b p-[1px] transition-colors duration-300", RING[state])}>
        <div className="size-full rounded-full bg-background/70" />
      </div>
      {orbitColor && (
        <div
          className="absolute inset-0 rounded-full motion-safe:animate-orbit"
          style={{
            background: `conic-gradient(from 0deg, transparent 0deg, transparent 250deg, ${orbitColor} 360deg)`,
            mask: "radial-gradient(farthest-side, transparent calc(100% - 3px), #000 calc(100% - 3px))",
            WebkitMask: "radial-gradient(farthest-side, transparent calc(100% - 3px), #000 calc(100% - 3px))",
          }}
          aria-hidden
        />
      )}
      <div className={cn("absolute inset-5 rounded-full bg-linear-to-b opacity-60", RING[state])} aria-hidden />
      <button
        type="button"
        onClick={onClick}
        disabled={disabled || pending}
        aria-label={label}
        className={cn(
          "relative z-10 flex size-[132px] flex-col items-center justify-center gap-1 rounded-full border-2 transition-all duration-250",
          "focus-visible:outline-3 focus-visible:outline-offset-4 focus-visible:outline-ring",
          "enabled:hover:scale-[1.03] enabled:active:scale-[0.98] disabled:cursor-not-allowed",
          CORE[state],
          disabled && "opacity-60",
        )}
      >
        {busy ? <Loader2 className="size-9 animate-spin" strokeWidth={2.25} /> : <Power className="size-10" strokeWidth={2.25} />}
        <span className="text-[11px] font-semibold tracking-[0.12em] uppercase opacity-90">{label}</span>
      </button>
    </div>
  );
}
