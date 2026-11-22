import type { HTMLAttributes } from "react";
import { cn } from "../../lib/utils";

export type BadgeTone = "neutral" | "primary" | "success" | "warning" | "danger" | "outline";

const TONES: Record<BadgeTone, string> = {
  neutral: "bg-surface-3 text-muted border-transparent",
  primary: "bg-primary/12 text-primary border-primary/20",
  success: "bg-success/12 text-success border-success/20",
  warning: "bg-warning/12 text-warning border-warning/25",
  danger: "bg-danger/12 text-danger border-danger/20",
  outline: "bg-transparent text-muted border-border",
};

export function Badge({ className, tone = "neutral", ...props }: HTMLAttributes<HTMLSpanElement> & { tone?: BadgeTone }) {
  return (
    <span
      className={cn(
        "inline-flex h-5 shrink-0 items-center gap-1 rounded-md border px-1.5 text-[11px] font-medium whitespace-nowrap [&_svg]:size-3",
        TONES[tone],
        className,
      )}
      {...props}
    />
  );
}

export function Dot({ className, pulse }: { className?: string; pulse?: boolean }) {
  return (
    <span className="relative inline-flex size-2 shrink-0">
      {pulse && <span className={cn("absolute inset-0 rounded-full opacity-60 motion-safe:animate-ping", className)} />}
      <span className={cn("relative inline-flex size-2 rounded-full", className)} />
    </span>
  );
}
