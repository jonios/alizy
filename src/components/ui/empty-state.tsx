import type { ReactNode } from "react";
import { cn } from "../../lib/utils";

export function EmptyState({
  icon,
  title,
  description,
  action,
  className,
  tone = "neutral",
}: {
  icon?: ReactNode;
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  className?: string;
  tone?: "neutral" | "danger" | "warning" | "primary";
}) {
  const toneCls = {
    neutral: "bg-surface-2 text-muted ring-border",
    danger: "bg-danger/10 text-danger ring-danger/20",
    warning: "bg-warning/10 text-warning ring-warning/20",
    primary: "bg-primary/10 text-primary ring-primary/20",
  }[tone];
  return (
    <div className={cn("flex flex-col items-center justify-center px-6 py-12 text-center", className)}>
      {icon && (
        <div className={cn("mb-4 flex size-12 items-center justify-center rounded-2xl ring-1 [&_svg]:size-6", toneCls)}>{icon}</div>
      )}
      <h3 className="text-sm font-semibold text-fg">{title}</h3>
      {description && <div className="mt-1.5 max-w-md text-[13px] leading-relaxed text-muted">{description}</div>}
      {action && <div className="mt-5 flex flex-wrap items-center justify-center gap-2">{action}</div>}
    </div>
  );
}
