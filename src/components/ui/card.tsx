import type { HTMLAttributes, ReactNode } from "react";
import { cn } from "../../lib/utils";

export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("rounded-2xl border border-border bg-surface shadow-card", className)} {...props} />;
}

interface CardHeaderProps {
  title: ReactNode;
  description?: ReactNode;
  icon?: ReactNode;
  action?: ReactNode;
  className?: string;
}

export function CardHeader({ title, description, icon, action, className }: CardHeaderProps) {
  return (
    <div className={cn("flex items-start gap-3 px-5 pt-4 pb-3", className)}>
      {icon && (
        <div className="mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-lg bg-surface-2 text-muted [&_svg]:size-4">
          {icon}
        </div>
      )}
      <div className="min-w-0 flex-1">
        <h3 className="text-sm font-semibold tracking-tight text-fg">{title}</h3>
        {description && <p className="mt-0.5 text-[13px] leading-relaxed text-muted">{description}</p>}
      </div>
      {action && <div className="flex shrink-0 items-center gap-2">{action}</div>}
    </div>
  );
}

export function CardContent({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("px-5 pb-5", className)} {...props} />;
}

/** A label/value row used in detail cards. */
export function InfoRow({ label, children, className }: { label: ReactNode; children: ReactNode; className?: string }) {
  return (
    <div className={cn("flex items-start justify-between gap-4 py-2 text-[13px]", className)}>
      <span className="shrink-0 text-muted">{label}</span>
      <span className="min-w-0 text-right text-fg">{children}</span>
    </div>
  );
}
