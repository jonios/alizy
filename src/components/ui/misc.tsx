import type { ReactNode } from "react";
import { cn } from "../../lib/utils";

/** A settings row: title + description on the left, control on the right. */
export function SettingRow({
  title,
  description,
  control,
  children,
  htmlFor,
  className,
  disabled,
}: {
  title: ReactNode;
  description?: ReactNode;
  control?: ReactNode;
  children?: ReactNode;
  htmlFor?: string;
  className?: string;
  disabled?: boolean;
}) {
  return (
    <div className={cn("flex flex-col gap-3 px-5 py-4", className)}>
      <div className="flex items-center justify-between gap-6">
        <div className={cn("min-w-0", disabled && "opacity-60")}>
          <label htmlFor={htmlFor} className="text-sm font-medium text-fg">
            {title}
          </label>
          {description && <div className="mt-0.5 text-[13px] leading-relaxed text-muted">{description}</div>}
        </div>
        {control && <div className="shrink-0">{control}</div>}
      </div>
      {children}
    </div>
  );
}

export function Divider({ className }: { className?: string }) {
  return <div className={cn("h-px bg-border", className)} />;
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <code className={cn("selectable font-mono text-[12px] text-fg", className)}>{children}</code>;
}

export function SectionTitle({ children, className, action }: { children: ReactNode; className?: string; action?: ReactNode }) {
  return (
    <div className={cn("mb-3 flex items-center justify-between gap-4", className)}>
      <h2 className="text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">{children}</h2>
      {action}
    </div>
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return (
    <kbd className="inline-flex h-5 items-center rounded border border-border bg-surface-2 px-1.5 font-mono text-[10px] text-muted">
      {children}
    </kbd>
  );
}
