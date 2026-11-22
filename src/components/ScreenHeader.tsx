import type { ReactNode } from "react";
import { cn } from "../lib/utils";

export function ScreenHeader({
  title,
  description,
  actions,
  children,
  className,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <header className={cn("shrink-0 border-b border-border bg-background/80 px-5 pt-6 pb-5 backdrop-blur @3xl:px-8", className)}>
      <div className="mx-auto flex w-full max-w-[1200px] flex-wrap items-end justify-between gap-x-6 gap-y-3">
        <div className="min-w-0">
          <h1 className="text-[22px] font-semibold tracking-tight text-fg">{title}</h1>
          {description && <p className="mt-1 text-[13px] text-muted">{description}</p>}
        </div>
        {actions && <div className="flex shrink-0 flex-wrap items-center justify-end gap-2">{actions}</div>}
      </div>
      {children && <div className="mx-auto mt-4 w-full max-w-[1200px]">{children}</div>}
    </header>
  );
}

export function ScreenBody({ children, className, narrow }: { children: ReactNode; className?: string; narrow?: boolean }) {
  return (
    <div className="min-h-0 flex-1 overflow-y-auto">
      <div className="mx-auto w-full max-w-[1200px] px-5 py-6 @3xl:px-8">
        <div className={cn(narrow && "max-w-[880px]", className)}>{children}</div>
      </div>
    </div>
  );
}
