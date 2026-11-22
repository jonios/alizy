import { cn } from "../../lib/utils";

export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden className={cn("rounded-md bg-surface-3/70 motion-safe:animate-pulse", className)} />;
}

export function SkeletonRows({ rows = 4, className }: { rows?: number; className?: string }) {
  return (
    <div className={cn("flex flex-col gap-2", className)} role="status" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-12 w-full rounded-xl" />
      ))}
    </div>
  );
}
