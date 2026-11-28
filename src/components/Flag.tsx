import { flagUrl } from "../lib/geo/countries";
import { cn } from "../lib/utils";

/** Round country flag; a neutral disc when the country is unknown. */
export function Flag({ cc, className }: { cc: string | null | undefined; className?: string }) {
  const url = flagUrl(cc);
  return url ? (
    <img src={url} alt="" draggable={false} className={cn("shrink-0 rounded-full object-cover ring-1 ring-border", className)} />
  ) : (
    <span className={cn("block shrink-0 rounded-full bg-surface-3 ring-1 ring-border", className)} aria-hidden />
  );
}
