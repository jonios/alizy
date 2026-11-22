import { ChevronRight, CircleAlert, Clock, Loader2 } from "lucide-react";
import { useState } from "react";
import { Badge } from "../../components/ui/badge";
import type { DomainStatus } from "../../lib/types";
import { formatDuration, relativeTime } from "../../lib/format";
import { useNow } from "../../lib/hooks";
import { cn } from "../../lib/utils";

export function DomainStatusLine({ st, enabled, splitOn }: { st: DomainStatus | undefined; enabled: boolean; splitOn: boolean }) {
  const now = useNow(1000);
  const [open, setOpen] = useState(false);

  if (!enabled || !splitOn) {
    return <div className="text-xs text-faint">{!splitOn ? "Split tunneling is off — not resolving." : "Rule disabled — not resolving."}</div>;
  }
  if (!st) {
    return (
      <div className="flex items-center gap-1.5 text-xs text-muted">
        <Loader2 className="size-3 animate-spin" /> Waiting for first resolution…
      </div>
    );
  }
  const live = st.addrs.filter((a) => !a.stale).length;
  const stale = st.addrs.length - live;

  return (
    <div className="text-xs">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex w-full flex-wrap items-center gap-x-3 gap-y-1 rounded text-left text-muted hover:text-fg focus-visible:outline-2 focus-visible:outline-ring"
      >
        <ChevronRight className={cn("size-3.5 shrink-0 transition-transform", open && "rotate-90")} />
        <span>
          <b className="font-medium text-fg">{st.addrs.length}</b> address{st.addrs.length === 1 ? "" : "es"}
          {stale > 0 && <span className="text-warning"> ({stale} stale)</span>}
        </span>
        {st.cnames.length > 0 && <span className="truncate">via CNAME {st.cnames[st.cnames.length - 1]}</span>}
        {st.last_error && (
          <span className="inline-flex items-center gap-1 text-danger">
            <CircleAlert className="size-3" /> resolution error
          </span>
        )}
        <span className="ml-auto inline-flex items-center gap-1 text-faint">
          <Clock className="size-3" />
          {st.last_resolved ? `resolved ${relativeTime(st.last_resolved, now)}` : "not resolved"}
          {st.next_refresh ? ` · refresh ${st.next_refresh > now ? `in ${formatDuration(st.next_refresh - now)}` : "due"}` : ""}
        </span>
      </button>
      {open && (
        <div className="mt-2.5 ml-5 flex flex-col gap-2.5 pb-1">
          {st.cnames.length > 0 && (
            <div>
              <div className="mb-1 text-faint">CNAME chain</div>
              <div className="selectable flex flex-wrap items-center gap-1 font-mono text-[11px] text-fg">
                <span>{st.domain}</span>
                {st.cnames.map((c) => (
                  <span key={c} className="flex items-center gap-1">
                    <ChevronRight className="size-3 text-faint" />
                    {c}
                  </span>
                ))}
              </div>
            </div>
          )}
          {st.last_error && (
            <div className="selectable rounded-lg border border-danger/25 bg-danger/[0.06] px-2.5 py-1.5 text-danger">{st.last_error}</div>
          )}
          {st.addrs.length > 0 ? (
            <div className="grid grid-cols-[repeat(auto-fill,minmax(220px,1fr))] gap-1.5">
              {st.addrs.map((a) => {
                const ttl = a.expires_at - now;
                return (
                  <div key={a.ip} className="flex items-center justify-between gap-2 rounded-md border border-border bg-surface-2/60 px-2 py-1">
                    <span className="selectable truncate font-mono text-[11px] text-fg">{a.ip}</span>
                    {a.stale ? (
                      <Badge tone="warning">stale</Badge>
                    ) : (
                      <span className={cn("text-[11px] tabular", ttl < 30 ? "text-warning" : "text-faint")}>
                        TTL {ttl > 0 ? formatDuration(ttl) : "expired"}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-faint">No addresses resolved.</div>
          )}
          <div className="text-faint">Source: {st.source}</div>
        </div>
      )}
    </div>
  );
}
