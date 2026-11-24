import { ArrowRight, FileCode2, Star, Zap } from "lucide-react";
import { useMemo } from "react";
import { Card, CardHeader } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { Skeleton } from "../../components/ui/skeleton";
import { EmptyState } from "../../components/ui/empty-state";
import { Dot } from "../../components/ui/badge";
import type { ProfileSummary } from "../../lib/types";
import { endpointLabel, relativeTime } from "../../lib/format";
import { cn } from "../../lib/utils";
import { useProfiles } from "../../store/profiles";
import { useStatus } from "../../store/status";
import { useNav } from "../../store/nav";
import { STATE_TONE, TONE_BG, isBusyState } from "../../lib/constants";

export function quickOrder(profiles: ProfileSummary[]): ProfileSummary[] {
  return [...profiles].sort((a, b) => {
    if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
    const la = a.last_connected_at ?? 0;
    const lb = b.last_connected_at ?? 0;
    if (la !== lb) return lb - la;
    return a.name.localeCompare(b.name);
  });
}

export function QuickSwitcher({ disabled }: { disabled: boolean }) {
  const { profiles, loaded, error } = useProfiles();
  const status = useStatus((s) => s.status);
  const pending = useStatus((s) => s.pending);
  const connect = useStatus((s) => s.connect);
  const go = useNav((s) => s.go);
  const openDetails = useNav((s) => s.openDetails);
  const list = useMemo(() => quickOrder(profiles).slice(0, 8), [profiles]);

  return (
    <Card>
      <CardHeader
        icon={<Zap />}
        title="Quick switch"
        description="Favorites first, then most recently used"
        action={
          <Button variant="ghost" size="sm" onClick={() => go("configurations")}>
            All configurations <ArrowRight />
          </Button>
        }
      />
      <div className="px-3 pb-3">
        {!loaded ? (
          <div className="grid grid-cols-1 gap-2 px-2 pb-2 @3xl:grid-cols-2">
            {[0, 1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-14 rounded-xl" />
            ))}
          </div>
        ) : error && profiles.length === 0 ? (
          <EmptyState tone="danger" icon={<FileCode2 />} title="Couldn’t load profiles" description={error} className="py-8" />
        ) : list.length === 0 ? (
          <EmptyState
            icon={<FileCode2 />}
            title="No configurations yet"
            description="Import a WireGuard .conf file to get started. You can also drag files onto this window."
            action={
              <Button variant="primary" size="sm" onClick={() => go("configurations")}>
                Import configuration
              </Button>
            }
            className="py-8"
          />
        ) : (
          <div className="grid grid-cols-1 gap-1.5 @3xl:grid-cols-2">
            {list.map((p) => {
              const active = status?.profile_id === p.id && status.state !== "disconnected";
              const tone = active && status ? STATE_TONE[status.state] : null;
              const isPending = pending === p.id;
              return (
                <div
                  key={p.id}
                  className={cn(
                    "group flex items-center gap-3 rounded-xl border px-3 py-2.5 transition-colors duration-150",
                    active ? "border-primary/30 bg-primary/[0.06]" : "border-transparent hover:border-border hover:bg-surface-2/60",
                  )}
                >
                  <button
                    type="button"
                    className="flex min-w-0 flex-1 items-center gap-3 text-left focus-visible:outline-2 focus-visible:outline-ring"
                    onClick={() => openDetails(p.id)}
                    aria-label={`Open details for ${p.name}`}
                  >
                    <div className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-surface-2 text-[13px] font-semibold text-muted uppercase">
                      {p.name.slice(0, 2)}
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span className="truncate text-[13px] font-medium text-fg">{p.name}</span>
                        {p.favorite && <Star className="size-3 shrink-0 fill-warning text-warning" aria-label="Favorite" />}
                        {tone && <Dot className={TONE_BG[tone]} pulse={status ? isBusyState(status.state) : false} />}
                      </div>
                      <div className="truncate text-xs text-faint">
                        {endpointLabel(p) ?? "No endpoint"} · {p.last_connected_at ? relativeTime(p.last_connected_at) : "never used"}
                      </div>
                    </div>
                  </button>
                  {active ? (
                    <span className="text-xs font-medium text-primary">Active</span>
                  ) : (
                    <Button
                      size="xs"
                      variant="secondary"
                      onClick={() => connect(p.id)}
                      loading={isPending}
                      disabled={disabled || (pending !== null && !isPending)}
                      className="opacity-80 group-hover:opacity-100"
                    >
                      Connect
                    </Button>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </Card>
  );
}
