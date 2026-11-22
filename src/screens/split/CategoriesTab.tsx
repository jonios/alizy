import { Tags } from "lucide-react";
import { useMemo } from "react";
import { Card } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { Switch } from "../../components/ui/switch";
import { EmptyState } from "../../components/ui/empty-state";
import { Badge } from "../../components/ui/badge";
import type { SplitRule } from "../../lib/types";
import { targetText } from "./rules";
import { useRules, useSplit } from "./store";

const UNCATEGORIZED = "\u0000none";

export function CategoriesTab() {
  const rules = useRules();
  const mutate = useSplit((s) => s.mutate);

  const groups = useMemo(() => {
    const m = new Map<string, SplitRule[]>();
    for (const r of rules) {
      const k = r.category ?? UNCATEGORIZED;
      m.set(k, [...(m.get(k) ?? []), r]);
    }
    return [...m].sort(([a], [b]) => (a === UNCATEGORIZED ? 1 : b === UNCATEGORIZED ? -1 : a.localeCompare(b)));
  }, [rules]);

  if (rules.length === 0) {
    return (
      <div className="rounded-2xl border-2 border-dashed border-border">
        <EmptyState icon={<Tags />} title="No rules yet" description="Give rules a category (e.g. Banking, Streaming) to manage them together here." />
      </div>
    );
  }

  const setAll = (key: string, enabled: boolean) =>
    mutate(
      (c) => ({
        ...c,
        rules: c.rules.map((r) => ((r.category ?? UNCATEGORIZED) === key ? { ...r, enabled } : r)),
      }),
      `${enabled ? "Enabled" : "Disabled"} ${key === UNCATEGORIZED ? "uncategorized" : `“${key}”`} rules`,
    );

  return (
    <div className="grid grid-cols-1 gap-3 @3xl:grid-cols-2">
      {groups.map(([key, list]) => {
        const on = list.filter((r) => r.enabled).length;
        const direct = list.filter((r) => r.action === "direct").length;
        const allOn = on === list.length;
        return (
          <Card key={key} className="p-4">
            <div className="flex items-center gap-3">
              <div className="flex size-9 items-center justify-center rounded-lg bg-surface-2 text-muted">
                <Tags className="size-4" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-medium text-fg">{key === UNCATEGORIZED ? "Uncategorized" : key}</div>
                <div className="text-xs text-muted">
                  {list.length} rule{list.length === 1 ? "" : "s"} · {on} enabled · {direct} direct
                </div>
              </div>
              <Switch
                checked={allOn}
                onCheckedChange={(v) => void setAll(key, v)}
                aria-label={`Toggle all rules in ${key === UNCATEGORIZED ? "uncategorized" : key}`}
              />
            </div>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {list.slice(0, 12).map((r) => (
                <Badge key={r.id} tone={r.enabled ? (r.action === "direct" ? "warning" : "primary") : "outline"} className="font-mono">
                  {targetText(r.target)}
                </Badge>
              ))}
              {list.length > 12 && <Badge tone="outline">+{list.length - 12} more</Badge>}
            </div>
            {!allOn && on > 0 && (
              <div className="mt-3 flex gap-2">
                <Button size="xs" variant="secondary" onClick={() => void setAll(key, true)}>
                  Enable all
                </Button>
                <Button size="xs" variant="ghost" onClick={() => void setAll(key, false)}>
                  Disable all
                </Button>
              </div>
            )}
          </Card>
        );
      })}
    </div>
  );
}
