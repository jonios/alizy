import { Search, TriangleAlert } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { Input } from "../../components/ui/input";
import { EmptyState } from "../../components/ui/empty-state";
import { Badge } from "../../components/ui/badge";
import { Tooltip } from "../../components/ui/tooltip";
import type { SplitRule } from "../../lib/types";
import { RuleRow } from "./RuleRow";
import { RuleEditDialog } from "./RuleEditDialog";
import { targetKey, targetText } from "./rules";
import { useSplit } from "./store";
import { t } from "../../i18n";

/** Lists rules of one kind with filter, duplicate detection and shared-IP warnings. */
export function RuleListTab({
  kind,
  addBar,
  emptyIcon,
  emptyTitle,
  emptyDescription,
  details,
}: {
  kind: "domain" | "ip";
  addBar: ReactNode;
  emptyIcon: ReactNode;
  emptyTitle: string;
  emptyDescription: ReactNode;
  details?: (r: SplitRule) => ReactNode;
}) {
  const data = useSplit((s) => s.data);
  const [filter, setFilter] = useState("");
  const [editing, setEditing] = useState<SplitRule | null>(null);

  const all = data?.config.rules ?? [];
  const rules = useMemo(
    () => all.filter((r) => r.target.type === kind).sort((a, b) => targetText(a.target).localeCompare(targetText(b.target))),
    [all, kind],
  );
  const dupKeys = useMemo(() => {
    const seen = new Map<string, number>();
    for (const r of all) seen.set(targetKey(r.target), (seen.get(targetKey(r.target)) ?? 0) + 1);
    return new Set([...seen].filter(([, n]) => n > 1).map(([k]) => k));
  }, [all]);
  const warnByRule = useMemo(() => {
    const m = new Map<string, string[]>();
    for (const w of data?.warnings ?? []) for (const id of w.rule_ids) m.set(id, [...(m.get(id) ?? []), `${w.ip}: ${w.message}`]);
    return m;
  }, [data?.warnings]);

  const q = filter.trim().toLowerCase();
  const shown = q ? rules.filter((r) => targetText(r.target).includes(q) || (r.category ?? "").toLowerCase().includes(q)) : rules;

  return (
    <div className="flex flex-col gap-4">
      {addBar}
      {rules.length === 0 ? (
        <div className="rounded-2xl border-2 border-dashed border-border">
          <EmptyState icon={emptyIcon} title={emptyTitle} description={emptyDescription} />
        </div>
      ) : (
        <>
          <div className="flex items-center justify-between gap-3">
            <div className="text-xs text-muted">
              {rules.length === 1
                ? t("{count} rule · {on} enabled", { count: rules.length, on: rules.filter((r) => r.enabled).length })
                : t("{count} rules · {on} enabled", { count: rules.length, on: rules.filter((r) => r.enabled).length })}
            </div>
            {rules.length > 6 && (
              <Input leading={<Search />} value={filter} onChange={(e) => setFilter(e.target.value)} placeholder={t("Filter rules…")} className="w-60" aria-label={t("Filter rules")} />
            )}
          </div>
          <div className="flex flex-col gap-2">
            {shown.map((r) => {
              const warns = warnByRule.get(r.id);
              return (
                <RuleRow
                  key={r.id}
                  rule={r}
                  onEdit={() => setEditing(r)}
                  duplicate={dupKeys.has(targetKey(r.target))}
                  details={details?.(r)}
                  warning={
                    warns && (
                      <Tooltip
                        content={
                          <ul className="list-disc ps-4">
                            {warns.map((w, i) => (
                              <li key={i}>{w}</li>
                            ))}
                          </ul>
                        }
                      >
                        <span tabIndex={0}>
                          <Badge tone="warning">
                            <TriangleAlert /> {t("Shared IP")}
                          </Badge>
                        </span>
                      </Tooltip>
                    )
                  }
                />
              );
            })}
            {shown.length === 0 && <div className="py-6 text-center text-[13px] text-muted">{t("No rules match “{filter}”.", { filter })}</div>}
          </div>
        </>
      )}
      <RuleEditDialog rule={editing} onOpenChange={(o) => !o && setEditing(null)} />
    </div>
  );
}
