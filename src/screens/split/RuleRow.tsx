import { Pencil, Trash2 } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { Switch } from "../../components/ui/switch";
import { Button } from "../../components/ui/button";
import { Badge } from "../../components/ui/badge";
import { Tooltip } from "../../components/ui/tooltip";
import { ConfirmDialog } from "../../components/ui/dialog";
import type { SplitAction, SplitRule } from "../../lib/types";
import { cn } from "../../lib/utils";
import { MATCH_LABEL, targetText } from "./rules";
import { useSplit } from "./store";

export function ActionToggle({
  value,
  onChange,
  disabled,
  size = "sm",
}: {
  value: SplitAction;
  onChange: (v: SplitAction) => void;
  disabled?: boolean;
  size?: "sm" | "md";
}) {
  const opts: { v: SplitAction; label: string }[] = [
    { v: "direct", label: "Direct" },
    { v: "vpn", label: "VPN" },
  ];
  return (
    <div role="radiogroup" aria-label="Route via" className={cn("inline-flex rounded-lg border border-border bg-surface-2/70 p-0.5", disabled && "opacity-50")}>
      {opts.map((o) => {
        const on = value === o.v;
        return (
          <button
            key={o.v}
            type="button"
            role="radio"
            aria-checked={on}
            disabled={disabled}
            onClick={() => !on && onChange(o.v)}
            className={cn(
              "rounded-md font-medium transition-colors duration-150 focus-visible:outline-2 focus-visible:outline-ring",
              size === "sm" ? "h-6 px-2 text-[11px]" : "h-7 px-3 text-xs",
              on
                ? o.v === "direct"
                  ? "bg-warning/15 text-warning shadow-soft"
                  : "bg-primary/15 text-primary shadow-soft"
                : "text-muted hover:text-fg",
            )}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

function PriorityInput({ value, onCommit, disabled }: { value: number; onCommit: (n: number) => void; disabled?: boolean }) {
  const [v, setV] = useState(String(value));
  useEffect(() => setV(String(value)), [value]);
  const commit = () => {
    const n = Math.round(Number(v));
    if (!Number.isFinite(n) || v.trim() === "") return setV(String(value));
    const clamped = Math.max(0, Math.min(65535, n));
    if (clamped !== value) onCommit(clamped);
    else setV(String(value));
  };
  return (
    <Tooltip content="Priority — lower wins within the same precedence tier (default 100)">
      <input
        type="number"
        inputMode="numeric"
        min={0}
        max={65535}
        value={v}
        disabled={disabled}
        onChange={(e) => setV(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLInputElement).blur()}
        aria-label="Priority"
        className="h-7 w-16 rounded-md border border-border bg-surface px-2 text-center text-xs text-fg tabular hover:border-border-strong focus:border-primary focus:ring-3 focus:ring-primary/20 focus:outline-none [appearance:textfield] [&::-webkit-inner-spin-button]:appearance-none"
      />
    </Tooltip>
  );
}

export function RuleRow({
  rule,
  onEdit,
  details,
  duplicate,
  warning,
}: {
  rule: SplitRule;
  onEdit: () => void;
  details?: ReactNode;
  duplicate?: boolean;
  warning?: ReactNode;
}) {
  const mutate = useSplit((s) => s.mutate);
  const [confirm, setConfirm] = useState(false);
  const patch = (p: Partial<SplitRule>) =>
    mutate((c) => ({ ...c, rules: c.rules.map((r) => (r.id === rule.id ? { ...r, ...p } : r)) }));
  const label = targetText(rule.target);

  return (
    <div className={cn("rounded-xl border bg-surface transition-colors", rule.enabled ? "border-border" : "border-border/60 bg-surface/60")}>
      <div className="flex items-center gap-4 px-4 py-3">
        <Switch
          size="sm"
          checked={rule.enabled}
          onCheckedChange={(enabled) => void patch({ enabled })}
          aria-label={`${rule.enabled ? "Disable" : "Enable"} rule for ${label}`}
        />
        <div className={cn("min-w-0 flex-1", !rule.enabled && "opacity-55")}>
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <span className="selectable truncate font-mono text-[13px] text-fg">{label}</span>
            {rule.target.type === "domain" && <Badge tone="outline">{MATCH_LABEL[rule.target.mode]}</Badge>}
            {rule.category && <Badge tone="neutral">{rule.category}</Badge>}
            {duplicate && <Badge tone="warning">Duplicate</Badge>}
            {warning}
          </div>
          {rule.note && <div className="mt-0.5 truncate text-xs text-faint">{rule.note}</div>}
        </div>
        <ActionToggle value={rule.action} onChange={(action) => void patch({ action })} />
        <PriorityInput value={rule.priority} onCommit={(priority) => void patch({ priority })} />
        <div className="flex items-center">
          <Button variant="ghost" size="icon-sm" onClick={onEdit} aria-label={`Edit rule for ${label}`}>
            <Pencil />
          </Button>
          <Button variant="ghost" size="icon-sm" onClick={() => setConfirm(true)} aria-label={`Delete rule for ${label}`} className="hover:text-danger">
            <Trash2 />
          </Button>
        </div>
      </div>
      {details && <div className="border-t border-border px-4 py-2.5">{details}</div>}
      <ConfirmDialog
        open={confirm}
        onOpenChange={setConfirm}
        destructive
        icon={<Trash2 />}
        title="Delete rule?"
        description={
          <>
            Traffic to <span className="font-mono text-fg">{label}</span> will follow the remaining rules (by default, through the VPN).
          </>
        }
        confirmLabel="Delete rule"
        onConfirm={() => mutate((c) => ({ ...c, rules: c.rules.filter((r) => r.id !== rule.id) }), "Rule deleted")}
      />
    </div>
  );
}
