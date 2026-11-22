import { useEffect, useMemo, useState } from "react";
import { Dialog, DialogBody, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "../../components/ui/dialog";
import { Button } from "../../components/ui/button";
import { Field, Input } from "../../components/ui/input";
import { Select } from "../../components/ui/select";
import type { DomainMatch, SplitAction, SplitRule, SplitTarget } from "../../lib/types";
import { checkDomain, checkNet } from "../../lib/validate";
import { MATCH_HELP, MATCH_LABEL, parseDomainInput, targetKey, targetText } from "./rules";
import { ActionToggle } from "./RuleRow";
import { useRules, useSplit } from "./store";

export function RuleEditDialog({ rule, onOpenChange }: { rule: SplitRule | null; onOpenChange: (o: boolean) => void }) {
  const mutate = useSplit((s) => s.mutate);
  const rules = useRules();
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState<DomainMatch>("exact");
  const [action, setAction] = useState<SplitAction>("direct");
  const [category, setCategory] = useState("");
  const [priority, setPriority] = useState("100");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!rule) return;
    setTarget(rule.target.type === "domain" ? rule.target.domain : targetText(rule.target));
    if (rule.target.type === "domain") setMode(rule.target.mode);
    setAction(rule.action);
    setCategory(rule.category ?? "");
    setPriority(String(rule.priority));
    setNote(rule.note ?? "");
  }, [rule]);

  const isDomain = rule?.target.type === "domain";
  const built = useMemo((): { target: SplitTarget | null; error: string | null } => {
    if (!rule) return { target: null, error: null };
    if (isDomain) {
      const c = checkDomain(target);
      if (!c.ok) return { target: null, error: c.error };
      const d = parseDomainInput(target, mode);
      return { target: { type: "domain", domain: d.domain, mode: d.mode }, error: null };
    }
    const c = checkNet(target);
    if (!c.ok) return { target: null, error: c.error };
    return { target: { type: "ip", net: c.normalized }, error: null };
  }, [rule, isDomain, target, mode]);

  const dup = built.target && rules.some((r) => r.id !== rule?.id && targetKey(r.target) === targetKey(built.target!));
  const prio = Number(priority);
  const prioOk = priority.trim() !== "" && Number.isInteger(prio) && prio >= 0 && prio <= 65535;

  const save = async () => {
    if (!rule || !built.target || !prioOk) return;
    setBusy(true);
    const ok = await mutate(
      (c) => ({
        ...c,
        rules: c.rules.map((r) =>
          r.id === rule.id
            ? { ...r, target: built.target!, action, category: category.trim() || null, priority: prio, note: note.trim() || null }
            : r,
        ),
      }),
      "Rule updated",
    );
    setBusy(false);
    if (ok) onOpenChange(false);
  };

  return (
    <Dialog open={rule !== null} onOpenChange={(o) => !busy && onOpenChange(o)}>
      <DialogContent size="md" aria-describedby={undefined}>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void save();
          }}
          className="flex min-h-0 flex-col"
        >
          <DialogHeader>
            <DialogTitle>Edit {isDomain ? "domain" : "IP"} rule</DialogTitle>
          </DialogHeader>
          <DialogBody className="flex flex-col gap-4">
            <Field
              label={isDomain ? "Domain" : "IP address or CIDR"}
              htmlFor="rule-target"
              error={built.error ?? (dup ? "Another rule already targets this." : null)}
            >
              <Input id="rule-target" value={target} onChange={(e) => setTarget(e.target.value)} className="font-mono" invalid={!!built.error || !!dup} autoFocus />
            </Field>
            {isDomain && (
              <Field label="Match" hint={MATCH_HELP[mode]}>
                <Select
                  value={mode}
                  onValueChange={(v) => setMode(v as DomainMatch)}
                  aria-label="Match mode"
                  options={(["exact", "wildcard", "parent"] as DomainMatch[]).map((m) => ({ value: m, label: MATCH_LABEL[m], description: MATCH_HELP[m] }))}
                />
              </Field>
            )}
            <div className="grid grid-cols-2 gap-4">
              <Field label="Route via">
                <div>
                  <ActionToggle value={action} onChange={setAction} size="md" />
                </div>
              </Field>
              <Field label="Priority" htmlFor="rule-prio" error={prioOk ? null : "0–65535"} hint="Lower wins within a tier">
                <Input id="rule-prio" type="number" min={0} max={65535} value={priority} onChange={(e) => setPriority(e.target.value)} invalid={!prioOk} />
              </Field>
            </div>
            <Field label="Category" htmlFor="rule-cat" hint="Optional, e.g. Banking or Streaming">
              <Input id="rule-cat" value={category} onChange={(e) => setCategory(e.target.value)} maxLength={40} list="split-categories" />
            </Field>
            <Field label="Note" htmlFor="rule-note">
              <Input id="rule-note" value={note} onChange={(e) => setNote(e.target.value)} maxLength={200} placeholder="Optional" />
            </Field>
          </DialogBody>
          <DialogFooter>
            <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={busy} disabled={!built.target || !!dup || !prioOk}>
              Save rule
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
