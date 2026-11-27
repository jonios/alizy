import { Plus } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import type { SplitAction, SplitTarget } from "../../lib/types";
import { uuid } from "../../lib/utils";
import { ActionToggle } from "./RuleRow";
import { DEFAULT_PRIORITY, targetKey } from "./rules";
import { useRules, useSplit } from "./store";
import { t } from "../../i18n";

/** Shared add-rule form. `build` returns either a target or an error message. */
export function AddRuleBar({
  placeholder,
  value,
  onValueChange,
  build,
  extra,
  hint,
}: {
  placeholder: string;
  value: string;
  onValueChange: (v: string) => void;
  build: (raw: string) => { target: SplitTarget } | { error: string };
  extra?: ReactNode;
  hint?: ReactNode;
}) {
  const rules = useRules();
  const [action, setAction] = useState<SplitAction>("direct");
  const [category, setCategory] = useState("");
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);

  const res = value.trim() ? build(value) : null;
  const dup = res && "target" in res && rules.some((r) => targetKey(r.target) === targetKey(res.target));
  const error = res && "error" in res ? res.error : dup ? t("A rule for this target already exists.") : null;

  const add = async () => {
    setTouched(true);
    if (!res || !("target" in res) || dup) return;
    setBusy(true);
    const ok = await useSplit.getState().mutate(
      (c) => ({
        ...c,
        rules: [
          ...c.rules,
          { id: uuid(), target: res.target, action, enabled: true, priority: DEFAULT_PRIORITY, category: category.trim() || null, note: null },
        ],
      }),
      t("Rule added"),
    );
    setBusy(false);
    if (ok) {
      onValueChange("");
      setTouched(false);
    }
  };

  return (
    <form
      className="rounded-2xl border border-border bg-surface p-4 shadow-soft"
      onSubmit={(e) => {
        e.preventDefault();
        void add();
      }}
    >
      <div className="flex flex-wrap items-start gap-2">
        <div className="min-w-[200px] flex-1">
          <Input
            value={value}
            onChange={(e) => {
              onValueChange(e.target.value);
              setTouched(false);
            }}
            onBlur={() => value.trim() && setTouched(true)}
            placeholder={placeholder}
            className="font-mono text-[13px]"
            dir="ltr"
            invalid={!!error && touched}
            aria-label={placeholder}
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
          />
        </div>
        {extra}
        <div className="flex h-9 items-center">
          <ActionToggle value={action} onChange={setAction} size="md" />
        </div>
        <Input value={category} onChange={(e) => setCategory(e.target.value)} placeholder={t("Category")} className="w-36" maxLength={40} list="split-categories" aria-label={t("Category")} />
        <Button type="submit" variant="primary" loading={busy} disabled={!value.trim() || (!!error && touched)}>
          {!busy && <Plus />} {t("Add rule")}
        </Button>
      </div>
      <div className="mt-2 min-h-4 text-xs">
        {error && (touched || dup) ? <span className="text-danger">{error}</span> : <span className="text-faint">{hint}</span>}
      </div>
    </form>
  );
}
