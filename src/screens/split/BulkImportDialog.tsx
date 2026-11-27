import { CircleAlert, FileUp, Upload } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "../../components/ui/dialog";
import { Button } from "../../components/ui/button";
import { Textarea } from "../../components/ui/input";
import { Badge } from "../../components/ui/badge";
import { api } from "../../lib/api";
import type { SplitAction, SplitImportResult } from "../../lib/types";
import { errMsg, uuid } from "../../lib/utils";
import { useDebounced } from "../../lib/hooks";
import { ActionToggle } from "./RuleRow";
import { DEFAULT_PRIORITY, MATCH_LABEL, targetKey, targetText } from "./rules";
import { useRules, useSplit } from "./store";
import { t, tk } from "../../i18n";

const EXAMPLE_COMMENT = tk("# one entry per line — comments start with #");
const EXAMPLE_ENTRIES = `bank.example.com
*.cdn.example.net
192.0.2.10
2001:db8::/32`;

export function BulkImportDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const [text, setText] = useState("");
  const [action, setAction] = useState<SplitAction>("direct");
  const [result, setResult] = useState<SplitImportResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [parsing, setParsing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const debounced = useDebounced(text, 400);
  const existing = useRules();

  useEffect(() => {
    if (!open) {
      setText("");
      setResult(null);
      setError(null);
      setFileName(null);
    }
  }, [open]);

  useEffect(() => {
    if (!debounced.trim()) {
      setResult(null);
      setError(null);
      return;
    }
    let stale = false;
    setParsing(true);
    api
      .splitParseImport(debounced, action)
      .then((r) => !stale && (setResult(r), setError(null)))
      .catch((e) => !stale && (setResult(null), setError(errMsg(e))))
      .finally(() => !stale && setParsing(false));
    return () => {
      stale = true;
    };
  }, [debounced, action]);

  const existingKeys = new Set(existing.map((r) => targetKey(r.target)));
  const fresh = (result?.rules ?? []).filter((r) => !existingKeys.has(targetKey(r.target)));
  const alreadyPresent = (result?.rules.length ?? 0) - fresh.length;

  const onFile = async (f: File | undefined) => {
    if (!f) return;
    if (f.size > 5 * 1024 * 1024) {
      setError(t("File is larger than 5 MB."));
      return;
    }
    try {
      setText(await f.text());
      setFileName(f.name);
    } catch (e) {
      setError(errMsg(e));
    }
  };

  const confirm = async () => {
    if (!fresh.length) return;
    setBusy(true);
    const ok = await useSplit.getState().mutate(
      (c) => ({
        ...c,
        rules: [
          ...c.rules,
          ...fresh.map((r) => ({
            id: uuid(),
            target: r.target,
            action: r.action,
            enabled: true,
            priority: DEFAULT_PRIORITY,
            category: r.category,
            note: null,
          })),
        ],
      }),
      fresh.length === 1 ? t("Imported {count} rule", { count: fresh.length }) : t("Imported {count} rules", { count: fresh.length }),
    );
    setBusy(false);
    if (ok) onOpenChange(false);
  };

  const upToDate = debounced === text && !parsing;

  return (
    <Dialog open={open} onOpenChange={(o) => !busy && onOpenChange(o)}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>{t("Bulk import rules")}</DialogTitle>
          <DialogDescription>{t("Paste domains, IPs and CIDR ranges (plain text, CSV or JSON), or load a file. Nothing is saved until you confirm.")}</DialogDescription>
        </DialogHeader>
        <DialogBody className="flex flex-col gap-4">
          <div className="flex flex-wrap items-center gap-3">
            <input
              ref={fileRef}
              type="file"
              accept=".txt,.csv,.json,text/plain,text/csv,application/json"
              className="hidden"
              onChange={(e) => {
                void onFile(e.target.files?.[0]);
                e.target.value = "";
              }}
            />
            <Button variant="secondary" size="sm" onClick={() => fileRef.current?.click()}>
              <FileUp /> {t("Load file…")}
            </Button>
            {fileName && <span className="truncate text-xs text-muted">{fileName}</span>}
            <div className="ms-auto flex items-center gap-2 text-xs text-muted">
              {t("Default action")}
              <ActionToggle value={action} onChange={setAction} size="md" />
            </div>
          </div>
          <Textarea
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              setFileName(null);
            }}
            placeholder={`${t(EXAMPLE_COMMENT)}\n${EXAMPLE_ENTRIES}`}
            spellCheck={false}
            className="h-48 font-mono text-[12px]"
            dir="ltr"
            aria-label={t("Rules to import")}
          />

          {error && (
            <div className="flex items-start gap-2 rounded-xl border border-danger/30 bg-danger/[0.06] px-3.5 py-2.5 text-[13px]">
              <CircleAlert className="mt-0.5 size-4 shrink-0 text-danger" />
              <span className="selectable text-fg">{error}</span>
            </div>
          )}

          {result && upToDate && (
            <div className="flex flex-col gap-3">
              <div className="grid grid-cols-4 gap-2">
                <Stat label={t("New rules")} value={fresh.length} cls="text-success" />
                <Stat label={t("Already present")} value={alreadyPresent} cls="text-fg" />
                <Stat label={t("Duplicates in input")} value={result.duplicates} cls="text-fg" />
                <Stat label={t("Errors")} value={result.errors.length} cls="text-danger" />
              </div>
              {fresh.length > 0 && (
                <div className="max-h-44 overflow-y-auto rounded-xl border border-border">
                  {fresh.slice(0, 200).map((r, i) => (
                    <div key={i} className="flex items-center gap-2 border-b border-border px-3 py-1.5 text-[12px] last:border-b-0">
                      <span className="selectable min-w-0 flex-1 truncate font-mono text-fg" dir="ltr">{targetText(r.target)}</span>
                      {r.target.type === "domain" && <Badge tone="outline">{t(MATCH_LABEL[r.target.mode])}</Badge>}
                      {r.category && <Badge>{r.category}</Badge>}
                      <Badge tone={r.action === "direct" ? "warning" : "primary"}>{r.action === "direct" ? t("Direct") : t("VPN")}</Badge>
                    </div>
                  ))}
                  {fresh.length > 200 && <div className="px-3 py-1.5 text-xs text-faint">{t("…and {count} more", { count: fresh.length - 200 })}</div>}
                </div>
              )}
              {result.errors.length > 0 && (
                <div className="max-h-32 overflow-y-auto rounded-xl border border-danger/25 bg-danger/[0.05] px-3 py-2">
                  <ul className="list-disc space-y-0.5 ps-4 text-[12px] text-muted">
                    {result.errors.map((e, i) => (
                      <li key={i} className="selectable">
                        {e}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
            {t("Cancel")}
          </Button>
          <Button variant="primary" onClick={confirm} loading={busy} disabled={!upToDate || fresh.length === 0}>
            {!busy && <Upload />}{" "}
            {fresh.length === 0
              ? t("Import rules")
              : fresh.length === 1
                ? t("Import {count} rule", { count: fresh.length })
                : t("Import {count} rules", { count: fresh.length })}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function Stat({ label, value, cls }: { label: string; value: number; cls: string }) {
  return (
    <div className="rounded-xl border border-border bg-surface-2/60 px-3 py-2">
      <div className={`text-lg font-semibold tabular ${value === 0 ? "text-faint" : cls}`}>{value}</div>
      <div className="text-[11px] text-muted">{label}</div>
    </div>
  );
}
