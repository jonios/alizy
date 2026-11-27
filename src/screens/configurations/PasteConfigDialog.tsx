import { ChevronRight, CircleCheck, CircleAlert, Loader2, TriangleAlert } from "lucide-react";
import { useEffect, useState } from "react";
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "../../components/ui/dialog";
import { Button } from "../../components/ui/button";
import { Field, Input, Textarea } from "../../components/ui/input";
import { api } from "../../lib/api";
import type { ValidationResult } from "../../lib/types";
import { useDebounced } from "../../lib/hooks";
import { errMsg } from "../../lib/utils";
import { useImportReport } from "../../store/importReport";
import { t } from "../../i18n";

/** Shown only in a separate, read-only example panel — never inside an input. */
const EXAMPLE = `[Interface]
PrivateKey = …
Address = 10.0.0.2/32
DNS = 10.0.0.1

[Peer]
PublicKey = …
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.com:51820`;

/** Heuristic: text typed into the Name field that is really configuration. */
const looksLikeConfig = (s: string) => /\[(interface|peer)\]|privatekey|publickey|allowedips|endpoint\s*=|=/i.test(s);

export function PasteConfigDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const [text, setText] = useState("");
  const [name, setName] = useState("");
  const [result, setResult] = useState<ValidationResult | null>(null);
  const [validating, setValidating] = useState(false);
  const [validateError, setValidateError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const debounced = useDebounced(text, 400);

  useEffect(() => {
    if (!open) {
      setText("");
      setName("");
      setResult(null);
      setValidateError(null);
    }
  }, [open]);

  useEffect(() => {
    if (!debounced.trim()) {
      setResult(null);
      setValidateError(null);
      return;
    }
    let stale = false;
    setValidating(true);
    api
      .validateText(debounced)
      .then((r) => !stale && (setResult(r), setValidateError(null)))
      .catch((e) => !stale && (setResult(null), setValidateError(errMsg(e))))
      .finally(() => !stale && setValidating(false));
    return () => {
      stale = true;
    };
  }, [debounced]);

  const upToDate = debounced === text;
  const canImport = !!text.trim() && upToDate && !!result?.ok && !validating;

  const submit = async () => {
    setBusy(true);
    const r = await useImportReport.getState().run(() => api.importText(text, name.trim() || null), t("Import report"));
    setBusy(false);
    if (r) onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={(o) => !busy && onOpenChange(o)}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>{t("Paste configuration")}</DialogTitle>
          <DialogDescription>{t("Paste the contents of a WireGuard .conf file into the box below. It’s validated as you type.")}</DialogDescription>
        </DialogHeader>
        <DialogBody className="flex flex-col gap-4">
          <Field label={t("Configuration")} htmlFor="paste-text">
            <Textarea
              id="paste-text"
              autoFocus
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={t("Paste the full contents of your .conf file here. It starts with [Interface].")}
              spellCheck={false}
              autoComplete="off"
              dir="ltr"
              className="h-56 font-mono text-[12px] placeholder:font-sans placeholder:italic"
              invalid={!!result && !result.ok && upToDate}
            />
          </Field>
          <ValidationPanel text={text} upToDate={upToDate} validating={validating} result={result} error={validateError} />
          <details className="group rounded-xl border border-dashed border-border-strong bg-surface-2/40">
            <summary className="flex cursor-pointer list-none items-center gap-1.5 px-3.5 py-2 text-[12px] font-medium text-muted select-none">
              <ChevronRight className="size-3.5 transition-transform group-open:rotate-90 rtl:-scale-x-100 rtl:group-open:-rotate-90" />
              {t("Show an example configuration")}
              <span className="ms-1 rounded-md border border-border px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-faint">{t("Example only")}</span>
            </summary>
            <pre
              aria-label={t("Example WireGuard configuration (read-only, for reference)")}
              dir="ltr"
              className="selectable mx-3.5 mb-3 overflow-x-auto rounded-lg bg-background/60 px-3 py-2 font-mono text-[11.5px] leading-relaxed text-faint"
            >
              {EXAMPLE}
            </pre>
          </details>
          <Field
            label={t("Name (optional)")}
            htmlFor="paste-name"
            hint={
              looksLikeConfig(name)
                ? undefined
                : t("A short label for this profile. If empty, one is derived from the configuration.")
            }
          >
            <Input id="paste-name" value={name} onChange={(e) => setName(e.target.value)} placeholder={t("e.g. Home router")} maxLength={64} />
          </Field>
          {looksLikeConfig(name) && (
            <div className="flex items-start gap-2 rounded-xl border border-warning/30 bg-warning/[0.06] px-3.5 py-2.5 text-[13px]">
              <TriangleAlert className="mt-0.5 size-4 shrink-0 text-warning" />
              <span>{t("This looks like configuration text. Paste the configuration into the Configuration box above; this field is only a name.")}</span>
            </div>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
            {t("Cancel")}
          </Button>
          <Button variant="primary" onClick={submit} loading={busy} disabled={!canImport}>
            {t("Import")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ValidationPanel({
  text,
  upToDate,
  validating,
  result,
  error,
}: {
  text: string;
  upToDate: boolean;
  validating: boolean;
  result: ValidationResult | null;
  error: string | null;
}) {
  if (!text.trim()) return null;
  if (!upToDate || validating) {
    return (
      <div className="flex items-center gap-2 text-[13px] text-muted">
        <Loader2 className="size-4 animate-spin" /> {t("Validating…")}
      </div>
    );
  }
  if (error) {
    return (
      <div className="flex items-start gap-2 rounded-xl border border-danger/30 bg-danger/[0.06] px-3.5 py-2.5 text-[13px]">
        <CircleAlert className="mt-0.5 size-4 shrink-0 text-danger" />
        <span className="selectable text-fg">{t("Validation unavailable: {error}", { error })}</span>
      </div>
    );
  }
  if (!result) return null;
  return (
    <div className="flex flex-col gap-2">
      {result.ok ? (
        <div className="flex items-start gap-2 rounded-xl border border-success/30 bg-success/[0.06] px-3.5 py-2.5 text-[13px]">
          <CircleCheck className="mt-0.5 size-4 shrink-0 text-success" />
          <div className="text-fg">
            {t("Valid configuration")}
            {result.config && (
              <span className="text-muted">
                {" "}
                ·{" "}
                {result.config.peers.length === 1
                  ? t("{count} peer", { count: result.config.peers.length })
                  : t("{count} peers", { count: result.config.peers.length })}{" "}
                ·{" "}
                {result.config.addresses.length ? <span dir="ltr">{result.config.addresses.join(", ")}</span> : t("no addresses")}
              </span>
            )}
          </div>
        </div>
      ) : (
        <div className="flex items-start gap-2 rounded-xl border border-danger/30 bg-danger/[0.06] px-3.5 py-2.5 text-[13px]">
          <CircleAlert className="mt-0.5 size-4 shrink-0 text-danger" />
          <span className="selectable text-fg">{result.error ?? t("Invalid configuration")}</span>
        </div>
      )}
      {result.warnings.length > 0 && (
        <div className="rounded-xl border border-warning/30 bg-warning/[0.06] px-3.5 py-2.5 text-[13px]">
          <div className="flex items-center gap-2 font-medium text-fg">
            <TriangleAlert className="size-4 text-warning" />{" "}
            {result.warnings.length === 1
              ? t("{count} warning", { count: result.warnings.length })
              : t("{count} warnings", { count: result.warnings.length })}
          </div>
          <ul className="mt-1 list-disc space-y-0.5 ps-10 text-muted">
            {result.warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
