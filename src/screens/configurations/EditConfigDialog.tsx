import { Info, TriangleAlert } from "lucide-react";
import { useEffect, useState } from "react";
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "../../components/ui/dialog";
import { Button } from "../../components/ui/button";
import { Textarea } from "../../components/ui/input";
import { Alert } from "../../components/ui/alert";
import { api } from "../../lib/api";
import { errMsg } from "../../lib/utils";
import { toast } from "../../store/toast";
import { useProfiles } from "../../store/profiles";
import { t } from "../../i18n";

export function EditConfigDialog({
  open,
  onOpenChange,
  id,
  name,
  initial,
  onSaved,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  id: string;
  name: string;
  initial: string;
  onSaved: () => void;
}) {
  const [text, setText] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [warnings, setWarnings] = useState<string[] | null>(null);

  useEffect(() => {
    if (open) {
      setText(initial);
      setError(null);
      setWarnings(null);
    }
  }, [open, initial]);

  const dirty = text !== initial;
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      const w = await api.updateText(id, text);
      void useProfiles.getState().load();
      onSaved();
      if (w.length) {
        setWarnings(w);
        toast.warning(t("Configuration saved with warnings"));
      } else {
        toast.success(t("Configuration saved"));
        onOpenChange(false);
      }
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(o) => !busy && onOpenChange(o)}>
      <DialogContent size="xl">
        <DialogHeader>
          <DialogTitle>{t("Edit configuration · {name}", { name })}</DialogTitle>
          <DialogDescription>{t("Changes apply the next time this profile connects.")}</DialogDescription>
        </DialogHeader>
        <DialogBody className="flex flex-col gap-3">
          <Alert tone="info" icon={<Info />}>
            {t("Secrets are hidden. Leave the redacted keys unchanged to keep the stored key, or replace them with a new key:")}{" "}
            <code className="font-mono text-fg" dir="ltr">
              PrivateKey = &lt;redacted&gt;
            </code>
            ,{" "}
            <code className="font-mono text-fg" dir="ltr">
              PresharedKey
            </code>
          </Alert>
          <Textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            spellCheck={false}
            autoComplete="off"
            dir="ltr"
            className="h-[min(52vh,440px)] font-mono text-[12px] leading-[1.6]"
            aria-label={t("Configuration text")}
            invalid={!!error}
          />
          {error && (
            <Alert tone="danger" title={t("Couldn’t save")}>
              <span className="selectable">{error}</span>
            </Alert>
          )}
          {warnings && warnings.length > 0 && (
            <Alert tone="warning" icon={<TriangleAlert />} title={t("Saved with warnings")}>
              <ul className="list-disc ps-4">
                {warnings.map((w, i) => (
                  <li key={i}>{w}</li>
                ))}
              </ul>
            </Alert>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
            {warnings ? t("Close") : t("Cancel")}
          </Button>
          <Button variant="primary" onClick={save} loading={busy} disabled={!dirty || !text.trim()}>
            {t("Save changes")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
