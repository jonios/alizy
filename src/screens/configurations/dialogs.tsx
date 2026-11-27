import { open as openDialog, save } from "@tauri-apps/plugin-dialog";
import { useEffect, useState } from "react";
import { KeyRound, TriangleAlert } from "lucide-react";
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "../../components/ui/dialog";
import { Button } from "../../components/ui/button";
import { Input, Field } from "../../components/ui/input";
import { Alert } from "../../components/ui/alert";
import { api } from "../../lib/api";
import { errMsg } from "../../lib/utils";
import { toast } from "../../store/toast";
import { useProfiles } from "../../store/profiles";
import { useImportReport } from "../../store/importReport";
import { ConfirmDialog } from "../../components/ui/dialog";
import { t } from "../../i18n";

const safeFileName = (name: string) => name.replace(/[^\w.-]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 15) || "wg0";

/* ─── Rename ─── */
export function RenameDialog({
  open,
  onOpenChange,
  id,
  current,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  id: string;
  current: string;
}) {
  const [name, setName] = useState(current);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (open) {
      setName(current);
      setError(null);
    }
  }, [open, current]);
  const trimmed = name.trim();
  const submit = async () => {
    if (!trimmed || trimmed === current) return onOpenChange(false);
    setBusy(true);
    try {
      await api.rename(id, trimmed);
      toast.success(t("Profile renamed"));
      void useProfiles.getState().load();
      onOpenChange(false);
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="sm" aria-describedby={undefined}>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <DialogHeader>
            <DialogTitle>{t("Rename profile")}</DialogTitle>
          </DialogHeader>
          <DialogBody>
            <Field label={t("Name")} htmlFor="rename-input" error={error} hint={t("Shown in the app and the tray menu.")}>
              <Input id="rename-input" value={name} onChange={(e) => setName(e.target.value)} autoFocus maxLength={64} invalid={!!error} />
            </Field>
          </DialogBody>
          <DialogFooter>
            <Button variant="ghost" onClick={() => onOpenChange(false)}>
              {t("Cancel")}
            </Button>
            <Button variant="primary" type="submit" loading={busy} disabled={!trimmed}>
              {t("Rename")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/* ─── Export ─── */
export function ExportDialog({
  open,
  onOpenChange,
  id,
  name,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  id: string;
  name: string;
}) {
  const [includePrivate, setIncludePrivate] = useState(false);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (open) setIncludePrivate(false);
  }, [open]);
  const run = async () => {
    let path: string | null;
    try {
      path = await save({
        title: t("Export WireGuard configuration"),
        defaultPath: `${safeFileName(name)}.conf`,
        filters: [{ name: "WireGuard", extensions: ["conf"] }],
      });
    } catch (e) {
      toast.error(t("Could not open the save dialog"), e);
      return;
    }
    if (!path) return;
    setBusy(true);
    try {
      await api.exportProfile(id, path, includePrivate);
      toast.success(t("Configuration exported"), path);
      onOpenChange(false);
    } catch (e) {
      toast.error(t("Export failed"), e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog open={open} onOpenChange={(o) => !busy && onOpenChange(o)}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>{t("Export “{name}”", { name })}</DialogTitle>
          <DialogDescription>{t("Save this profile as a wg-quick compatible .conf file.")}</DialogDescription>
        </DialogHeader>
        <DialogBody className="flex flex-col gap-3">
          <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-border bg-surface-2/50 p-3.5 transition-colors hover:border-border-strong">
            <input
              type="checkbox"
              checked={includePrivate}
              onChange={(e) => setIncludePrivate(e.target.checked)}
              className="mt-0.5 size-4 accent-[var(--primary)]"
            />
            <div>
              <div className="flex items-center gap-1.5 text-[13px] font-medium text-fg">
                <KeyRound className="size-3.5 text-muted" /> {t("Include private key")}
              </div>
              <div className="mt-0.5 text-xs leading-relaxed text-muted">
                {t("Without it, the file contains")}{" "}
                <code className="font-mono" dir="ltr">
                  PrivateKey = &lt;redacted&gt;
                </code>{" "}
                {t("and can’t be used to connect elsewhere.")}
              </div>
            </div>
          </label>
          {includePrivate && (
            <Alert tone="warning" title={t("The exported file will contain your private key")}>
              {t("Anyone with this file can impersonate this device on the VPN. Store it securely and don’t share it.")}
            </Alert>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
            {t("Cancel")}
          </Button>
          <Button variant="primary" onClick={run} loading={busy}>
            {t("Choose location…")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/* ─── Delete ─── */
export function DeleteProfileDialog({
  open,
  onOpenChange,
  id,
  name,
  onDeleted,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  id: string;
  name: string;
  onDeleted?: () => void;
}) {
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      destructive
      icon={<TriangleAlert />}
      title={t("Delete “{name}”?", { name })}
      description={t("The profile and its stored private key will be permanently removed from this device. This cannot be undone.")}
      confirmLabel={t("Delete profile")}
      onConfirm={async () => {
        try {
          await api.remove(id);
          toast.success(t("Profile deleted"), name);
          void useProfiles.getState().load();
          onDeleted?.();
        } catch (e) {
          toast.error(t("Could not delete profile"), e);
          return false;
        }
      }}
    />
  );
}

/* ─── Backup / restore ─── */
export function BackupDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      icon={<KeyRound />}
      title={t("Back up all profiles")}
      description={t("The backup file contains every profile including its private key. Anyone who obtains it can use your VPN identities — keep it somewhere safe and encrypted.")}
      confirmLabel={t("Choose location…")}
      onConfirm={async () => {
        let path: string | null;
        try {
          path = await save({
            title: t("Save Alizy backup"),
            defaultPath: `alizy-backup-${new Date().toISOString().slice(0, 10)}.json`,
            filters: [{ name: t("Alizy backup"), extensions: ["json", "alizy"] }],
          });
        } catch (e) {
          toast.error(t("Could not open the save dialog"), e);
          return false;
        }
        if (!path) return false;
        try {
          const n = await api.backupExport(path);
          toast.success(n === 1 ? t("Backed up {count} profile", { count: n }) : t("Backed up {count} profiles", { count: n }), path);
        } catch (e) {
          toast.error(t("Backup failed"), e);
          return false;
        }
      }}
    />
  );
}

export async function restoreBackup() {
  let picked: string | string[] | null;
  try {
    picked = await openDialog({
      title: t("Restore Alizy backup"),
      multiple: false,
      filters: [{ name: t("Alizy backup"), extensions: ["json", "alizy"] }],
    });
  } catch (e) {
    toast.error(t("Could not open the file dialog"), e);
    return;
  }
  const path = Array.isArray(picked) ? picked[0] : picked;
  if (!path) return;
  await useImportReport.getState().run(() => api.backupImport(path), t("Backup restored"));
}

export async function importFiles() {
  let picked: string | string[] | null;
  try {
    picked = await openDialog({ multiple: true, title: t("Import WireGuard configurations"), filters: [{ name: "WireGuard", extensions: ["conf"] }] });
  } catch (e) {
    toast.error(t("Could not open the file dialog"), e);
    return;
  }
  const paths = picked === null ? [] : Array.isArray(picked) ? picked : [picked];
  if (!paths.length) return;
  await useImportReport.getState().run(() => api.importPaths(paths), t("Import report"));
}

export async function importFolder() {
  let picked: string | string[] | null;
  try {
    picked = await openDialog({ directory: true, multiple: false, title: t("Import every .conf in a folder") });
  } catch (e) {
    toast.error(t("Could not open the folder dialog"), e);
    return;
  }
  const path = Array.isArray(picked) ? picked[0] : picked;
  if (!path) return;
  await useImportReport.getState().run(() => api.importPaths([path]), t("Folder import report"));
}
