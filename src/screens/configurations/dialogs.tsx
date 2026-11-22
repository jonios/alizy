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
      toast.success("Profile renamed");
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
            <DialogTitle>Rename profile</DialogTitle>
          </DialogHeader>
          <DialogBody>
            <Field label="Name" htmlFor="rename-input" error={error} hint="Shown in the app and the tray menu.">
              <Input id="rename-input" value={name} onChange={(e) => setName(e.target.value)} autoFocus maxLength={64} invalid={!!error} />
            </Field>
          </DialogBody>
          <DialogFooter>
            <Button variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button variant="primary" type="submit" loading={busy} disabled={!trimmed}>
              Rename
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
        title: "Export WireGuard configuration",
        defaultPath: `${safeFileName(name)}.conf`,
        filters: [{ name: "WireGuard", extensions: ["conf"] }],
      });
    } catch (e) {
      toast.error("Could not open the save dialog", e);
      return;
    }
    if (!path) return;
    setBusy(true);
    try {
      await api.exportProfile(id, path, includePrivate);
      toast.success("Configuration exported", path);
      onOpenChange(false);
    } catch (e) {
      toast.error("Export failed", e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog open={open} onOpenChange={(o) => !busy && onOpenChange(o)}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>Export “{name}”</DialogTitle>
          <DialogDescription>Save this profile as a wg-quick compatible .conf file.</DialogDescription>
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
                <KeyRound className="size-3.5 text-muted" /> Include private key
              </div>
              <div className="mt-0.5 text-xs leading-relaxed text-muted">
                Without it, the file contains <code className="font-mono">PrivateKey = &lt;redacted&gt;</code> and can’t be used to connect
                elsewhere.
              </div>
            </div>
          </label>
          {includePrivate && (
            <Alert tone="warning" title="The exported file will contain your private key">
              Anyone with this file can impersonate this device on the VPN. Store it securely and don’t share it.
            </Alert>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" onClick={run} loading={busy}>
            Choose location…
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
      title={`Delete “${name}”?`}
      description="The profile and its stored private key will be permanently removed from this device. This cannot be undone."
      confirmLabel="Delete profile"
      onConfirm={async () => {
        try {
          await api.remove(id);
          toast.success("Profile deleted", name);
          void useProfiles.getState().load();
          onDeleted?.();
        } catch (e) {
          toast.error("Could not delete profile", e);
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
      title="Back up all profiles"
      description="The backup file contains every profile including its private key. Anyone who obtains it can use your VPN identities — keep it somewhere safe and encrypted."
      confirmLabel="Choose location…"
      onConfirm={async () => {
        let path: string | null;
        try {
          path = await save({
            title: "Save Alizy backup",
            defaultPath: `alizy-backup-${new Date().toISOString().slice(0, 10)}.json`,
            filters: [{ name: "Alizy backup", extensions: ["json", "alizy"] }],
          });
        } catch (e) {
          toast.error("Could not open the save dialog", e);
          return false;
        }
        if (!path) return false;
        try {
          const n = await api.backupExport(path);
          toast.success(`Backed up ${n} profile${n === 1 ? "" : "s"}`, path);
        } catch (e) {
          toast.error("Backup failed", e);
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
      title: "Restore Alizy backup",
      multiple: false,
      filters: [{ name: "Alizy backup", extensions: ["json", "alizy"] }],
    });
  } catch (e) {
    toast.error("Could not open the file dialog", e);
    return;
  }
  const path = Array.isArray(picked) ? picked[0] : picked;
  if (!path) return;
  await useImportReport.getState().run(() => api.backupImport(path), "Backup restored");
}

export async function importFiles() {
  let picked: string | string[] | null;
  try {
    picked = await openDialog({ multiple: true, title: "Import WireGuard configurations", filters: [{ name: "WireGuard", extensions: ["conf"] }] });
  } catch (e) {
    toast.error("Could not open the file dialog", e);
    return;
  }
  const paths = picked === null ? [] : Array.isArray(picked) ? picked : [picked];
  if (!paths.length) return;
  await useImportReport.getState().run(() => api.importPaths(paths), "Import report");
}

export async function importFolder() {
  let picked: string | string[] | null;
  try {
    picked = await openDialog({ directory: true, multiple: false, title: "Import every .conf in a folder" });
  } catch (e) {
    toast.error("Could not open the folder dialog", e);
    return;
  }
  const path = Array.isArray(picked) ? picked[0] : picked;
  if (!path) return;
  await useImportReport.getState().run(() => api.importPaths([path]), "Folder import report");
}
