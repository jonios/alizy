import { Info } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Dialog, DialogBody, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "../../components/ui/dialog";
import { Button } from "../../components/ui/button";
import { Field, Input } from "../../components/ui/input";
import { api } from "../../lib/api";
import type { ProfileSummary } from "../../lib/types";
import { validateSsh, type SshFields } from "../../lib/validate";
import { errMsg } from "../../lib/utils";
import { useProfiles } from "../../store/profiles";
import { toast } from "../../store/toast";

export const SSH_UDP_NOTE = "Only TCP traffic is carried over SSH. UDP (e.g. QUIC, voice and video calls, games) is blocked while connected.";

export function UdpNote({ className }: { className?: string }) {
  return (
    <div className={`flex items-start gap-2 rounded-xl border border-warning/30 bg-warning/[0.06] px-3.5 py-2.5 text-[13px] ${className ?? ""}`}>
      <Info className="mt-0.5 size-4 shrink-0 text-warning" />
      <span className="text-fg">{SSH_UDP_NOTE}</span>
    </div>
  );
}

const EMPTY: SshFields = { name: "", host: "", port: "22", username: "", password: "" };

/**
 * Create (profile omitted) or edit an SSH connection. `focusPassword` is used by the
 * connect flow when the stored password is unusable; `onSaved` then retries the connect.
 */
export function SshProfileDialog({
  open,
  onOpenChange,
  profile,
  focusPassword,
  onSaved,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  profile?: ProfileSummary | null;
  focusPassword?: boolean;
  onSaved?: (p: ProfileSummary) => void;
}) {
  // The form (and the typed password in its state) exists only while the dialog is open.
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!open) setBusy(false);
  }, [open]);
  return (
    <Dialog open={open} onOpenChange={(o) => !busy && onOpenChange(o)}>
      {open && <SshDialogBody onOpenChange={onOpenChange} onBusyChange={setBusy} profile={profile} focusPassword={focusPassword} onSaved={onSaved} />}
    </Dialog>
  );
}

function SshDialogBody({
  onOpenChange,
  onBusyChange,
  profile,
  focusPassword,
  onSaved,
}: {
  onOpenChange: (o: boolean) => void;
  onBusyChange: (b: boolean) => void;
  profile?: ProfileSummary | null;
  focusPassword?: boolean;
  onSaved?: (p: ProfileSummary) => void;
}) {
  const editing = !!profile;
  const [f, setF] = useState<SshFields>(() =>
    profile?.ssh
      ? { name: profile.name, host: profile.ssh.host, port: String(profile.ssh.port), username: profile.ssh.username, password: "" }
      : EMPTY,
  );
  const [touched, setTouched] = useState<Partial<Record<keyof SshFields, boolean>>>({});
  const [submitted, setSubmitted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const passwordRef = useRef<HTMLInputElement>(null);
  const nameRef = useRef<HTMLInputElement>(null);

  const errors = validateSsh(f, { editing });
  const show = (k: keyof SshFields) => (submitted || touched[k] ? errors[k] : undefined);
  const set = (k: keyof SshFields) => (e: React.ChangeEvent<HTMLInputElement>) => setF((p) => ({ ...p, [k]: e.target.value }));
  const blur = (k: keyof SshFields) => () => setTouched((t) => ({ ...t, [k]: true }));

  const submit = async () => {
    setSubmitted(true);
    if (Object.keys(errors).length > 0) return;
    setBusy(true);
    onBusyChange(true);
    setError(null);
    try {
      const port = Number(f.port.trim());
      const host = f.host.trim();
      const saved = profile
        ? await api.updateSsh(profile.id, f.name.trim(), host, port, f.username, f.password || null)
        : await api.createSsh(f.name.trim(), host, port, f.username, f.password);
      setF((p) => ({ ...p, password: "" }));
      toast.success(profile ? "Connection updated" : "Connection added", saved.name);
      void useProfiles.getState().load();
      onOpenChange(false);
      onSaved?.(saved);
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
      onBusyChange(false);
    }
  };

  return (
    <>
      <DialogContent
        size="md"
        aria-describedby={undefined}
        onEscapeKeyDown={(e) => busy && e.preventDefault()}
        onInteractOutside={(e) => busy && e.preventDefault()}
        onOpenAutoFocus={(e) => {
          e.preventDefault();
          (focusPassword ? passwordRef : nameRef).current?.focus();
        }}
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
          noValidate
        >
          <DialogHeader>
            <DialogTitle>{editing ? "Edit SSH connection" : "New SSH connection"}</DialogTitle>
          </DialogHeader>
          <DialogBody className="flex flex-col gap-4">
            <Field label="Connection Name" htmlFor="ssh-name" error={show("name")}>
              <Input id="ssh-name" ref={nameRef} value={f.name} onChange={set("name")} onBlur={blur("name")} maxLength={64} invalid={!!show("name")} autoComplete="off" />
            </Field>
            <div className="grid grid-cols-[minmax(0,1fr)_7rem] gap-3">
              <Field label="Server IP Address" htmlFor="ssh-host" error={show("host")}>
                <Input
                  id="ssh-host"
                  value={f.host}
                  onChange={set("host")}
                  onBlur={blur("host")}
                  invalid={!!show("host")}
                  spellCheck={false}
                  autoComplete="off"
                  className="font-mono"
                />
              </Field>
              <Field label="Port" htmlFor="ssh-port" error={show("port")}>
                <Input
                  id="ssh-port"
                  value={f.port}
                  onChange={set("port")}
                  onBlur={blur("port")}
                  invalid={!!show("port")}
                  inputMode="numeric"
                  autoComplete="off"
                  className="font-mono"
                />
              </Field>
            </div>
            <Field label="Username" htmlFor="ssh-user" error={show("username")}>
              <Input
                id="ssh-user"
                value={f.username}
                onChange={set("username")}
                onBlur={blur("username")}
                invalid={!!show("username")}
                spellCheck={false}
                autoComplete="off"
                autoCapitalize="none"
              />
            </Field>
            <Field label="Password" htmlFor="ssh-password" error={show("password")}>
              <Input
                id="ssh-password"
                ref={passwordRef}
                type="password"
                value={f.password}
                onChange={set("password")}
                onBlur={blur("password")}
                invalid={!!show("password")}
                placeholder={editing ? "Leave blank to keep the current password" : undefined}
                autoComplete="new-password"
              />
            </Field>
            <UdpNote />
            {error && (
              <p className="selectable text-[13px] text-danger" role="alert">
                {error}
              </p>
            )}
          </DialogBody>
          <DialogFooter>
            <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
              Cancel
            </Button>
            <Button variant="primary" type="submit" loading={busy}>
              {editing ? "Save" : "Add"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </>
  );
}
