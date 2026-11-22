import { ShieldAlert, ShieldQuestion } from "lucide-react";
import { useEffect, useState } from "react";
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "../../components/ui/dialog";
import { Button } from "../../components/ui/button";
import { api } from "../../lib/api";
import { useProfiles } from "../../store/profiles";
import { useSshFlow } from "../../store/sshFlow";
import { useStatus } from "../../store/status";
import { toast } from "../../store/toast";
import { SshProfileDialog } from "./SshProfileDialog";

/** Mounted once in App: the dialogs the SSH connect flow opens (host key trust, password re-entry). */
export function SshFlowDialogs() {
  const passwordFor = useSshFlow((s) => s.passwordFor);
  const closePassword = useSshFlow((s) => s.closePassword);
  const profiles = useProfiles((s) => s.profiles);
  const pwProfile = profiles.find((p) => p.id === passwordFor) ?? null;
  return (
    <>
      <HostKeyDialog />
      <SshProfileDialog
        open={!!pwProfile}
        onOpenChange={(o) => !o && closePassword()}
        profile={pwProfile}
        focusPassword
        onSaved={(p) => void useStatus.getState().connect(p.id)}
      />
    </>
  );
}

function HostKeyDialog() {
  const prompt = useSshFlow((s) => s.hostKey);
  const close = useSshFlow((s) => s.closeHostKey);
  const profile = useProfiles((s) => s.profiles.find((p) => p.id === prompt?.profileId));
  const [busy, setBusy] = useState(false);
  const [armed, setArmed] = useState(false);

  useEffect(() => {
    setArmed(false);
    setBusy(false);
  }, [prompt]);

  const open = !!prompt;
  const changed = !!prompt?.changed;
  const hostPort = profile?.ssh
    ? `${profile.ssh.host.includes(":") ? `[${profile.ssh.host}]` : profile.ssh.host}:${profile.ssh.port}`
    : "this server";

  const trust = async () => {
    if (!prompt) return;
    if (changed && !armed) return setArmed(true);
    setBusy(true);
    try {
      await api.trustHostKey(prompt.profileId, prompt.hostKey);
      const id = prompt.profileId;
      close();
      void useProfiles.getState().load();
      void useStatus.getState().connect(id);
    } catch (e) {
      toast.error("Could not save the host key", e);
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(o) => !o && !busy && close()}>
      <DialogContent size="md" hideClose onOpenAutoFocus={(e) => e.preventDefault()}>
        {prompt && (
          <>
            <DialogHeader className="pr-6">
              <div className="flex items-start gap-3">
                <div
                  className={`flex size-9 shrink-0 items-center justify-center rounded-full [&_svg]:size-[18px] ${
                    changed ? "bg-danger/12 text-danger" : "bg-primary/12 text-primary"
                  }`}
                >
                  {changed ? <ShieldAlert /> : <ShieldQuestion />}
                </div>
                <div className="flex min-w-0 flex-col gap-1.5">
                  <DialogTitle>{changed ? "Server identity changed" : "Verify server identity"}</DialogTitle>
                  <DialogDescription>
                    {changed
                      ? `The key for ${hostPort} is different from the one you trusted. This can mean someone is intercepting the connection.`
                      : `First connection to ${hostPort}. Make sure this fingerprint matches the server's:`}
                  </DialogDescription>
                </div>
              </div>
            </DialogHeader>
            <DialogBody>
              <div className="selectable rounded-xl border border-border bg-surface-2 px-3.5 py-3 font-mono text-[12px] break-all text-fg">
                {prompt.fingerprint}
              </div>
              {changed && profile?.ssh?.host_key_fingerprint && (
                <p className="mt-2 text-xs text-muted">
                  Previously trusted: <span className="selectable font-mono break-all">{profile.ssh.host_key_fingerprint}</span>
                </p>
              )}
            </DialogBody>
            <DialogFooter>
              <Button variant="ghost" autoFocus onClick={close} disabled={busy}>
                Cancel
              </Button>
              {changed ? (
                <Button variant="danger" onClick={trust} loading={busy}>
                  {armed ? "Click again to trust" : "Trust new key"}
                </Button>
              ) : (
                <Button variant="primary" onClick={trust} loading={busy}>
                  Trust and connect
                </Button>
              )}
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
