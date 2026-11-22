import { Eye, EyeOff, KeyRound, ShieldAlert } from "lucide-react";
import { useEffect, useState } from "react";
import { Button } from "../../components/ui/button";
import { ConfirmDialog } from "../../components/ui/dialog";
import { CopyButton } from "../../components/ui/copy-button";
import { api } from "../../lib/api";
import { toast } from "../../store/toast";

const HIDE_AFTER = 30;

export function RevealKey({ id }: { id: string }) {
  const [confirm, setConfirm] = useState(false);
  const [key, setKey] = useState<string | null>(null);
  const [left, setLeft] = useState(HIDE_AFTER);

  // reset when switching profile
  useEffect(() => {
    setKey(null);
  }, [id]);

  useEffect(() => {
    if (!key) return;
    setLeft(HIDE_AFTER);
    const t = window.setInterval(() => {
      setLeft((l) => {
        if (l <= 1) {
          setKey(null);
          return HIDE_AFTER;
        }
        return l - 1;
      });
    }, 1000);
    return () => window.clearInterval(t);
  }, [key]);

  return (
    <div className="rounded-xl border border-border bg-surface p-4">
      <div className="flex items-center gap-3">
        <div className="flex size-9 items-center justify-center rounded-lg bg-surface-2 text-muted">
          <KeyRound className="size-4" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-[13px] font-medium text-fg">Private key</div>
          <div className="text-xs text-muted">
            {key ? `Visible — hides automatically in ${left} s` : "Stored securely and never shown unless you ask."}
          </div>
        </div>
        {key ? (
          <Button variant="secondary" size="sm" onClick={() => setKey(null)}>
            <EyeOff /> Hide
          </Button>
        ) : (
          <Button variant="secondary" size="sm" onClick={() => setConfirm(true)}>
            <Eye /> Reveal
          </Button>
        )}
      </div>
      {key && (
        <div className="mt-3 flex items-center gap-2 rounded-lg border border-warning/30 bg-warning/[0.06] px-3 py-2">
          <code className="selectable min-w-0 flex-1 font-mono text-[12px] break-all text-fg">{key}</code>
          <CopyButton text={key} label="Copy private key" />
          <div
            className="h-1 w-12 overflow-hidden rounded-full bg-surface-3"
            role="progressbar"
            aria-label="Time until hidden"
            aria-valuemin={0}
            aria-valuemax={HIDE_AFTER}
            aria-valuenow={left}
          >
            <div className="h-full bg-warning transition-[width] duration-1000 ease-linear" style={{ width: `${(left / HIDE_AFTER) * 100}%` }} />
          </div>
        </div>
      )}
      <ConfirmDialog
        open={confirm}
        onOpenChange={setConfirm}
        icon={<ShieldAlert />}
        destructive
        title="Reveal private key?"
        description="Anyone who sees this key can impersonate this device on the VPN. Make sure nobody is looking at your screen and that you are not screen-sharing. It will be hidden again after 30 seconds."
        confirmLabel="Reveal key"
        onConfirm={async () => {
          try {
            setKey(await api.revealPrivateKey(id));
          } catch (e) {
            toast.error("Could not reveal the private key", e);
            return false;
          }
        }}
      />
    </div>
  );
}
