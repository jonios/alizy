import { ShieldCheck, ShieldOff } from "lucide-react";
import { ConfirmDialog } from "./ui/dialog";
import { usePolicy } from "../store/policy";
import { t } from "../i18n";

/** Confirmation before turning the kill switch on or off; saves the policy on confirm. */
export function KillSwitchConfirm({ which, onClose }: { which: "on" | "off" | null; onClose: () => void }) {
  const policy = usePolicy((s) => s.policy);
  const save = usePolicy((s) => s.save);
  return (
    <>
      <ConfirmDialog
        open={which === "on"}
        onOpenChange={(o) => !o && onClose()}
        icon={<ShieldCheck />}
        title={t("Turn on the kill switch?")}
        description={t(
          "All internet traffic that doesn’t go through the VPN will be blocked by the system firewall. This stays in effect even when the Alizy window is closed, after a crash, and while disconnected — you’ll have no internet until you connect or turn this off.",
        )}
        confirmLabel={t("Turn on kill switch")}
        onConfirm={async () => {
          if (!policy) return;
          return (await save({ ...policy, kill_switch: true })) ? undefined : false;
        }}
      >
        {policy && !policy.allow_lan && <p className="text-xs text-muted">{t("Local network access is currently blocked too. You can allow it below.")}</p>}
      </ConfirmDialog>
      <ConfirmDialog
        open={which === "off"}
        onOpenChange={(o) => !o && onClose()}
        destructive
        icon={<ShieldOff />}
        title={t("Turn off the kill switch?")}
        description={t("If the VPN connection drops, your traffic will immediately flow through your regular connection and may expose your real IP address.")}
        confirmLabel={t("Turn off")}
        onConfirm={async () => {
          if (!policy) return;
          return (await save({ ...policy, kill_switch: false })) ? undefined : false;
        }}
      />
    </>
  );
}
