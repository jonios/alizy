import { useCallback, useEffect, useState } from "react";
import { api } from "../../lib/api";
import { useSettings } from "../../store/settings";
import { useStatus } from "../../store/status";

/** The address the internet sees, when the user turned that on in Settings
 * (asked of api.ipify.org); refreshed whenever the connection settles. */
export function usePublicIp(): { ip: string | null; failed: boolean } {
  const enabled = useSettings((s) => !!s.settings?.show_public_ip);
  const state = useStatus((s) => s.status?.state ?? null);
  const [ip, setIp] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  const load = useCallback(async () => {
    try {
      setIp(await api.publicIp());
      setFailed(false);
    } catch {
      setFailed(true);
    }
  }, []);

  useEffect(() => {
    if (!enabled || state === "connecting" || state === "disconnecting" || state === "reconnecting") return;
    void load();
  }, [enabled, state, load]);

  return enabled ? { ip, failed } : { ip: null, failed: false };
}
