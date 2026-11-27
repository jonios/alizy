import { Globe2, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Card } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { Skeleton } from "../../components/ui/skeleton";
import { api } from "../../lib/api";
import { errMsg } from "../../lib/utils";
import { useStatus } from "../../store/status";
import { t } from "../../i18n";

export function PublicIpCard() {
  const state = useStatus((s) => s.status?.state ?? null);
  const [ip, setIp] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setIp(await api.publicIp());
      setError(null);
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setLoading(false);
    }
  }, []);

  // refresh whenever the connection settles into a new stable state
  useEffect(() => {
    if (state === "connecting" || state === "disconnecting" || state === "reconnecting") return;
    void load();
  }, [state, load]);

  return (
    <Card className="p-5">
      <div className="flex items-start gap-3">
        <div className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-primary/12 text-primary">
          <Globe2 className="size-5" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-xs text-muted">{t("Public IP address")}</div>
          {loading && !ip && !error ? (
            <Skeleton className="mt-1.5 h-5 w-32" />
          ) : error ? (
            <div className="text-[13px] font-medium text-warning">{t("Couldn’t determine")}</div>
          ) : (
            <div dir="ltr" className="selectable truncate text-start font-mono text-[15px] font-semibold text-fg">{ip ?? "—"}</div>
          )}
        </div>
        <Button variant="ghost" size="icon-sm" onClick={load} disabled={loading} aria-label={t("Refresh public IP")}>
          <RefreshCw className={loading ? "animate-spin" : ""} />
        </Button>
      </div>
      <p className="mt-3 text-xs leading-relaxed text-faint">
        {error ? <span className="selectable text-muted">{error}</span> : t("As seen by api.ipify.org. Disable in Settings.")}
      </p>
    </Card>
  );
}
