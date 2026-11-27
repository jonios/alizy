import { History, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Button } from "../../components/ui/button";
import { Badge } from "../../components/ui/badge";
import { SkeletonRows } from "../../components/ui/skeleton";
import { EmptyState } from "../../components/ui/empty-state";
import { api } from "../../lib/api";
import type { HistoryEntry } from "../../lib/types";
import { formatBytes, formatDateTime, formatDuration } from "../../lib/format";
import { useNow } from "../../lib/hooks";
import { errMsg } from "../../lib/utils";
import { useNav } from "../../store/nav";
import { useProfiles } from "../../store/profiles";
import { t } from "../../i18n";

export function HistoryTable() {
  const [rows, setRows] = useState<HistoryEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const now = useNow(1000);
  const openDetails = useNav((s) => s.openDetails);
  const profiles = useProfiles((s) => s.profiles);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setRows(await api.historyList(100));
      setError(null);
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    void load();
  }, [load]);

  if (rows === null) {
    return error ? (
      <EmptyState tone="danger" icon={<History />} title={t("History unavailable")} description={<span className="selectable">{error}</span>} action={<Button size="sm" variant="secondary" onClick={() => void load()}><RefreshCw /> {t("Try again")}</Button>} />
    ) : (
      <SkeletonRows rows={6} />
    );
  }
  if (rows.length === 0) {
    return <EmptyState icon={<History />} title={t("No connections yet")} description={t("Each VPN session is recorded here with its duration and data usage.")} />;
  }

  const totalRx = rows.reduce((n, r) => n + r.rx_bytes, 0);
  const totalTx = rows.reduce((n, r) => n + r.tx_bytes, 0);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between text-xs text-muted">
        <span>
          {rows.length === 1 ? t("{count} session", { count: rows.length }) : t("{count} sessions", { count: rows.length })} · ↓ {formatBytes(totalRx)} · ↑ {formatBytes(totalTx)}
        </span>
        <Button variant="ghost" size="sm" onClick={() => void load()} disabled={loading}>
          <RefreshCw className={loading ? "animate-spin" : ""} /> {t("Refresh")}
        </Button>
      </div>
      {error && <div className="text-xs text-danger">{t("Refresh failed: {error}", { error })}</div>}
      <div className="overflow-hidden rounded-2xl border border-border bg-surface shadow-card">
        <table className="w-full text-[13px]">
          <thead>
            <tr className="border-b border-border bg-surface-2/60 text-start text-[11px] font-medium tracking-wide text-faint uppercase">
              <th className="px-4 py-2">{t("Profile")}</th>
              <th className="px-4 py-2">{t("Started")}</th>
              <th className="px-4 py-2">{t("Duration")}</th>
              <th className="px-4 py-2 text-end">{t("Download")}</th>
              <th className="px-4 py-2 text-end">{t("Upload")}</th>
              <th className="px-4 py-2">{t("Ended")}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((h) => {
              const exists = profiles.some((p) => p.id === h.profile_id);
              return (
                <tr key={h.id} className="border-b border-border last:border-b-0 hover:bg-surface-2/40">
                  <td className="px-4 py-2.5">
                    {exists ? (
                      <button type="button" className="font-medium text-fg hover:text-primary hover:underline" onClick={() => openDetails(h.profile_id)}>
                        {h.profile_name}
                      </button>
                    ) : (
                      <span className="text-muted" title={t("Profile has been deleted")}>
                        {h.profile_name}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-muted tabular">{formatDateTime(h.started_at)}</td>
                  <td className="px-4 py-2.5 tabular">
                    {h.ended_at ? formatDuration(h.ended_at - h.started_at) : <Badge tone="success">{t("Active · {duration}", { duration: formatDuration(now - h.started_at) })}</Badge>}
                  </td>
                  <td className="px-4 py-2.5 text-end text-muted tabular">{formatBytes(h.rx_bytes)}</td>
                  <td className="px-4 py-2.5 text-end text-muted tabular">{formatBytes(h.tx_bytes)}</td>
                  <td className="px-4 py-2.5 text-xs text-muted">{h.end_reason ?? (h.ended_at ? "—" : "")}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
