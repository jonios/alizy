import { ArrowDown, ArrowUp, Activity } from "lucide-react";
import type { ReactNode } from "react";
import { Card, CardHeader } from "../../components/ui/card";
import { formatBytes, formatRate } from "../../lib/format";
import { useStatus } from "../../store/status";
import { Sparkline } from "./Sparkline";
import { t } from "../../i18n";

export function TrafficCard({ active }: { active: boolean }) {
  const stats = useStatus((s) => s.status?.stats ?? null);
  const rates = useStatus((s) => s.rates);
  const latest = rates[rates.length - 1];
  const rx = active ? (latest?.rx ?? 0) : null;
  const tx = active ? (latest?.tx ?? 0) : null;

  return (
    <Card className="flex flex-col">
      <CardHeader
        icon={<Activity />}
        title={t("Traffic")}
        description={active ? t("Live throughput over the last minute") : t("Connect to see live throughput")}
      />
      <div className="grid grid-cols-2 gap-3 px-5">
        <Metric
          icon={<ArrowDown className="size-3.5" />}
          tone="text-primary bg-primary/12"
          label={t("Download")}
          rate={formatRate(rx)}
          total={stats && active ? formatBytes(stats.rx_bytes) : "—"}
        />
        <Metric
          icon={<ArrowUp className="size-3.5" />}
          tone="text-success bg-success/12"
          label={t("Upload")}
          rate={formatRate(tx)}
          total={stats && active ? formatBytes(stats.tx_bytes) : "—"}
        />
      </div>
      <div className="relative mt-3 h-[72px] overflow-hidden rounded-b-2xl">
        <Sparkline points={active ? rates : []} height={72} />
        {active && rates.length < 2 && (
          <div className="absolute inset-0 flex items-center justify-center text-xs text-faint">{t("Collecting samples…")}</div>
        )}
      </div>
    </Card>
  );
}

function Metric({ icon, tone, label, rate, total }: { icon: ReactNode; tone: string; label: string; rate: string; total: string }) {
  return (
    <div>
      <div className="flex items-center gap-1.5 text-xs text-muted">
        <span className={`flex size-5 items-center justify-center rounded-md ${tone}`}>{icon}</span>
        {label}
      </div>
      <div className="mt-1.5 text-xl font-semibold tracking-tight text-fg tabular">{rate}</div>
      <div className="text-xs text-faint tabular">{t("Total {total}", { total })}</div>
    </div>
  );
}
