import { CircleAlert, CircleCheck, CircleX, Info, RefreshCw, Stethoscope, TriangleAlert } from "lucide-react";
import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Card, CardHeader } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { Badge, type BadgeTone } from "../../components/ui/badge";
import { Skeleton } from "../../components/ui/skeleton";
import { EmptyState } from "../../components/ui/empty-state";
import { CopyButton } from "../../components/ui/copy-button";
import { api } from "../../lib/api";
import type { Finding, Severity, SystemReport } from "../../lib/types";
import { cn, errMsg } from "../../lib/utils";
import { t, tk } from "../../i18n";

const DNS_LABEL = { systemd_resolved: "systemd-resolved", resolvconf: "resolvconf", resolv_conf_file: "/etc/resolv.conf" } as const;
const SEV: Record<Severity, { label: string; tone: BadgeTone; Icon: typeof Info; cls: string }> = {
  blocker: { label: tk("Blockers"), tone: "danger", Icon: CircleX, cls: "border-danger/30 bg-danger/[0.05]" },
  warning: { label: tk("Warnings"), tone: "warning", Icon: TriangleAlert, cls: "border-warning/30 bg-warning/[0.05]" },
  info: { label: tk("Notes"), tone: "primary", Icon: Info, cls: "border-border bg-surface-2/50" },
};

export function SystemCheck() {
  const [report, setReport] = useState<SystemReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const run = useCallback(async () => {
    setLoading(true);
    try {
      setReport(await api.systemReport());
      setError(null);
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void run();
  }, [run]);

  return (
    <Card id="system-check" className="scroll-mt-6 overflow-hidden">
      <CardHeader
        icon={<Stethoscope />}
        title={t("System Check")}
        description={t("Checks this machine for everything Alizy needs. Alizy never runs fixes for you.")}
        action={
          <Button size="sm" variant="secondary" onClick={() => void run()} loading={loading}>
            {!loading && <RefreshCw />} {t("Re-run")}
          </Button>
        }
      />
      {error && !report ? (
        <EmptyState tone="danger" icon={<CircleAlert />} title={t("System check failed")} description={<span className="selectable">{error}</span>} className="py-8" />
      ) : !report ? (
        <div className="grid grid-cols-2 gap-3 px-5 pb-5">
          {Array.from({ length: 6 }, (_, i) => (
            <Skeleton key={i} className="h-12 rounded-xl" />
          ))}
        </div>
      ) : (
        <div className="flex flex-col gap-5 px-5 pb-5">
          {error && <div className="text-xs text-danger">{t("Last re-run failed: {error}", { error })}</div>}
          <Findings findings={report.findings} />

          <div className="grid grid-cols-2 gap-x-6 gap-y-0 rounded-xl border border-border px-4 py-1 @3xl:grid-cols-3">
            <Fact label={t("Distribution")}>{report.os.pretty_name || report.os.name}</Fact>
            <Fact label={t("Kernel")} mono>
              {report.kernel}
            </Fact>
            <Fact label={t("Kernel WireGuard")}>
              <Badge tone={report.kernel_wireguard === "loaded" ? "success" : report.kernel_wireguard === "available" ? "primary" : "danger"}>
                {report.kernel_wireguard === "loaded" ? t("Loaded") : report.kernel_wireguard === "available" ? t("Available (not loaded)") : t("Missing")}
              </Badge>
            </Fact>
            <Fact label={t("Package manager")}>
              <span dir="ltr">{report.package_manager}</span>
            </Fact>
            <Fact label={t("DNS backend")}>
              <span dir="ltr">{DNS_LABEL[report.dns_backend]}</span>
            </Fact>
            <Fact label="resolv.conf" mono>
              {report.resolv_conf_target ?? t("regular file")}
            </Fact>
            <Fact label="iptables">
              <Badge tone={report.iptables === "absent" ? "outline" : "neutral"}>{report.iptables}</Badge>
            </Fact>
            <Fact label="firewalld">
              <OnOff on={report.firewalld_active} />
            </Fact>
            <Fact label="ufw">
              <OnOff on={report.ufw_active} />
            </Fact>
            <Fact label="NetworkManager">
              <OnOff on={report.network_manager_active} />
            </Fact>
            <Fact label="systemd-resolved">
              <OnOff on={report.resolved_active} />
            </Fact>
            <Fact label="systemd">
              <OnOff on={report.systemd} />
            </Fact>
          </div>

          <div>
            <div className="mb-2 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">{t("Executables")}</div>
            <div className="overflow-hidden rounded-xl border border-border">
              <table className="w-full text-[13px]">
                <tbody>
                  {Object.entries(report.executables)
                    .sort(([a], [b]) => a.localeCompare(b))
                    .map(([name, path]) => (
                      <tr key={name} className="border-b border-border last:border-b-0">
                        <td className="w-40 px-4 py-2 font-mono text-[12px] text-fg">
                          <span dir="ltr">{name}</span>
                        </td>
                        <td className="px-4 py-2">
                          {path ? (
                            <span className="flex items-center gap-2">
                              <CircleCheck className="size-3.5 shrink-0 text-success" />
                              <span dir="ltr" className="selectable truncate font-mono text-[12px] text-muted">
                                {path}
                              </span>
                            </span>
                          ) : (
                            <span className="flex items-center gap-2 text-danger">
                              <CircleX className="size-3.5" /> {t("Not found")}
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </Card>
  );
}

function Findings({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return (
      <div className="flex items-center gap-3 rounded-xl border border-success/30 bg-success/[0.06] px-4 py-3 text-[13px]">
        <CircleCheck className="size-5 text-success" />
        <div>
          <div className="font-medium text-fg">{t("Everything looks good")}</div>
          <div className="text-muted">{t("No problems were found on this system.")}</div>
        </div>
      </div>
    );
  }
  const order: Severity[] = ["blocker", "warning", "info"];
  return (
    <div className="flex flex-col gap-4">
      {order.map((sev) => {
        const list = findings.filter((f) => f.severity === sev);
        if (!list.length) return null;
        const s = SEV[sev];
        return (
          <div key={sev}>
            <div className="mb-2 flex items-center gap-2">
              <Badge tone={s.tone}>
                <s.Icon /> {t(s.label)}
              </Badge>
              <span className="text-xs text-faint">{list.length}</span>
            </div>
            <div className="flex flex-col gap-2">
              {list.map((f, i) => (
                <div key={i} className={cn("rounded-xl border p-3.5", s.cls)}>
                  <div className="text-[13px] text-fg">{f.message}</div>
                  {f.fix && (
                    <div className="mt-2.5">
                      <div className="mb-1 text-[11px] text-muted">{t("Run this in a terminal:")}</div>
                      <div className="flex items-start gap-2 rounded-lg border border-border bg-background px-3 py-2">
                        <pre dir="ltr" className="selectable min-w-0 flex-1 overflow-x-auto font-mono text-[12px] whitespace-pre-wrap text-fg">{f.fix}</pre>
                        <CopyButton text={f.fix} label={t("Copy command")} />
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function Fact({ label, children, mono }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="min-w-0 border-b border-border py-2.5 [&:nth-last-child(-n+3)]:border-b-0">
      <div className="text-[11px] text-faint">{label}</div>
      <div className={cn("selectable mt-0.5 truncate text-[13px] text-fg", mono && "font-mono text-[12px]")}>{mono ? <span dir="ltr">{children}</span> : children}</div>
    </div>
  );
}

function OnOff({ on }: { on: boolean }) {
  return <Badge tone={on ? "success" : "outline"}>{on ? t("Active") : t("Inactive")}</Badge>;
}
