import { CircleCheck, ListOrdered, TriangleAlert } from "lucide-react";
import { useMemo } from "react";
import { Card, CardHeader } from "../../components/ui/card";
import { Badge } from "../../components/ui/badge";
import { EmptyState } from "../../components/ui/empty-state";
import { cn } from "../../lib/utils";
import { MATCH_LABEL, TIER_LABEL, precedenceSort, targetText, tierOf } from "./rules";
import { useSplit } from "./store";
import { useSplitState } from "./splitState";

export function ActiveRulesTab() {
  const data = useSplit((s) => s.data);
  const fw = useSplitState(data).firewall;
  const enabled = useMemo(() => precedenceSort((data?.config.rules ?? []).filter((r) => r.enabled && r.target.type !== "app")), [data]);
  const direct = data?.direct;
  const ranges = [...(direct?.v4 ?? []).map((r) => ({ fam: "IPv4", r })), ...(direct?.v6 ?? []).map((r) => ({ fam: "IPv6", r }))];

  return (
    <div className="flex flex-col gap-5">
      <Card className="overflow-hidden">
        <CardHeader
          icon={<ListOrdered />}
          title="Effective rules in precedence order"
          description="The first matching rule decides. IP rules (most specific prefix first) beat exact domains, which beat wildcard domains. Unmatched traffic uses the VPN."
          action={!data?.config.enabled && <Badge tone="warning">Split tunneling off</Badge>}
        />
        <div className="overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead>
              <tr className="border-y border-border bg-surface-2/60 text-left text-[11px] font-medium tracking-wide text-faint uppercase">
                <th className="w-12 px-5 py-2">#</th>
                <th className="px-3 py-2">Target</th>
                <th className="px-3 py-2">Tier</th>
                <th className="px-3 py-2">Priority</th>
                <th className="px-3 py-2">Category</th>
                <th className="px-5 py-2 text-right">Route</th>
              </tr>
            </thead>
            <tbody>
              {enabled.map((r, i) => (
                <tr key={r.id} className="border-b border-border last:border-b-0 hover:bg-surface-2/40">
                  <td className="px-5 py-2 text-faint tabular">{i + 1}</td>
                  <td className="selectable px-3 py-2 font-mono text-[12px] text-fg">{targetText(r.target)}</td>
                  <td className="px-3 py-2 text-muted">
                    {TIER_LABEL[tierOf(r.target)]}
                    {r.target.type === "domain" && r.target.mode !== "exact" && <span className="text-faint"> · {MATCH_LABEL[r.target.mode]}</span>}
                  </td>
                  <td className="px-3 py-2 text-muted tabular">{r.priority}</td>
                  <td className="px-3 py-2 text-muted">{r.category ?? "—"}</td>
                  <td className="px-5 py-2 text-right">
                    <Badge tone={r.action === "direct" ? "warning" : "primary"}>{r.action === "direct" ? "Direct" : "VPN"}</Badge>
                  </td>
                </tr>
              ))}
              <tr className="bg-surface-2/40">
                <td className="px-5 py-2.5 text-faint">∞</td>
                <td className="px-3 py-2.5 font-medium text-fg">Everything else</td>
                <td className="px-3 py-2.5 text-muted">Default</td>
                <td className="px-3 py-2.5 text-faint">—</td>
                <td className="px-3 py-2.5 text-faint">—</td>
                <td className="px-5 py-2.5 text-right">
                  <Badge tone="primary">VPN</Badge>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </Card>

      <Card className="overflow-hidden">
        <CardHeader
          title="Kernel bypass set"
          description={
            fw === "installed"
              ? "Address ranges installed in the firewall right now. This is what actually takes effect."
              : fw === "not-needed"
                ? "Address ranges compiled from your rules. They are installed in the firewall only while the VPN is connected or the kill switch is on."
                : "Address ranges compiled from your rules. The firewall state is not verified."
          }
          action={
            fw === "installed" ? (
              <Badge tone="success">
                <CircleCheck /> Installed · verified
              </Badge>
            ) : fw === "not-needed" ? (
              <Badge tone="outline">Not installed (VPN disconnected)</Badge>
            ) : (
              <Badge tone="warning">
                <TriangleAlert /> Not verified
              </Badge>
            )
          }
        />
        {ranges.length === 0 ? (
          <EmptyState
            className="py-8"
            title="No bypass ranges installed"
            description={
              data?.config.enabled
                ? "No enabled Direct rule currently resolves to an address, or the VPN isn’t connected."
                : "Split tunneling is off, so all traffic uses the VPN."
            }
          />
        ) : (
          <div className="grid grid-cols-1 gap-px border-t border-border bg-border @2xl:grid-cols-2">
            {ranges.map(({ fam, r }, i) => (
              <div key={i} className={cn("flex items-center gap-3 bg-surface px-5 py-2")}>
                <Badge tone="outline">{fam}</Badge>
                <span className="selectable min-w-0 truncate font-mono text-[12px] text-fg">
                  {r[0] === r[1] ? r[0] : `${r[0]} – ${r[1]}`}
                </span>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
