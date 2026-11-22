import { ArrowRight, CircleCheck, CircleHelp, CircleX, FlaskConical, Route } from "lucide-react";
import { useState } from "react";
import { Card, CardHeader } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { Badge } from "../../components/ui/badge";
import { Alert } from "../../components/ui/alert";
import { EmptyState } from "../../components/ui/empty-state";
import { api } from "../../lib/api";
import type { Decision, RouteTest } from "../../lib/types";
import { errMsg } from "../../lib/utils";
import { TIER_LABEL, targetText } from "./rules";
import { useRules } from "./store";

function ActionBadge({ action }: { action: Decision["action"] }) {
  return <Badge tone={action === "direct" ? "warning" : "primary"}>{action === "direct" ? "Direct" : "VPN"}</Badge>;
}

export function RoutingTest() {
  const rules = useRules();
  const [q, setQ] = useState("");
  const [res, setRes] = useState<RouteTest | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const ruleName = (id: string | null) => {
    if (!id) return "No rule (default)";
    const r = rules.find((x) => x.id === id);
    return r ? targetText(r.target) : `rule ${id.slice(0, 8)}`;
  };

  const run = async () => {
    const query = q.trim();
    if (!query) return;
    setBusy(true);
    try {
      setRes(await api.routeTest(query));
      setError(null);
    } catch (e) {
      setError(errMsg(e));
      setRes(null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader
        icon={<FlaskConical />}
        title="Routing test"
        description="Check how traffic to a domain or IP address is routed right now, and whether the kernel agrees."
      />
      <div className="px-5 pb-5">
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            void run();
          }}
        >
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="example.com or 203.0.113.5"
            className="flex-1 font-mono text-[13px]"
            aria-label="Domain or IP to test"
            spellCheck={false}
          />
          <Button type="submit" variant="primary" loading={busy} disabled={!q.trim()}>
            {!busy && <Route />} Test route
          </Button>
        </form>

        <div className="mt-4">
          {error ? (
            <Alert tone="danger" title="Test failed">
              <span className="selectable">{error}</span>
            </Alert>
          ) : !res ? (
            <EmptyState className="py-8" icon={<Route />} title="Enter a destination to test" description="Domains are resolved the same way Alizy resolves them for rules." />
          ) : (
            <div className="flex flex-col gap-3">
              {res.error && (
                <Alert tone="warning" title="Partial result">
                  <span className="selectable">{res.error}</span>
                </Alert>
              )}
              {res.domain_decision && (
                <div className="rounded-xl border border-border bg-surface-2/50 p-3.5">
                  <div className="flex flex-wrap items-center gap-2 text-[13px]">
                    <span className="font-medium text-fg">Domain decision</span>
                    <ActionBadge action={res.domain_decision.action} />
                    <Badge tone="outline">{TIER_LABEL[res.domain_decision.tier]}</Badge>
                    <span className="text-muted">matched {ruleName(res.domain_decision.rule_id)}</span>
                  </div>
                  <p className="mt-1 text-xs text-muted">{res.domain_decision.explanation}</p>
                  {res.cnames.length > 0 && (
                    <div className="selectable mt-2 flex flex-wrap items-center gap-1 font-mono text-[11px] text-muted">
                      <span className="text-fg">{res.query}</span>
                      {res.cnames.map((c) => (
                        <span key={c} className="flex items-center gap-1">
                          <ArrowRight className="size-3 text-faint" /> {c}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}
              {res.entries.length === 0 ? (
                <div className="py-4 text-center text-[13px] text-muted">No addresses to evaluate.</div>
              ) : (
                res.entries.map((e) => (
                  <div key={e.ip} className="rounded-xl border border-border bg-surface p-3.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="selectable font-mono text-[13px] font-medium text-fg">{e.ip}</span>
                      <ActionBadge action={e.decision.action} />
                      <Badge tone="outline">{TIER_LABEL[e.decision.tier]}</Badge>
                      <span className="ml-auto">
                        {e.in_kernel_direct_set === true ? (
                          <Badge tone="success">
                            <CircleCheck /> In kernel bypass set
                          </Badge>
                        ) : e.in_kernel_direct_set === false ? (
                          <Badge tone={e.decision.action === "direct" ? "danger" : "neutral"}>
                            <CircleX /> Not in bypass set
                          </Badge>
                        ) : (
                          <Badge tone="outline">
                            <CircleHelp /> Kernel state unknown
                          </Badge>
                        )}
                      </span>
                    </div>
                    <dl className="mt-2 grid grid-cols-[110px_1fr] gap-x-3 gap-y-1 text-xs">
                      <dt className="text-faint">Matched rule</dt>
                      <dd className="font-mono text-fg">{ruleName(e.decision.rule_id)}</dd>
                      <dt className="text-faint">Why</dt>
                      <dd className="text-muted">{e.decision.explanation}</dd>
                      <dt className="text-faint">Intended path</dt>
                      <dd className="text-fg">{e.intended}</dd>
                    </dl>
                    {e.kernel_route && (
                      <pre className="selectable mt-2 overflow-x-auto rounded-lg border border-border bg-background px-3 py-2 font-mono text-[11px] text-muted">
                        {e.kernel_route}
                      </pre>
                    )}
                    {e.decision.action === "direct" && e.in_kernel_direct_set === false && (
                      <p className="mt-2 text-xs text-danger">
                        A Direct rule matched but the address isn’t in the kernel bypass set — this traffic currently goes through the VPN.
                      </p>
                    )}
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      </div>
    </Card>
  );
}
