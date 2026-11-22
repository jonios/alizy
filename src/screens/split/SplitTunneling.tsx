import { save } from "@tauri-apps/plugin-dialog";
import {
  AppWindow,
  Binary,
  ChevronRight,
  Download,
  FlaskConical,
  Globe,
  Info,
  ListOrdered,
  RefreshCw,
  Split,
  Tags,
  TriangleAlert,
  Upload,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { ScreenBody, ScreenHeader } from "../../components/ScreenHeader";
import { Button } from "../../components/ui/button";
import { Switch } from "../../components/ui/switch";
import { Card } from "../../components/ui/card";
import { Badge } from "../../components/ui/badge";
import { Skeleton } from "../../components/ui/skeleton";
import { EmptyState } from "../../components/ui/empty-state";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../../components/ui/tabs";
import { useInterval } from "../../lib/hooks";
import { cn } from "../../lib/utils";
import { toast } from "../../store/toast";
import { api } from "../../lib/api";
import { useSplit } from "./store";
import { useSplitState, type SplitData } from "./splitState";
import { targetText } from "./rules";
import { DomainsTab } from "./DomainsTab";
import { IpTab } from "./IpTab";
import { AppsTab } from "./AppsTab";
import { CategoriesTab } from "./CategoriesTab";
import { ActiveRulesTab } from "./ActiveRulesTab";
import { RoutingTest } from "./RoutingTest";
import { BulkImportDialog } from "./BulkImportDialog";

export function SplitTunneling() {
  const { data, loaded, error, saving, load, mutate } = useSplit();
  const [bulkOpen, setBulkOpen] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [tab, setTab] = useState("domains");

  useEffect(() => {
    void load();
  }, [load]);
  useInterval(() => void load(), 5000);

  const rules = data?.config.rules ?? [];
  const counts = useMemo(
    () => ({
      domain: rules.filter((r) => r.target.type === "domain").length,
      ip: rules.filter((r) => r.target.type === "ip").length,
      active: rules.filter((r) => r.enabled && r.target.type !== "app").length,
      categories: new Set(rules.map((r) => r.category ?? "")).size,
    }),
    [rules],
  );
  const categories = useMemo(() => [...new Set(rules.map((r) => r.category).filter((c): c is string => !!c))], [rules]);

  const doExport = async () => {
    let path: string | null;
    try {
      path = await save({
        title: "Export split tunneling rules",
        defaultPath: "alizy-split-rules.json",
        filters: [{ name: "JSON", extensions: ["json"] }],
      });
    } catch (e) {
      toast.error("Could not open the save dialog", e);
      return;
    }
    if (!path) return;
    setExporting(true);
    try {
      const n = await api.splitExport(path);
      toast.success(`Exported ${n} rule${n === 1 ? "" : "s"}`, path);
    } catch (e) {
      toast.error("Export failed", e);
    } finally {
      setExporting(false);
    }
  };

  return (
    <>
      <ScreenHeader
        title="Split Tunneling"
        description="Choose which destinations bypass the VPN."
        actions={
          <>
            {saving && (
              <span className="flex items-center gap-1.5 text-xs text-muted">
                <RefreshCw className="size-3.5 animate-spin" /> Saving…
              </span>
            )}
            <Button variant="ghost" size="sm" onClick={doExport} loading={exporting} disabled={!data}>
              {!exporting && <Download />} Export
            </Button>
            <Button variant="secondary" size="sm" onClick={() => setBulkOpen(true)} disabled={!data}>
              <Upload /> Bulk import
            </Button>
          </>
        }
      />
      <ScreenBody className="flex flex-col gap-5">
        {!loaded ? (
          <div className="flex flex-col gap-4">
            <Skeleton className="h-24 w-full rounded-2xl" />
            <Skeleton className="h-10 w-full max-w-[520px] rounded-xl" />
            <Skeleton className="h-64 w-full rounded-2xl" />
          </div>
        ) : !data ? (
          <EmptyState
            tone="danger"
            icon={<Split />}
            title="Couldn’t load split tunneling"
            description={<span className="selectable">{error}</span>}
            action={
              <Button variant="secondary" size="sm" onClick={() => void load()}>
                <RefreshCw /> Try again
              </Button>
            }
          />
        ) : (
          <>
            {error && (
              <div className="flex items-center gap-2 rounded-xl border border-warning/30 bg-warning/[0.06] px-4 py-2 text-xs text-muted">
                <TriangleAlert className="size-3.5 text-warning" /> Live refresh failed: <span className="selectable">{error}</span>
              </div>
            )}

            <Card className="relative overflow-hidden p-5">
              <div
                className={cn(
                  "pointer-events-none absolute inset-y-0 left-0 w-1 transition-colors",
                  data.config.enabled ? "bg-primary" : "bg-border-strong",
                )}
                aria-hidden
              />
              <div className="flex items-center gap-4">
                <div
                  className={cn(
                    "flex size-11 shrink-0 items-center justify-center rounded-xl transition-colors",
                    data.config.enabled ? "bg-primary/12 text-primary" : "bg-surface-2 text-muted",
                  )}
                >
                  <Split className="size-5" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <label htmlFor="split-master" className="text-[15px] font-semibold text-fg">
                      Split tunneling
                    </label>
                    {data.config.enabled && <SplitStateBadges data={data} />}
                  </div>
                  <p className="mt-0.5 text-[13px] text-muted">Everything uses the VPN by default; Direct rules bypass it.</p>
                  {data.config.enabled && <SplitStateNote data={data} />}
                </div>
                <Switch
                  id="split-master"
                  checked={data.config.enabled}
                  onCheckedChange={(enabled) =>
                    void mutate((c) => ({ ...c, enabled }), enabled ? "Split tunneling enabled" : "Split tunneling disabled")
                  }
                />
              </div>
            </Card>

            {data.warnings.length > 0 && (
              <div role="alert" className="rounded-2xl border border-warning/35 bg-warning/[0.07] p-4">
                <div className="flex items-start gap-3">
                  <TriangleAlert className="mt-0.5 size-5 shrink-0 text-warning" />
                  <div className="min-w-0 flex-1">
                    <div className="text-[13px] font-semibold text-fg">
                      {data.warnings.length} shared address warning{data.warnings.length === 1 ? "" : "s"}
                    </div>
                    <p className="mt-0.5 text-[13px] leading-relaxed text-muted">
                      Routing works per IP address. When a bypassed domain shares an address with other sites — common with CDNs
                      and shared hosting — traffic to <i>those</i> sites will bypass the VPN too.
                    </p>
                    <ul className="mt-2.5 flex flex-col gap-1.5">
                      {data.warnings.map((w, i) => (
                        <li key={i} className="rounded-lg border border-warning/20 bg-background/50 px-3 py-1.5 text-xs">
                          <span className="selectable font-mono text-fg">{w.ip}</span>
                          <span className="text-muted"> — {w.message}</span>
                          {w.rule_ids.length > 0 && (
                            <span className="text-faint">
                              {" "}
                              (
                              {w.rule_ids
                                .map((id) => rules.find((r) => r.id === id))
                                .filter((r) => !!r)
                                .map((r) => targetText(r!.target))
                                .join(", ")}
                              )
                            </span>
                          )}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            )}

            <Tabs value={tab} onValueChange={setTab}>
              <div className="overflow-x-auto pb-1">
                <TabsList>
                  <TabsTrigger value="domains">
                    <Globe /> Domains <Count n={counts.domain} />
                  </TabsTrigger>
                  <TabsTrigger value="ips">
                    <Binary /> IP Addresses <Count n={counts.ip} />
                  </TabsTrigger>
                  <TabsTrigger value="apps">
                    <AppWindow /> Applications
                  </TabsTrigger>
                  <TabsTrigger value="categories">
                    <Tags /> Categories
                  </TabsTrigger>
                  <TabsTrigger value="active">
                    <ListOrdered /> Active Rules <Count n={counts.active} />
                  </TabsTrigger>
                  <TabsTrigger value="test">
                    <FlaskConical /> Routing Test
                  </TabsTrigger>
                </TabsList>
              </div>
              <div className={cn("mt-4 transition-opacity", !data.config.enabled && tab !== "test" && tab !== "apps" && "opacity-[0.85]")}>
                <TabsContent value="domains">
                  <DomainsTab />
                </TabsContent>
                <TabsContent value="ips">
                  <IpTab />
                </TabsContent>
                <TabsContent value="apps">
                  <AppsTab />
                </TabsContent>
                <TabsContent value="categories">
                  <CategoriesTab />
                </TabsContent>
                <TabsContent value="active">
                  <ActiveRulesTab />
                </TabsContent>
                <TabsContent value="test">
                  <RoutingTest />
                </TabsContent>
              </div>
            </Tabs>

            <Limitations />
          </>
        )}
      </ScreenBody>
      <datalist id="split-categories">
        {categories.map((c) => (
          <option key={c} value={c} />
        ))}
      </datalist>
      <BulkImportDialog open={bulkOpen} onOpenChange={setBulkOpen} />
    </>
  );
}

function Count({ n }: { n: number }) {
  if (!n) return null;
  return <span className="rounded-md bg-surface-3 px-1.5 text-[10px] font-semibold text-muted tabular">{n}</span>;
}

function Limitations() {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-xl border border-border bg-surface/60">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex w-full items-center gap-2 px-4 py-3 text-left text-[13px] font-medium text-muted hover:text-fg focus-visible:outline-2 focus-visible:outline-ring"
      >
        <Info className="size-4" />
        Limitations
        <ChevronRight className={cn("ml-auto size-4 transition-transform", open && "rotate-90")} />
      </button>
      {open && (
        <ul className="list-disc space-y-1.5 px-4 pb-4 pl-10 text-[13px] leading-relaxed text-muted">
          <li>
            Apps that use their own DNS-over-HTTPS (some browsers) may receive different addresses than the system resolver, so their
            domain rules may not match. That traffic then stays inside the VPN — it fails safe.
          </li>
          <li>Wildcard and parent-domain rules only apply to names Alizy has resolved; arbitrary unseen subdomains aren’t known in advance.</li>
          <li>Routing is per IP address. Bypassing an address shared by a CDN also bypasses the other sites hosted there.</li>
          <li>Per-application rules are not available on Linux in this build.</li>
        </ul>
      )}
    </div>
  );
}

function SplitStateBadges({ data }: { data: SplitData }) {
  const st = useSplitState(data);
  return (
    <>
      {st.firewall === "installed" && <Badge tone="success">Installed in firewall</Badge>}
      {st.firewall === "unverified" && <Badge tone="warning">Firewall not verified</Badge>}
      {st.firewall === "not-needed" && <Badge tone="outline">Not installed</Badge>}
      {st.traffic === "bypassing" && <Badge tone="success">Active · bypassing the VPN</Badge>}
      {st.traffic === "through-ks" && <Badge tone="success">Active · allowed through kill switch</Badge>}
      {st.traffic === "inactive" && <Badge tone="outline">Inactive · VPN disconnected</Badge>}
      {st.traffic === "no-addresses" && <Badge tone="outline">No bypass addresses yet</Badge>}
    </>
  );
}

function SplitStateNote({ data }: { data: SplitData }) {
  const st = useSplitState(data);
  const n = `${st.ranges} address range${st.ranges === 1 ? "" : "s"}`;
  const text =
    st.firewall === "unverified"
      ? "The firewall state could not be verified yet. Direct rules may not be in effect."
      : st.traffic === "bypassing"
        ? `${n} currently bypass the VPN; everything else goes through the tunnel.`
        : st.traffic === "through-ks"
          ? `The VPN is disconnected and the kill switch is on: only Direct addresses (${n}) can be reached.`
          : st.traffic === "inactive"
            ? "The VPN is disconnected, so all traffic already uses your normal connection. Direct rules take effect when you connect."
            : "No Direct addresses are resolved yet, so nothing bypasses the VPN.";
  return <p className="mt-1 text-[12px] text-faint">{text}</p>;
}
