import { save } from "@tauri-apps/plugin-dialog";
import { Download, History, RefreshCw, ScrollText, Search, SearchX, Trash2, X } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { ScreenBody, ScreenHeader } from "../../components/ScreenHeader";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { Select } from "../../components/ui/select";
import { Switch } from "../../components/ui/switch";
import { Badge, type BadgeTone } from "../../components/ui/badge";
import { SkeletonRows } from "../../components/ui/skeleton";
import { EmptyState } from "../../components/ui/empty-state";
import { Alert } from "../../components/ui/alert";
import { ConfirmDialog } from "../../components/ui/dialog";
import { Tabs, TabsList, TabsTrigger } from "../../components/ui/tabs";
import { Tooltip } from "../../components/ui/tooltip";
import { api } from "../../lib/api";
import type { LogCategory, LogEntry, LogLevel } from "../../lib/types";
import { formatDateTime, formatTime, relativeTime } from "../../lib/format";
import { useDebounced, useInterval, useNow } from "../../lib/hooks";
import { cn, errMsg } from "../../lib/utils";
import { toast } from "../../store/toast";
import { HistoryTable } from "./HistoryTable";
import { t, tk } from "../../i18n";

const ALL = "__all";
const LEVEL_TONE: Record<LogLevel, BadgeTone> = { info: "neutral", warn: "warning", error: "danger" };
const CATEGORIES: LogCategory[] = ["connection", "firewall", "dns", "network", "service", "app"];
const CATEGORY_LABEL: Record<LogCategory, string> = {
  connection: tk("Connection"),
  firewall: tk("Firewall"),
  dns: "DNS",
  network: tk("Network"),
  service: tk("Service"),
  app: tk("App"),
};
const LEVEL_LABEL: Record<LogLevel, string> = { info: tk("Info"), warn: tk("Warn"), error: tk("Error") };
const SOURCE_LABEL: Record<LogEntry["source"], string> = { app: tk("app"), daemon: tk("daemon") };

export function Logs() {
  const [tab, setTab] = useState("logs");
  return (
    <>
      <ScreenHeader title={t("Logs")} description={t("Events from the app and the background service, plus your connection history.")}>
        <Tabs value={tab} onValueChange={setTab}>
          <TabsList>
            <TabsTrigger value="logs">
              <ScrollText /> {t("Event log")}
            </TabsTrigger>
            <TabsTrigger value="history">
              <History /> {t("Connection history")}
            </TabsTrigger>
          </TabsList>
        </Tabs>
      </ScreenHeader>
      {tab === "logs" ? <LogView /> : <HistoryView />}
    </>
  );
}

function LogView() {
  const [level, setLevel] = useState(ALL);
  const [category, setCategory] = useState(ALL);
  const [search, setSearch] = useState("");
  const [auto, setAuto] = useState(true);
  const [entries, setEntries] = useState<LogEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [clearOpen, setClearOpen] = useState(false);
  const [exporting, setExporting] = useState(false);
  const debounced = useDebounced(search, 300);
  const now = useNow(5000);
  const seq = useRef(0);

  const load = useCallback(async () => {
    const id = ++seq.current;
    setLoading(true);
    try {
      const res = await api.logsQuery({
        level: level === ALL ? null : (level as LogLevel),
        category: category === ALL ? null : (category as LogCategory),
        search: debounced.trim() || null,
        limit: 500,
      });
      if (id === seq.current) {
        setEntries(res);
        setError(null);
      }
    } catch (e) {
      if (id === seq.current) setError(errMsg(e));
    } finally {
      if (id === seq.current) setLoading(false);
    }
  }, [level, category, debounced]);

  useEffect(() => {
    void load();
  }, [load]);
  useInterval(() => void load(), 3000, auto);

  const doExport = async () => {
    let path: string | null;
    try {
      path = await save({ title: t("Export logs"), defaultPath: `alizy-logs-${new Date().toISOString().slice(0, 10)}.log`, filters: [{ name: t("Log"), extensions: ["log", "txt"] }] });
    } catch (e) {
      toast.error(t("Could not open the save dialog"), e);
      return;
    }
    if (!path) return;
    setExporting(true);
    try {
      const n = await api.logsExport(path);
      toast.success(n === 1 ? t("Exported {count} log entry", { count: n }) : t("Exported {count} log entries", { count: n }), path);
    } catch (e) {
      toast.error(t("Export failed"), e);
    } finally {
      setExporting(false);
    }
  };

  const filtered = level !== ALL || category !== ALL || !!debounced.trim();

  return (
    <ScreenBody className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          leading={<Search />}
          trailing={
            search ? (
              <Button variant="ghost" size="icon-sm" onClick={() => setSearch("")} aria-label={t("Clear search")}>
                <X />
              </Button>
            ) : undefined
          }
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder={t("Search messages…")}
          className="w-64"
          aria-label={t("Search logs")}
        />
        <Select
          value={level}
          onValueChange={setLevel}
          aria-label={t("Filter by level")}
          className="w-32"
          options={[
            { value: ALL, label: t("All levels") },
            { value: "info", label: t("Info") },
            { value: "warn", label: t("Warning") },
            { value: "error", label: t("Error") },
          ]}
        />
        <Select
          value={category}
          onValueChange={setCategory}
          aria-label={t("Filter by category")}
          className="w-40"
          options={[{ value: ALL, label: t("All categories") }, ...CATEGORIES.map((c) => ({ value: c, label: t(CATEGORY_LABEL[c]) }))]}
        />
        <label className="ms-2 flex items-center gap-2 text-[13px] text-muted">
          <Switch size="sm" checked={auto} onCheckedChange={setAuto} aria-label={t("Auto-refresh every 3 seconds")} />
          {t("Auto-refresh")}
        </label>
        <div className="ms-auto flex items-center gap-1.5">
          <Tooltip content={t("Refresh now")}>
            <Button variant="ghost" size="icon" onClick={() => void load()} aria-label={t("Refresh logs")} disabled={loading}>
              <RefreshCw className={loading ? "animate-spin" : ""} />
            </Button>
          </Tooltip>
          <Button variant="secondary" size="sm" onClick={doExport} loading={exporting}>
            {!exporting && <Download />} {t("Export")}
          </Button>
          <Button variant="danger-ghost" size="sm" onClick={() => setClearOpen(true)}>
            <Trash2 /> {t("Clear")}
          </Button>
        </div>
      </div>

      {error && entries && (
        <Alert tone="danger" title={t("Couldn’t refresh logs")}>
          <span className="selectable">{error}</span>
        </Alert>
      )}

      {entries === null ? (
        error ? (
          <EmptyState tone="danger" icon={<ScrollText />} title={t("Logs unavailable")} description={<span className="selectable">{error}</span>} />
        ) : (
          <SkeletonRows rows={8} />
        )
      ) : entries.length === 0 ? (
        <EmptyState
          icon={filtered ? <SearchX /> : <ScrollText />}
          title={filtered ? t("No matching log entries") : t("No log entries yet")}
          description={
            filtered
              ? t("Try a different filter or search term.")
              : t("Events appear here as you connect, change settings, or when the service reports something.")
          }
        />
      ) : (
        <div className="overflow-hidden rounded-2xl border border-border bg-surface shadow-card">
          <div className="grid grid-cols-[150px_72px_100px_64px_1fr] gap-3 border-b border-border bg-surface-2/60 px-4 py-2 text-[11px] font-medium tracking-wide text-faint uppercase">
            <span>{t("Time")}</span>
            <span>{t("Level")}</span>
            <span>{t("Category")}</span>
            <span>{t("Source")}</span>
            <span>{t("Message")}</span>
          </div>
          <div role="log" aria-live="off" className="divide-y divide-border">
            {entries.map((e) => (
              <div
                key={e.id}
                className={cn(
                  "grid grid-cols-[150px_72px_100px_64px_1fr] items-start gap-3 px-4 py-2 text-[13px] hover:bg-surface-2/40",
                  e.level === "error" && "bg-danger/[0.03]",
                )}
              >
                <Tooltip content={formatDateTime(e.ts)}>
                  <span className="text-xs text-muted tabular" tabIndex={0}>
                    {formatTime(e.ts)}
                    <span className="block text-[11px] text-faint">{relativeTime(e.ts, now)}</span>
                  </span>
                </Tooltip>
                <span>
                  <Badge tone={LEVEL_TONE[e.level]} className="uppercase">
                    {LEVEL_LABEL[e.level] ? t(LEVEL_LABEL[e.level]) : e.level}
                  </Badge>
                </span>
                <span className="text-xs text-muted capitalize">{CATEGORY_LABEL[e.category] ? t(CATEGORY_LABEL[e.category]) : e.category}</span>
                <span>
                  <Badge tone={e.source === "daemon" ? "primary" : "outline"}>{SOURCE_LABEL[e.source] ? t(SOURCE_LABEL[e.source]) : e.source}</Badge>
                </span>
                <span className="selectable font-mono text-[12px] leading-relaxed break-words whitespace-pre-wrap text-fg">{e.message}</span>
              </div>
            ))}
          </div>
          {entries.length >= 500 && <div className="border-t border-border px-4 py-2 text-center text-xs text-faint">{t("Showing the latest 500 entries. Export for the full log.")}</div>}
        </div>
      )}

      <ConfirmDialog
        open={clearOpen}
        onOpenChange={setClearOpen}
        destructive
        icon={<Trash2 />}
        title={t("Clear all logs?")}
        description={t(
          "This permanently removes all stored log entries. Connection history is not affected. Export them first if you may need them for troubleshooting.",
        )}
        confirmLabel={t("Clear logs")}
        onConfirm={async () => {
          try {
            await api.logsClear();
            toast.success(t("Logs cleared"));
            await load();
          } catch (e) {
            toast.error(t("Could not clear logs"), e);
            return false;
          }
        }}
      />
    </ScreenBody>
  );
}

function HistoryView() {
  return (
    <ScreenBody>
      <HistoryTable />
    </ScreenBody>
  );
}
