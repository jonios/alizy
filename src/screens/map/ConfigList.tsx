import { ClipboardPaste, FileUp, Search, Star } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Flag } from "../../components/Flag";
import { countryName } from "../../lib/geo/countries";
import { cn } from "../../lib/utils";
import { useGeo } from "../../store/geo";
import { useNav } from "../../store/nav";
import { usePing } from "../../store/ping";
import { useProfiles } from "../../store/profiles";
import { useStatus } from "../../store/status";
import { FAST_MS, OK_MS } from "../configurations/PingBadge";
import { PasteConfigDialog } from "../configurations/PasteConfigDialog";
import { importFiles } from "../configurations/dialogs";
import { serverHost } from "./profileView";
import { t, tk } from "../../i18n";

type Filter = "all" | "wireguard" | "ssh" | "fav";
const FILTERS: { id: Filter; label: string }[] = [
  { id: "all", label: tk("All") },
  { id: "wireguard", label: "WireGuard" },
  { id: "ssh", label: "SSH" },
];

export function ConfigList() {
  const profiles = useProfiles((s) => s.profiles);
  const loaded = useProfiles((s) => s.loaded);
  const country = useGeo((s) => s.country);
  const ping = usePing((s) => s.results);
  const pingAll = usePing((s) => s.pingAll);
  const liveId = useStatus((s) => (s.status && s.status.state !== "disconnected" ? s.status.profile_id : null));
  const selectedId = useNav((s) => s.selectedId);
  const select = useNav((s) => s.select);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [pasteOpen, setPasteOpen] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (loaded && profiles.length > 0 && Object.keys(usePing.getState().results).length === 0) void pingAll();
  }, [loaded, profiles.length, pingAll]);

  // "/" focuses the search, like most list views.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = document.activeElement;
      if (e.key !== "/" || (el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA"))) return;
      e.preventDefault();
      input.current?.focus();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return profiles
      .filter((p) => {
        if (filter === "fav" && !p.favorite) return false;
        if (filter === "ssh" && p.kind !== "ssh") return false;
        if (filter === "wireguard" && p.kind === "ssh") return false;
        if (!q) return true;
        const cc = country[p.id];
        return [p.name, serverHost(p) ?? "", cc ?? "", countryName(cc) ?? ""].some((s) => s.toLowerCase().includes(q));
      })
      .sort((a, b) => Number(b.favorite) - Number(a.favorite) || (b.last_connected_at ?? 0) - (a.last_connected_at ?? 0) || a.name.localeCompare(b.name));
  }, [profiles, query, filter, country]);

  return (
    <aside className="flex w-[284px] shrink-0 flex-col border-e border-border bg-sidebar">
      <div className="px-3.5 pt-4 pb-2">
        <label className="flex items-center gap-2 rounded-lg border border-border bg-surface-2 px-2.5 py-2 text-muted focus-within:border-border-strong">
          <Search className="size-3.5 shrink-0" />
          <input
            ref={input}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t("Search")}
            className="min-w-0 flex-1 bg-transparent text-[13px] text-fg outline-none placeholder:text-faint"
          />
          <kbd className="rounded border border-border px-1.5 font-mono text-[10px] text-faint">/</kbd>
        </label>
        <div className="mt-2.5 flex items-center gap-1.5">
          {FILTERS.map((f) => (
            <Chip key={f.id} on={filter === f.id} onClick={() => setFilter(f.id)}>
              {t(f.label)}
            </Chip>
          ))}
          <Chip on={filter === "fav"} onClick={() => setFilter(filter === "fav" ? "all" : "fav")} label={t("Favorites")}>
            <Star className={cn("size-3", filter === "fav" && "fill-warning text-warning")} />
          </Chip>
          <span className="ms-auto font-mono text-[11px] text-faint tabular" dir="ltr">
            {rows.length}/{profiles.length}
          </span>
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto px-2 pb-2">
        {rows.map((p) => {
          const cc = country[p.id] ?? null;
          const live = p.id === liveId;
          const ms = ping[p.id]?.ms ?? null;
          return (
            <button
              key={p.id}
              type="button"
              onClick={() => select(p.id)}
              aria-current={p.id === selectedId ? "true" : undefined}
              className={cn(
                "relative flex w-full items-center gap-3 rounded-xl px-2.5 py-2.5 text-start transition-colors focus-visible:outline-2 focus-visible:outline-ring",
                p.id === selectedId ? "bg-primary/12" : "hover:bg-surface-2",
              )}
            >
              {p.id === selectedId && <span className="absolute inset-y-3 start-0 w-0.5 rounded-full bg-primary" aria-hidden />}
              <Flag cc={cc} className="size-[30px]" />
              <div className="min-w-0 flex-1">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="truncate text-[13px] font-semibold text-fg">{countryName(cc) ?? t("Unknown")}</span>
                  <span dir="ltr" className="shrink-0 font-mono text-[11px] text-muted">
                    {serverHost(p)}
                  </span>
                </div>
                <div className="mt-0.5 flex items-center justify-between gap-2">
                  <span className="truncate text-xs text-faint">
                    {p.favorite && <Star className="me-1 inline size-3 -translate-y-px fill-warning text-warning" />}
                    {p.name}
                  </span>
                  {live ? <span className="size-[7px] shrink-0 rounded-full bg-success shadow-[0_0_8px_var(--success)]" aria-label={t("Active")} /> : <Bars ms={ms} />}
                </div>
              </div>
            </button>
          );
        })}
        {loaded && rows.length === 0 && (
          <p className="px-3 py-8 text-center text-xs text-faint">{profiles.length ? t("No matches") : t("No configurations yet")}</p>
        )}
      </div>

      <div className="flex gap-2 border-t border-border p-3">
        <button type="button" onClick={() => void importFiles()} className="flex flex-1 items-center justify-center gap-1.5 rounded-lg bg-surface-2 py-2 text-xs text-muted transition-colors hover:text-fg">
          <FileUp className="size-3.5" /> {t("Import")}
        </button>
        <button type="button" onClick={() => setPasteOpen(true)} className="flex flex-1 items-center justify-center gap-1.5 rounded-lg bg-surface-2 py-2 text-xs text-muted transition-colors hover:text-fg">
          <ClipboardPaste className="size-3.5" /> {t("Paste")}
        </button>
      </div>
      <PasteConfigDialog open={pasteOpen} onOpenChange={setPasteOpen} />
    </aside>
  );
}

function Chip({ on, onClick, children, label }: { on: boolean; onClick: () => void; children: React.ReactNode; label?: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={on}
      aria-label={label}
      className={cn(
        "flex h-6 items-center rounded-full border px-2.5 text-[11px] transition-colors",
        on ? "border-surface-3 bg-surface-3 text-fg" : "border-border text-muted hover:text-fg",
      )}
    >
      {children}
    </button>
  );
}

/** Three signal bars coloured by the last ping. */
export function Bars({ ms, className }: { ms: number | null; className?: string }) {
  const level = ms === null ? 0 : ms < FAST_MS ? 3 : ms < OK_MS ? 2 : 1;
  const tone = level === 3 ? "bg-success" : level === 2 ? "bg-warning" : "bg-danger";
  return (
    <span className={cn("flex h-2.5 shrink-0 items-end gap-0.5", className)} aria-label={ms === null ? undefined : t("Ping {ms} milliseconds", { ms })}>
      {[4, 7, 10].map((h, i) => (
        <i key={h} className={cn("w-[3px] rounded-[1px]", i < level ? tone : "bg-border")} style={{ height: h }} />
      ))}
    </span>
  );
}
