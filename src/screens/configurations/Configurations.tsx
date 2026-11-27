import {
  Activity,
  ArchiveRestore,
  ChevronDown,
  ClipboardPaste,
  DatabaseBackup,
  FileCode2,
  FileUp,
  FolderOpen,
  RefreshCw,
  Search,
  SearchX,
  Star,
  Terminal,
  Upload,
  X,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { ScreenBody, ScreenHeader } from "../../components/ScreenHeader";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { Select } from "../../components/ui/select";
import { SkeletonRows } from "../../components/ui/skeleton";
import { EmptyState } from "../../components/ui/empty-state";
import { Alert } from "../../components/ui/alert";
import { Tooltip } from "../../components/ui/tooltip";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "../../components/ui/dropdown-menu";
import { useNow } from "../../lib/hooks";
import { cn } from "../../lib/utils";
import { t } from "../../i18n";
import { useProfiles } from "../../store/profiles";
import { useImportReport } from "../../store/importReport";
import { usePing } from "../../store/ping";
import { ProfileRow } from "./ProfileRow";
import { PasteConfigDialog } from "./PasteConfigDialog";
import { SshProfileDialog } from "./SshProfileDialog";
import { BackupDialog, importFiles, importFolder, restoreBackup } from "./dialogs";

type Sort = "name" | "last_used" | "created";
const ALL = "__all";
const NONE = "__none";

export function Configurations() {
  const { profiles, loaded, loading, error, load } = useProfiles();
  const importing = useImportReport((s) => s.busy);
  const pinging = usePing((s) => s.busy);
  const pingAll = usePing((s) => s.pingAll);
  const now = useNow(30_000);
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState(ALL);
  const [favOnly, setFavOnly] = useState(false);
  const [sort, setSort] = useState<Sort>("last_used");
  const [pasteOpen, setPasteOpen] = useState(false);
  const [backupOpen, setBackupOpen] = useState(false);
  const [sshOpen, setSshOpen] = useState(false);

  // Measure every endpoint as soon as the list is known — also after imports,
  // which is the only way new profiles ever get a first ping.
  useEffect(() => {
    if (loaded && profiles.length > 0) void pingAll();
  }, [loaded, profiles.length, pingAll]);

  const categories = useMemo(() => {
    const set = new Set<string>();
    for (const p of profiles) if (p.category) set.add(p.category);
    return [...set].sort((a, b) => a.localeCompare(b));
  }, [profiles]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = profiles.filter((p) => {
      if (favOnly && !p.favorite) return false;
      if (category === NONE && p.category) return false;
      if (category !== ALL && category !== NONE && p.category !== category) return false;
      if (!q) return true;
      return (
        p.name.toLowerCase().includes(q) ||
        (p.endpoint ?? "").toLowerCase().includes(q) ||
        (p.ssh ? `${p.ssh.username}@${p.ssh.host}:${p.ssh.port}`.toLowerCase().includes(q) : false) ||
        (p.category ?? "").toLowerCase().includes(q) ||
        p.addresses.some((a) => a.toLowerCase().includes(q))
      );
    });
    list.sort((a, b) => {
      if (sort === "name") return a.name.localeCompare(b.name);
      if (sort === "created") return b.created_at - a.created_at;
      return (b.last_connected_at ?? 0) - (a.last_connected_at ?? 0) || a.name.localeCompare(b.name);
    });
    return list;
  }, [profiles, query, category, favOnly, sort]);

  const hasFilters = !!query || category !== ALL || favOnly;

  return (
    <>
      <ScreenHeader
        title={t("Configurations")}
        description={
          loaded
            ? `${profiles.length === 1 ? t("{count} profile", { count: profiles.length }) : t("{count} profiles", { count: profiles.length })} · ${t("drag .conf files anywhere onto the window to import")}`
            : t("WireGuard profiles")
        }
        actions={
          <>
            <Tooltip content={t("Re-measure the ping of every profile")}>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => void pingAll()}
                loading={pinging}
                disabled={profiles.length === 0}
                aria-label={t("Re-measure pings")}
              >
                {!pinging && <Activity />} {t("Ping")}
              </Button>
            </Tooltip>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="sm" aria-label={t("Backup and restore")}>
                  <DatabaseBackup /> {t("Backup")} <ChevronDown className="!size-3.5 opacity-60" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent>
                <DropdownMenuItem onSelect={() => setBackupOpen(true)}>
                  <DatabaseBackup /> {t("Create backup…")}
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={() => void restoreBackup()}>
                  <ArchiveRestore /> {t("Restore from backup…")}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="primary" size="sm" loading={importing}>
                  {!importing && <Upload />} {t("Import")} <ChevronDown className="!size-3.5 opacity-80" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent className="w-56">
                <DropdownMenuItem onSelect={() => void importFiles()}>
                  <FileUp /> {t("Import files…")}
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={() => void importFolder()}>
                  <FolderOpen /> {t("Import folder…")}
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onSelect={() => setPasteOpen(true)}>
                  <ClipboardPaste /> {t("Paste configuration…")}
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onSelect={() => setSshOpen(true)}>
                  <Terminal /> {t("SSH connection…")}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </>
        }
      >
        <div className="flex flex-wrap items-center gap-2">
          <Input
            leading={<Search />}
            trailing={
              query ? (
                <Button variant="ghost" size="icon-sm" onClick={() => setQuery("")} aria-label={t("Clear search")}>
                  <X />
                </Button>
              ) : undefined
            }
            placeholder={t("Search name, endpoint, address…")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-72"
            aria-label={t("Search profiles")}
          />
          <Select
            size="md"
            value={category}
            onValueChange={setCategory}
            aria-label={t("Filter by category")}
            className="w-44"
            options={[
              { value: ALL, label: t("All categories") },
              { value: NONE, label: t("Uncategorized") },
              ...categories.map((c) => ({ value: c, label: c })),
            ]}
          />
          <Button
            variant={favOnly ? "primary" : "secondary"}
            size="md"
            onClick={() => setFavOnly((v) => !v)}
            aria-pressed={favOnly}
            className={cn(favOnly && "shadow-none")}
          >
            <Star className={cn(favOnly && "fill-current")} /> {t("Favorites")}
          </Button>
          <div className="ms-auto flex items-center gap-2">
            <span className="text-xs text-faint">{t("Sort")}</span>
            <Select
              value={sort}
              onValueChange={(v) => setSort(v as Sort)}
              aria-label={t("Sort profiles")}
              className="w-36"
              options={[
                { value: "last_used", label: t("Last used") },
                { value: "name", label: t("Name") },
                { value: "created", label: t("Date added") },
              ]}
            />
            <Tooltip content={t("Reload")}>
              <Button variant="ghost" size="icon" onClick={() => void load()} aria-label={t("Reload profiles")} disabled={loading}>
                <RefreshCw className={loading ? "animate-spin" : ""} />
              </Button>
            </Tooltip>
          </div>
        </div>
      </ScreenHeader>

      <ScreenBody>
        {error && loaded && profiles.length > 0 && (
          <Alert tone="danger" title={t("Couldn’t refresh the profile list")} className="mb-4">
            {error}
          </Alert>
        )}
        {!loaded ? (
          <SkeletonRows rows={5} />
        ) : error && profiles.length === 0 ? (
          <EmptyState
            tone="danger"
            icon={<FileCode2 />}
            title={t("Couldn’t load your configurations")}
            description={<span className="selectable">{error}</span>}
            action={
              <Button variant="secondary" size="sm" onClick={() => void load()}>
                <RefreshCw /> {t("Try again")}
              </Button>
            }
          />
        ) : profiles.length === 0 ? (
          <div className="rounded-2xl border-2 border-dashed border-border">
            <EmptyState
              tone="primary"
              icon={<FileCode2 />}
              title={t("Add your first WireGuard configuration")}
              description={t("Import .conf files from your VPN provider or router, paste a configuration, or simply drag files and folders onto this window.")}
              action={
                <>
                  <Button variant="primary" size="sm" onClick={() => void importFiles()}>
                    <FileUp /> {t("Import files")}
                  </Button>
                  <Button variant="secondary" size="sm" onClick={() => void importFolder()}>
                    <FolderOpen /> {t("Import folder")}
                  </Button>
                  <Button variant="ghost" size="sm" onClick={() => setPasteOpen(true)}>
                    <ClipboardPaste /> {t("Paste")}
                  </Button>
                  <Button variant="ghost" size="sm" onClick={() => setSshOpen(true)}>
                    <Terminal /> {t("SSH connection")}
                  </Button>
                </>
              }
              className="py-16"
            />
          </div>
        ) : filtered.length === 0 ? (
          <EmptyState
            icon={<SearchX />}
            title={t("No matching profiles")}
            description={t("Try a different search term or clear the filters.")}
            action={
              hasFilters && (
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => {
                    setQuery("");
                    setCategory(ALL);
                    setFavOnly(false);
                  }}
                >
                  {t("Clear filters")}
                </Button>
              )
            }
          />
        ) : (
          <div className="flex flex-col gap-2">
            {filtered.map((p) => (
              <ProfileRow key={p.id} p={p} now={now} />
            ))}
            {hasFilters && (
              <p className="pt-2 text-center text-xs text-faint">
                {t("Showing {shown} of {total}", { shown: filtered.length, total: profiles.length })}
              </p>
            )}
          </div>
        )}
      </ScreenBody>

      <PasteConfigDialog open={pasteOpen} onOpenChange={setPasteOpen} />
      <SshProfileDialog open={sshOpen} onOpenChange={setSshOpen} />
      <BackupDialog open={backupOpen} onOpenChange={setBackupOpen} />
    </>
  );
}
