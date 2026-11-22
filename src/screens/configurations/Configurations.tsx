import {
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
import { useMemo, useState } from "react";
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
import { plural } from "../../lib/format";
import { useProfiles } from "../../store/profiles";
import { useImportReport } from "../../store/importReport";
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
  const now = useNow(30_000);
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState(ALL);
  const [favOnly, setFavOnly] = useState(false);
  const [sort, setSort] = useState<Sort>("last_used");
  const [pasteOpen, setPasteOpen] = useState(false);
  const [backupOpen, setBackupOpen] = useState(false);
  const [sshOpen, setSshOpen] = useState(false);

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
        title="Configurations"
        description={loaded ? `${plural(profiles.length, "profile")} · drag .conf files anywhere onto the window to import` : "WireGuard profiles"}
        actions={
          <>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="sm" aria-label="Backup and restore">
                  <DatabaseBackup /> Backup <ChevronDown className="!size-3.5 opacity-60" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent>
                <DropdownMenuItem onSelect={() => setBackupOpen(true)}>
                  <DatabaseBackup /> Create backup…
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={() => void restoreBackup()}>
                  <ArchiveRestore /> Restore from backup…
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="primary" size="sm" loading={importing}>
                  {!importing && <Upload />} Import <ChevronDown className="!size-3.5 opacity-80" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent className="w-56">
                <DropdownMenuItem onSelect={() => void importFiles()}>
                  <FileUp /> Import files…
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={() => void importFolder()}>
                  <FolderOpen /> Import folder…
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onSelect={() => setPasteOpen(true)}>
                  <ClipboardPaste /> Paste configuration…
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onSelect={() => setSshOpen(true)}>
                  <Terminal /> SSH connection…
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
                <Button variant="ghost" size="icon-sm" onClick={() => setQuery("")} aria-label="Clear search">
                  <X />
                </Button>
              ) : undefined
            }
            placeholder="Search name, endpoint, address…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-72"
            aria-label="Search profiles"
          />
          <Select
            size="md"
            value={category}
            onValueChange={setCategory}
            aria-label="Filter by category"
            className="w-44"
            options={[
              { value: ALL, label: "All categories" },
              { value: NONE, label: "Uncategorized" },
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
            <Star className={cn(favOnly && "fill-current")} /> Favorites
          </Button>
          <div className="ml-auto flex items-center gap-2">
            <span className="text-xs text-faint">Sort</span>
            <Select
              value={sort}
              onValueChange={(v) => setSort(v as Sort)}
              aria-label="Sort profiles"
              className="w-36"
              options={[
                { value: "last_used", label: "Last used" },
                { value: "name", label: "Name" },
                { value: "created", label: "Date added" },
              ]}
            />
            <Tooltip content="Reload">
              <Button variant="ghost" size="icon" onClick={() => void load()} aria-label="Reload profiles" disabled={loading}>
                <RefreshCw className={loading ? "animate-spin" : ""} />
              </Button>
            </Tooltip>
          </div>
        </div>
      </ScreenHeader>

      <ScreenBody>
        {error && loaded && profiles.length > 0 && (
          <Alert tone="danger" title="Couldn’t refresh the profile list" className="mb-4">
            {error}
          </Alert>
        )}
        {!loaded ? (
          <SkeletonRows rows={5} />
        ) : error && profiles.length === 0 ? (
          <EmptyState
            tone="danger"
            icon={<FileCode2 />}
            title="Couldn’t load your configurations"
            description={<span className="selectable">{error}</span>}
            action={
              <Button variant="secondary" size="sm" onClick={() => void load()}>
                <RefreshCw /> Try again
              </Button>
            }
          />
        ) : profiles.length === 0 ? (
          <div className="rounded-2xl border-2 border-dashed border-border">
            <EmptyState
              tone="primary"
              icon={<FileCode2 />}
              title="Add your first WireGuard configuration"
              description="Import .conf files from your VPN provider or router, paste a configuration, or simply drag files and folders onto this window."
              action={
                <>
                  <Button variant="primary" size="sm" onClick={() => void importFiles()}>
                    <FileUp /> Import files
                  </Button>
                  <Button variant="secondary" size="sm" onClick={() => void importFolder()}>
                    <FolderOpen /> Import folder
                  </Button>
                  <Button variant="ghost" size="sm" onClick={() => setPasteOpen(true)}>
                    <ClipboardPaste /> Paste
                  </Button>
                  <Button variant="ghost" size="sm" onClick={() => setSshOpen(true)}>
                    <Terminal /> SSH connection
                  </Button>
                </>
              }
              className="py-16"
            />
          </div>
        ) : filtered.length === 0 ? (
          <EmptyState
            icon={<SearchX />}
            title="No matching profiles"
            description="Try a different search term or clear the filters."
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
                  Clear filters
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
                Showing {filtered.length} of {profiles.length}
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
