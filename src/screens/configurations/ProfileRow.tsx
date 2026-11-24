import {
  CopyPlus,
  Download,
  Info,
  MoreHorizontal,
  Pencil,
  Plug,
  Star,
  Trash2,
  Unplug,
} from "lucide-react";
import { useState } from "react";
import { Badge, Dot } from "../../components/ui/badge";
import { Button } from "../../components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "../../components/ui/dropdown-menu";
import { Tooltip } from "../../components/ui/tooltip";
import { STATE_LABEL, STATE_TONE, TONE_BG, TONE_TEXT, isBusyState } from "../../lib/constants";
import { relativeTime } from "../../lib/format";
import type { ProfileSummary } from "../../lib/types";
import { api } from "../../lib/api";
import { cn } from "../../lib/utils";
import { useStatus } from "../../store/status";
import { useNav } from "../../store/nav";
import { useProfiles } from "../../store/profiles";
import { toast } from "../../store/toast";
import { DeleteProfileDialog, ExportDialog, RenameDialog } from "./dialogs";
import { PingBadge } from "./PingBadge";

export function ProfileRow({ p, now }: { p: ProfileSummary; now: number }) {
  const status = useStatus((s) => s.status);
  const pending = useStatus((s) => s.pending);
  const daemonDown = useStatus((s) => !!s.daemonError);
  const connect = useStatus((s) => s.connect);
  const disconnect = useStatus((s) => s.disconnect);
  const openDetails = useNav((s) => s.openDetails);
  const [dialog, setDialog] = useState<"rename" | "export" | "delete" | null>(null);

  const isActive = !!status && status.profile_id === p.id && status.state !== "disconnected";
  const tone = isActive && status ? STATE_TONE[status.state] : null;

  const toggleFavorite = async () => {
    try {
      await api.setFavorite(p.id, !p.favorite);
      void useProfiles.getState().load();
    } catch (e) {
      toast.error("Could not update favorite", e);
    }
  };
  const duplicate = async () => {
    try {
      const copy = await api.duplicate(p.id);
      toast.success("Profile duplicated", copy.name);
      void useProfiles.getState().load();
    } catch (e) {
      toast.error("Could not duplicate profile", e);
    }
  };

  return (
    <div
      className={cn(
        "group grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-4 rounded-xl border px-4 py-3 transition-[border-color,background-color] duration-150",
        isActive ? "border-primary/30 bg-primary/[0.05]" : "border-border bg-surface hover:border-border-strong",
      )}
    >
      <Tooltip content={p.favorite ? "Remove from favorites" : "Add to favorites"}>
        <button
          type="button"
          onClick={toggleFavorite}
          aria-label={p.favorite ? `Remove ${p.name} from favorites` : `Add ${p.name} to favorites`}
          aria-pressed={p.favorite}
          className="flex size-8 items-center justify-center rounded-lg text-faint transition-colors hover:bg-surface-2 hover:text-warning focus-visible:outline-2 focus-visible:outline-ring"
        >
          <Star className={cn("size-4", p.favorite && "fill-warning text-warning")} />
        </button>
      </Tooltip>

      <button
        type="button"
        onClick={() => openDetails(p.id)}
        className="min-w-0 text-left focus-visible:outline-2 focus-visible:outline-ring rounded-md"
        aria-label={`Open details for ${p.name}`}
      >
        <div className="flex min-w-0 items-center gap-2">
          <span className="truncate text-sm font-medium text-fg">{p.name}</span>
          {tone && status && (
            <span className={cn("inline-flex items-center gap-1.5 text-xs font-medium", TONE_TEXT[tone])}>
              <Dot className={TONE_BG[tone]} pulse={isBusyState(status.state) || status.state === "connected"} />
              {STATE_LABEL[status.state]}
            </span>
          )}
          {p.category && <Badge tone="outline">{p.category}</Badge>}
        </div>
        <div className="mt-1 flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 text-xs text-faint">
          <span className="font-mono">{p.endpoint ?? "no endpoint"}</span>
          {p.endpoint && <PingBadge id={p.id} />}
          <span className="flex items-center gap-1">
            {p.has_ipv4 && <Badge tone="neutral">IPv4</Badge>}
            {p.has_ipv6 && <Badge tone="neutral">IPv6</Badge>}
            {p.full_tunnel ? <Badge tone="primary">Full tunnel</Badge> : <Badge tone="outline">Partial routes</Badge>}
          </span>
          <span>Last used {relativeTime(p.last_connected_at, now)}</span>
        </div>
      </button>

      <div className="flex items-center gap-1.5">
        {isActive ? (
          <Button size="sm" variant="secondary" onClick={() => disconnect()} loading={pending === "disconnect"} disabled={daemonDown}>
            <Unplug /> Disconnect
          </Button>
        ) : (
          <Button
            size="sm"
            variant="secondary"
            onClick={() => connect(p.id)}
            loading={pending === p.id}
            disabled={daemonDown || (pending !== null && pending !== p.id)}
            className="opacity-90 group-hover:opacity-100"
          >
            <Plug /> Connect
          </Button>
        )}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" aria-label={`More actions for ${p.name}`}>
              <MoreHorizontal />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem onSelect={() => openDetails(p.id)}>
              <Info /> Details
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={toggleFavorite}>
              <Star /> {p.favorite ? "Unfavorite" : "Favorite"}
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={() => setDialog("rename")}>
              <Pencil /> Rename…
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={duplicate}>
              <CopyPlus /> Duplicate
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={() => setDialog("export")}>
              <Download /> Export…
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem destructive onSelect={() => setDialog("delete")}>
              <Trash2 /> Delete…
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <RenameDialog open={dialog === "rename"} onOpenChange={(o) => !o && setDialog(null)} id={p.id} current={p.name} />
      <ExportDialog open={dialog === "export"} onOpenChange={(o) => !o && setDialog(null)} id={p.id} name={p.name} />
      <DeleteProfileDialog open={dialog === "delete"} onOpenChange={(o) => !o && setDialog(null)} id={p.id} name={p.name} />
    </div>
  );
}
