import * as DialogPrimitive from "@radix-ui/react-dialog";
import {
  Check,
  CopyPlus,
  Download,
  FileCode2,
  History,
  Pencil,
  Plug,
  RefreshCw,
  Star,
  Tag,
  Trash2,
  TriangleAlert,
  Unplug,
  X,
} from "lucide-react";
import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Dialog, SheetContent } from "../../components/ui/dialog";
import { Button } from "../../components/ui/button";
import { Badge, Dot } from "../../components/ui/badge";
import { Input } from "../../components/ui/input";
import { Skeleton } from "../../components/ui/skeleton";
import { EmptyState } from "../../components/ui/empty-state";
import { CopyButton } from "../../components/ui/copy-button";
import { Tooltip } from "../../components/ui/tooltip";
import { api } from "../../lib/api";
import type { HistoryEntry, ProfileDetail, PublicPeer } from "../../lib/types";
import { endpointLabel, formatBytes, formatDateTime, formatDuration, relativeTime, shortKey } from "../../lib/format";
import { STATE_LABEL, STATE_TONE, TONE_BG, TONE_TEXT, isBusyState } from "../../lib/constants";
import { cn, errMsg } from "../../lib/utils";
import { useNav } from "../../store/nav";
import { useProfiles } from "../../store/profiles";
import { usePing } from "../../store/ping";
import { useStatus } from "../../store/status";
import { toast } from "../../store/toast";
import { DeleteProfileDialog, ExportDialog } from "./dialogs";
import { EditConfigDialog } from "./EditConfigDialog";
import { PingBadge } from "./PingBadge";
import { RevealKey } from "./RevealKey";
import { SshProfileDialog, UdpNote } from "./SshProfileDialog";
import { t } from "../../i18n";

export function ProfileDetailsSheet() {
  const id = useNav((s) => s.detailsId);
  const close = useNav((s) => s.closeDetails);
  return (
    <Dialog open={id !== null} onOpenChange={(o) => !o && close()}>
      <SheetContent aria-describedby={undefined}>{id && <ProfileDetails id={id} onClose={close} />}</SheetContent>
    </Dialog>
  );
}

function hostOf(peer: PublicPeer): string | null {
  if (!peer.endpoint) return null;
  const h = peer.endpoint.host.value;
  const host = peer.endpoint.host.kind === "ip" && h.includes(":") ? `[${h}]` : h;
  return `${host}:${peer.endpoint.port}`;
}

function ProfileDetails({ id, onClose }: { id: string; onClose: () => void }) {
  const profilesVersion = useProfiles((s) => s.profiles);
  const allProfiles = useProfiles((s) => s.profiles);
  const [detail, setDetail] = useState<ProfileDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryEntry[] | null>(null);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [dialog, setDialog] = useState<"edit" | "export" | "delete" | "ssh" | null>(null);
  const [forgetting, setForgetting] = useState(false);

  const load = useCallback(async () => {
    try {
      setDetail(await api.profileGet(id));
      setError(null);
    } catch (e) {
      setError(errMsg(e));
    }
  }, [id]);

  const loadHistory = useCallback(async () => {
    try {
      const all = await api.historyList(200);
      setHistory(all.filter((h) => h.profile_id === id).slice(0, 10));
      setHistoryError(null);
    } catch (e) {
      setHistoryError(errMsg(e));
    }
  }, [id]);

  useEffect(() => {
    setDetail(null);
    setError(null);
    setHistory(null);
  }, [id]);

  useEffect(() => {
    void load();
  }, [load, profilesVersion]);

  useEffect(() => {
    void loadHistory();
  }, [loadHistory]);

  // A quick-switcher deep link opens this sheet before the list ever ran a
  // probe, so measure once here if this profile has no result yet.
  const knownPing = usePing((st) => st.results[id]);
  useEffect(() => {
    if (!knownPing && !usePing.getState().busy) void usePing.getState().pingAll();
  }, [id, knownPing]);

  if (error && !detail) {
    return (
      <>
        <SheetTopBar onClose={onClose} title={t("Profile")} />
        <EmptyState
          tone="danger"
          icon={<FileCode2 />}
          title={t("Couldn’t load this profile")}
          description={<span className="selectable">{error}</span>}
          action={
            <Button size="sm" variant="secondary" onClick={() => void load()}>
              <RefreshCw /> {t("Retry")}
            </Button>
          }
          className="flex-1"
        />
      </>
    );
  }

  if (!detail) {
    return (
      <>
        <SheetTopBar onClose={onClose} title={t("Profile")} />
        <div className="flex flex-col gap-4 p-6">
          <Skeleton className="h-8 w-56" />
          <Skeleton className="h-4 w-40" />
          <Skeleton className="mt-4 h-32 w-full rounded-xl" />
          <Skeleton className="h-48 w-full rounded-xl" />
        </div>
      </>
    );
  }

  const s = detail.summary;
  const c = detail.config;
  const ssh = s.kind === "ssh" ? s.ssh : null;
  const forgetKey = async () => {
    setForgetting(true);
    try {
      await api.clearHostKey(s.id);
      toast.success(t("Host key forgotten"), t("You will be asked to verify the server again on the next connection."));
      void useProfiles.getState().load();
      await load();
    } catch (e) {
      toast.error(t("Could not forget the host key"), e);
    } finally {
      setForgetting(false);
    }
  };
  const categories = [...new Set(allProfiles.map((p) => p.category).filter((x): x is string => !!x))];

  return (
    <>
      <SheetTopBar onClose={onClose} title={t("Profile details")} />
      <div className="min-h-0 flex-1 overflow-y-auto">
        <div className="flex flex-col gap-6 px-6 pt-2 pb-8">
          <HeaderBlock detail={detail} onChanged={load} categories={categories} />

          {!ssh && detail.warnings.length > 0 && (
            <div className="rounded-xl border border-warning/30 bg-warning/[0.06] p-4">
              <div className="flex items-center gap-2 text-[13px] font-medium text-fg">
                <TriangleAlert className="size-4 text-warning" /> {t("Compatibility warnings")}
              </div>
              <ul className="mt-2 list-disc space-y-1 ps-6 text-[13px] text-muted">
                {detail.warnings.map((w, i) => (
                  <li key={i}>{w}</li>
                ))}
              </ul>
            </div>
          )}

          {ssh ? (
            <Section title={t("SSH connection")}>
              <Grid>
                <KV label={t("Server")} mono copy={ssh.host}>
                  {ssh.host}
                </KV>
                <KV label={t("Port")}>{ssh.port}</KV>
                <KV label={t("Username")}>
                  <span dir="ltr">{ssh.username}</span>
                </KV>
                <KV label={t("Password")}>
                  {s.password_needed ? <Badge tone="warning">{t("Password needed")}</Badge> : <Badge tone="success">{t("Saved")}</Badge>}
                </KV>
                <KV label={t("Host key")} mono copy={ssh.host_key_fingerprint ?? undefined}>
                  {ssh.host_key_fingerprint ?? <span className="font-sans text-faint">{t("Not trusted yet")}</span>}
                </KV>
              </Grid>
              {ssh.host_key_fingerprint && (
                <div className="mt-3">
                  <Button variant="secondary" size="sm" onClick={() => void forgetKey()} loading={forgetting}>
                    {t("Forget host key")}
                  </Button>
                </div>
              )}
              <UdpNote className="mt-3" />
            </Section>
          ) : (
            <>
          <Section title={t("Interface")}>
              <Grid>
                <KV label={t("Public key")} mono copy={c.interface_public_key}>
                  {shortKey(c.interface_public_key, 12, 6)}
                </KV>
                <KV label={t("Addresses")} mono>
                  {c.addresses.length ? c.addresses.join(", ") : "—"}
                </KV>
                <KV label="DNS" mono>
                  {c.dns.length ? c.dns.join(", ") : "—"}
                  {c.dns_search.length > 0 && <span className="text-faint"> · {t("search {domains}", { domains: c.dns_search.join(", ") })}</span>}
                </KV>
                <KV label="MTU">{c.mtu ?? t("auto")}</KV>
                <KV label={t("Listen port")}>{c.listen_port ?? t("random")}</KV>
                <KV label={t("Routing")}>
                  {s.full_tunnel ? <Badge tone="primary">{t("Full tunnel")}</Badge> : <Badge tone="outline">{t("Partial routes")}</Badge>}
                </KV>
              </Grid>
              <div className="mt-3">
                <RevealKey id={s.id} />
              </div>
            </Section>
  
            <Section title={t("Peers ({count})", { count: c.peers.length })}>
              {c.peers.length === 0 ? (
                <div className="rounded-xl border border-dashed border-border p-4 text-[13px] text-muted">{t("This configuration has no peers.")}</div>
              ) : (
                <div className="flex flex-col gap-3">
                  {c.peers.map((peer, i) => (
                    <div key={i} className="rounded-xl border border-border bg-surface p-4">
                      <Grid>
                        <KV label={t("Public key")} mono copy={peer.public_key}>
                          {shortKey(peer.public_key, 12, 6)}
                        </KV>
                        <KV label={t("Endpoint")} mono>
                          {hostOf(peer) ?? "—"}
                        </KV>
                        <KV label={t("Keepalive")}>
                          {peer.persistent_keepalive ? t("every {seconds} s", { seconds: peer.persistent_keepalive }) : t("off")}
                        </KV>
                        <KV label={t("Preshared key")}>
                          {peer.has_preshared_key ? <Badge tone="success">{t("Present")}</Badge> : <Badge tone="neutral">{t("None")}</Badge>}
                        </KV>
                      </Grid>
                      <div className="mt-3">
                        <div className="mb-1.5 text-xs text-muted">{t("Allowed IPs")}</div>
                        <div className="flex flex-wrap gap-1.5">
                          {peer.allowed_ips.length ? (
                            peer.allowed_ips.map((ip) => (
                              <span key={ip} dir="ltr" className="selectable rounded-md border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[11px] text-fg">
                                {ip}
                              </span>
                            ))
                          ) : (
                            <span className="text-xs text-faint">{t("none")}</span>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Section>
  
            </>
          )}

          <Section title={t("Recent connections")} icon={<History className="size-3.5" />}>
            {historyError ? (
              <div className="rounded-xl border border-danger/25 bg-danger/[0.05] p-3 text-[13px] text-muted">{historyError}</div>
            ) : history === null ? (
              <Skeleton className="h-24 w-full rounded-xl" />
            ) : history.length === 0 ? (
              <div className="rounded-xl border border-dashed border-border p-4 text-center text-[13px] text-muted">
                {t("This profile hasn’t been used yet.")}
              </div>
            ) : (
              <div className="overflow-hidden rounded-xl border border-border">
                {history.map((h) => (
                  <div key={h.id} className="flex items-center gap-4 border-b border-border bg-surface px-4 py-2.5 text-[13px] last:border-b-0">
                    <div className="min-w-0 flex-1">
                      <div className="text-fg">{formatDateTime(h.started_at)}</div>
                      <div className="text-xs text-faint">
                        {h.ended_at ? formatDuration(h.ended_at - h.started_at) : t("ongoing")}
                        {h.end_reason ? ` · ${h.end_reason}` : ""}
                      </div>
                    </div>
                    <div className="text-end text-xs text-muted tabular">
                      ↓ {formatBytes(h.rx_bytes)}
                      <br />↑ {formatBytes(h.tx_bytes)}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Section>

          <div className="text-xs text-faint">
            {t("Added {date} · updated {time}", { date: formatDateTime(s.created_at), time: relativeTime(s.updated_at) })}
            {!ssh && (
              <>
                {" "}
                · {t("fingerprint")}{" "}
                <span className="selectable font-mono" dir="ltr">{s.fingerprint}</span>
              </>
            )}
          </div>
        </div>
      </div>

      <div className="flex shrink-0 items-center gap-2 border-t border-border bg-surface px-6 py-3">
        {ssh ? (
          <Button variant="secondary" size="sm" onClick={() => setDialog("ssh")}>
            <Pencil /> {t("Edit connection")}
          </Button>
        ) : (
          <>
            <Button variant="secondary" size="sm" onClick={() => setDialog("edit")}>
              <Pencil /> {t("Edit configuration")}
            </Button>
            <Button variant="secondary" size="sm" onClick={() => setDialog("export")}>
              <Download /> {t("Export")}
            </Button>
          </>
        )}
        <Button
          variant="ghost"
          size="sm"
          onClick={async () => {
            try {
              const copy = await api.duplicate(s.id);
              toast.success(t("Profile duplicated"), copy.name);
              void useProfiles.getState().load();
            } catch (e) {
              toast.error(t("Could not duplicate profile"), e);
            }
          }}
        >
          <CopyPlus /> {t("Duplicate")}
        </Button>
        <Button variant="danger-ghost" size="sm" className="ms-auto" onClick={() => setDialog("delete")}>
          <Trash2 /> {t("Delete")}
        </Button>
      </div>

      {ssh ? (
        <SshProfileDialog
          open={dialog === "ssh"}
          onOpenChange={(o) => !o && setDialog(null)}
          profile={s}
          onSaved={() => void load()}
        />
      ) : (
        <>
          <EditConfigDialog
            open={dialog === "edit"}
            onOpenChange={(o) => !o && setDialog(null)}
            id={s.id}
            name={s.name}
            initial={detail.config_text_redacted}
            onSaved={load}
          />
          <ExportDialog open={dialog === "export"} onOpenChange={(o) => !o && setDialog(null)} id={s.id} name={s.name} />
        </>
      )}
      <DeleteProfileDialog open={dialog === "delete"} onOpenChange={(o) => !o && setDialog(null)} id={s.id} name={s.name} onDeleted={onClose} />
    </>
  );
}

function SheetTopBar({ title, onClose }: { title: string; onClose: () => void }) {
  return (
    <div className="flex h-14 shrink-0 items-center justify-between border-b border-border px-6">
      <DialogPrimitive.Title className="text-[13px] font-medium text-muted">{title}</DialogPrimitive.Title>
      <Button variant="ghost" size="icon-sm" onClick={onClose} aria-label={t("Close details")}>
        <X />
      </Button>
    </div>
  );
}

function HeaderBlock({ detail, onChanged, categories }: { detail: ProfileDetail; onChanged: () => void; categories: string[] }) {
  const s = detail.summary;
  const status = useStatus((st) => st.status);
  const pending = useStatus((st) => st.pending);
  const daemonDown = useStatus((st) => !!st.daemonError);
  const connect = useStatus((st) => st.connect);
  const disconnect = useStatus((st) => st.disconnect);
  const [editingName, setEditingName] = useState(false);
  const [name, setName] = useState(s.name);
  const [category, setCategory] = useState(s.category ?? "");
  const [savingCat, setSavingCat] = useState(false);

  useEffect(() => setName(s.name), [s.name]);
  useEffect(() => setCategory(s.category ?? ""), [s.category]);

  const active = !!status && status.profile_id === s.id && status.state !== "disconnected";
  const tone = active && status ? STATE_TONE[status.state] : null;

  const saveName = async () => {
    const n = name.trim();
    setEditingName(false);
    if (!n || n === s.name) return setName(s.name);
    try {
      await api.rename(s.id, n);
      void useProfiles.getState().load();
      onChanged();
    } catch (e) {
      setName(s.name);
      toast.error(t("Could not rename profile"), e);
    }
  };

  const saveCategory = async () => {
    const c = category.trim();
    if (c === (s.category ?? "")) return;
    setSavingCat(true);
    try {
      await api.setCategory(s.id, c || null);
      void useProfiles.getState().load();
      onChanged();
      toast.success(c ? t("Category set to “{category}”", { category: c }) : t("Category cleared"));
    } catch (e) {
      setCategory(s.category ?? "");
      toast.error(t("Could not update category"), e);
    } finally {
      setSavingCat(false);
    }
  };

  const toggleFav = async () => {
    try {
      await api.setFavorite(s.id, !s.favorite);
      void useProfiles.getState().load();
      onChanged();
    } catch (e) {
      toast.error(t("Could not update favorite"), e);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-start gap-3">
        <div className="flex size-12 shrink-0 items-center justify-center rounded-2xl bg-linear-to-br from-primary/25 to-primary/5 text-base font-semibold text-primary uppercase ring-1 ring-primary/20">
          {s.name.slice(0, 2)}
        </div>
        <div className="min-w-0 flex-1">
          {editingName ? (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void saveName();
              }}
              className="flex items-center gap-1.5"
            >
              <Input
                value={name}
                onChange={(e) => setName(e.target.value)}
                autoFocus
                onBlur={() => void saveName()}
                onKeyDown={(e) => {
                  if (e.key === "Escape") {
                    e.stopPropagation();
                    setName(s.name);
                    setEditingName(false);
                  }
                }}
                className="h-9 text-base font-semibold"
                aria-label={t("Profile name")}
                maxLength={64}
              />
              <Button type="submit" variant="ghost" size="icon" aria-label={t("Save name")}>
                <Check />
              </Button>
            </form>
          ) : (
            <div className="group flex items-center gap-1.5">
              <h2 className="truncate text-xl font-semibold tracking-tight text-fg">{s.name}</h2>
              <Button
                variant="ghost"
                size="icon-sm"
                onClick={() => setEditingName(true)}
                aria-label={t("Rename profile")}
                className="opacity-60 group-hover:opacity-100"
              >
                <Pencil />
              </Button>
            </div>
          )}
          <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted">
            <span className="selectable font-mono" dir="ltr">
              {endpointLabel(s) ?? t("no endpoint")}
            </span>
            {(s.endpoint || s.ssh) && <PingBadge id={s.id} />}
            {s.kind === "ssh" && <Badge tone="primary">SSH</Badge>}
            {s.password_needed && <Badge tone="warning">{t("Password needed")}</Badge>}
            {tone && status && (
              <span className={cn("inline-flex items-center gap-1.5 font-medium", TONE_TEXT[tone])}>
                <Dot className={TONE_BG[tone]} pulse={isBusyState(status.state)} />
                {t(STATE_LABEL[status.state])}
              </span>
            )}
          </div>
        </div>
        <Tooltip content={s.favorite ? t("Remove from favorites") : t("Add to favorites")}>
          <Button variant="ghost" size="icon" onClick={toggleFav} aria-pressed={s.favorite} aria-label={t("Toggle favorite")}>
            <Star className={cn(s.favorite && "fill-warning text-warning")} />
          </Button>
        </Tooltip>
        {active ? (
          <Button variant="secondary" onClick={() => disconnect()} loading={pending === "disconnect"} disabled={daemonDown}>
            <Unplug /> {t("Disconnect")}
          </Button>
        ) : (
          <Button variant="primary" onClick={() => connect(s.id)} loading={pending === s.id} disabled={daemonDown || pending !== null}>
            <Plug /> {t("Connect")}
          </Button>
        )}
      </div>

      <div className="flex items-center gap-2">
        <Tag className="size-4 text-faint" aria-hidden />
        <Input
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          onBlur={() => void saveCategory()}
          onKeyDown={(e) => {
            if (e.key === "Enter") (e.target as HTMLInputElement).blur();
          }}
          placeholder={t("Add a category (e.g. Work, Home)")}
          list="alizy-categories"
          aria-label={t("Category")}
          className="h-8 max-w-xs text-[13px]"
          disabled={savingCat}
          maxLength={40}
        />
        <datalist id="alizy-categories">
          {categories.map((c) => (
            <option key={c} value={c} />
          ))}
        </datalist>
      </div>
    </div>
  );
}

function Section({ title, icon, children }: { title: string; icon?: ReactNode; children: ReactNode }) {
  return (
    <section>
      <h3 className="mb-2.5 flex items-center gap-1.5 text-[11px] font-semibold tracking-[0.08em] text-faint uppercase">
        {icon}
        {title}
      </h3>
      {children}
    </section>
  );
}

function Grid({ children }: { children: ReactNode }) {
  return <div className="grid grid-cols-2 gap-x-6 gap-y-3">{children}</div>;
}

function KV({ label, children, mono, copy }: { label: string; children: ReactNode; mono?: boolean; copy?: string }) {
  return (
    <div className="min-w-0">
      <div className="text-xs text-muted">{label}</div>
      <div className="mt-0.5 flex min-w-0 items-center gap-1">
        <div className={cn("selectable min-w-0 truncate text-[13px] text-fg", mono && "font-mono text-[12px]")} title={copy} dir={mono ? "ltr" : undefined}>
          {children}
        </div>
        {copy && <CopyButton text={copy} label={t("Copy {label}", { label: label.toLowerCase() })} />}
      </div>
    </div>
  );
}
