import {
  Cast,
  Check,
  CircleAlert,
  Globe,
  KeyRound,
  Network,
  Plus,
  RefreshCw,
  Router,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Waypoints,
  Wifi,
  X,
} from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { ScreenBody, ScreenHeader } from "../../components/ScreenHeader";
import { KillSwitchConfirm } from "../../components/KillSwitchConfirm";
import { Card, CardHeader } from "../../components/ui/card";
import { Switch } from "../../components/ui/switch";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { Select } from "../../components/ui/select";
import { Alert } from "../../components/ui/alert";
import { Skeleton } from "../../components/ui/skeleton";
import { EmptyState } from "../../components/ui/empty-state";
import { ConfirmDialog } from "../../components/ui/dialog";
import { CopyButton } from "../../components/ui/copy-button";
import { Divider, SettingRow } from "../../components/ui/misc";
import { Tooltip } from "../../components/ui/tooltip";
import type { ConnectionMode, LanProxyConfig, LanProxyStatus, NetworkPolicy } from "../../lib/types";
import { api } from "../../lib/api";
import { isIP } from "../../lib/validate";
import { cn } from "../../lib/utils";
import { t } from "../../i18n";
import { toast } from "../../store/toast";
import { usePolicy } from "../../store/policy";
import { useStatus } from "../../store/status";
import { useSettings } from "../../store/settings";
import { useProfiles } from "../../store/profiles";

const NONE = "__none";

export function NetworkSettings() {
  const { policy, loading, loadError, saving, saveError, load, save } = usePolicy();
  const ks = useStatus((s) => s.status?.kill_switch ?? null);
  const state = useStatus((s) => s.status?.state ?? "disconnected");
  // The service reports `local_proxy` only once it supports proxy mode.
  const modeSupported = useStatus((s) => s.status?.local_proxy !== undefined);
  const [ksDialog, setKsDialog] = useState<"on" | "off" | null>(null);
  const [modeDialog, setModeDialog] = useState<ConnectionMode | null>(null);

  const set = (patch: Partial<NetworkPolicy>) => policy && void save({ ...policy, ...patch });
  const mode: ConnectionMode = policy?.mode ?? "tunnel";
  const proxy = mode === "proxy";
  const live = state === "connected" || state === "connecting" || state === "reconnecting";

  const chooseMode = (m: ConnectionMode) => {
    if (!policy || m === mode) return;
    if (live) setModeDialog(m);
    else void save({ ...policy, mode: m });
  };

  return (
    <>
      <ScreenHeader
        title={t("Network")}
        description={t("Connection mode, leak protection, kill switch and sharing. Enforced by the background service.")}
        actions={
          saving ? (
            <span className="flex items-center gap-1.5 text-xs text-muted">
              <RefreshCw className="size-3.5 animate-spin" /> {t("Saving…")}
            </span>
          ) : policy && !saveError ? (
            <span className="flex items-center gap-1.5 text-xs text-faint">
              <Check className="size-3.5" /> {t("All changes saved")}
            </span>
          ) : null
        }
      />
      <ScreenBody narrow className="flex flex-col gap-5">
        {saveError && (
          <Alert
            tone="danger"
            title={t("Couldn’t apply the change")}
            action={
              <Button size="xs" variant="ghost" onClick={() => void load()}>
                {t("Reload")}
              </Button>
            }
          >
            <span className="selectable">{saveError}</span>
          </Alert>
        )}

        {!policy ? (
          loading || !loadError ? (
            <div className="flex flex-col gap-4">
              <Skeleton className="h-40 rounded-2xl" />
              <Skeleton className="h-64 rounded-2xl" />
            </div>
          ) : (
            <EmptyState
              tone="danger"
              icon={<Network />}
              title={t("Network policy unavailable")}
              description={<span className="selectable">{loadError}</span>}
              action={
                <Button size="sm" variant="secondary" onClick={() => void load()}>
                  <RefreshCw /> {t("Try again")}
                </Button>
              }
            />
          )
        ) : (
          <>
            {/* Connection mode */}
            <Card className="overflow-hidden">
              <CardHeader
                icon={<Waypoints />}
                title={t("Connection mode")}
                description={t("Choose whether the whole system or only selected apps use the VPN.")}
              />
              <div className="grid grid-cols-1 gap-3 px-5 pb-5 @xl:grid-cols-2">
                <ModeOption
                  selected={!proxy}
                  disabled={saving || !modeSupported}
                  onSelect={() => chooseMode("tunnel")}
                  icon={<Globe />}
                  title={t("Tunnel mode")}
                  text={t("All traffic on this computer goes through the VPN, including apps without proxy support. The kill switch is available.")}
                />
                <ModeOption
                  selected={proxy}
                  disabled={saving || !modeSupported}
                  onSelect={() => chooseMode("proxy")}
                  icon={<Waypoints />}
                  title={t("Proxy mode")}
                  text={t("Only apps you point at Alizy’s local SOCKS5/HTTP proxy use the VPN. Everything else connects directly.")}
                />
              </div>
              {!modeSupported && (
                <div className="px-5 pb-5">
                  <Alert tone="warning" title={t("Update the background service")}>
                    {t("The installed service doesn’t support proxy mode yet. Run the matching alizy-installer to update it.")}
                  </Alert>
                </div>
              )}
            </Card>

            {proxy && <LocalProxyCard policy={policy} saving={saving} onSave={(p) => void save(p)} />}

            {/* Kill switch */}
            <Card className="overflow-hidden">
              <CardHeader
                icon={
                  proxy ? (
                    <ShieldOff />
                  ) : ks?.enabled && ks.firewall_verified ? (
                    <ShieldCheck className="text-success" />
                  ) : ks?.enabled ? (
                    <ShieldAlert className="text-warning" />
                  ) : (
                    <ShieldOff />
                  )
                }
                title={t("Kill switch")}
                description={t(
                  "Blocks all traffic outside the VPN tunnel at the OS firewall — even if Alizy’s window is closed or the tunnel drops.",
                )}
                action={
                  proxy ? (
                    <Tooltip content={t("Available in tunnel mode only.")}>
                      <span tabIndex={0}>
                        <Switch checked={false} disabled aria-label={t("Kill switch")} />
                      </span>
                    </Tooltip>
                  ) : (
                    <Switch
                      checked={policy.kill_switch}
                      onCheckedChange={(v) => setKsDialog(v ? "on" : "off")}
                      aria-label={t("Kill switch")}
                      disabled={saving}
                    />
                  )
                }
              />
              {proxy ? (
                <div className="px-5 pb-4">
                  <Alert tone="info" title={t("Not used in proxy mode")}>
                    {policy.kill_switch
                      ? t("Proxy mode never blocks your normal connection, so the kill switch is off. It turns back on when you return to tunnel mode.")
                      : t("Proxy mode never blocks your normal connection, so the kill switch is off. Switch to tunnel mode to use it.")}{" "}
                    {t("Alizy’s proxy itself never connects directly: while the VPN is down, it refuses connections instead.")}
                  </Alert>
                </div>
              ) : (
                <>
                  {policy.kill_switch && ks && !ks.firewall_verified && (
                    <div className="px-5 pb-4">
                      <Alert tone="warning" title={t("Enabled, but not verified by the firewall")}>
                        {t(
                          "The service could not confirm that its blocking rules are active. Traffic may leak. Check the System Check in Settings for firewall conflicts (firewalld/ufw) or missing nftables support.",
                        )}
                      </Alert>
                    </div>
                  )}
                  {policy.kill_switch && ks?.firewall_verified && (
                    <div className="px-5 pb-4">
                      <Alert tone="success">{t("Firewall rules are installed and verified.")}</Alert>
                    </div>
                  )}
                  <Divider />
                  <SettingRow
                    htmlFor="allow-lan"
                    title={t("Allow local network while protected")}
                    description={t("Keep access to printers, NAS and other devices on your LAN while the kill switch is active.")}
                    control={
                      <Switch id="allow-lan" checked={policy.allow_lan} onCheckedChange={(v) => set({ allow_lan: v })} disabled={saving} />
                    }
                  />
                </>
              )}
            </Card>

            {/* IP families + DNS */}
            <Card className="overflow-hidden">
              <CardHeader icon={<Router />} title={t("Leak protection")} description={t("Control which traffic is allowed to leave this machine.")} />
              {proxy && (
                <div className="px-5 pb-4">
                  <Alert tone="info">
                    {t("IPv4/IPv6 blocking and DNS leak protection apply in tunnel mode only. In proxy mode, custom DNS servers are used to resolve names for the proxy through the VPN.")}
                  </Alert>
                </div>
              )}
              <Divider />
              <SettingRow
                htmlFor="ipv4"
                title={t("IPv4")}
                description={t("Allow IPv4 traffic.")}
                disabled={proxy}
                control={
                  <FamilySwitch
                    id="ipv4"
                    checked={policy.ipv4_enabled}
                    lockOn={!policy.ipv6_enabled}
                    onChange={(v) => set({ ipv4_enabled: v })}
                    disabled={saving || proxy}
                  />
                }
              />
              <Divider className="mx-5" />
              <SettingRow
                htmlFor="ipv6"
                title={t("IPv6")}
                description={t("Allow IPv6 traffic. Many VPN providers don’t tunnel IPv6 — disable it to avoid leaks.")}
                disabled={proxy}
                control={
                  <FamilySwitch
                    id="ipv6"
                    checked={policy.ipv6_enabled}
                    lockOn={!policy.ipv4_enabled}
                    onChange={(v) => set({ ipv6_enabled: v })}
                    disabled={saving || proxy}
                  />
                }
              />
              <div className="px-5 pb-4">
                <p className="text-xs leading-relaxed text-faint">
                  {t("A disabled family is blocked at the OS firewall, not merely left unrouted — so nothing can leak over it. At least one family must stay enabled.")}
                </p>
              </div>
              <Divider />
              <SettingRow
                htmlFor="dns-leak"
                title={t("DNS leak protection")}
                description={t("Force all DNS queries through the tunnel’s DNS servers while connected.")}
                disabled={proxy}
                control={
                  <Switch
                    id="dns-leak"
                    checked={policy.dns_leak_protection}
                    onCheckedChange={(v) => set({ dns_leak_protection: v })}
                    disabled={saving || proxy}
                  />
                }
              />
              <Divider className="mx-5" />
              <SettingRow title={t("Custom DNS servers")} description={t("Override the DNS servers from your profiles. Leave empty to use each profile’s DNS.")}>
                <DnsEditor value={policy.custom_dns} onChange={(custom_dns) => set({ custom_dns })} disabled={saving} />
              </SettingRow>
            </Card>

            {/* Connection behaviour */}
            <Card className="overflow-hidden">
              <CardHeader icon={<Wifi />} title={t("Connection")} description={t("How Alizy connects and recovers.")} />
              <Divider />
              <SettingRow
                htmlFor="auto-reconnect"
                title={t("Auto-reconnect")}
                description={t("Re-establish the tunnel automatically after network changes, sleep, or interruptions.")}
                control={
                  <Switch id="auto-reconnect" checked={policy.auto_reconnect} onCheckedChange={(v) => set({ auto_reconnect: v })} disabled={saving} />
                }
              />
              <Divider className="mx-5" />
              <AutoConnect />
            </Card>

            {/* LAN forward proxy */}
            <LanProxyCard proxyMode={proxy} />
          </>
        )}
      </ScreenBody>

      <KillSwitchConfirm which={ksDialog} onClose={() => setKsDialog(null)} />
      <ConfirmDialog
        open={modeDialog !== null}
        onOpenChange={(o) => !o && setModeDialog(null)}
        icon={modeDialog === "proxy" ? <Waypoints /> : <Globe />}
        title={modeDialog === "proxy" ? t("Switch to proxy mode?") : t("Switch to tunnel mode?")}
        description={
          modeDialog === "proxy"
            ? t("The VPN reconnects without capturing system traffic. Only apps using Alizy’s local proxy will go through it, and the kill switch stops applying.")
            : t("The VPN reconnects and captures all traffic on this computer. Your kill switch setting applies again.")
        }
        confirmLabel={t("Switch and reconnect")}
        onConfirm={async () => {
          if (!policy || !modeDialog) return;
          return (await save({ ...policy, mode: modeDialog })) ? undefined : false;
        }}
      />
    </>
  );
}

function ModeOption({
  selected,
  disabled,
  onSelect,
  icon,
  title,
  text,
}: {
  selected: boolean;
  disabled?: boolean;
  onSelect: () => void;
  icon: ReactNode;
  title: string;
  text: string;
}) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={selected}
      disabled={disabled}
      onClick={onSelect}
      className={cn(
        "flex flex-col gap-1.5 rounded-xl border p-4 text-start transition-colors duration-150 [&_svg]:size-4",
        "focus-visible:outline-2 focus-visible:outline-ring disabled:cursor-not-allowed disabled:opacity-60",
        selected ? "border-primary bg-primary/8" : "border-border hover:border-border-strong hover:bg-surface-2",
      )}
    >
      <span className={cn("flex items-center gap-2 text-sm font-semibold", selected ? "text-primary" : "text-fg")}>
        {icon}
        {title}
        {selected && <Check className="ms-auto" />}
      </span>
      <span className="text-[13px] leading-relaxed text-muted">{text}</span>
    </button>
  );
}

function portOk(s: string) {
  const n = Number(s);
  return /^\d{1,5}$/.test(s.trim()) && n >= 1 && n <= 65535;
}

/** Proxy mode: where apps should point, and whether it works right now. */
function LocalProxyCard({ policy, saving, onSave }: { policy: NetworkPolicy; saving: boolean; onSave: (p: NetworkPolicy) => void }) {
  const local = useStatus((s) => s.status?.local_proxy ?? null);
  const state = useStatus((s) => s.status?.state ?? "disconnected");
  const socks = policy.proxy_socks_port ?? 10808;
  const http = policy.proxy_http_port ?? 10809;
  const [socksDraft, setSocksDraft] = useState<string | null>(null);
  const [httpDraft, setHttpDraft] = useState<string | null>(null);
  const shownSocks = socksDraft ?? String(socks);
  const shownHttp = httpDraft ?? String(http);
  const bad = !portOk(shownSocks) || !portOk(shownHttp) || shownSocks.trim() === shownHttp.trim();

  const commit = () => {
    if (bad) return;
    const [s, h] = [Number(shownSocks), Number(shownHttp)];
    setSocksDraft(null);
    setHttpDraft(null);
    if (s !== socks || h !== http) onSave({ ...policy, proxy_socks_port: s, proxy_http_port: h });
  };

  const connected = state === "connected";
  const listening = !!local && (local.socks_listening || local.http_listening);
  const socksAddr = `127.0.0.1:${socks}`;
  const httpAddr = `127.0.0.1:${http}`;

  return (
    <Card className="overflow-hidden">
      <CardHeader
        icon={<Waypoints />}
        title={t("Local proxy")}
        description={t("Set these addresses as the proxy in the apps that should use the VPN (browser, Telegram, terminal tools).")}
      />
      <div className="flex flex-col gap-3 px-5 pb-5">
        {local?.error ? (
          <Alert tone="danger" title={t("The local proxy isn’t running")}>
            <span className="selectable">{local.error}</span>
          </Alert>
        ) : !listening ? (
          <Alert tone="info">{t("Starting the local proxy…")}</Alert>
        ) : connected ? (
          <Alert tone="success" title={t("Ready")}>
            {local!.udp ? t("TCP and UDP (SOCKS5) go through the VPN.") : t("TCP goes through the VPN. This tunnel cannot carry UDP.")}
          </Alert>
        ) : (
          <Alert tone="warning" title={t("Waiting for the VPN")}>
            {t("Connect a profile to start using the proxy. Until then it refuses connections instead of using your normal connection.")}
          </Alert>
        )}
        <ProxyAddress label={t("SOCKS5")} hint={t("for most apps, including UDP")} addr={socksAddr} />
        <ProxyAddress label={t("HTTP")} hint={t("for browsers and tools that only speak HTTP proxy")} addr={httpAddr} />
        <div className="flex flex-wrap items-end gap-3">
          <PortField id="local-socks-port" label={t("SOCKS5 port")} value={shownSocks} onChange={setSocksDraft} onCommit={commit} disabled={saving} />
          <PortField id="local-http-port" label={t("HTTP port")} value={shownHttp} onChange={setHttpDraft} onCommit={commit} disabled={saving} />
        </div>
        {bad && (
          <p className="flex items-center gap-1 text-xs text-danger">
            <CircleAlert className="size-3" /> {t("Enter two different ports between 1 and 65535.")}
          </p>
        )}
        <p className="text-xs leading-relaxed text-faint">
          {t("The local proxy listens on this computer only (127.0.0.1). Other users of this computer can use it too.")}
        </p>
      </div>
    </Card>
  );
}

function ProxyAddress({ label, hint, addr }: { label: string; hint: string; addr: string }) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-lg border border-border bg-surface-2/60 px-3 py-2">
      <div className="min-w-0">
        <span className="text-sm font-medium text-fg">{label}</span> <span className="text-xs text-faint">— {hint}</span>
        <div dir="ltr" className="selectable text-start font-mono text-[13px] text-fg">
          {addr}
        </div>
      </div>
      <CopyButton text={addr} label={t("Copy")} />
    </div>
  );
}

function PortField({
  id,
  label,
  value,
  onChange,
  onCommit,
  disabled,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  onCommit: () => void;
  disabled?: boolean;
}) {
  return (
    <label htmlFor={id} className="flex flex-col gap-1 text-xs text-muted">
      {label}
      <Input
        id={id}
        dir="ltr"
        value={value}
        inputMode="numeric"
        className="w-24 font-mono text-[13px]"
        disabled={disabled}
        invalid={!portOk(value)}
        onChange={(e) => onChange(e.target.value)}
        onBlur={onCommit}
        onKeyDown={(e) => e.key === "Enter" && onCommit()}
      />
    </label>
  );
}

function FamilySwitch({
  id,
  checked,
  lockOn,
  onChange,
  disabled,
}: {
  id: string;
  checked: boolean;
  lockOn: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  const sw = <Switch id={id} checked={checked} onCheckedChange={onChange} disabled={disabled || (checked && lockOn)} />;
  if (checked && lockOn && !disabled) {
    return (
      <Tooltip content={t("At least one of IPv4 or IPv6 must stay enabled.")}>
        <span tabIndex={0}>{sw}</span>
      </Tooltip>
    );
  }
  return sw;
}

function DnsEditor({ value, onChange, disabled }: { value: string[]; onChange: (v: string[]) => void; disabled?: boolean }) {
  const [draft, setDraft] = useState("");
  const v = draft.trim();
  const error = !v ? null : !isIP(v) ? t("Enter a valid IPv4 or IPv6 address.") : value.includes(v) ? t("Already in the list.") : null;
  const add = () => {
    if (!v || error) return;
    onChange([...value, v]);
    setDraft("");
  };
  return (
    <div className="flex flex-col gap-2">
      {value.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {value.map((d) => (
            <span
              key={d}
              dir="ltr"
              className="inline-flex h-7 items-center gap-1 rounded-lg border border-border bg-surface-2 ps-2.5 pe-1 font-mono text-[12px] text-fg"
            >
              {d}
              <button
                type="button"
                onClick={() => onChange(value.filter((x) => x !== d))}
                disabled={disabled}
                aria-label={t("Remove DNS server {addr}", { addr: d })}
                className="rounded p-0.5 text-faint hover:bg-surface-3 hover:text-danger"
              >
                <X className="size-3.5" />
              </button>
            </span>
          ))}
        </div>
      )}
      <form
        className="flex items-start gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          add();
        }}
      >
        <div className="flex-1">
          <Input
            dir="ltr"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder={t("e.g. 1.1.1.1 or 2606:4700:4700::1111")}
            className="font-mono text-[13px]"
            invalid={!!error}
            aria-label={t("DNS server address")}
            disabled={disabled}
          />
          {error && (
            <p className="mt-1 flex items-center gap-1 text-xs text-danger">
              <CircleAlert className="size-3" /> {error}
            </p>
          )}
        </div>
        <Button type="submit" variant="secondary" disabled={!v || !!error || disabled}>
          <Plus /> {t("Add")}
        </Button>
      </form>
    </div>
  );
}

/** Share this machine's VPN with other devices on the LAN. */
function LanProxyCard({ proxyMode }: { proxyMode: boolean }) {
  const polled = useStatus((s) => s.status?.lan_proxy ?? null);
  const [saving, setSaving] = useState(false);
  const [portDraft, setPortDraft] = useState<string | null>(null);
  const [socksPortDraft, setSocksPortDraft] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [mine, setMine] = useState<LanProxyStatus | null>(null);
  const lan = mine ?? polled;
  useEffect(() => {
    if (
      mine &&
      polled &&
      polled.enabled === mine.enabled &&
      polled.port === mine.port &&
      polled.socks_port === mine.socks_port &&
      polled.listening === mine.listening &&
      polled.socks_listening === mine.socks_listening &&
      (polled.auth_username ?? null) === (mine.auth_username ?? null)
    ) {
      setMine(null);
    }
  }, [mine, polled]);

  const enabled = lan?.enabled ?? false;
  const port = lan?.port || 8080;
  const socksPort = lan?.socks_port || 1080;
  const authUser = lan?.auth_username ?? null;
  const shownPort = portDraft ?? String(port);
  const shownSocksPort = socksPortDraft ?? String(socksPort);
  const portInvalid = !portOk(shownPort);
  const socksPortInvalid = !portOk(shownSocksPort);

  // Login editor.
  const [authOn, setAuthOn] = useState<boolean | null>(null);
  const [user, setUser] = useState<string | null>(null);
  const [pass, setPass] = useState("");
  const wantAuth = authOn ?? !!authUser;
  const shownUser = user ?? authUser ?? "";
  const userError = !shownUser.trim()
    ? t("Enter a username.")
    : /[\s:]/.test(shownUser)
      ? t("No spaces or colons in the username.")
      : null;
  const needPass = shownUser !== authUser;
  const passError = needPass && !pass ? t("Enter a password.") : pass.length > 255 ? t("At most 255 characters.") : null;

  const current = (patch: Partial<LanProxyConfig> = {}): LanProxyConfig => ({
    enabled,
    port: portInvalid ? port : Number(shownPort),
    socks_port: socksPortInvalid ? socksPort : Number(shownSocksPort),
    // Keep the stored login (no password: the service keeps the current one).
    auth: authUser ? { username: authUser } : null,
    ...patch,
  });

  const apply = async (config: LanProxyConfig) => {
    setSaving(true);
    setError(null);
    try {
      const next = await api.lanProxySet(config);
      setMine(next);
      if (next.error) setError(next.error);
      if (next.socks_error) setError((prev) => (prev ? `${prev}; ${next.socks_error}` : next.socks_error!) as string);
      setPortDraft(null);
      setSocksPortDraft(null);
      return true;
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
      toast.error(t("Couldn’t change the LAN proxy"), e);
      return false;
    } finally {
      setSaving(false);
    }
  };

  const commitPort = () => {
    if (portDraft === null || portInvalid || Number(shownPort) === port) return setPortDraft(null);
    void apply(current());
  };
  const commitSocksPort = () => {
    if (socksPortDraft === null || socksPortInvalid || Number(shownSocksPort) === socksPort) return setSocksPortDraft(null);
    void apply(current());
  };
  const saveLogin = async () => {
    if (userError || passError) return;
    const ok = await apply(current({ auth: { username: shownUser, ...(pass ? { password: pass } : {}) } }));
    if (ok) {
      setPass("");
      setUser(null);
      setAuthOn(null);
      toast.success(t("Login saved"));
    }
  };
  const toggleAuth = (v: boolean) => {
    if (v) return setAuthOn(true);
    setAuthOn(null);
    setUser(null);
    setPass("");
    if (authUser) void apply(current({ auth: null }));
  };

  return (
    <Card className="overflow-hidden">
      <CardHeader
        icon={<Cast />}
        title={t("Share VPN with other devices")}
        description={t("Run a proxy on this computer so a smart TV, console or any other device on your Wi-Fi can browse through Alizy’s tunnel.")}
        action={
          <Switch checked={enabled} onCheckedChange={(v) => void apply(current({ enabled: v }))} disabled={saving} aria-label={t("LAN proxy")} />
        }
      />
      {enabled && (
        <div className="flex flex-col gap-4 px-5 pb-5">
          {authUser ? (
            <Alert tone="info" title={t("Login required")}>
              {t("Devices must sign in as “{user}”. Note that HTTP proxy logins travel unencrypted on your local network.", { user: authUser })}
            </Alert>
          ) : (
            <Alert tone="warning" title={t("No password — anyone on your network can use it")}>
              {t("Every device that can reach this computer on the local network can browse through your VPN, for free. Require a login below, or turn the proxy off when you don’t need it.")}
            </Alert>
          )}
          {(lan?.error ?? error) && (
            <Alert tone="danger" title={t("The proxy isn’t running")}>
              <span className="selectable">{lan?.error ?? error}</span>
            </Alert>
          )}
          {!lan?.error && !error && (lan?.listening || lan?.socks_listening) && (
            <Alert tone="success" title={t("Listening")}>
              {lan!.addresses.length > 0 ? (
                <div className="flex flex-col gap-1">
                  {lan!.listening && (
                    <span>
                      <b className="font-medium text-muted">{t("HTTP proxy")}</b>{" "}
                      <span dir="ltr" className="font-mono text-xs">
                        {lan!.addresses[0]}:{port}
                      </span>
                      <span className="text-faint"> — {t("for browsers and most apps")}</span>
                    </span>
                  )}
                  {lan!.socks_listening && (
                    <span>
                      <b className="font-medium text-muted">{t("SOCKS5 proxy")}</b>{" "}
                      <span dir="ltr" className="font-mono text-xs">
                        {lan!.addresses[0]}:{socksPort}
                      </span>
                      <span className="text-faint"> — {lan!.socks_udp ? t("TCP and UDP: Telegram calls, games, any app") : t("for Telegram, SSH and other TCP apps")}</span>
                    </span>
                  )}
                  {lan!.addresses.length > 1 && (
                    <span className="mt-1 text-xs text-faint">
                      {t("Also reachable at {addrs}", { addrs: lan!.addresses.slice(1).join(", ") })}
                    </span>
                  )}
                </div>
              ) : (
                <span>{t("Listening but this computer has no address other devices can reach. Is Wi-Fi connected?")}</span>
              )}
            </Alert>
          )}
          {lan?.socks_error && (
            <Alert tone="danger" title={t("SOCKS5 proxy isn’t running")}>
              <span className="selectable">{lan.socks_error}</span>
            </Alert>
          )}
          <SettingRow
            htmlFor="lan-proxy-port"
            title={t("HTTP proxy port")}
            description={t("For browsers and apps that support HTTP proxies.")}
            className="px-0 py-0"
            control={
              <Input
                id="lan-proxy-port"
                dir="ltr"
                value={shownPort}
                inputMode="numeric"
                className="w-24 font-mono text-[13px]"
                disabled={saving}
                invalid={portInvalid}
                aria-label={t("HTTP proxy port")}
                onChange={(e) => setPortDraft(e.target.value)}
                onBlur={commitPort}
                onKeyDown={(e) => e.key === "Enter" && commitPort()}
              />
            }
          />
          <SettingRow
            htmlFor="lan-socks-port"
            title={t("SOCKS5 proxy port")}
            description={t("For Telegram, games and other apps; carries TCP and UDP on the same port.")}
            className="px-0 py-0"
            control={
              <Input
                id="lan-socks-port"
                dir="ltr"
                value={shownSocksPort}
                inputMode="numeric"
                className="w-24 font-mono text-[13px]"
                disabled={saving}
                invalid={socksPortInvalid}
                aria-label={t("SOCKS5 proxy port")}
                onChange={(e) => setSocksPortDraft(e.target.value)}
                onBlur={commitSocksPort}
                onKeyDown={(e) => e.key === "Enter" && commitSocksPort()}
              />
            }
          />
          {(portInvalid || socksPortInvalid) && (
            <p className="-mt-2 flex items-center gap-1 text-xs text-danger">
              <CircleAlert className="size-3" /> {t("Enter a port between 1 and 65535.")}
            </p>
          )}
          <Divider />
          <SettingRow
            htmlFor="lan-auth"
            title={t("Require a username and password")}
            description={t("Devices must log in before they can use the shared VPN (SOCKS5 and HTTP proxy).")}
            className="px-0 py-0"
            control={<Switch id="lan-auth" checked={wantAuth} onCheckedChange={toggleAuth} disabled={saving} />}
          />
          {wantAuth && (
            <form
              className="flex flex-col gap-3 rounded-xl border border-border bg-surface-2/50 p-4"
              onSubmit={(e) => {
                e.preventDefault();
                void saveLogin();
              }}
            >
              <div className="grid grid-cols-1 gap-3 @lg:grid-cols-2">
                <label className="flex flex-col gap-1 text-xs text-muted">
                  {t("Username")}
                  <Input
                    dir="ltr"
                    value={shownUser}
                    autoComplete="off"
                    invalid={!!userError && user !== null}
                    onChange={(e) => setUser(e.target.value)}
                    disabled={saving}
                  />
                </label>
                <label className="flex flex-col gap-1 text-xs text-muted">
                  {authUser && !needPass ? t("New password (leave empty to keep)") : t("Password")}
                  <Input
                    dir="ltr"
                    type="password"
                    value={pass}
                    autoComplete="new-password"
                    invalid={!!passError && pass !== ""}
                    onChange={(e) => setPass(e.target.value)}
                    disabled={saving}
                  />
                </label>
              </div>
              {(userError || passError) && (user !== null || pass !== "") && (
                <p className="flex items-center gap-1 text-xs text-danger">
                  <CircleAlert className="size-3" /> {userError ?? passError}
                </p>
              )}
              <div className="flex items-center justify-between gap-3">
                <p className="text-xs leading-relaxed text-faint">{t("The service stores only a salted hash of the password.")}</p>
                <Button type="submit" size="sm" disabled={saving || !!userError || !!passError || (!needPass && !pass)}>
                  <KeyRound /> {t("Save login")}
                </Button>
              </div>
            </form>
          )}
          <p className="text-xs leading-relaxed text-faint">
            {proxyMode
              ? t("In proxy mode, shared devices go through the VPN the same way as this computer’s proxy, and are refused while it is disconnected.")
              : t("The kill switch still applies to this computer; only devices using a proxy get the tunnel. SSH tunnels carry TCP only, so UDP isn’t available through them.")}
          </p>
        </div>
      )}
    </Card>
  );
}

function AutoConnect() {
  const settings = useSettings((s) => s.settings);
  const settingsError = useSettings((s) => s.settingsError);
  const update = useSettings((s) => s.update);
  const profiles = useProfiles((s) => s.profiles);
  const current = settings?.auto_connect_profile_id ?? null;
  const missing = current && !profiles.some((p) => p.id === current);

  return (
    <SettingRow
      title={t("Auto-connect on launch")}
      description={
        settingsError ? (
          <span className="text-danger">{t("Settings unavailable: {error}", { error: settingsError })}</span>
        ) : (
          t("Connect this profile automatically when Alizy starts.")
        )
      }
      control={
        <Select
          value={current ?? NONE}
          onValueChange={(v) => void update({ auto_connect_profile_id: v === NONE ? null : v })}
          disabled={!settings}
          aria-label={t("Auto-connect profile")}
          className="w-56"
          options={[
            { value: NONE, label: t("Don’t auto-connect") },
            ...(missing ? [{ value: current!, label: t("Deleted profile"), disabled: true }] : []),
            ...[...profiles].sort((a, b) => a.name.localeCompare(b.name)).map((p) => ({ value: p.id, label: p.name })),
          ]}
        />
      }
    />
  );
}
