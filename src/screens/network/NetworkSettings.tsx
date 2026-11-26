import { Cast, Check, CircleAlert, Network, Plus, RefreshCw, Router, ShieldAlert, ShieldCheck, ShieldOff, Wifi, X } from "lucide-react";
import { useEffect, useState } from "react";
import { ScreenBody, ScreenHeader } from "../../components/ScreenHeader";
import { Card, CardHeader } from "../../components/ui/card";
import { Switch } from "../../components/ui/switch";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { Select } from "../../components/ui/select";
import { Alert } from "../../components/ui/alert";
import { Skeleton } from "../../components/ui/skeleton";
import { EmptyState } from "../../components/ui/empty-state";
import { ConfirmDialog } from "../../components/ui/dialog";
import { Divider, SettingRow } from "../../components/ui/misc";
import { Tooltip } from "../../components/ui/tooltip";
import type { LanProxyConfig, LanProxyStatus, NetworkPolicy } from "../../lib/types";
import { api } from "../../lib/api";
import { isIP } from "../../lib/validate";
import { toast } from "../../store/toast";
import { usePolicy } from "../../store/policy";
import { useStatus } from "../../store/status";
import { useSettings } from "../../store/settings";
import { useProfiles } from "../../store/profiles";

const NONE = "__none";

export function NetworkSettings() {
  const { policy, loading, loadError, saving, saveError, load, save } = usePolicy();
  const ks = useStatus((s) => s.status?.kill_switch ?? null);
  const [ksDialog, setKsDialog] = useState<"on" | "off" | null>(null);

  const set = (patch: Partial<NetworkPolicy>) => policy && void save({ ...policy, ...patch });

  return (
    <>
      <ScreenHeader
        title="Network"
        description="Leak protection, kill switch and connection behaviour. Enforced by the background service."
        actions={
          saving ? (
            <span className="flex items-center gap-1.5 text-xs text-muted">
              <RefreshCw className="size-3.5 animate-spin" /> Saving…
            </span>
          ) : policy && !saveError ? (
            <span className="flex items-center gap-1.5 text-xs text-faint">
              <Check className="size-3.5" /> All changes saved
            </span>
          ) : null
        }
      />
      <ScreenBody narrow className="flex flex-col gap-5">
        {saveError && (
          <Alert tone="danger" title="Couldn’t apply the change" action={<Button size="xs" variant="ghost" onClick={() => void load()}>Reload</Button>}>
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
              title="Network policy unavailable"
              description={<span className="selectable">{loadError}</span>}
              action={
                <Button size="sm" variant="secondary" onClick={() => void load()}>
                  <RefreshCw /> Try again
                </Button>
              }
            />
          )
        ) : (
          <>
            {/* Kill switch */}
            <Card className="overflow-hidden">
              <CardHeader
                icon={ks?.enabled && ks.firewall_verified ? <ShieldCheck className="text-success" /> : ks?.enabled ? <ShieldAlert className="text-warning" /> : <ShieldOff />}
                title="Kill switch"
                description="Blocks all traffic outside the VPN tunnel at the OS firewall — even if Alizy’s window is closed or the tunnel drops."
                action={
                  <Switch
                    checked={policy.kill_switch}
                    onCheckedChange={(v) => setKsDialog(v ? "on" : "off")}
                    aria-label="Kill switch"
                    disabled={saving}
                  />
                }
              />
              {policy.kill_switch && ks && !ks.firewall_verified && (
                <div className="px-5 pb-4">
                  <Alert tone="warning" title="Enabled, but not verified by the firewall">
                    The service could not confirm that its blocking rules are active. Traffic may leak. Check the System Check in Settings
                    for firewall conflicts (firewalld/ufw) or missing nftables support.
                  </Alert>
                </div>
              )}
              {policy.kill_switch && ks?.firewall_verified && (
                <div className="px-5 pb-4">
                  <Alert tone="success">Firewall rules are installed and verified.</Alert>
                </div>
              )}
              <Divider />
              <SettingRow
                htmlFor="allow-lan"
                title="Allow local network while protected"
                description="Keep access to printers, NAS and other devices on your LAN while the kill switch is active."
                control={<Switch id="allow-lan" checked={policy.allow_lan} onCheckedChange={(v) => set({ allow_lan: v })} disabled={saving} />}
              />
            </Card>

            {/* IP families + DNS */}
            <Card className="overflow-hidden">
              <CardHeader icon={<Router />} title="Leak protection" description="Control which traffic is allowed to leave this machine." />
              <Divider />
              <SettingRow
                htmlFor="ipv4"
                title="IPv4"
                description="Allow IPv4 traffic."
                control={
                  <FamilySwitch
                    id="ipv4"
                    checked={policy.ipv4_enabled}
                    lockOn={!policy.ipv6_enabled}
                    onChange={(v) => set({ ipv4_enabled: v })}
                    disabled={saving}
                  />
                }
              />
              <Divider className="mx-5" />
              <SettingRow
                htmlFor="ipv6"
                title="IPv6"
                description="Allow IPv6 traffic. Many VPN providers don’t tunnel IPv6 — disable it to avoid leaks."
                control={
                  <FamilySwitch
                    id="ipv6"
                    checked={policy.ipv6_enabled}
                    lockOn={!policy.ipv4_enabled}
                    onChange={(v) => set({ ipv6_enabled: v })}
                    disabled={saving}
                  />
                }
              />
              <div className="px-5 pb-4">
                <p className="text-xs leading-relaxed text-faint">
                  A disabled family is <b className="font-medium text-muted">blocked at the OS firewall</b>, not merely left unrouted — so
                  nothing can leak over it. At least one family must stay enabled.
                </p>
              </div>
              <Divider />
              <SettingRow
                htmlFor="dns-leak"
                title="DNS leak protection"
                description="Force all DNS queries through the tunnel’s DNS servers while connected."
                control={
                  <Switch id="dns-leak" checked={policy.dns_leak_protection} onCheckedChange={(v) => set({ dns_leak_protection: v })} disabled={saving} />
                }
              />
              <Divider className="mx-5" />
              <SettingRow title="Custom DNS servers" description="Override the DNS servers from your profiles. Leave empty to use each profile’s DNS.">
                <DnsEditor value={policy.custom_dns} onChange={(custom_dns) => set({ custom_dns })} disabled={saving} />
              </SettingRow>
            </Card>

            {/* Connection behaviour */}
            <Card className="overflow-hidden">
              <CardHeader icon={<Wifi />} title="Connection" description="How Alizy connects and recovers." />
              <Divider />
              <SettingRow
                htmlFor="auto-reconnect"
                title="Auto-reconnect"
                description="Re-establish the tunnel automatically after network changes, sleep, or interruptions."
                control={
                  <Switch id="auto-reconnect" checked={policy.auto_reconnect} onCheckedChange={(v) => set({ auto_reconnect: v })} disabled={saving} />
                }
              />
              <Divider className="mx-5" />
              <AutoConnect />
            </Card>

            {/* LAN forward proxy */}
            <LanProxyCard />
          </>
        )}
      </ScreenBody>

      <ConfirmDialog
        open={ksDialog === "on"}
        onOpenChange={(o) => !o && setKsDialog(null)}
        icon={<ShieldCheck />}
        title="Turn on the kill switch?"
        description="All internet traffic that doesn’t go through the VPN will be blocked by the system firewall. This stays in effect even when the Alizy window is closed, after a crash, and while disconnected — you’ll have no internet until you connect or turn this off."
        confirmLabel="Turn on kill switch"
        onConfirm={async () => {
          if (!policy) return;
          return (await save({ ...policy, kill_switch: true })) ? undefined : false;
        }}
      >
        {policy && !policy.allow_lan && <p className="text-xs text-muted">Local network access is currently blocked too. You can allow it below.</p>}
      </ConfirmDialog>
      <ConfirmDialog
        open={ksDialog === "off"}
        onOpenChange={(o) => !o && setKsDialog(null)}
        destructive
        icon={<ShieldOff />}
        title="Turn off the kill switch?"
        description="If the VPN connection drops, your traffic will immediately flow through your regular connection and may expose your real IP address."
        confirmLabel="Turn off"
        onConfirm={async () => {
          if (!policy) return;
          return (await save({ ...policy, kill_switch: false })) ? undefined : false;
        }}
      />
    </>
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
  if (checked && lockOn) {
    return (
      <Tooltip content="At least one of IPv4 or IPv6 must stay enabled.">
        <span tabIndex={0}>{sw}</span>
      </Tooltip>
    );
  }
  return sw;
}

function DnsEditor({ value, onChange, disabled }: { value: string[]; onChange: (v: string[]) => void; disabled?: boolean }) {
  const [draft, setDraft] = useState("");
  const t = draft.trim();
  const error = !t ? null : !isIP(t) ? "Enter a valid IPv4 or IPv6 address." : value.includes(t) ? "Already in the list." : null;
  const add = () => {
    if (!t || error) return;
    onChange([...value, t]);
    setDraft("");
  };
  return (
    <div className="flex flex-col gap-2">
      {value.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {value.map((d) => (
            <span key={d} className="inline-flex h-7 items-center gap-1 rounded-lg border border-border bg-surface-2 pr-1 pl-2.5 font-mono text-[12px] text-fg">
              {d}
              <button
                type="button"
                onClick={() => onChange(value.filter((x) => x !== d))}
                disabled={disabled}
                aria-label={`Remove DNS server ${d}`}
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
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="e.g. 1.1.1.1 or 2606:4700:4700::1111"
            className="font-mono text-[13px]"
            invalid={!!error}
            aria-label="DNS server address"
            disabled={disabled}
          />
          {error && (
            <p className="mt-1 flex items-center gap-1 text-xs text-danger">
              <CircleAlert className="size-3" /> {error}
            </p>
          )}
        </div>
        <Button type="submit" variant="secondary" disabled={!t || !!error || disabled}>
          <Plus /> Add
        </Button>
      </form>
    </div>
  );
}

/** Share this machine's VPN with other devices on the LAN (phase A: no auth). */
function LanProxyCard() {
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
      polled.socks_listening === mine.socks_listening
    ) {
      setMine(null);
    }
  }, [mine, polled]);

  const enabled = lan?.enabled ?? false;
  const port = lan?.port || 8080;
  const socksPort = lan?.socks_port || 1080;
  const shownPort = portDraft ?? String(port);
  const shownSocksPort = socksPortDraft ?? String(socksPort);
  const portNum = Number(shownPort);
  const socksPortNum = Number(shownSocksPort);
  const portInvalid = !/^\d{1,5}$/.test(shownPort.trim()) || portNum < 1 || portNum > 65535;
  const socksPortInvalid = !/^\d{1,5}$/.test(shownSocksPort.trim()) || socksPortNum < 1 || socksPortNum > 65535;

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
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
      toast.error("Couldn’t change the LAN proxy", e);
    } finally {
      setSaving(false);
    }
  };

  const commitPort = () => {
    if (portDraft === null || portInvalid || portNum === port) {
      setPortDraft(null);
      return;
    }
    void apply({ enabled, port: portNum, socks_port: socksPortInvalid ? socksPort : socksPortNum });
  };

  const commitSocksPort = () => {
    if (socksPortDraft === null || socksPortInvalid || socksPortNum === socksPort) {
      setSocksPortDraft(null);
      return;
    }
    void apply({ enabled, port: portInvalid ? port : portNum, socks_port: socksPortNum });
  };

  return (
    <Card className="overflow-hidden">
      <CardHeader
        icon={<Cast />}
        title="Share VPN with other devices"
        description="Run a proxy on this computer so a smart TV, console or any other device on your Wi-Fi can browse through Alizy’s tunnel."
        action={
          <Switch
            checked={enabled}
            onCheckedChange={(v) => void apply({ enabled: v, port: portInvalid ? port : portNum, socks_port: socksPortInvalid ? socksPort : socksPortNum })}
            disabled={saving}
            aria-label="LAN proxy"
          />
        }
      />
      {enabled && (
        <div className="flex flex-col gap-4 px-5 pb-5">
          <Alert tone="warning" title="No password — anyone on your network can use it">
            Every device that can reach this computer on the local network can browse through your VPN, for free. Turn the proxy off when you
            don’t need it.
          </Alert>
          {(lan?.error ?? error) && (
            <Alert tone="danger" title="The proxy isn’t running">
              <span className="selectable">{lan?.error ?? error}</span>
            </Alert>
          )}
          {!lan?.error && !error && (lan?.listening || lan?.socks_listening) && (
            <Alert tone="success" title="Listening">
              {lan!.addresses.length > 0 ? (
                <div className="flex flex-col gap-1">
                  {lan!.listening && (
                    <span>
                      <b className="font-medium text-muted">HTTP proxy</b>{" "}
                      <span className="font-mono text-xs">{lan!.addresses[0]}:{port}</span>
                      <span className="text-faint"> — for browsers and most apps</span>
                    </span>
                  )}
                  {lan!.socks_listening && (
                    <span>
                      <b className="font-medium text-muted">SOCKS5 proxy</b>{" "}
                      <span className="font-mono text-xs">{lan!.addresses[0]}:{socksPort}</span>
                      <span className="text-faint"> — for Telegram, SSH and other TCP apps</span>
                    </span>
                  )}
                  {lan!.addresses.length > 1 && (
                    <span className="text-faint text-xs mt-1">
                      Also reachable at{" "}
                      {lan!.addresses.slice(1).join(", ")}
                    </span>
                  )}
                </div>
              ) : (
                <span>Listening but this computer has no address other devices can reach. Is Wi-Fi connected?</span>
              )}
            </Alert>
          )}
          {lan?.socks_error && (
            <Alert tone="danger" title="SOCKS5 proxy isn’t running">
              <span className="selectable">{lan.socks_error}</span>
            </Alert>
          )}
          <SettingRow
            htmlFor="lan-proxy-port"
            title="HTTP proxy port"
            description="For browsers and apps that support HTTP proxies."
            control={
              <Input
                id="lan-proxy-port"
                value={shownPort}
                inputMode="numeric"
                className="w-24 font-mono text-[13px]"
                disabled={saving}
                invalid={portInvalid}
                aria-label="HTTP proxy port"
                onChange={(e) => setPortDraft(e.target.value)}
                onBlur={commitPort}
                onKeyDown={(e) => e.key === "Enter" && commitPort()}
              />
            }
          />
          {portInvalid && (
            <p className="-mt-2 flex items-center gap-1 text-xs text-danger">
              <CircleAlert className="size-3" /> Enter a port between 1 and 65535.
            </p>
          )}
          <SettingRow
            htmlFor="lan-socks-port"
            title="SOCKS5 proxy port"
            description="For Telegram, SSH and other apps that need raw TCP tunnelling."
            control={
              <Input
                id="lan-socks-port"
                value={shownSocksPort}
                inputMode="numeric"
                className="w-24 font-mono text-[13px]"
                disabled={saving}
                invalid={socksPortInvalid}
                aria-label="SOCKS5 proxy port"
                onChange={(e) => setSocksPortDraft(e.target.value)}
                onBlur={commitSocksPort}
                onKeyDown={(e) => e.key === "Enter" && commitSocksPort()}
              />
            }
          />
          {socksPortInvalid && (
            <p className="-mt-2 flex items-center gap-1 text-xs text-danger">
              <CircleAlert className="size-3" /> Enter a port between 1 and 65535.
            </p>
          )}
          <p className="text-xs leading-relaxed text-faint">
            TCP only — apps that insist on UDP (some games, QUIC-only clients) won’t work through either proxy. The kill switch still applies to
            this computer; only devices using a proxy get the tunnel.
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
      title="Auto-connect on launch"
      description={settingsError ? <span className="text-danger">Settings unavailable: {settingsError}</span> : "Connect this profile automatically when Alizy starts."}
      control={
        <Select
          value={current ?? NONE}
          onValueChange={(v) => void update({ auto_connect_profile_id: v === NONE ? null : v })}
          disabled={!settings}
          aria-label="Auto-connect profile"
          className="w-56"
          options={[
            { value: NONE, label: "Don’t auto-connect" },
            ...(missing ? [{ value: current!, label: "Deleted profile", disabled: true }] : []),
            ...[...profiles].sort((a, b) => a.name.localeCompare(b.name)).map((p) => ({ value: p.id, label: p.name })),
          ]}
        />
      }
    />
  );
}
