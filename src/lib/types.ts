// Types mirrored from the Rust side (alizy-core / src-tauri). Keep in sync.

export type ConnectionState =
  | "disconnected"
  | "connecting"
  | "connected"
  | "disconnecting"
  | "reconnecting"
  | "error"
  | "protected";

/** "tunnel": all traffic through the VPN (kill switch available).
 * "proxy": only apps using the local SOCKS5/HTTP proxy go through the VPN. */
export type ConnectionMode = "tunnel" | "proxy";

export interface NetworkPolicy {
  /** The user's kill-switch preference; it only takes effect in tunnel mode. */
  kill_switch: boolean;
  allow_lan: boolean;
  ipv4_enabled: boolean;
  ipv6_enabled: boolean;
  dns_leak_protection: boolean;
  custom_dns: string[];
  auto_reconnect: boolean;
  /** Absent when the background service predates proxy mode. */
  mode?: ConnectionMode;
  proxy_socks_port?: number;
  proxy_http_port?: number;
}

/** Proxy mode's local proxy on 127.0.0.1. */
export interface LocalProxyStatus {
  active: boolean;
  socks_port: number;
  http_port: number;
  socks_listening: boolean;
  http_listening: boolean;
  error?: string | null;
  /** SOCKS5 UDP ASSOCIATE works with the current tunnel. */
  udp: boolean;
}

export interface TunnelStats {
  rx_bytes: number;
  tx_bytes: number;
  /** unix seconds, 0 = never */
  last_handshake: number;
  endpoint: string | null;
}

export type Host = { kind: "ip"; value: string } | { kind: "name"; value: string };
export interface Endpoint {
  host: Host;
  port: number;
}

export interface PublicPeer {
  public_key: string;
  has_preshared_key: boolean;
  allowed_ips: string[];
  endpoint: Endpoint | null;
  persistent_keepalive: number | null;
}

export interface PublicConfig {
  interface_public_key: string;
  addresses: string[];
  dns: string[];
  dns_search: string[];
  mtu: number | null;
  listen_port: number | null;
  peers: PublicPeer[];
}

export type DnsBackend = "systemd_resolved" | "resolvconf" | "resolv_conf_file";

export interface DaemonStatus {
  state: ConnectionState;
  profile_id: string | null;
  profile_name: string | null;
  interface: string | null;
  connected_since: number | null;
  stats: TunnelStats | null;
  kill_switch: { enabled: boolean; firewall_verified: boolean; firewall_tag: string | null };
  policy: NetworkPolicy;
  last_error: string | null;
  tunnel_config: PublicConfig | null;
  daemon_version: string;
  dns_backend: DnsBackend;
  /** "wireguard" | "ssh" while a tunnel is up, else null/absent. */
  tunnel_kind?: string | null;
  /** LAN forward proxy (share this machine's VPN with other devices). */
  lan_proxy?: LanProxyStatus;
  /** Proxy mode's local proxy; absent when the service predates proxy mode. */
  local_proxy?: LocalProxyStatus;
}

/** LAN forward proxy configuration: devices on the local network reach the
 * internet through this machine's tunnel, optionally with a login. */
export interface LanProxyConfig {
  enabled: boolean;
  port: number;
  socks_port: number;
  /** null: open to anyone on the network. `password` is sent only to set or
   * change it; omitted, the service keeps the current one for that username. */
  auth?: { username: string; password?: string } | null;
}

/** What the daemon reports about the LAN proxy. */
export interface LanProxyStatus {
  enabled: boolean;
  /** Configured HTTP proxy port; 0 only in the default (never configured) status. */
  port: number;
  /** Configured SOCKS5 proxy port. */
  socks_port: number;
  /** IPv4 addresses other devices can reach the proxy on. */
  addresses: string[];
  /** Set when the HTTP listener could not be started. */
  error?: string | null;
  /** Whether the HTTP listener is accepting connections right now. */
  listening: boolean;
  /** Set when the SOCKS5 listener could not be started. */
  socks_error?: string | null;
  /** Whether the SOCKS5 listener is accepting connections right now. */
  socks_listening: boolean;
  /** Username clients must log in with; absent when the proxy is open. */
  auth_username?: string | null;
  /** SOCKS5 UDP ASSOCIATE is available. */
  socks_udp?: boolean;
}

/** Emitted on "alizy://status" about once per second. */
export interface StatusEvent {
  status: DaemonStatus | null;
  /** Set when the daemon is unreachable (not installed, not running, no permission). */
  daemon_error: string | null;
}

export interface ProfileSummary {
  id: string;
  name: string;
  category: string | null;
  favorite: boolean;
  /** "host:port" of the first peer */
  endpoint: string | null;
  addresses: string[];
  has_ipv4: boolean;
  has_ipv6: boolean;
  full_tunnel: boolean;
  created_at: number;
  updated_at: number;
  last_connected_at: number | null;
  fingerprint: string;
  kind: ProfileKind;
  /** Non-secret SSH fields; null for WireGuard profiles. */
  ssh: SshSummary | null;
  /** SSH only: the stored password is unusable and must be re-entered. */
  password_needed: boolean;
}

export type ProfileKind = "wireguard" | "ssh";

/** A pinned SSH server host key (known_hosts style). */
export interface HostKey {
  key_type: string;
  key_b64: string;
}

export interface SshSummary {
  host: string;
  port: number;
  username: string;
  /** "SHA256:..." of the pinned host key, null until one is trusted. */
  host_key_fingerprint: string | null;
}

/** What `api.connect` rejects with (a plain object, not an Error). */
export type ConnectErrorCode =
  | "host_key_unknown"
  | "host_key_changed"
  | "auth_failed"
  | "missing_dependency"
  | "cancelled"
  | "password_needed"
  | "tunnel"
  | "bad_request"
  | "unauthorized"
  | "invalid_config"
  | "firewall"
  | "busy"
  | "unsupported"
  | "internal"
  | "other";

export interface ConnectError {
  code: ConnectErrorCode;
  message: string;
  /** Present for host_key_unknown / host_key_changed: the key the server presented. */
  host_key?: HostKey;
  /** SHA256 fingerprint of host_key. */
  fingerprint?: string;
}

export interface ProfileDetail {
  summary: ProfileSummary;
  /** Placeholder for SSH profiles (summary.kind === "ssh"): ignore it, use summary.ssh. */
  config: PublicConfig;
  /** wg-quick text with secrets replaced by "<redacted>" */
  config_text_redacted: string;
  /** compatibility warnings against the current network policy */
  warnings: string[];
}

export interface ImportReport {
  imported: ProfileSummary[];
  duplicates: { source: string; name: string; existing_id: string }[];
  errors: { source: string; message: string }[];
  warnings: { source: string; messages: string[] }[];
}

/** Result of one ICMP probe of a profile's endpoint host. */
export interface PingResult {
  profile_id: string;
  /** endpoint host exactly as configured */
  host: string;
  /** round-trip time in ms (≥ 1), null when the probe failed */
  latency_ms: number | null;
  /** reason when latency_ms is null: "timeout", "blocked", "unreachable", … */
  error: string | null;
}

export interface ValidationResult {
  ok: boolean;
  error: string | null;
  warnings: string[];
  config: PublicConfig | null;
}

export type Theme = "dark" | "light" | "system";
export interface AppSettings {
  theme: Theme;
  language: string;
  launch_at_startup: boolean;
  start_minimized: boolean;
  close_to_tray: boolean;
  notifications: boolean;
  auto_connect_profile_id: string | null;
  /** Update channel is not configured in this build; the UI shows it as unavailable. */
  auto_updates: boolean;
  /** Opt-in: queries an external service (api.ipify.org) for the public IP. */
  show_public_ip: boolean;
}

export type LogLevel = "info" | "warn" | "error";
export type LogCategory = "connection" | "firewall" | "dns" | "network" | "service" | "app";
export interface LogEntry {
  id: number;
  ts: number;
  level: LogLevel;
  category: LogCategory;
  source: "app" | "daemon";
  message: string;
}
export interface LogQuery {
  level?: LogLevel | null;
  category?: LogCategory | null;
  search?: string | null;
  limit?: number;
}

export interface HistoryEntry {
  id: number;
  profile_id: string;
  profile_name: string;
  started_at: number;
  ended_at: number | null;
  rx_bytes: number;
  tx_bytes: number;
  end_reason: string | null;
}

export interface AppInfo {
  version: string;
  platform: string;
  /** "keyring" (Secret Service) or "file" (0600 fallback) */
  secret_backend: string;
  tray_available: boolean;
  desktop: string | null;
  daemon: { reachable: boolean; version: string | null; error: string | null };
}

export interface UpdateInfo {
  current: string;
  latest: string;
  update_available: boolean;
  url: string;
}

// ─── system probe ───
export type Severity = "blocker" | "warning" | "info";
export interface Finding {
  severity: Severity;
  message: string;
  fix: string | null;
}
export interface SystemReport {
  os: { id: string; id_like: string[]; name: string; version_id: string; pretty_name: string };
  kernel: string;
  package_manager: "pacman" | "apt" | "dnf" | "zypper" | "unknown";
  kernel_wireguard: "loaded" | "available" | "missing";
  executables: Record<string, string | null>;
  systemd: boolean;
  firewalld_active: boolean;
  ufw_active: boolean;
  iptables: "nft" | "legacy" | "absent";
  network_manager_active: boolean;
  resolved_active: boolean;
  resolv_conf_target: string | null;
  dns_backend: DnsBackend;
  desktop: string | null;
  findings: Finding[];
}

// ─── split tunnelling ───
export type SplitAction = "direct" | "vpn";
export type DomainMatch = "exact" | "wildcard" | "parent";
export type SplitTarget =
  | { type: "domain"; domain: string; mode: DomainMatch }
  | { type: "ip"; net: string }
  | { type: "app"; path: string; sha256: string | null };

export interface SplitRule {
  id: string;
  target: SplitTarget;
  action: SplitAction;
  enabled: boolean;
  /** lower = stronger within a precedence tier; default 100 */
  priority: number;
  category: string | null;
  note: string | null;
}
export interface SplitConfig {
  enabled: boolean;
  rules: SplitRule[];
}
export interface DirectSets {
  v4: [string, string][];
  v6: [string, string][];
}
export interface ResolvedIp {
  ip: string;
  expires_at: number;
  stale: boolean;
}
export interface DomainStatus {
  rule_id: string;
  domain: string;
  addrs: ResolvedIp[];
  cnames: string[];
  last_resolved: number | null;
  next_refresh: number | null;
  last_error: string | null;
  source: string;
}
export interface SplitWarning {
  ip: string;
  rule_ids: string[];
  message: string;
}
export interface SplitStatus {
  config: SplitConfig;
  domains: DomainStatus[];
  warnings: SplitWarning[];
  direct: DirectSets;
  applied: boolean;
}
export type Tier = "default" | "app" | "wildcard_domain" | "exact_domain" | "ip";
export interface Decision {
  action: SplitAction;
  tier: Tier;
  rule_id: string | null;
  explanation: string;
}
export interface RouteTest {
  query: string;
  domain_decision: Decision | null;
  cnames: string[];
  entries: {
    ip: string;
    decision: Decision;
    intended: string;
    in_kernel_direct_set: boolean | null;
    kernel_route: string | null;
  }[];
  error: string | null;
}
export interface SplitImportResult {
  rules: { target: SplitTarget; action: SplitAction; category: string | null }[];
  errors: string[];
  duplicates: number;
}
