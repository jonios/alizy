// Typed wrappers around the allow-listed Tauri commands (src-tauri/src/commands).
// Every command returns a Promise and rejects with a human-readable string (except `connect`, which rejects with a ConnectError object).

import { invoke } from "@tauri-apps/api/core";
import type {
  AppInfo,
  AppSettings,
  DaemonStatus,
  HistoryEntry,
  ImportReport,
  LanProxyConfig,
  LanProxyStatus,
  LogEntry,
  LogQuery,
  NetworkPolicy,
  HostKey,
  PingResult,
  ProfileDetail,
  ProfileSummary,
  RouteTest,
  SplitAction,
  SplitConfig,
  SplitImportResult,
  SplitStatus,
  SystemReport,
  UpdateInfo,
  ValidationResult,
} from "./types";

export const api = {
  appInfo: () => invoke<AppInfo>("app_info"),
  systemReport: () => invoke<SystemReport>("system_report"),
  status: () => invoke<DaemonStatus | null>("status"),
  /** Asks GitHub for the newest release; downloads nothing. */
  checkUpdate: () => invoke<UpdateInfo>("check_update"),
  openReleasesPage: () => invoke<void>("open_releases_page"),

  // profiles
  profilesList: () => invoke<ProfileSummary[]>("profiles_list"),
  /** ICMP-echo every profile endpoint; resolves when all probes finished. */
  profilesPing: () => invoke<PingResult[]>("profiles_ping"),
  profileGet: (id: string) => invoke<ProfileDetail>("profile_get", { id }),
  validateText: (text: string) => invoke<ValidationResult>("profile_validate_text", { text }),
  importText: (text: string, name: string | null) => invoke<ImportReport>("profile_import_text", { text, name }),
  /** files and/or directories (directories: *.conf, non-recursive) */
  importPaths: (paths: string[]) => invoke<ImportReport>("profile_import_paths", { paths }),
  rename: (id: string, name: string) => invoke<void>("profile_rename", { id, name }),
  setCategory: (id: string, category: string | null) => invoke<void>("profile_set_category", { id, category }),
  setFavorite: (id: string, favorite: boolean) => invoke<void>("profile_set_favorite", { id, favorite }),
  /** text may keep "PrivateKey = <redacted>" to retain the stored key */
  updateText: (id: string, text: string) => invoke<string[]>("profile_update_text", { id, text }),
  createSsh: (name: string, host: string, port: number, username: string, password: string) =>
    invoke<ProfileSummary>("profile_create_ssh", { name, host, port, username, password }),
  /** password: null or "" keeps the stored password. */
  updateSsh: (id: string, name: string, host: string, port: number, username: string, password: string | null) =>
    invoke<ProfileSummary>("profile_update_ssh", { id, name, host, port, username, password }),
  trustHostKey: (id: string, key: HostKey) => invoke<void>("profile_trust_host_key", { id, key }),
  clearHostKey: (id: string) => invoke<void>("profile_clear_host_key", { id }),
  duplicate: (id: string) => invoke<ProfileSummary>("profile_duplicate", { id }),
  remove: (id: string) => invoke<void>("profile_delete", { id }),
  exportProfile: (id: string, path: string, includePrivate: boolean) =>
    invoke<void>("profile_export", { id, path, includePrivate }),
  revealPrivateKey: (id: string) => invoke<string>("profile_reveal_private_key", { id }),
  backupExport: (path: string) => invoke<number>("backup_export", { path }),
  backupImport: (path: string) => invoke<ImportReport>("backup_import", { path }),

  // connection
  /** Rejects with a `ConnectError` (see types.ts), a plain object, not a string. */
  connect: (id: string) => invoke<void>("connect", { id }),
  disconnect: () => invoke<void>("disconnect"),
  policyGet: () => invoke<NetworkPolicy>("policy_get"),
  policySet: (policy: NetworkPolicy) => invoke<void>("policy_set", { policy }),

  // settings, logs, history
  settingsGet: () => invoke<AppSettings>("settings_get"),
  settingsSet: (settings: AppSettings) => invoke<void>("settings_set", { settings }),
  logsQuery: (q: LogQuery) => invoke<LogEntry[]>("logs_query", { query: q }),
  logsExport: (path: string) => invoke<number>("logs_export", { path }),
  logsClear: () => invoke<void>("logs_clear"),
  historyList: (limit: number) => invoke<HistoryEntry[]>("history_list", { limit }),
  publicIp: () => invoke<string>("public_ip"),

  // split tunnelling
  splitGet: () => invoke<SplitStatus>("split_get"),
  splitSet: (config: SplitConfig) => invoke<void>("split_set", { config }),
  splitParseImport: (text: string, defaultAction: SplitAction) =>
    invoke<SplitImportResult>("split_parse_import", { text, defaultAction }),
  splitExport: (path: string) => invoke<number>("split_export", { path }),
  routeTest: (query: string) => invoke<RouteTest>("route_test", { query }),

  // LAN forward proxy (share this machine's VPN with other devices)
  lanProxyGet: () => invoke<LanProxyStatus>("lan_proxy_get"),
  lanProxySet: (config: LanProxyConfig) => invoke<LanProxyStatus>("lan_proxy_set", { config }),

  // window / lifecycle
  quitUi: () => invoke<void>("quit_ui"),
};

export const EVENTS = {
  status: "alizy://status",
  profilesChanged: "alizy://profiles-changed",
  navigate: "alizy://navigate",
} as const;
