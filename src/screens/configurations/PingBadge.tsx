import { Badge } from "../../components/ui/badge";
import { Tooltip } from "../../components/ui/tooltip";
import { usePing } from "../../store/ping";
import { useStatus } from "../../store/status";
import { t } from "../../i18n";

/** Colour thresholds for the round trip: green < 80 ms < yellow < 250 ms. */
const FAST_MS = 80;
const OK_MS = 250;

function failureHint(error: string | null, killSwitch: boolean): string {
  switch (error) {
    case "timeout":
      return killSwitch
        ? t("No reply — the kill switch is blocking outbound traffic, so this server can't be reached.")
        : t("No reply within one second.");
    case "blocked":
      return t("Blocked by Alizy's firewall — the kill switch is on.");
    case "unreachable":
      return t("The host is unreachable from this network.");
    default:
      return error ?? t("No reply.");
  }
}

/**
 * Latency of a profile's endpoint: `42 ms` (colour coded), `…` while the
 * first measurement is running, or `✕` with the reason on hover.
 */
export function PingBadge({ id }: { id: string }) {
  const entry = usePing((s) => s.results[id]);
  const probing = usePing((s) => s.busy);
  const killSwitch = useStatus((s) => !!s.status?.kill_switch.enabled);

  if (!entry) {
    if (!probing) return null;
    return (
      <Badge tone="neutral" className="animate-pulse" aria-label={t("Measuring ping")}>
        …
      </Badge>
    );
  }

  if (entry.ms !== null) {
    const tone = entry.ms < FAST_MS ? "success" : entry.ms < OK_MS ? "warning" : "danger";
    return (
      <Badge tone={tone} aria-label={t("Ping {ms} milliseconds", { ms: entry.ms })}>
        {entry.ms} ms
      </Badge>
    );
  }

  const hint = failureHint(entry.error, killSwitch);
  return (
    <Tooltip content={hint}>
      <Badge tone="danger" className="cursor-help" aria-label={hint}>
        ✕
      </Badge>
    </Tooltip>
  );
}
