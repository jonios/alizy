import { Clock, Server, TriangleAlert, Waypoints } from "lucide-react";
import { Card, CardContent, CardHeader, InfoRow } from "../../components/ui/card";
import { Badge } from "../../components/ui/badge";
import { HANDSHAKE_WARN_SEC } from "../../lib/constants";
import { formatDuration } from "../../lib/format";
import { useNow } from "../../lib/hooks";
import { useStatus } from "../../store/status";
import { Tooltip } from "../../components/ui/tooltip";

export function TunnelCard({ active }: { active: boolean }) {
  const status = useStatus((s) => s.status);
  const now = useNow(1000);
  const stats = status?.stats;
  const hs = stats?.last_handshake ?? 0;
  const age = hs > 0 ? Math.max(0, now - hs) : null;
  const stale = age !== null && age > HANDSHAKE_WARN_SEC;
  const cfg = status?.tunnel_config;
  const isSsh = status?.tunnel_kind === "ssh";

  return (
    <Card>
      <CardHeader icon={<Waypoints />} title={isSsh ? "SSH tunnel" : "Tunnel"} description={active ? status?.interface ?? undefined : "Not connected"} />
      <CardContent className="divide-y divide-border pb-3">
        <InfoRow
          label={
            <span className="flex items-center gap-1.5">
              <Clock className="size-3.5" /> {isSsh ? "Last keepalive" : "Latest handshake"}
            </span>
          }
        >
          {!active ? (
            <span className="text-faint">—</span>
          ) : age === null ? (
            <Badge tone="warning">{isSsh ? "No keepalive yet" : "No handshake yet"}</Badge>
          ) : stale ? (
            <Tooltip content={
              isSsh
                ? "No keepalive for over 3 minutes — the SSH server may be unreachable."
                : "No handshake for over 3 minutes — the peer may be unreachable or traffic is being blocked."
            }>
              <span className="inline-flex items-center gap-1.5 font-medium text-warning tabular" tabIndex={0}>
                <TriangleAlert className="size-3.5" />
                {formatDuration(age)} ago
              </span>
            </Tooltip>
          ) : (
            <span className="tabular">{age < 2 ? "just now" : `${age} s ago`}</span>
          )}
        </InfoRow>
        <InfoRow
          label={
            <span className="flex items-center gap-1.5">
              <Server className="size-3.5" /> Endpoint
            </span>
          }
        >
          <span className="selectable font-mono text-[12px]">{active ? stats?.endpoint ?? "—" : "—"}</span>
        </InfoRow>
        <InfoRow label="Tunnel addresses">
          <span className="selectable font-mono text-[12px]">{active && cfg?.addresses.length ? cfg.addresses.join(", ") : "—"}</span>
        </InfoRow>
        <InfoRow label="DNS servers">
          <span className="selectable font-mono text-[12px]">{active && cfg?.dns.length ? cfg.dns.join(", ") : "—"}</span>
        </InfoRow>
      </CardContent>
    </Card>
  );
}
