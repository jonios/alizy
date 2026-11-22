import { useStatus } from "../../store/status";
import type { useSplit } from "./store";

export type SplitData = NonNullable<ReturnType<typeof useSplit.getState>["data"]>;

/** Two separate facts: are the rules installed in the kernel firewall, and do they change traffic right now. */
export function useSplitState(data: SplitData | null) {
  const status = useStatus((s) => s.status);
  const connected = status?.state === "connected";
  const ksOn = !!status?.kill_switch.enabled;
  const ranges = data ? data.direct.v4.length + data.direct.v6.length : 0;
  // The daemon only installs bypass sets while a tunnel is up or the kill switch is on.
  const needed = connected || ksOn;
  const firewall: "installed" | "not-needed" | "unverified" = !data?.applied ? "unverified" : needed && ranges > 0 ? "installed" : "not-needed";
  const traffic: "bypassing" | "through-ks" | "inactive" | "no-addresses" =
    ranges === 0 ? "no-addresses" : firewall !== "installed" ? "inactive" : connected ? "bypassing" : "through-ks";
  return { firewall, traffic, ranges, connected, ksOn };
}

