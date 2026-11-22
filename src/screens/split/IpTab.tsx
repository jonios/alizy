import { Binary } from "lucide-react";
import { useState } from "react";
import { checkNet } from "../../lib/validate";
import { AddRuleBar } from "./AddRuleBar";
import { RuleListTab } from "./RuleListTab";

export function IpTab() {
  const [value, setValue] = useState("");
  const c = value.trim() ? checkNet(value) : null;
  return (
    <RuleListTab
      kind="ip"
      addBar={
        <AddRuleBar
          placeholder="192.0.2.10, 198.51.100.0/24 or 2001:db8::/32"
          value={value}
          onValueChange={setValue}
          hint={
            c && c.ok
              ? `IPv${c.family} ${c.normalized.includes("/") ? "range" : "address"} — ${c.normalized}`
              : "Single addresses or CIDR ranges, IPv4 or IPv6."
          }
          build={(raw) => {
            const r = checkNet(raw);
            return r.ok ? { target: { type: "ip", net: r.normalized } } : { error: r.error };
          }}
        />
      }
      emptyIcon={<Binary />}
      emptyTitle="No IP rules"
      emptyDescription="IP and CIDR rules take precedence over domain rules. More specific ranges (longer prefixes) win over broader ones."
    />
  );
}
