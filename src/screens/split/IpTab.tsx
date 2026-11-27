import { Binary } from "lucide-react";
import { useState } from "react";
import { checkNet } from "../../lib/validate";
import { AddRuleBar } from "./AddRuleBar";
import { RuleListTab } from "./RuleListTab";
import { t } from "../../i18n";

export function IpTab() {
  const [value, setValue] = useState("");
  const c = value.trim() ? checkNet(value) : null;
  return (
    <RuleListTab
      kind="ip"
      addBar={
        <AddRuleBar
          placeholder={t("{a}, {b} or {c}", { a: "192.0.2.10", b: "198.51.100.0/24", c: "2001:db8::/32" })}
          value={value}
          onValueChange={setValue}
          hint={
            c && c.ok
              ? c.normalized.includes("/")
                ? t("IPv{family} range — {net}", { family: c.family, net: c.normalized })
                : t("IPv{family} address — {net}", { family: c.family, net: c.normalized })
              : t("Single addresses or CIDR ranges, IPv4 or IPv6.")
          }
          build={(raw) => {
            const r = checkNet(raw);
            return r.ok ? { target: { type: "ip", net: r.normalized } } : { error: r.error };
          }}
        />
      }
      emptyIcon={<Binary />}
      emptyTitle={t("No IP rules")}
      emptyDescription={t("IP and CIDR rules take precedence over domain rules. More specific ranges (longer prefixes) win over broader ones.")}
    />
  );
}
