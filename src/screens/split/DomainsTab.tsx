import { Globe } from "lucide-react";
import { useState } from "react";
import { Select } from "../../components/ui/select";
import type { DomainMatch } from "../../lib/types";
import { checkDomain } from "../../lib/validate";
import { AddRuleBar } from "./AddRuleBar";
import { DomainStatusLine } from "./DomainStatusLine";
import { RuleListTab } from "./RuleListTab";
import { MATCH_HELP, MATCH_LABEL, parseDomainInput } from "./rules";
import { useSplit } from "./store";

export function DomainsTab() {
  const data = useSplit((s) => s.data);
  const [value, setValue] = useState("");
  const [mode, setMode] = useState<DomainMatch>("exact");

  const onValue = (v: string) => {
    setValue(v);
    if (v.trim().startsWith("*.") && mode === "exact") setMode("wildcard");
  };

  return (
    <RuleListTab
      kind="domain"
      addBar={
        <AddRuleBar
          placeholder="bank.example.com or *.bank.example.com"
          value={value}
          onValueChange={onValue}
          hint={MATCH_HELP[mode]}
          build={(raw) => {
            const c = checkDomain(raw);
            if (!c.ok) return { error: c.error };
            const d = parseDomainInput(raw, mode);
            return { target: { type: "domain", domain: d.domain, mode: d.mode } };
          }}
          extra={
            <Select
              value={mode}
              onValueChange={(v) => setMode(v as DomainMatch)}
              aria-label="Match mode"
              className="w-48"
              options={(["exact", "wildcard", "parent"] as DomainMatch[]).map((m) => ({
                value: m,
                label: m === "wildcard" ? "Wildcard (subdomains only)" : m === "parent" ? "Parent (domain + subdomains)" : MATCH_LABEL[m],
                description: MATCH_HELP[m],
              }))}
            />
          }
        />
      }
      emptyIcon={<Globe />}
      emptyTitle="No domain rules"
      emptyDescription="Add a domain to send it directly through your regular connection (or force it through the VPN). Alizy resolves the name and keeps the routes in sync with DNS."
      details={(r) => (
        <DomainStatusLine st={data?.domains.find((d) => d.rule_id === r.id)} enabled={r.enabled} splitOn={!!data?.config.enabled} />
      )}
    />
  );
}
