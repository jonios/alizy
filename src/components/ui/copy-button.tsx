import { Check, Copy } from "lucide-react";
import { useEffect, useState } from "react";
import { copyText } from "../../lib/utils";
import { toast } from "../../store/toast";
import { Button, type ButtonSize } from "./button";
import { Tooltip } from "./tooltip";
import { t } from "../../i18n";

export function CopyButton({ text, label = t("Copy"), size = "icon-sm", className }: { text: string; label?: string; size?: ButtonSize; className?: string }) {
  const [done, setDone] = useState(false);
  useEffect(() => {
    if (!done) return;
    const t = window.setTimeout(() => setDone(false), 1500);
    return () => window.clearTimeout(t);
  }, [done]);
  return (
    <Tooltip content={done ? t("Copied") : label}>
      <Button
        variant="ghost"
        size={size}
        className={className}
        aria-label={label}
        onClick={async () => {
          try {
            await copyText(text);
            setDone(true);
          } catch (e) {
            toast.error(t("Could not copy to clipboard"), e);
          }
        }}
      >
        {done ? <Check className="text-success" /> : <Copy />}
      </Button>
    </Tooltip>
  );
}
