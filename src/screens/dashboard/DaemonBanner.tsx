import { ServerCrash, Stethoscope } from "lucide-react";
import { Button } from "../../components/ui/button";
import { useNav } from "../../store/nav";
import { t } from "../../i18n";

export function DaemonBanner({ error }: { error: string }) {
  const go = useNav((s) => s.go);
  return (
    <div role="alert" className="relative overflow-hidden rounded-2xl border border-danger/35 bg-danger/[0.07] p-5 shadow-card">
      <div className="pointer-events-none absolute -top-16 -end-16 size-48 rounded-full bg-danger/10 blur-3xl" aria-hidden />
      <div className="relative flex items-start gap-4">
        <div className="flex size-11 shrink-0 items-center justify-center rounded-xl bg-danger/15 text-danger">
          <ServerCrash className="size-5" />
        </div>
        <div className="min-w-0 flex-1">
          <h2 className="text-[15px] font-semibold text-fg">{t("The Alizy background service isn’t reachable")}</h2>
          <p className="mt-1 text-[13px] leading-relaxed text-muted">
            {t(
              "Connections, the kill switch and split tunneling are handled by the privileged service alizyd. It may not be installed, not running, or this user may lack permission to talk to it. Your profiles are safe; nothing can connect until the service is available.",
            )}
          </p>
          <pre dir="ltr" className="selectable mt-3 max-h-28 overflow-auto rounded-lg border border-danger/20 bg-background/60 px-3 py-2 font-mono text-[12px] whitespace-pre-wrap text-danger">
            {error}
          </pre>
          <div className="mt-4 flex flex-wrap items-center gap-2">
            <Button variant="primary" size="sm" onClick={() => go("general", "system-check")}>
              <Stethoscope />
              {t("Open System Check")}
            </Button>
            <span className="text-xs text-muted">
              {error.includes("not installed") ? (
                <>{t("Install it: download and run alizy-installer from the release page.")}</>
              ) : (
                <>
                  {t("Typical fix:")}{" "}
                  <code dir="ltr" className="selectable font-mono text-fg">
                    sudo systemctl enable --now alizyd
                  </code>
                </>
              )}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
