import { CircleAlert, CircleCheck, Copy as CopyIcon, FileWarning, TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";
import { useImportReport } from "../store/importReport";
import { useNav } from "../store/nav";
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "./ui/dialog";
import { Button } from "./ui/button";
import { cn } from "../lib/utils";
import { t } from "../i18n";

export function ImportReportDialog() {
  const { report, title, close } = useImportReport();
  const openDetails = useNav((s) => s.openDetails);
  const open = report !== null;

  const imported = report?.imported ?? [];
  const duplicates = report?.duplicates ?? [];
  const errors = report?.errors ?? [];
  const warnings = (report?.warnings ?? []).filter((w) => w.messages.length > 0);
  const warnCount = warnings.reduce((n, w) => n + w.messages.length, 0);

  const summary =
    imported.length === 0 && errors.length === 0 && duplicates.length === 0
      ? t("Nothing was found to import.")
      : [
          imported.length === 1 ? t("{count} profile imported", { count: imported.length }) : t("{count} profiles imported", { count: imported.length }),
          duplicates.length
            ? duplicates.length === 1
              ? t("{count} duplicate skipped", { count: duplicates.length })
              : t("{count} duplicates skipped", { count: duplicates.length })
            : "",
          errors.length ? (errors.length === 1 ? t("{count} error", { count: errors.length }) : t("{count} errors", { count: errors.length })) : "",
        ]
          .filter(Boolean)
          .join(t(", ")) + t(".");

  return (
    <Dialog open={open} onOpenChange={(o) => !o && close()}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{summary}</DialogDescription>
        </DialogHeader>
        <DialogBody className="flex flex-col gap-4">
          <div className="grid grid-cols-4 gap-2">
            <Stat label={t("Imported")} value={imported.length} tone="success" />
            <Stat label={t("Duplicates")} value={duplicates.length} tone="neutral" />
            <Stat label={t("Errors")} value={errors.length} tone="danger" />
            <Stat label={t("Warnings")} value={warnCount} tone="warning" />
          </div>

          {imported.length > 0 && (
            <Section icon={<CircleCheck className="text-success" />} title={t("Imported")}>
              {imported.map((p) => (
                <Row key={p.id}>
                  <span className="truncate font-medium text-fg">{p.name}</span>
                  <span dir="ltr" className="truncate text-faint">{p.endpoint ?? t("no endpoint")}</span>
                  <Button
                    variant="link"
                    size="xs"
                    className="ms-auto"
                    onClick={() => {
                      close();
                      openDetails(p.id);
                    }}
                  >
                    {t("Details")}
                  </Button>
                </Row>
              ))}
            </Section>
          )}

          {warnings.length > 0 && (
            <Section icon={<TriangleAlert className="text-warning" />} title={t("Warnings — review these")}>
              {warnings.map((w, i) => (
                <div key={i} className="rounded-lg border border-warning/25 bg-warning/[0.06] px-3 py-2">
                  <div dir="ltr" className="truncate text-start font-mono text-[11px] text-muted">{w.source}</div>
                  <ul className="mt-1 list-disc space-y-0.5 ps-4 text-[13px] text-fg">
                    {w.messages.map((m, j) => (
                      <li key={j}>{m}</li>
                    ))}
                  </ul>
                </div>
              ))}
            </Section>
          )}

          {duplicates.length > 0 && (
            <Section icon={<CopyIcon className="text-muted" />} title={t("Skipped duplicates")}>
              {duplicates.map((d, i) => (
                <Row key={i}>
                  <span className="truncate font-medium text-fg">{d.name}</span>
                  <span dir="ltr" className="truncate font-mono text-[11px] text-faint">{d.source}</span>
                  <Button
                    variant="link"
                    size="xs"
                    className="ms-auto"
                    onClick={() => {
                      close();
                      openDetails(d.existing_id);
                    }}
                  >
                    {t("View existing")}
                  </Button>
                </Row>
              ))}
            </Section>
          )}

          {errors.length > 0 && (
            <Section icon={<CircleAlert className="text-danger" />} title={t("Errors")}>
              {errors.map((e, i) => (
                <div key={i} className="rounded-lg border border-danger/25 bg-danger/[0.06] px-3 py-2">
                  <div dir="ltr" className="truncate text-start font-mono text-[11px] text-muted">{e.source}</div>
                  <div className="selectable mt-0.5 text-[13px] text-fg">{e.message}</div>
                </div>
              ))}
            </Section>
          )}

          {imported.length === 0 && errors.length === 0 && duplicates.length === 0 && (
            <div className="flex flex-col items-center gap-2 py-6 text-center text-[13px] text-muted">
              <FileWarning className="size-6 text-faint" />
              {t("No WireGuard configuration files were found in the selection.")}
            </div>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="primary" onClick={close}>
            {t("Done")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function Stat({ label, value, tone }: { label: string; value: number; tone: "success" | "neutral" | "danger" | "warning" }) {
  const cls = {
    success: "text-success",
    neutral: "text-fg",
    danger: "text-danger",
    warning: "text-warning",
  }[tone];
  return (
    <div className="rounded-xl border border-border bg-surface-2/60 px-3 py-2.5">
      <div className={cn("text-xl font-semibold tabular", value === 0 ? "text-faint" : cls)}>{value}</div>
      <div className="text-[11px] text-muted">{label}</div>
    </div>
  );
}

function Section({ icon, title, children }: { icon: ReactNode; title: string; children: ReactNode }) {
  return (
    <section>
      <div className="mb-2 flex items-center gap-2 text-[13px] font-medium text-fg [&_svg]:size-4">
        {icon}
        {title}
      </div>
      <div className="flex flex-col gap-1.5">{children}</div>
    </section>
  );
}

function Row({ children }: { children: ReactNode }) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-border bg-surface px-3 py-1.5 text-[13px]">{children}</div>
  );
}

