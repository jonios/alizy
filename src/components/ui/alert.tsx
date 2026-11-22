import { CircleAlert, CircleCheck, Info, TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "../../lib/utils";

export type AlertTone = "info" | "success" | "warning" | "danger";

const STYLES: Record<AlertTone, { box: string; icon: string; Icon: typeof Info }> = {
  info: { box: "border-primary/25 bg-primary/[0.07]", icon: "text-primary", Icon: Info },
  success: { box: "border-success/25 bg-success/[0.07]", icon: "text-success", Icon: CircleCheck },
  warning: { box: "border-warning/30 bg-warning/[0.08]", icon: "text-warning", Icon: TriangleAlert },
  danger: { box: "border-danger/30 bg-danger/[0.07]", icon: "text-danger", Icon: CircleAlert },
};

export function Alert({
  tone = "info",
  title,
  children,
  action,
  icon,
  className,
}: {
  tone?: AlertTone;
  title?: ReactNode;
  children?: ReactNode;
  action?: ReactNode;
  icon?: ReactNode;
  className?: string;
}) {
  const s = STYLES[tone];
  return (
    <div
      role={tone === "danger" || tone === "warning" ? "alert" : "status"}
      className={cn("flex items-start gap-3 rounded-xl border px-4 py-3", s.box, className)}
    >
      <span className={cn("mt-0.5 shrink-0 [&_svg]:size-4", s.icon)}>{icon ?? <s.Icon />}</span>
      <div className="min-w-0 flex-1 text-[13px] leading-relaxed">
        {title && <div className="font-medium text-fg">{title}</div>}
        {children && <div className={cn("text-muted", title && "mt-0.5")}>{children}</div>}
      </div>
      {action && <div className="shrink-0 self-center">{action}</div>}
    </div>
  );
}
