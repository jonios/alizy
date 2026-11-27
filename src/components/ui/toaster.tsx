import { CircleAlert, CircleCheck, Info, TriangleAlert, X } from "lucide-react";
import { useToasts, type ToastKind } from "../../store/toast";
import { cn } from "../../lib/utils";
import { t } from "../../i18n";

const ICONS: Record<ToastKind, { Icon: typeof Info; cls: string }> = {
  success: { Icon: CircleCheck, cls: "text-success" },
  error: { Icon: CircleAlert, cls: "text-danger" },
  warning: { Icon: TriangleAlert, cls: "text-warning" },
  info: { Icon: Info, cls: "text-primary" },
};

export function Toaster() {
  const { toasts, dismiss } = useToasts();
  return (
    <div
      className="pointer-events-none fixed end-4 bottom-4 z-[100] flex w-[380px] max-w-[calc(100vw-32px)] flex-col gap-2"
      aria-live="polite"
      aria-relevant="additions"
    >
      {toasts.map((item) => {
        const { Icon, cls } = ICONS[item.kind];
        return (
          <div
            key={item.id}
            role={item.kind === "error" ? "alert" : "status"}
            className="pointer-events-auto flex animate-toast-in items-start gap-3 rounded-xl border border-border bg-surface px-4 py-3 shadow-pop"
          >
            <Icon className={cn("mt-0.5 size-4 shrink-0", cls)} aria-hidden />
            <div className="min-w-0 flex-1">
              <div className="text-[13px] font-medium text-fg">{item.title}</div>
              {item.description && (
                <div className="selectable mt-0.5 text-xs leading-relaxed break-words text-muted">{item.description}</div>
              )}
            </div>
            <button
              type="button"
              onClick={() => dismiss(item.id)}
              aria-label={t("Dismiss notification")}
              className="-me-1 rounded-md p-1 text-faint transition-colors hover:bg-surface-2 hover:text-fg"
            >
              <X className="size-3.5" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
