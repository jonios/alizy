import * as DialogPrimitive from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { forwardRef, useState, type ComponentPropsWithoutRef, type ElementRef, type HTMLAttributes, type ReactNode } from "react";
import { cn } from "../../lib/utils";
import { Button } from "./button";

export const Dialog = DialogPrimitive.Root;
export const DialogTrigger = DialogPrimitive.Trigger;
export const DialogClose = DialogPrimitive.Close;

const Overlay = forwardRef<ElementRef<typeof DialogPrimitive.Overlay>, ComponentPropsWithoutRef<typeof DialogPrimitive.Overlay>>(
  ({ className, ...props }, ref) => (
    <DialogPrimitive.Overlay
      ref={ref}
      className={cn("overlay-surface fixed inset-0 z-50 bg-[var(--overlay)] backdrop-blur-[2px]", className)}
      {...props}
    />
  ),
);
Overlay.displayName = "DialogOverlay";

type ContentProps = ComponentPropsWithoutRef<typeof DialogPrimitive.Content> & {
  size?: "sm" | "md" | "lg" | "xl";
  hideClose?: boolean;
};

const SIZE = { sm: "max-w-md", md: "max-w-lg", lg: "max-w-2xl", xl: "max-w-4xl" };

export const DialogContent = forwardRef<ElementRef<typeof DialogPrimitive.Content>, ContentProps>(
  ({ className, children, size = "md", hideClose, ...props }, ref) => (
    <DialogPrimitive.Portal>
      <Overlay />
      <div className="pointer-events-none fixed inset-0 z-50 flex items-center justify-center p-6">
        <DialogPrimitive.Content
          ref={ref}
          className={cn(
            "dialog-surface pointer-events-auto relative flex max-h-[calc(100vh-48px)] w-full flex-col overflow-hidden rounded-2xl border border-border bg-surface shadow-pop outline-none",
            SIZE[size],
            className,
          )}
          {...props}
        >
          {children}
          {!hideClose && (
            <DialogPrimitive.Close asChild>
              <Button variant="ghost" size="icon-sm" className="absolute top-3.5 right-3.5" aria-label="Close dialog">
                <X />
              </Button>
            </DialogPrimitive.Close>
          )}
        </DialogPrimitive.Content>
      </div>
    </DialogPrimitive.Portal>
  ),
);
DialogContent.displayName = "DialogContent";

export const SheetContent = forwardRef<
  ElementRef<typeof DialogPrimitive.Content>,
  ComponentPropsWithoutRef<typeof DialogPrimitive.Content>
>(({ className, children, ...props }, ref) => (
  <DialogPrimitive.Portal>
    <Overlay />
    <DialogPrimitive.Content
      ref={ref}
      className={cn(
        "sheet-surface fixed inset-y-0 right-0 z-50 flex w-full max-w-[640px] flex-col border-l border-border bg-background shadow-pop outline-none",
        className,
      )}
      {...props}
    >
      {children}
    </DialogPrimitive.Content>
  </DialogPrimitive.Portal>
));
SheetContent.displayName = "SheetContent";

export function DialogHeader({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("flex flex-col gap-1 px-6 pt-5 pb-4 pr-14", className)} {...props} />;
}
export function DialogBody({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("min-h-0 flex-1 overflow-y-auto px-6 pb-5", className)} {...props} />;
}
export function DialogFooter({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("flex items-center justify-end gap-2 border-t border-border bg-surface-2/50 px-6 py-3.5", className)}
      {...props}
    />
  );
}
export const DialogTitle = forwardRef<ElementRef<typeof DialogPrimitive.Title>, ComponentPropsWithoutRef<typeof DialogPrimitive.Title>>(
  ({ className, ...props }, ref) => (
    <DialogPrimitive.Title ref={ref} className={cn("text-base font-semibold tracking-tight text-fg", className)} {...props} />
  ),
);
DialogTitle.displayName = "DialogTitle";
export const DialogDescription = forwardRef<
  ElementRef<typeof DialogPrimitive.Description>,
  ComponentPropsWithoutRef<typeof DialogPrimitive.Description>
>(({ className, ...props }, ref) => (
  <DialogPrimitive.Description ref={ref} className={cn("text-[13px] leading-relaxed text-muted", className)} {...props} />
));
DialogDescription.displayName = "DialogDescription";

interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  description?: ReactNode;
  children?: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  destructive?: boolean;
  /** may be async; the dialog shows a spinner and closes when it resolves to anything but false */
  onConfirm: () => unknown | Promise<unknown>;
  icon?: ReactNode;
  confirmDisabled?: boolean;
}

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  children,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  destructive,
  onConfirm,
  icon,
  confirmDisabled,
}: ConfirmDialogProps) {
  const [busy, setBusy] = useState(false);
  const handle = async () => {
    setBusy(true);
    try {
      const r = await onConfirm();
      if (r !== false) onOpenChange(false);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog open={open} onOpenChange={(o) => !busy && onOpenChange(o)}>
      <DialogContent size="sm" hideClose {...(description ? {} : { "aria-describedby": undefined })}>
        <DialogHeader className="pr-6">
          <div className="flex items-start gap-3">
            {icon && (
              <div
                className={cn(
                  "flex size-9 shrink-0 items-center justify-center rounded-full [&_svg]:size-[18px]",
                  destructive ? "bg-danger/12 text-danger" : "bg-primary/12 text-primary",
                )}
              >
                {icon}
              </div>
            )}
            <div className="flex min-w-0 flex-col gap-1.5">
              <DialogTitle>{title}</DialogTitle>
              {description && <DialogDescription>{description}</DialogDescription>}
            </div>
          </div>
        </DialogHeader>
        {children && <DialogBody>{children}</DialogBody>}
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
            {cancelLabel}
          </Button>
          <Button variant={destructive ? "danger" : "primary"} onClick={handle} loading={busy} disabled={confirmDisabled}>
            {confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
