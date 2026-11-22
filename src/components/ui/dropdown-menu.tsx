import * as DM from "@radix-ui/react-dropdown-menu";
import { forwardRef, type ComponentPropsWithoutRef, type ElementRef, type ReactNode } from "react";
import { cn } from "../../lib/utils";

/** Non-modal by default so menu items can safely open dialogs. */
export function DropdownMenu(props: ComponentPropsWithoutRef<typeof DM.Root>) {
  return <DM.Root modal={false} {...props} />;
}
export const DropdownMenuTrigger = DM.Trigger;

export const DropdownMenuContent = forwardRef<ElementRef<typeof DM.Content>, ComponentPropsWithoutRef<typeof DM.Content>>(
  ({ className, sideOffset = 6, align = "end", ...props }, ref) => (
    <DM.Portal>
      <DM.Content
        ref={ref}
        sideOffset={sideOffset}
        align={align}
        collisionPadding={8}
        className={cn("menu-surface z-[60] min-w-[180px] rounded-xl border border-border bg-surface p-1 shadow-pop", className)}
        {...props}
      />
    </DM.Portal>
  ),
);
DropdownMenuContent.displayName = "DropdownMenuContent";

export const DropdownMenuItem = forwardRef<
  ElementRef<typeof DM.Item>,
  ComponentPropsWithoutRef<typeof DM.Item> & { destructive?: boolean }
>(({ className, destructive, ...props }, ref) => (
  <DM.Item
    ref={ref}
    className={cn(
      "flex cursor-pointer items-center gap-2.5 rounded-md px-2.5 py-1.5 text-[13px] outline-none select-none [&_svg]:size-4 [&_svg]:shrink-0",
      "data-[disabled]:pointer-events-none data-[disabled]:opacity-45",
      destructive
        ? "text-danger data-[highlighted]:bg-danger/10"
        : "text-fg data-[highlighted]:bg-surface-2 [&_svg]:text-muted",
      className,
    )}
    {...props}
  />
));
DropdownMenuItem.displayName = "DropdownMenuItem";

export function DropdownMenuSeparator() {
  return <DM.Separator className="-mx-1 my-1 h-px bg-border" />;
}

export function DropdownMenuLabel({ children }: { children: ReactNode }) {
  return <DM.Label className="px-2.5 pt-1.5 pb-1 text-[11px] font-medium tracking-wide text-faint uppercase">{children}</DM.Label>;
}
