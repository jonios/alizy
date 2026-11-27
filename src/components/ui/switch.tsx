import * as SwitchPrimitive from "@radix-ui/react-switch";
import { forwardRef, type ComponentPropsWithoutRef, type ElementRef } from "react";
import { cn } from "../../lib/utils";

export const Switch = forwardRef<
  ElementRef<typeof SwitchPrimitive.Root>,
  ComponentPropsWithoutRef<typeof SwitchPrimitive.Root> & { size?: "sm" | "md" }
>(({ className, size = "md", ...props }, ref) => (
  <SwitchPrimitive.Root
    ref={ref}
    className={cn(
      "peer inline-flex shrink-0 cursor-pointer items-center rounded-full border border-transparent transition-colors duration-200",
      "bg-surface-3 data-[state=checked]:bg-primary",
      "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring",
      "disabled:cursor-not-allowed disabled:opacity-45",
      size === "md" ? "h-[22px] w-[38px]" : "h-[18px] w-[30px]",
      className,
    )}
    {...props}
  >
    <SwitchPrimitive.Thumb
      className={cn(
        "pointer-events-none block rounded-full bg-white shadow-[0_1px_3px_rgb(0_0_0/0.3)] transition-transform duration-200 ease-out",
        size === "md"
          ? "size-[18px] translate-x-[2px] data-[state=checked]:translate-x-[18px] rtl:-translate-x-[2px] rtl:data-[state=checked]:-translate-x-[18px]"
          : "size-[14px] translate-x-[2px] data-[state=checked]:translate-x-[14px] rtl:-translate-x-[2px] rtl:data-[state=checked]:-translate-x-[14px]",
      )}
    />
  </SwitchPrimitive.Root>
));
Switch.displayName = "Switch";
