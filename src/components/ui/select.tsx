import * as SelectPrimitive from "@radix-ui/react-select";
import { Check, ChevronDown } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "../../lib/utils";

export interface SelectOption {
  value: string;
  label: ReactNode;
  description?: ReactNode;
  disabled?: boolean;
}

interface SelectProps {
  value: string;
  onValueChange: (v: string) => void;
  options: SelectOption[];
  placeholder?: string;
  disabled?: boolean;
  className?: string;
  id?: string;
  "aria-label"?: string;
  size?: "sm" | "md";
}

/** Radix Select with a fixed option list. Note: Radix forbids "" as an item value. */
export function Select({ value, onValueChange, options, placeholder, disabled, className, id, size = "md", ...rest }: SelectProps) {
  return (
    <SelectPrimitive.Root value={value} onValueChange={onValueChange} disabled={disabled}>
      <SelectPrimitive.Trigger
        id={id}
        aria-label={rest["aria-label"]}
        className={cn(
          "inline-flex items-center justify-between gap-2 rounded-lg border border-border bg-surface text-left text-sm text-fg",
          "transition-[border-color,box-shadow] duration-150 hover:border-border-strong",
          "focus:border-primary focus:outline-none focus:ring-3 focus:ring-primary/20 disabled:cursor-not-allowed disabled:opacity-50",
          "data-[placeholder]:text-faint",
          size === "md" ? "h-9 px-3" : "h-8 px-2.5 text-[13px]",
          className,
        )}
      >
        <span className="truncate">
          <SelectPrimitive.Value placeholder={placeholder} />
        </span>
        <SelectPrimitive.Icon>
          <ChevronDown className="size-4 text-faint" />
        </SelectPrimitive.Icon>
      </SelectPrimitive.Trigger>
      <SelectPrimitive.Portal>
        <SelectPrimitive.Content
          position="popper"
          sideOffset={6}
          className="menu-surface z-[60] max-h-[min(360px,var(--radix-select-content-available-height))] min-w-[var(--radix-select-trigger-width)] overflow-hidden rounded-xl border border-border bg-surface p-1 shadow-pop"
        >
          <SelectPrimitive.Viewport>
            {options.map((o) => (
              <SelectPrimitive.Item
                key={o.value}
                value={o.value}
                disabled={o.disabled}
                className={cn(
                  "relative flex cursor-pointer items-center rounded-md py-1.5 pr-8 pl-2.5 text-[13px] text-fg outline-none select-none",
                  "data-[highlighted]:bg-surface-2 data-[disabled]:cursor-not-allowed data-[disabled]:opacity-45",
                )}
              >
                <div className="flex flex-col">
                  <SelectPrimitive.ItemText>{o.label}</SelectPrimitive.ItemText>
                  {o.description && <span className="text-xs text-muted">{o.description}</span>}
                </div>
                <SelectPrimitive.ItemIndicator className="absolute right-2.5 inline-flex items-center text-primary">
                  <Check className="size-4" />
                </SelectPrimitive.ItemIndicator>
              </SelectPrimitive.Item>
            ))}
          </SelectPrimitive.Viewport>
        </SelectPrimitive.Content>
      </SelectPrimitive.Portal>
    </SelectPrimitive.Root>
  );
}
