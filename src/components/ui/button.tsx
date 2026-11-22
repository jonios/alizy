import { forwardRef, type ButtonHTMLAttributes } from "react";
import { Loader2 } from "lucide-react";
import { cn } from "../../lib/utils";

export type ButtonVariant = "primary" | "secondary" | "outline" | "ghost" | "danger" | "danger-ghost" | "link";
export type ButtonSize = "xs" | "sm" | "md" | "lg" | "icon" | "icon-sm";

const VARIANTS: Record<ButtonVariant, string> = {
  primary:
    "bg-primary text-primary-fg shadow-soft hover:bg-primary-hover active:brightness-95 border border-transparent",
  secondary: "bg-surface-2 text-fg border border-border hover:bg-surface-3 hover:border-border-strong",
  outline: "bg-transparent text-fg border border-border hover:bg-surface-2 hover:border-border-strong",
  ghost: "bg-transparent text-muted hover:text-fg hover:bg-surface-2 border border-transparent",
  danger: "bg-danger text-white shadow-soft hover:brightness-110 border border-transparent",
  "danger-ghost": "bg-transparent text-danger hover:bg-danger/10 border border-transparent",
  link: "bg-transparent text-primary hover:underline underline-offset-4 border border-transparent px-0 h-auto",
};

const SIZES: Record<ButtonSize, string> = {
  xs: "h-7 px-2 text-xs gap-1 rounded-md",
  sm: "h-8 px-3 text-[13px] gap-1.5 rounded-lg",
  md: "h-9 px-4 text-sm gap-2 rounded-lg",
  lg: "h-11 px-5 text-sm gap-2 rounded-xl",
  icon: "h-9 w-9 rounded-lg",
  "icon-sm": "h-7 w-7 rounded-md",
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "secondary", size = "md", loading, disabled, children, type = "button", ...props }, ref) => (
    <button
      ref={ref}
      type={type}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={cn(
        "inline-flex shrink-0 select-none items-center justify-center whitespace-nowrap font-medium",
        "transition-[background-color,border-color,color,box-shadow,filter] duration-150",
        "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring",
        "disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0",
        VARIANTS[variant],
        SIZES[size],
        className,
      )}
      {...props}
    >
      {loading && <Loader2 className="animate-spin" aria-hidden />}
      {children}
    </button>
  ),
);
Button.displayName = "Button";
