import { forwardRef, type InputHTMLAttributes, type ReactNode, type TextareaHTMLAttributes, type LabelHTMLAttributes } from "react";
import { cn } from "../../lib/utils";

const FIELD =
  "w-full rounded-lg border bg-surface text-sm text-fg placeholder:text-faint transition-[border-color,box-shadow] duration-150 " +
  "border-border hover:border-border-strong focus:border-primary focus:outline-none focus:ring-3 focus:ring-primary/20 " +
  "disabled:cursor-not-allowed disabled:opacity-50";

export interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  invalid?: boolean;
  leading?: ReactNode;
  trailing?: ReactNode;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(({ className, invalid, leading, trailing, ...props }, ref) => {
  const input = (
    <input
      ref={ref}
      aria-invalid={invalid || undefined}
      className={cn(
        FIELD,
        "h-9 px-3",
        leading && "pl-9",
        trailing && "pr-9",
        invalid && "border-danger/70 focus:border-danger focus:ring-danger/20",
        !leading && !trailing && className,
      )}
      {...props}
    />
  );
  if (!leading && !trailing) return input;
  return (
    <div className={cn("relative", className)}>
      {leading && (
        <span className="pointer-events-none absolute inset-y-0 left-3 flex items-center text-faint [&_svg]:size-4">{leading}</span>
      )}
      {input}
      {trailing && <span className="absolute inset-y-0 right-2 flex items-center">{trailing}</span>}
    </div>
  );
});
Input.displayName = "Input";

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement> & { invalid?: boolean }>(
  ({ className, invalid, ...props }, ref) => (
    <textarea
      ref={ref}
      aria-invalid={invalid || undefined}
      className={cn(FIELD, "min-h-24 resize-y px-3 py-2 leading-relaxed", invalid && "border-danger/70", className)}
      {...props}
    />
  ),
);
Textarea.displayName = "Textarea";

export function Label({ className, ...props }: LabelHTMLAttributes<HTMLLabelElement>) {
  return <label className={cn("text-[13px] font-medium text-fg", className)} {...props} />;
}

export function Field({
  label,
  htmlFor,
  hint,
  error,
  children,
  className,
}: {
  label: ReactNode;
  htmlFor?: string;
  hint?: ReactNode;
  error?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col gap-1.5", className)}>
      <Label htmlFor={htmlFor}>{label}</Label>
      {children}
      {error ? (
        <p className="text-xs text-danger" role="alert">
          {error}
        </p>
      ) : hint ? (
        <p className="text-xs text-muted">{hint}</p>
      ) : null}
    </div>
  );
}
