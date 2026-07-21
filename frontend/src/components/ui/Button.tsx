import { clsx } from "clsx";
import type { ButtonHTMLAttributes } from "react";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "ghost" | "danger";
  size?: "sm" | "md";
}

const VARIANTS: Record<NonNullable<ButtonProps["variant"]>, string> = {
  primary: "bg-signal-500 text-white hover:bg-signal-400 shadow-[0_0_0_1px_rgba(62,123,250,0.4)]",
  secondary: "bg-base-700 text-ink-100 hover:bg-base-600 border border-base-600",
  ghost: "bg-transparent text-ink-300 hover:bg-base-800 hover:text-ink-100",
  danger: "bg-sev-critical/15 text-sev-critical hover:bg-sev-critical/25 border border-sev-critical/40",
};

const SIZES: Record<NonNullable<ButtonProps["size"]>, string> = {
  sm: "px-3 py-1.5 text-xs",
  md: "px-4 py-2 text-sm",
};

export function Button({ variant = "primary", size = "md", className, ...props }: ButtonProps) {
  return (
    <button
      className={clsx(
        "inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-colors duration-150 disabled:opacity-50 disabled:cursor-not-allowed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-signal-400 focus-visible:ring-offset-2 focus-visible:ring-offset-base-950",
        VARIANTS[variant],
        SIZES[size],
        className
      )}
      {...props}
    />
  );
}
