import { cva, type VariantProps } from "class-variance-authority";
import type { HTMLAttributes } from "react";

import { cn } from "@/lib/utils";

const badgeVariants = cva("inline-flex w-fit items-center rounded-full px-2.5 py-1 text-xs font-semibold", {
  variants: {
    variant: {
      default: "bg-slate-100 text-slate-700",
      critical: "bg-rose-100 text-rose-800",
      high: "bg-orange-100 text-orange-800",
      medium: "bg-amber-100 text-amber-800",
      low: "bg-sky-100 text-sky-800",
      info: "bg-indigo-100 text-indigo-800",
      success: "bg-emerald-100 text-emerald-800",
      muted: "bg-slate-100 text-slate-600",
    },
    outline: { true: "border border-current bg-transparent" },
  },
  defaultVariants: { variant: "default" },
});

export interface BadgeProps extends HTMLAttributes<HTMLDivElement>, VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, outline, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant, outline }), className)} {...props} />;
}
