import { cn } from "@/lib/utils";

export function Progress({ value, className }: { value: number; className?: string }) {
  const boundedValue = Math.min(100, Math.max(0, value));
  return (
    <div className={cn("h-2 overflow-hidden rounded-full bg-slate-100", className)}>
      <div className="h-full rounded-full bg-sky-600 transition-all duration-500" style={{ width: `${boundedValue}%` }} />
    </div>
  );
}
