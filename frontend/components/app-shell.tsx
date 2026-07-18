"use client";

import Link from "next/link";
import { ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <header className="border-b border-slate-200/80 bg-white/90 backdrop-blur">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-5 sm:px-8">
          <Link href="/dashboard" className="flex items-center gap-2.5" aria-label="Sentinel AI dashboard">
            <span className="flex size-9 items-center justify-center rounded-xl bg-slate-950 text-sky-300 shadow-sm">
              <ShieldCheck className="size-5" aria-hidden="true" />
            </span>
            <span className="text-sm font-bold tracking-tight text-slate-950">SENTINEL <span className="text-sky-600">AI</span></span>
          </Link>
          <div className="hidden items-center gap-2 text-xs font-medium text-slate-500 sm:flex">
            <span className="size-2 rounded-full bg-emerald-500" />
            Detection workspace
          </div>
        </div>
      </header>
      {children}
    </div>
  );
}
