import { ArrowRight, Github, ShieldCheck } from "lucide-react";

import { Button } from "@/components/ui/button";
import { githubLoginUrl } from "@/lib/api";

export default function LoginPage() {
  return (
    <main className="relative flex min-h-screen items-center justify-center overflow-hidden bg-slate-950 px-5 py-12 text-white">
      <div className="absolute left-1/2 top-0 h-96 w-96 -translate-x-1/2 rounded-full bg-sky-500/20 blur-3xl" />
      <section className="relative w-full max-w-md rounded-2xl border border-white/10 bg-white/[0.06] p-8 shadow-2xl backdrop-blur sm:p-10">
        <div className="mb-8 flex size-12 items-center justify-center rounded-2xl bg-sky-400 text-slate-950">
          <ShieldCheck className="size-7" aria-hidden="true" />
        </div>
        <p className="text-xs font-bold uppercase tracking-[0.2em] text-sky-300">Sentinel AI</p>
        <h1 className="mt-3 text-balance text-3xl font-semibold tracking-tight">Ship fast. Scan with confidence.</h1>
        <p className="mt-4 leading-7 text-slate-300">
          Connect GitHub to scan a repository for real security risks, see the findings live, and review safe fixes.
        </p>
        <Button asChild size="lg" className="mt-8 w-full bg-white text-slate-950 hover:bg-slate-100">
          <a href={githubLoginUrl()}>
            <Github className="size-5" aria-hidden="true" />
            Continue with GitHub
            <ArrowRight className="ml-auto size-4" aria-hidden="true" />
          </a>
        </Button>
        <p className="mt-5 text-center text-xs leading-5 text-slate-400">Repository access is used only for repositories you explicitly import.</p>
      </section>
    </main>
  );
}
