import Link from "next/link";
import {
  ArrowRight,
  Box,
  Braces,
  CircuitBoard,
  Github,
  GitPullRequestArrow,
  KeyRound,
  MessageSquareWarning,
  Network,
  PackageSearch,
  ScanSearch,
  Settings2,
  ShieldCheck,
  TerminalSquare,
} from "lucide-react";

const capabilities = [
  { title: "Exposed secrets", description: "Keys, tokens, private material, and risky entropy patterns.", icon: KeyRound },
  { title: "Insecure config", description: "Debug modes, permissive CORS, and committed environment files.", icon: Settings2 },
  { title: "Dependency integrity", description: "Typosquats, obscure packages, and dangerous install scripts.", icon: PackageSearch },
  { title: "Backdoor behavior", description: "Obfuscated execution, shell payloads, and outbound beacons.", icon: TerminalSquare },
  { title: "Auth bypasses", description: "Hardcoded comparisons and unsafe authorization conditions.", icon: ShieldCheck },
  { title: "Prompt injection", description: "Unbounded user input flowing into LLM instructions.", icon: MessageSquareWarning },
  { title: "Unsafe model loading", description: "Pickle, joblib, and unsafe PyTorch deserialization.", icon: Box },
  { title: "Network anomalies", description: "Raw-IP calls and isolated, unexplained destinations.", icon: Network },
];

const workflow = [
  {
    step: "01",
    title: "Import repository",
    description: "Choose one GitHub repository. Sentinel scopes access to the project you select.",
    icon: Github,
  },
  {
    step: "02",
    title: "AI-powered scan",
    description: "Static detectors establish evidence first; GPT-5.6 or Gemini explains real-world impact.",
    icon: ScanSearch,
  },
  {
    step: "03",
    title: "Reviewable fixes",
    description: "Generate guarded patches and pull requests—never a direct write to your default branch.",
    icon: GitPullRequestArrow,
  },
];

export default function HomePage() {
  return (
    <main className="min-h-screen overflow-hidden bg-[#070b14] text-slate-100 selection:bg-sky-300 selection:text-slate-950">
      <div className="pointer-events-none fixed inset-0 bg-[linear-gradient(rgba(56,189,248,0.055)_1px,transparent_1px),linear-gradient(90deg,rgba(56,189,248,0.055)_1px,transparent_1px)] bg-[size:48px_48px] [mask-image:linear-gradient(to_bottom,black,transparent_74%)]" />
      <div className="pointer-events-none fixed inset-x-0 top-0 h-[38rem] bg-[radial-gradient(ellipse_at_top,rgba(14,116,144,0.22),transparent_68%)]" />

      <header className="relative z-10 border-b border-white/10">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-5 sm:px-8">
          <Link href="/" className="group flex items-center gap-3" aria-label="Sentinel AI home">
            <span className="grid size-8 place-items-center border border-sky-300/70 bg-sky-300 text-slate-950 transition-colors group-hover:bg-white">
              <ShieldCheck className="size-4" aria-hidden="true" />
            </span>
            <span className="font-mono text-sm font-semibold tracking-[0.16em] text-white">SENTINEL<span className="text-sky-300">_AI</span></span>
          </Link>
          <Link href="/login" className="inline-flex items-center gap-2 border border-sky-300/50 px-3 py-2 font-mono text-[11px] font-semibold uppercase tracking-[0.12em] text-sky-200 transition-colors hover:border-sky-200 hover:bg-sky-300 hover:text-slate-950">
            <span className="hidden sm:inline">Connect GitHub</span>
            <ArrowRight className="size-3.5" aria-hidden="true" />
          </Link>
        </div>
      </header>

      <section className="relative z-10 mx-auto max-w-7xl px-5 pb-24 pt-20 sm:px-8 sm:pb-32 sm:pt-28">
        <div className="landing-reveal max-w-4xl">
          <p className="flex items-center gap-2 font-mono text-xs uppercase tracking-[0.18em] text-sky-300"><CircuitBoard className="size-3.5" /> AI-native application security</p>
          <h1 className="mt-7 max-w-4xl text-balance text-5xl font-semibold leading-[0.98] tracking-[-0.055em] text-white sm:text-7xl">
            Security, before your <span className="text-sky-300">next deploy.</span>
          </h1>
          <p className="mt-7 max-w-2xl text-pretty text-base leading-7 text-slate-300 sm:text-lg">
            Sentinel AI detects, explains, and safely remediates vulnerabilities and backdoors in AI-generated code—built with Codex and powered by GPT-5.6 or Gemini.
          </p>
          <div className="mt-9 flex flex-col gap-3 sm:flex-row sm:items-center">
            <Link href="/login" className="inline-flex h-12 items-center justify-center gap-3 bg-sky-300 px-5 font-mono text-sm font-bold uppercase tracking-[0.09em] text-slate-950 transition-colors hover:bg-white">
              <Github className="size-4" aria-hidden="true" /> Get started <ArrowRight className="size-4" aria-hidden="true" />
            </Link>
            <span className="font-mono text-xs leading-5 text-slate-500">Static evidence first. <span className="text-slate-400">AI explanation second.</span></span>
          </div>
        </div>

        <div className="landing-reveal landing-reveal-delay mt-16 grid max-w-5xl border border-white/10 bg-slate-950/40 sm:grid-cols-3">
          <Signal label="DETECTORS" value="08" />
          <Signal label="AI REVIEW" value="BOUND" />
          <Signal label="REMEDIATION" value="PR-ONLY" />
        </div>
      </section>

      <section className="relative z-10 border-y border-white/10 bg-slate-950/55">
        <div className="mx-auto max-w-7xl px-5 py-20 sm:px-8 sm:py-28">
          <SectionHeading eyebrow="Operational flow" title="Evidence in. Reviewable action out." description="Sentinel gives teams a clear path from repository selection to an auditable remediation pull request." />
          <div className="mt-12 grid border-l border-white/10 lg:grid-cols-3 lg:border-l-0">
            {workflow.map((item) => {
              const Icon = item.icon;
              return (
                <article key={item.step} className="relative border-b border-r border-t border-white/10 p-6 last:border-b lg:border-b-0 lg:first:border-l lg:last:border-r sm:p-8">
                  <span className="font-mono text-xs tracking-[0.14em] text-sky-300">{item.step}</span>
                  <Icon className="mt-8 size-6 text-white" aria-hidden="true" />
                  <h3 className="mt-5 text-xl font-semibold tracking-tight text-white">{item.title}</h3>
                  <p className="mt-3 max-w-sm text-sm leading-6 text-slate-400">{item.description}</p>
                  <div className="absolute right-4 top-4 size-1.5 bg-sky-300" />
                </article>
              );
            })}
          </div>
        </div>
      </section>

      <section className="relative z-10 mx-auto max-w-7xl px-5 py-20 sm:px-8 sm:py-28">
        <SectionHeading eyebrow="Detection surface" title="Designed for the shortcuts that ship with AI-generated code." description="A compact, deterministic static layer catches high-signal risks before the reasoning layer adds context." />
        <div className="mt-12 grid border-l border-t border-white/10 sm:grid-cols-2 lg:grid-cols-4">
          {capabilities.map((capability) => {
            const Icon = capability.icon;
            return (
              <article key={capability.title} className="group min-h-48 border-b border-r border-white/10 bg-white/[0.015] p-5 transition-colors hover:bg-sky-300/[0.055]">
                <span className="grid size-9 place-items-center border border-white/15 text-sky-300 transition-colors group-hover:border-sky-300/60 group-hover:text-white"><Icon className="size-4" aria-hidden="true" /></span>
                <h3 className="mt-6 text-sm font-semibold uppercase tracking-[0.08em] text-white">{capability.title}</h3>
                <p className="mt-3 text-sm leading-6 text-slate-400">{capability.description}</p>
              </article>
            );
          })}
        </div>
      </section>

      <section className="relative z-10 border-t border-white/10 bg-sky-300 text-slate-950">
        <div className="mx-auto flex max-w-7xl flex-col gap-8 px-5 py-16 sm:px-8 sm:py-20 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <p className="font-mono text-xs font-bold uppercase tracking-[0.15em] text-sky-950/65">Ready when your repository is</p>
            <h2 className="mt-4 max-w-2xl text-balance text-3xl font-semibold tracking-[-0.04em] sm:text-4xl">Turn the next scan into a security decision, not a guessing game.</h2>
          </div>
          <Link href="/login" className="inline-flex h-12 shrink-0 items-center justify-center gap-3 border border-slate-950 bg-slate-950 px-5 font-mono text-sm font-bold uppercase tracking-[0.09em] text-white transition-colors hover:bg-transparent hover:text-slate-950">
            Get started <ArrowRight className="size-4" aria-hidden="true" />
          </Link>
        </div>
      </section>

      <footer className="relative z-10 border-t border-white/10 bg-[#070b14]">
        <div className="mx-auto flex max-w-7xl flex-col gap-3 px-5 py-6 font-mono text-[11px] uppercase tracking-[0.12em] text-slate-500 sm:flex-row sm:items-center sm:justify-between sm:px-8">
          <span>SENTINEL_AI / Security analysis for AI-native applications</span>
          <span className="flex items-center gap-2"><Braces className="size-3" aria-hidden="true" /> Evidence-led remediation</span>
        </div>
      </footer>
    </main>
  );
}

function Signal({ label, value }: { label: string; value: string }) {
  return <div className="border-b border-white/10 px-5 py-5 last:border-b-0 sm:border-b-0 sm:border-r sm:last:border-r-0"><p className="font-mono text-[10px] font-semibold tracking-[0.15em] text-slate-500">{label}</p><p className="mt-2 font-mono text-xl font-semibold tracking-tight text-sky-200">{value}</p></div>;
}

function SectionHeading({ eyebrow, title, description }: { eyebrow: string; title: string; description: string }) {
  return <div className="max-w-2xl"><p className="font-mono text-xs uppercase tracking-[0.18em] text-sky-300">// {eyebrow}</p><h2 className="mt-4 text-balance text-3xl font-semibold tracking-[-0.04em] text-white sm:text-4xl">{title}</h2><p className="mt-4 text-base leading-7 text-slate-400">{description}</p></div>;
}
