"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ArrowLeft, CheckCircle2, Download, ExternalLink, FileCode2, LoaderCircle, ShieldAlert, Sparkles, Wrench } from "lucide-react";

import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ApiError, approveRemediation, getRemediation, getReport, remediateFinding, reportExportUrl } from "@/lib/api";
import type { Remediation, Report, ReportFinding, Severity } from "@/lib/types";

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];
const severityVariant: Record<Severity, "critical" | "high" | "medium" | "low" | "info"> = { critical: "critical", high: "high", medium: "medium", low: "low", info: "info" };
const tierOne = new Set(["hardcoded_secret", "insecure_config", "typosquatted_dependency", "committed_env_file"]);
const tierTwo = new Set(["hardcoded_auth_bypass", "auth_bypass", "obfuscated_dynamic_execution", "obfuscated_code", "suspicious_dynamic_execution"]);

function remediationTier(finding: ReportFinding): 1 | 2 | 3 {
  if (finding.remediation) return finding.remediation.tier;
  if (tierOne.has(finding.category)) return 1;
  return tierTwo.has(finding.category) ? 2 : 3;
}

export function ReportClient({ scanId }: { scanId: string }) {
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      try { setReport(await getReport(scanId)); }
      catch (caught) { setError(caught instanceof Error ? caught.message : "Unable to load the report."); }
    })();
  }, [scanId]);

  if (!report && !error) return <ReportShell><div className="flex min-h-80 items-center justify-center text-sm text-slate-500"><LoaderCircle className="mr-2 size-4 animate-spin" />Loading final report</div></ReportShell>;
  if (!report) return <ReportShell><Card className="mx-auto mt-16 max-w-xl"><CardContent className="p-7 text-center"><ShieldAlert className="mx-auto size-8 text-amber-500" /><h1 className="mt-4 text-xl font-semibold">Report is not ready yet</h1><p className="mt-2 text-sm leading-6 text-slate-600">{error}</p><Button asChild className="mt-6"><Link href={`/scans/${scanId}`}><ArrowLeft className="size-4" />Return to live scan</Link></Button></CardContent></Card></ReportShell>;

  const grouped = Object.fromEntries(severityOrder.map((severity) => [severity, report.findings.filter((finding) => finding.severity === severity)])) as Record<Severity, ReportFinding[]>;
  return (
    <ReportShell>
      <div className="flex flex-col gap-6 sm:flex-row sm:items-start sm:justify-between"><div><Link href={`/scans/${scanId}`} className="inline-flex items-center gap-2 text-sm font-medium text-slate-500 hover:text-slate-950"><ArrowLeft className="size-4" />Live scan</Link><h1 className="mt-5 text-3xl font-semibold tracking-tight">Prioritized security report</h1><p className="mt-2 text-slate-600">Evidence-backed findings, AI context, and safe remediation controls.</p></div><Button asChild variant="outline"><a href={reportExportUrl(scanId)}><Download className="size-4" />Export Markdown</a></Button></div>
      <section className="mt-8 grid gap-5 lg:grid-cols-[.7fr_1.3fr]"><RiskScore score={report.overall_risk_score} counts={report.finding_counts} /><Card><CardHeader><div className="flex items-center gap-2"><Sparkles className="size-4 text-sky-600" /><CardTitle>Executive summary</CardTitle></div><CardDescription>Generated only from the persisted scan findings.</CardDescription></CardHeader><CardContent><p className="whitespace-pre-line text-sm leading-7 text-slate-700">{report.summary}</p></CardContent></Card></section>
      <section className="mt-10 space-y-8">{severityOrder.map((severity) => grouped[severity].length > 0 && <div key={severity}><div className="mb-4 flex items-center gap-3"><Badge variant={severityVariant[severity]}>{severity}</Badge><h2 className="text-lg font-semibold capitalize">{grouped[severity].length} {severity} finding{grouped[severity].length === 1 ? "" : "s"}</h2></div><div className="space-y-4">{grouped[severity].map((finding) => <FindingCard key={finding.id} finding={finding} />)}</div></div>)}</section>
    </ReportShell>
  );
}

function ReportShell({ children }: { children: React.ReactNode }) {
  return <AppShell><main className="mx-auto max-w-6xl px-5 py-10 sm:px-8 sm:py-14">{children}</main></AppShell>;
}

function RiskScore({ score, counts }: { score: number; counts: Report["finding_counts"] }) {
  const tone = score >= 70 ? "text-rose-600" : score >= 40 ? "text-amber-600" : "text-emerald-600";
  return <Card className="overflow-hidden"><CardContent className="p-0"><div className="bg-slate-950 p-6 text-white"><p className="text-xs font-bold uppercase tracking-[0.16em] text-slate-400">Overall risk score</p><p className={`mt-2 text-6xl font-semibold tracking-tighter ${tone}`}>{Number(score).toFixed(0)}<span className="text-2xl text-slate-400">/100</span></p><p className="mt-4 text-sm leading-6 text-slate-300">Weighted by severity and detector confidence.</p></div><div className="grid grid-cols-5 divide-x divide-slate-100">{severityOrder.map((severity) => <div key={severity} className="p-3 text-center"><p className="text-lg font-semibold text-slate-950">{counts[severity] || 0}</p><p className="mt-0.5 text-[10px] font-bold uppercase tracking-wide text-slate-500">{severity}</p></div>)}</div></CardContent></Card>;
}

function FindingCard({ finding }: { finding: ReportFinding }) {
  const tier = remediationTier(finding);
  const [remediation, setRemediation] = useState<Remediation | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!finding.remediation) return;
    void getRemediation(finding.remediation.id).then(setRemediation).catch((caught) => setError(caught instanceof Error ? caught.message : "Unable to load remediation."));
  }, [finding.remediation]);

  const current = remediation || finding.remediation;
  const failureReason = remediation?.status === "failed" ? remediationFailureReason(remediation) : null;
  async function generateFix() {
    setBusy(true); setError(null);
    try { setRemediation(await remediateFinding(finding.id)); }
    catch (caught) { setError(caught instanceof Error ? caught.message : "Unable to generate a fix."); }
    finally { setBusy(false); }
  }
  async function approveFix() {
    if (!current) return;
    setBusy(true); setError(null);
    try { setRemediation(await approveRemediation(current.id)); }
    catch (caught) { setError(caught instanceof Error ? caught.message : "Unable to approve the fix."); }
    finally { setBusy(false); }
  }

  return <Card><CardContent className="p-5 sm:p-6"><div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between"><div><div className="flex flex-wrap items-center gap-2"><Badge variant={severityVariant[finding.severity]}>{finding.severity}</Badge><Badge variant="muted">{Math.round(finding.confidence * 100)}% confidence</Badge><span className="font-mono text-xs text-slate-500">{finding.file_path}{finding.line_start ? `:${finding.line_start}` : ""}</span></div><h3 className="mt-3 text-lg font-semibold tracking-tight text-slate-950">{finding.title}</h3></div><RemediationControl tier={tier} remediation={current} busy={busy} onGenerate={generateFix} onApprove={approveFix} /></div><p className="mt-3 text-sm leading-6 text-slate-700">{finding.description}</p>{finding.ai_explanation && <div className="mt-4 rounded-lg border border-sky-100 bg-sky-50/70 p-4"><p className="flex items-center gap-2 text-xs font-bold uppercase tracking-wide text-sky-800"><Sparkles className="size-3.5" />AI reasoning</p><p className="mt-2 text-sm leading-6 text-slate-700">{finding.ai_explanation}</p></div>}{finding.fix_suggestion && <div className="mt-3 rounded-lg bg-slate-50 p-4"><p className="text-xs font-bold uppercase tracking-wide text-slate-500">Recommended action</p><p className="mt-1 text-sm leading-6 text-slate-700">{finding.fix_suggestion}</p></div>}{finding.code_snippet && <pre className="mt-4 overflow-x-auto rounded-lg bg-slate-950 p-4 text-xs leading-6 text-slate-100"><code>{finding.code_snippet}</code></pre>}{remediation?.diff && <div className="mt-4 overflow-hidden rounded-lg border border-slate-200"><div className="flex items-center gap-2 border-b border-slate-200 bg-slate-50 px-4 py-2 text-xs font-bold uppercase tracking-wide text-slate-600"><FileCode2 className="size-3.5" />Proposed diff</div><pre className="overflow-x-auto bg-slate-950 p-4 text-xs leading-6 text-emerald-200"><code>{remediation.diff}</code></pre></div>}{failureReason && <div role="alert" className="mt-4 flex gap-3 rounded-lg border border-rose-200 bg-rose-50 p-4 text-rose-900"><ShieldAlert className="mt-0.5 size-4 shrink-0 text-rose-600" /><div><p className="text-sm font-semibold">Remediation failed safely</p><p className="mt-1 text-sm leading-6 text-rose-800">{failureReason}</p></div></div>}{error && <p role="alert" className="mt-3 text-sm font-medium text-rose-700">{error}</p>}</CardContent></Card>;
}

function remediationFailureReason(remediation: Remediation) {
  const result = remediation.verification_result;
  if (result) {
    for (const field of ["notes", "error", "message"]) {
      const value = result[field];
      if (typeof value === "string" && value.trim()) return value;
    }
  }
  return "Sentinel could not safely prepare this remediation. No additional failure detail was recorded.";
}

function RemediationControl({ tier, remediation, busy, onGenerate, onApprove }: { tier: 1 | 2 | 3; remediation: Pick<Remediation, "id" | "tier" | "status" | "pr_url"> | null; busy: boolean; onGenerate: () => Promise<void>; onApprove: () => Promise<void> }) {
  if (tier === 3) return <Badge variant="muted" className="shrink-0">Review recommended</Badge>;
  if (remediation?.status === "pr_opened") return <Button asChild size="sm" variant="outline"><a href={remediation.pr_url || "#"} target="_blank" rel="noreferrer">View pull request<ExternalLink className="size-3.5" /></a></Button>;
  if (tier === 2 && remediation?.status === "pending_approval") return <Button size="sm" onClick={() => void onApprove()} disabled={busy}>{busy ? <LoaderCircle className="size-3.5 animate-spin" /> : <CheckCircle2 className="size-3.5" />}Approve fix</Button>;
  if (remediation) return <Badge variant={remediation.status === "failed" ? "critical" : "muted"} className="shrink-0">{remediation.status.replaceAll("_", " ")}</Badge>;
  return <Button size="sm" variant={tier === 1 ? "default" : "outline"} onClick={() => void onGenerate()} disabled={busy}>{busy ? <LoaderCircle className="size-3.5 animate-spin" /> : <Wrench className="size-3.5" />}{tier === 1 ? "Auto-fix" : "Generate fix"}</Button>;
}
