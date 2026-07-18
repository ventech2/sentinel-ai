"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { ArrowLeft, CheckCircle2, CircleAlert, LoaderCircle, Radio, ScanSearch, ShieldCheck } from "lucide-react";

import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { getFindings, getScan, scanWebSocketUrl } from "@/lib/api";
import type { Finding, Scan, ScanEvent, ScanStatus, Severity } from "@/lib/types";

const stages: Array<{ status: ScanStatus; title: string; description: string }> = [
  { status: "cloning", title: "Repository intake", description: "Cloning the selected repository and building its file inventory." },
  { status: "static_scan", title: "Static detection", description: "Running deterministic security checks across source and configuration files." },
  { status: "ai_review", title: "AI reasoning", description: "Explaining the evidence-backed findings with bounded code context." },
  { status: "merging", title: "Report generation", description: "Ranking findings and calculating the final risk score." },
  { status: "complete", title: "Complete", description: "Your prioritized security report is ready to review." },
];

const severityStyles: Record<Severity, "critical" | "high" | "medium" | "low" | "info"> = { critical: "critical", high: "high", medium: "medium", low: "low", info: "info" };

export function ScanProgressClient({ scanId }: { scanId: string }) {
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [events, setEvents] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [socketState, setSocketState] = useState<"connecting" | "live" | "reconnecting" | "offline">("connecting");
  const terminalRef = useRef(false);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const refreshFindings = useCallback(async () => {
    try { setFindings(await getFindings(scanId)); } catch (caught) { setError(caught instanceof Error ? caught.message : "Unable to load findings."); }
  }, [scanId]);

  useEffect(() => {
    let disposed = false;
    let socket: WebSocket | null = null;
    let attempts = 0;
    const pushEvent = (detail: string) => setEvents((current) => [detail, ...current].slice(0, 6));
    const hydrate = async () => {
      try {
        const [nextScan] = await Promise.all([getScan(scanId), refreshFindings()]);
        if (!disposed) {
          setScan(nextScan);
          terminalRef.current = nextScan.status === "complete" || nextScan.status === "failed";
        }
      } catch (caught) {
        if (!disposed) setError(caught instanceof Error ? caught.message : "Unable to load this scan.");
      }
    };
    void hydrate();

    const connect = () => {
      if (disposed || terminalRef.current) return;
      setSocketState(attempts === 0 ? "connecting" : "reconnecting");
      socket = new WebSocket(scanWebSocketUrl(scanId));
      socket.onopen = () => { attempts = 0; setSocketState("live"); };
      socket.onmessage = (message) => {
        try {
          const event = JSON.parse(message.data) as ScanEvent;
          if (event.type === "status") {
            pushEvent(event.detail);
            setScan((current) => current ? { ...current, status: event.status, files_scanned: event.files_scanned ?? current.files_scanned } : current);
            if (event.status === "complete" || event.status === "failed") {
              terminalRef.current = true;
              void hydrate();
            }
          } else if (event.type === "finding") {
            pushEvent(`Detected: ${event.title}`);
            // The event is the live trigger; the durable endpoint supplies the full explanation and confidence.
            void refreshFindings();
          } else {
            setError(event.detail);
          }
        } catch { setError("Received an unreadable live scan event."); }
      };
      socket.onerror = () => setSocketState("offline");
      socket.onclose = () => {
        if (!disposed && !terminalRef.current) {
          attempts += 1;
          reconnectTimer.current = setTimeout(connect, Math.min(8_000, 800 * attempts));
        }
      };
    };
    connect();
    return () => { disposed = true; socket?.close(); if (reconnectTimer.current) clearTimeout(reconnectTimer.current); };
  }, [refreshFindings, scanId]);

  const status = scan?.status || "queued";
  const stageIndex = Math.max(0, stages.findIndex((stage) => stage.status === status));
  const progress = status === "failed" ? 100 : status === "queued" ? 3 : ((stageIndex + 1) / stages.length) * 100;

  return (
    <AppShell>
      <main className="mx-auto max-w-6xl px-5 py-10 sm:px-8 sm:py-14">
        <Link href="/dashboard" className="inline-flex items-center gap-2 text-sm font-medium text-slate-500 transition-colors hover:text-slate-950"><ArrowLeft className="size-4" />All repositories</Link>
        <div className="mt-7 flex flex-col gap-5 sm:flex-row sm:items-start sm:justify-between"><div><Badge variant={status === "failed" ? "critical" : status === "complete" ? "success" : "low"}>{status.replaceAll("_", " ")}</Badge><h1 className="mt-4 text-3xl font-semibold tracking-tight">Live security scan</h1><p className="mt-2 text-slate-600">Evidence is streamed from the scan worker as it progresses through each stage.</p></div><LiveIndicator state={socketState} /></div>

        {error && <div role="alert" className="mt-7 rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800">{error}</div>}
        {status === "failed" && scan?.error_message && <div role="alert" className="mt-4 rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800">{scan.error_message}</div>}

        <section className="mt-8 grid gap-6 lg:grid-cols-[1.45fr_.9fr]">
          <Card><CardHeader><div className="flex items-center justify-between"><div><CardTitle>Scan progress</CardTitle><CardDescription>{scan ? `${scan.files_scanned.toLocaleString()} files inventoried` : "Connecting to scan worker"}</CardDescription></div><ScanSearch className="size-5 text-sky-600" /></div></CardHeader><CardContent><Progress value={progress} className="mb-7" /><ol className="space-y-1">{stages.map((stage, index) => <StageRow key={stage.status} stage={stage} index={index} currentIndex={stageIndex} failed={status === "failed"} />)}</ol></CardContent></Card>
          <Card><CardHeader><CardTitle>Live activity</CardTitle><CardDescription>Events arrive over a persistent WebSocket connection.</CardDescription></CardHeader><CardContent><div className="space-y-3">{events.length ? events.map((event, index) => <div key={`${event}-${index}`} className="flex gap-3 text-sm text-slate-600"><span className="mt-1.5 size-2 shrink-0 rounded-full bg-sky-500" />{event}</div>) : <div className="flex items-center gap-3 py-5 text-sm text-slate-500"><LoaderCircle className="size-4 animate-spin" />Waiting for the first worker event…</div>}</div></CardContent></Card>
        </section>

        <section className="mt-8"><div className="mb-4 flex items-center justify-between"><div><h2 className="text-xl font-semibold">Findings as they arrive</h2><p className="mt-1 text-sm text-slate-500">{findings.length} persisted finding{findings.length === 1 ? "" : "s"}</p></div>{status === "complete" && <Button asChild><Link href={`/scans/${scanId}/report`}><ShieldCheck className="size-4" />Open final report</Link></Button>}</div><div className="grid gap-3 md:grid-cols-2">{findings.length ? findings.map((finding) => <Card key={finding.id} className="shadow-none"><CardContent className="p-4"><div className="flex items-start justify-between gap-3"><Badge variant={severityStyles[finding.severity]}>{finding.severity}</Badge><span className="text-xs font-medium text-slate-500">{Math.round(finding.confidence * 100)}% confidence</span></div><h3 className="mt-3 font-semibold text-slate-950">{finding.title}</h3><p className="mt-1 line-clamp-2 text-sm leading-6 text-slate-600">{finding.description}</p><p className="mt-3 font-mono text-xs text-slate-400">{finding.file_path}{finding.line_start ? `:${finding.line_start}` : ""}</p></CardContent></Card>) : <Card className="col-span-full border-dashed shadow-none"><CardContent className="py-10 text-center text-sm text-slate-500">Findings will appear here as the detectors persist them.</CardContent></Card>}</div></section>
      </main>
    </AppShell>
  );
}

function LiveIndicator({ state }: { state: "connecting" | "live" | "reconnecting" | "offline" }) {
  const online = state === "live";
  return <div className="flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-2 text-xs font-semibold text-slate-600"><Radio className={`size-3.5 ${online ? "text-emerald-500" : "text-amber-500"}`} />{online ? "Live updates connected" : state === "offline" ? "Live connection interrupted" : "Connecting live updates"}</div>;
}

function StageRow({ stage, index, currentIndex, failed }: { stage: (typeof stages)[number]; index: number; currentIndex: number; failed: boolean }) {
  const complete = !failed && index < currentIndex;
  const active = !failed && index === currentIndex;
  return <li className="flex gap-4 rounded-lg p-3"><span className={`mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-full border ${complete ? "border-emerald-500 bg-emerald-500 text-white" : active ? "border-sky-500 bg-sky-50 text-sky-600" : "border-slate-200 bg-white text-slate-400"}`}>{complete ? <CheckCircle2 className="size-4" /> : failed && index === currentIndex ? <CircleAlert className="size-4 text-rose-600" /> : active ? <LoaderCircle className="size-3.5 animate-spin" /> : <span className="text-[10px] font-bold">{index + 1}</span>}</span><div><h3 className={`text-sm font-semibold ${active ? "text-slate-950" : "text-slate-700"}`}>{stage.title}</h3><p className="mt-0.5 text-sm leading-5 text-slate-500">{stage.description}</p></div></li>;
}
