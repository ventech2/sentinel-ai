"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { Github, LoaderCircle, Plus, ScanSearch, ShieldAlert } from "lucide-react";
import { FormEvent, useEffect, useState } from "react";

import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { ApiError, createProject, listProjects, startScan } from "@/lib/api";
import type { Project } from "@/lib/types";

export function DashboardClient() {
  const router = useRouter();
  const [projects, setProjects] = useState<Project[]>([]);
  const [repoUrl, setRepoUrl] = useState("");
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [startingProject, setStartingProject] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [needsLogin, setNeedsLogin] = useState(false);

  useEffect(() => {
    void loadProjects();
  }, []);

  async function loadProjects() {
    setLoading(true);
    setError(null);
    try {
      setProjects(await listProjects());
      setNeedsLogin(false);
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 401) {
        setNeedsLogin(true);
      } else {
        setError(caught instanceof Error ? caught.message : "Unable to load repositories.");
      }
    } finally {
      setLoading(false);
    }
  }

  async function importRepository(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const project = await createProject(repoUrl.trim());
      setProjects((current) => [project, ...current]);
      setRepoUrl("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to import this repository.");
    } finally {
      setSubmitting(false);
    }
  }

  async function triggerScan(project: Project) {
    setStartingProject(project.id);
    setError(null);
    try {
      const scan = await startScan(project.id);
      router.push(`/scans/${scan.id}`);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to start the scan.");
      setStartingProject(null);
    }
  }

  return (
    <AppShell>
      <main className="mx-auto max-w-7xl px-5 py-10 sm:px-8 sm:py-14">
        <section className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <Badge variant="success">Workspace ready</Badge>
            <h1 className="mt-4 text-balance text-3xl font-semibold tracking-tight text-slate-950 sm:text-4xl">Security, before your next deploy.</h1>
            <p className="mt-3 max-w-2xl text-base leading-7 text-slate-600">Import a GitHub repository, watch Sentinel scan it live, and turn prioritized findings into reviewable fixes.</p>
          </div>
          <div className="flex items-center gap-3 text-sm text-slate-500">
            <ShieldAlert className="size-4 text-sky-600" aria-hidden="true" />
            Static evidence first. AI explanation second.
          </div>
        </section>

        {needsLogin ? (
          <Card className="mt-10 border-sky-100 bg-sky-50/60">
            <CardContent className="flex flex-col gap-4 p-6 sm:flex-row sm:items-center sm:justify-between">
              <div><h2 className="font-semibold text-slate-950">Sign in to your security workspace</h2><p className="mt-1 text-sm text-slate-600">GitHub authentication is required before repositories can be imported.</p></div>
              <Button asChild><Link href="/login"><Github className="size-4" />Sign in with GitHub</Link></Button>
            </CardContent>
          </Card>
        ) : (
          <>
            <Card className="mt-10 border-slate-200">
              <CardHeader><CardTitle>Import repository</CardTitle><CardDescription>Enter one GitHub repository URL. Sentinel only scans the repository you explicitly select.</CardDescription></CardHeader>
              <CardContent>
                <form className="flex flex-col gap-3 sm:flex-row" onSubmit={importRepository}>
                  <Input value={repoUrl} onChange={(event) => setRepoUrl(event.target.value)} placeholder="https://github.com/owner/repository" type="url" required aria-label="GitHub repository URL" />
                  <Button type="submit" disabled={submitting} className="shrink-0">{submitting ? <LoaderCircle className="size-4 animate-spin" /> : <Plus className="size-4" />}Import repository</Button>
                </form>
                {error && <p role="alert" className="mt-3 text-sm font-medium text-rose-700">{error}</p>}
              </CardContent>
            </Card>

            <section className="mt-10">
              <div className="mb-5 flex items-center justify-between"><div><h2 className="text-xl font-semibold tracking-tight">Your repositories</h2><p className="mt-1 text-sm text-slate-500">Run a new scan whenever you need a fresh security report.</p></div><Badge variant="muted">{projects.length} connected</Badge></div>
              {loading ? (
                <div className="flex min-h-44 items-center justify-center rounded-xl border border-dashed border-slate-300 bg-white text-sm text-slate-500"><LoaderCircle className="mr-2 size-4 animate-spin" />Loading repositories</div>
              ) : projects.length === 0 ? (
                <Card className="border-dashed shadow-none"><CardContent className="flex min-h-48 flex-col items-center justify-center text-center"><span className="mb-3 flex size-11 items-center justify-center rounded-xl bg-slate-100 text-slate-500"><Github className="size-5" /></span><h3 className="font-semibold">No repositories connected yet</h3><p className="mt-1 max-w-sm text-sm leading-6 text-slate-500">Import the intentionally vulnerable demo repository to make the full detect → explain → fix flow tangible.</p></CardContent></Card>
              ) : (
                <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
                  {projects.map((project) => <ProjectCard key={project.id} project={project} starting={startingProject === project.id} onScan={() => void triggerScan(project)} />)}
                </div>
              )}
            </section>
          </>
        )}
      </main>
    </AppShell>
  );
}

function ProjectCard({ project, starting, onScan }: { project: Project; starting: boolean; onScan: () => void }) {
  return (
    <Card className="group flex flex-col transition-shadow hover:shadow-lg">
      <CardHeader><div className="flex items-start justify-between gap-4"><span className="flex size-10 items-center justify-center rounded-xl bg-slate-950 text-sky-300"><Github className="size-5" /></span><Badge variant="muted">{project.default_branch}</Badge></div><CardTitle className="mt-4 truncate">{project.repo_owner}/{project.repo_name}</CardTitle><CardDescription className="truncate">{project.repo_url}</CardDescription></CardHeader>
      <CardContent className="mt-auto pt-5"><Button onClick={onScan} disabled={starting} className="w-full">{starting ? <LoaderCircle className="size-4 animate-spin" /> : <ScanSearch className="size-4" />}Run security scan</Button></CardContent>
    </Card>
  );
}
