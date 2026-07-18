import type { Finding, Project, Remediation, Report, Scan } from "@/lib/types";

export const apiUrl = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/$/, "");

export class ApiError extends Error {
  constructor(message: string, public readonly status: number) {
    super(message);
    this.name = "ApiError";
  }
}

export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(`${apiUrl}${path}`, {
    ...init,
    headers,
    credentials: "include",
  });
  if (!response.ok) {
    let message = `Request failed with ${response.status}.`;
    try {
      const payload = (await response.json()) as { detail?: string };
      message = payload.detail || message;
    } catch {
      // A non-JSON error response still has a useful HTTP status.
    }
    throw new ApiError(message, response.status);
  }
  return response.json() as Promise<T>;
}

export const listProjects = () => apiFetch<Project[]>("/projects");
export const createProject = (repoUrl: string) => apiFetch<Project>("/projects", { method: "POST", body: JSON.stringify({ repo_url: repoUrl }) });
export const startScan = (projectId: string) => apiFetch<Scan>(`/projects/${projectId}/scans`, { method: "POST" });
export const getScan = (scanId: string) => apiFetch<Scan>(`/scans/${scanId}`);
export const getFindings = (scanId: string) => apiFetch<Finding[]>(`/scans/${scanId}/findings`);
export const getReport = (scanId: string) => apiFetch<Report>(`/scans/${scanId}/report`);
export const remediateFinding = (findingId: string) => apiFetch<Remediation>(`/findings/${findingId}/remediate`, { method: "POST" });
export const approveRemediation = (remediationId: string) => apiFetch<Remediation>(`/remediations/${remediationId}/approve`, { method: "POST" });
export const getRemediation = (remediationId: string) => apiFetch<Remediation>(`/remediations/${remediationId}`);
export const reportExportUrl = (scanId: string) => `${apiUrl}/scans/${scanId}/report/export`;
export const githubLoginUrl = () => `${apiUrl}/auth/github/login`;

export function scanWebSocketUrl(scanId: string) {
  const websocketBase = apiUrl.replace(/^http:/, "ws:").replace(/^https:/, "wss:");
  return `${websocketBase}/scans/${scanId}/live`;
}
