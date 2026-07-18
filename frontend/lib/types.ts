export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ScanStatus = "queued" | "cloning" | "static_scan" | "ai_review" | "merging" | "complete" | "failed";

export interface Project {
  id: string;
  repo_url: string;
  repo_owner: string;
  repo_name: string;
  default_branch: string;
  created_at: string;
}

export interface Scan {
  id: string;
  project_id: string;
  commit_sha: string;
  status: ScanStatus;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  files_scanned: number;
  duration_ms: number | null;
  created_at: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  detector: string;
  category: string;
  severity: Severity;
  confidence: number;
  file_path: string;
  line_start: number | null;
  line_end: number | null;
  code_snippet: string | null;
  title: string;
  description: string;
  ai_explanation: string | null;
  fix_suggestion: string | null;
  is_false_positive: boolean;
  created_at: string;
}

export interface Remediation {
  id: string;
  finding_id: string;
  tier: 1 | 2 | 3;
  status: "proposed" | "pending_approval" | "approved" | "verifying" | "pr_opened" | "rejected" | "failed";
  diff: string | null;
  verification_result: Record<string, unknown> | null;
  pr_url: string | null;
  approved_by: string | null;
  created_at: string;
}

export interface ReportFinding extends Finding {
  remediation: Pick<Remediation, "id" | "tier" | "status" | "pr_url"> | null;
}

export interface Report {
  id: string;
  scan_id: string;
  overall_risk_score: number;
  summary: string;
  finding_counts: Partial<Record<Severity, number>>;
  export_url: string | null;
  created_at: string;
  findings: ReportFinding[];
}

export type ScanEvent =
  | { type: "status"; scan_id: string; status: ScanStatus; detail: string; files_scanned?: number; languages?: string[]; total_bytes?: number }
  | { type: "finding"; scan_id: string; finding_id: string | null; detector: string; category: string; severity: Severity; confidence: number; file_path: string; line_start: number | null; title: string }
  | { type: "error"; scan_id: string; detail: string };
