# SENTINEL AI — Technical Specification
Companion document to `SENTINEL_AI_PRD.md`. Covers system architecture, database schema, backend service design, detection pipeline internals, and backdoor-detection feasibility.

---

# 1. System Architecture

## 1.1 High-Level Diagram

```
                         ┌─────────────────────────┐
                         │        Frontend         │
                         │  Next.js / TypeScript   │
                         │  Dashboard · Live Scan   │
                         │  Report Viewer · Export  │
                         └────────────┬────────────┘
                                      │ REST / WebSocket
                         ┌────────────▼────────────┐
                         │      API Gateway          │
                         │  FastAPI (auth, routing)  │
                         └────────────┬────────────┘
                                      │
              ┌───────────────────────┼───────────────────────┐
              │                       │                       │
   ┌──────────▼─────────┐  ┌──────────▼─────────┐  ┌──────────▼─────────┐
   │   Ingestion Service  │  │  Orchestrator (Job) │  │  Report Service     │
   │  Clone/pull repo     │  │  Scan job lifecycle │  │  Merge findings     │
   │  Language detection  │  │  Queue + status      │  │  Render + export    │
   └──────────┬─────────┘  └──────────┬─────────┘  └──────────┬─────────┘
              │                       │                       │
              │            ┌──────────▼─────────┐             │
              │            │   Job Queue (Redis)  │             │
              │            └──────────┬─────────┘             │
              │                       │                       │
   ┌──────────▼───────────────────────▼───────────────────────▼─────────┐
   │                          Detection Pipeline (workers)                │
   │  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────────────┐ │
   │  │ Static Layer     │  │ AI Reasoning     │  │ Backdoor Heuristics  │ │
   │  │ - secrets        │  │ Layer            │  │ - obfuscation checks │ │
   │  │ - config risk    │  │ - context read   │  │ - exfil/network      │ │
   │  │ - dep audit      │  │ - severity/why   │  │   pattern match      │ │
   │  │ - AST rules      │  │ - fix suggestion │  │ - suspicious exec    │ │
   │  └─────────────────┘  └─────────────────┘  └──────────────────────┘ │
   └────────────────────────────────┬──────────────────────────────────┘
                                     │
                         ┌───────────▼───────────┐
                         │      PostgreSQL         │
                         │  projects · scans        │
                         │  findings · reports      │
                         └───────────┬───────────┘
                                     │
                         ┌───────────▼───────────┐
                         │  Object Storage (S3)    │
                         │  cloned repo snapshots  │
                         │  exported reports        │
                         └─────────────────────────┘
```

## 1.2 Component Responsibilities

| Component | Responsibility |
|---|---|
| **API Gateway** | Auth (GitHub OAuth), request validation, rate limiting, routes to services |
| **Ingestion Service** | Shallow-clones the repo, detects languages/frameworks, builds file inventory, enforces size/time limits |
| **Orchestrator** | Creates a scan job, tracks lifecycle (queued → running → per-stage progress → complete/failed), pushes live status over WebSocket |
| **Job Queue** | Redis-backed queue so scanning is async and workers can scale horizontally |
| **Static Layer** | Deterministic, rule-based detectors — no LLM calls, fast, zero hallucination risk |
| **AI Reasoning Layer** | Takes static findings + surrounding code context, produces explanation/severity/fix; single LLM call per finding cluster, not per line |
| **Backdoor Heuristics** | Separate rule-set specifically for backdoor-shaped patterns (see Section 4) |
| **Report Service** | Merges all findings, deduplicates, ranks by severity, renders to Markdown/PDF |
| **PostgreSQL** | System of record for projects, scans, findings, reports |
| **Object Storage** | Temporary repo snapshots (deleted post-scan) and exported report files |

## 1.3 Why this shape
- Static and AI layers are **decoupled** — static detection never depends on the LLM being available or correct, so a demo never fails because of a flaky API call.
- Scans run **async via a queue**, not inline on the request — this is what makes the "live progress" UI possible and keeps the API responsive.
- Backdoor heuristics are their own module, not folded into general secret-scanning, because the signal (control-flow/obfuscation/exfiltration patterns) is structurally different from "found an API key."

---

# 2. Database Schema (PostgreSQL)

```sql
-- Users authenticate via GitHub OAuth
CREATE TABLE users (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    github_id         BIGINT UNIQUE NOT NULL,
    username          TEXT NOT NULL,
    email             TEXT,
    avatar_url        TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A project wraps one repository a user has connected
CREATE TABLE projects (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    repo_url          TEXT NOT NULL,
    repo_owner        TEXT NOT NULL,
    repo_name         TEXT NOT NULL,
    default_branch    TEXT NOT NULL DEFAULT 'main',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Each scan is one run of the detection pipeline against a project
CREATE TABLE scans (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id        UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    commit_sha        TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'queued',
        -- queued | cloning | static_scan | ai_review | merging | complete | failed
    started_at        TIMESTAMPTZ,
    completed_at       TIMESTAMPTZ,
    error_message      TEXT,
    files_scanned      INTEGER DEFAULT 0,
    duration_ms        INTEGER,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Individual findings from any detector (static, AI, or backdoor heuristics)
CREATE TABLE findings (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id           UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    detector          TEXT NOT NULL,
        -- e.g. 'secret_scan', 'config_risk', 'dependency_audit',
        --      'ai_reasoning', 'backdoor_heuristic'
    category          TEXT NOT NULL,
        -- e.g. 'hardcoded_secret', 'insecure_config', 'vulnerable_dependency',
        --      'suspicious_exfiltration', 'obfuscated_code', 'auth_bypass'
    severity          TEXT NOT NULL,  -- critical | high | medium | low | info
    confidence        NUMERIC(3,2) NOT NULL DEFAULT 1.0,  -- 0.00–1.00
    file_path         TEXT NOT NULL,
    line_start        INTEGER,
    line_end          INTEGER,
    code_snippet      TEXT,
    title             TEXT NOT NULL,
    description       TEXT NOT NULL,
    ai_explanation    TEXT,           -- filled by AI Reasoning Layer, nullable
    fix_suggestion    TEXT,
    is_false_positive  BOOLEAN DEFAULT FALSE,  -- user can mark/dismiss
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Final merged report per scan
CREATE TABLE reports (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id           UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE UNIQUE,
    overall_risk_score NUMERIC(4,1) NOT NULL,   -- 0–100
    summary            TEXT NOT NULL,
    finding_counts     JSONB NOT NULL,
        -- e.g. {"critical":1,"high":3,"medium":5,"low":2}
    export_url         TEXT,          -- link to PDF/Markdown in object storage
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes for common query patterns
CREATE INDEX idx_scans_project ON scans(project_id);
CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_category ON findings(category);
```

### Notes
- `confidence` on findings matters a lot for credibility — a judge (or real user) should see "Confidence: 0.9" next to a hardcoded-secret match versus "Confidence: 0.4" on a fuzzier AI-inferred issue.
- `is_false_positive` lets users dismiss noise, which also becomes training signal later for tuning detectors.
- `pgvector` isn't included here — it's only needed if you add semantic code search (roadmap item), not required for MVP scope.

---

# 3. Backend Service Design (FastAPI)

## 3.1 API Endpoints

```
POST   /auth/github/callback        Exchange OAuth code for session
GET    /projects                    List user's projects
POST   /projects                    Create project from repo URL
GET    /projects/{id}               Project detail

POST   /projects/{id}/scans         Trigger a new scan (enqueues job)
GET    /scans/{id}                  Scan status + progress
GET    /scans/{id}/findings         List findings for a scan
PATCH  /findings/{id}                Mark false positive / add note

GET    /scans/{id}/report           Get merged report
GET    /scans/{id}/report/export    Download PDF/Markdown

WS     /scans/{id}/live             WebSocket: live progress + streaming findings
```

## 3.2 Scan Job Lifecycle

```
1. POST /projects/{id}/scans
   → Orchestrator creates `scans` row (status=queued)
   → Job pushed to Redis queue

2. Worker picks up job
   → status=cloning: shallow git clone, file inventory, language detection
   → status=static_scan: run static detectors (parallel where possible)
   → status=ai_review: batch flagged findings → LLM calls for explanation/severity
   → status=merging: dedupe, rank, compute overall_risk_score
   → status=complete: report row created, export files generated

3. Each stage transition is pushed over WebSocket to the frontend
   for the live progress UI.
```

## 3.3 Static Detection Engine (module breakdown)

| Module | Technique | Example catch |
|---|---|---|
| `secret_scanner.py` | Shannon entropy + regex signatures (AWS keys, JWT, private keys, generic `API_KEY=` patterns) | Hardcoded API key left in a config file |
| `config_auditor.py` | Rule-based checks on common config files (`.env`, `settings.py`, `next.config.js`, Dockerfiles) | `DEBUG=True` in a file that looks production-bound, wildcard CORS |
| `dependency_auditor.py` | Parses `package.json` / `requirements.txt` / `go.mod`, cross-references against a known-vulnerable-package list and flags unusually low download counts / recent publish dates (proxy for unvetted AI-suggested packages) | A dependency the LLM invented or suggested that isn't a real, trusted package |
| `ast_rules.py` | Tree-sitter/Python AST walks for structural anti-patterns | Auth check present but inside a branch that's unreachable, `eval()`/`exec()` on user input |

## 3.4 AI Reasoning Layer
- Powered by **GPT-5.6**, called via the standard `/v1/messages`-equivalent OpenAI API pattern.
- Runs **after** static detection, not instead of it.
- Input per call: the finding + a bounded window of surrounding code (not the whole repo) to control cost and reduce hallucination risk.
- Output schema (forced via structured JSON prompting):

```json
{
  "severity": "high",
  "confidence": 0.85,
  "explanation": "This API key is hardcoded and committed to version control...",
  "fix_suggestion": "Move the key to an environment variable and rotate it immediately.",
  "exploitability_notes": "Publicly readable if the repo is public or later made public."
}
```
- The AI layer is **never allowed to introduce new findings on its own** in the MVP — it only explains/scores what static detection or backdoor heuristics already flagged. This is a deliberate constraint to prevent hallucinated vulnerabilities from appearing in a live demo.

---

# 4. Backdoor Detection — Can This Project Actually Do It?

Direct answer: **yes, partially, and it's worth being precise about what "detect a backdoor" can realistically mean in a 7-day MVP.**

## 4.1 What a "backdoor" actually looks like in code
Backdoors in real codebases (and especially in AI-generated code) tend to fall into a few concrete, detectable patterns rather than being magical or invisible:

1. **Hidden authentication bypass** — a conditional that grants access based on a hardcoded value (e.g. a secret query param, hardcoded username/token check) that isn't part of the documented auth flow.
2. **Obfuscated or encoded payloads** — base64/hex-encoded strings that get decoded and executed (`eval(atob(...))`, `exec(base64.b64decode(...))`), a very common backdoor pattern precisely because it's easy for an LLM to produce (and easy for an attacker to slip in) without looking obviously malicious.
3. **Unexpected outbound network calls** — code that phones home to a hardcoded IP/domain not related to the app's declared functionality (data exfiltration, C2 beaconing).
4. **Suspicious dynamic code execution** — building and running commands from string concatenation involving user input or remote data (`os.system(...)`, `subprocess` with unsanitized input, `child_process.exec` in Node).
5. **Dependency-level backdoors** — a package with a name close to a popular one (typosquatting) or a legitimate package with an unexpected postinstall script.

These are **structural/behavioral patterns**, not something you need a full binary-analysis or runtime sandbox to catch — static + AST analysis can realistically flag most of them.

## 4.2 What Sentinel AI's architecture *can* catch (realistic MVP scope)
Add a dedicated `backdoor_heuristics` detector module (already reflected in the architecture/schema above) that specifically checks for:

- `eval()` / `exec()` / `Function()` calls fed by decoded or concatenated strings
- Base64/hex blobs decoded and immediately executed
- Hardcoded IPs, raw sockets, or outbound HTTP calls to domains not referenced anywhere else in the codebase or its config
- Auth-related conditionals containing hardcoded string/token comparisons outside the normal auth module
- `package.json`/`requirements.txt` entries with suspicious install scripts, or names that are near-matches to popular packages (Levenshtein-distance check against a known-package list)

The AI Reasoning Layer then explains *why* a flagged pattern is suspicious and estimates confidence — this is valuable because backdoor heuristics have a higher false-positive rate than secret-scanning (an `eval()` isn't automatically malicious), so the explanation step is what makes findings usable rather than noise.

## 4.3 What it honestly cannot do in this timeframe
Be upfront about this if a judge asks — it's more credible than overclaiming:

- **No dynamic/runtime analysis.** It won't execute the code in a sandbox to observe actual behavior (no real "does this app phone home when run" detection) — that's a significant engineering lift (isolated execution environment, network monitoring, timeout handling) beyond hackathon scope.
- **No guarantee against a sufficiently subtle backdoor.** A backdoor that's logically disguised as normal business logic (no obfuscation, no suspicious API calls, just a cleverly-placed conditional) is genuinely hard for static or LLM analysis to catch reliably — this is an open problem in security research generally, not a gap unique to your MVP.
- **No supply-chain deep verification.** Flagging a suspicious dependency name is feasible; verifying that a legitimate-looking published package doesn't itself contain a backdoor would require deeper package content scanning, which is out of scope for the MVP.

## 4.4 Recommended framing for the pitch
> "Sentinel AI detects the backdoor patterns most likely to appear in AI-generated code — obfuscated execution, hidden auth bypasses, and unexpected network calls — using static analysis paired with AI-driven explanation. It's not a substitute for a full security audit or runtime sandboxing, but it catches the class of backdoor an LLM is statistically most likely to introduce or overlook."

This is honest, technically defensible under judge questioning, and still a genuinely differentiated claim versus generic SAST tools that don't specifically target this pattern class.

---

# 5. Remediation Engine — Auto-Fixing Findings (Including Backdoors)

## 5.1 Design Principle
Auto-fixing security findings is inherently riskier than detecting them: a wrong or overly aggressive fix can break the application, or worse, remove an *obvious* backdoor while missing a subtler one and giving the user false confidence that the app is now safe. Sentinel AI's remediation engine is built around **tiered autonomy**, not blanket auto-fix:

| Tier | Examples | Behavior |
|---|---|---|
| **Tier 1 — Auto-fixable** | Hardcoded secrets, insecure config flags (`DEBUG=True`, wildcard CORS), typosquatted dependency names | Fix generated automatically, applied on an isolated branch, opened as a PR — never pushed directly to the user's default branch |
| **Tier 2 — Suggested, human-approved** | Auth bypass conditionals, obfuscated `eval`/`exec` payloads, suspicious dynamic code execution | Sentinel generates a proposed diff + explanation, but requires explicit user approval (one click) before a PR is opened |
| **Tier 3 — Flagged only, no auto-fix** | Unexpected outbound network calls, ambiguous business logic that could be a disguised backdoor | Reported with full context and manual remediation guidance only — too high false-positive/business-impact risk to touch automatically |

This tiering is itself a demo talking point: it shows judges you've thought about the failure mode of "AI security tool that confidently breaks or over-trusts itself," which is a more sophisticated position than claiming full autonomy.

## 5.2 Remediation Flow

```
Finding (Tier 1/2)
      │
      ▼
Fix Generator (LLM + template-based patch for Tier 1)
      │
      ▼
Sandboxed Branch (sentinel-fix/{scan_id}/{finding_id})
      │
      ▼
Automated Verification
   - Does the file still parse / compile?
   - Do existing tests still pass (if test suite present)?
   - For secrets: was the env var actually wired up correctly?
      │
      ▼
Tier 1 → Open PR automatically, labeled "Sentinel AI: Auto-fix"
Tier 2 → Hold for user approval, then open PR
Tier 3 → No PR; guidance only
      │
      ▼
User reviews & merges PR via normal GitHub flow (Sentinel never merges to main itself)
```

Key safety rule: **Sentinel AI never writes directly to the user's default branch.** Every fix — even Tier 1 — lands as a pull request the user must merge themselves. This avoids the platform ever being the thing that silently altered production code.

## 5.3 Fix Generation Approach by Category

| Category | Fix strategy |
|---|---|
| Hardcoded secret | Replace literal with `os.environ["X"]` / `process.env.X`; add placeholder to `.env.example`; add the file to `.gitignore` if missing |
| Insecure config | Template-based flip (`DEBUG=True→False`, explicit CORS origin list instead of `*`) |
| Typosquatted dependency | Swap to verified legitimate package name + version, re-run dependency audit to confirm |
| Obfuscated eval/exec payload | LLM decodes and explains the payload's actual behavior; proposes removal *only if* the decoded behavior isn't part of any documented feature; otherwise flags for manual review with the decoded content shown |
| Auth bypass conditional | LLM explains what the bypass does and under what condition; proposes a diff removing the bypass, but requires explicit approval — never auto-applied, since it may be intentional (e.g. a debug backdoor the dev forgot to remove, or a real feature) |

## 5.4 Database Additions

```sql
CREATE TABLE remediations (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id        UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    tier              INTEGER NOT NULL,          -- 1, 2, or 3
    status            TEXT NOT NULL DEFAULT 'proposed',
        -- proposed | pending_approval | approved | verifying | pr_opened | rejected | failed
    diff              TEXT,                       -- proposed patch (unified diff format)
    verification_result JSONB,
        -- {"parses": true, "tests_passed": true, "notes": "..."}
    pr_url            TEXT,
    approved_by        UUID REFERENCES users(id),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

## 5.5 New API Endpoints

```
POST   /findings/{id}/remediate        Generate a fix (Tier 1 auto-runs; Tier 2 returns diff for approval)
POST   /remediations/{id}/approve      User approves a Tier 2 fix
GET    /remediations/{id}              Status + diff + verification result
```

## 5.6 What "fix the backdoor" honestly means for the demo
For Tier 2 items like an auth-bypass or decoded obfuscated payload, the strongest, most credible demo moment is: **Sentinel explains exactly what the backdoor does, shows the decoded/plain-language version of the malicious logic, proposes a diff, and the presenter clicks "approve" live** — showing human-in-the-loop judgment rather than a black box silently rewriting security-critical code. That reads as more mature security engineering than full autonomy, and it directly answers the "how do you know the fix is safe" question before a judge even asks it.

---

# 6. Suggested Build Order (7 Days)

| Day | Focus |
|---|---|
| 1 | Repo ingestion + DB schema + auth |
| 2 | Static secret/config detectors (highest-confidence, zero-hallucination wins) |
| 3 | Dependency auditor + backdoor heuristics module |
| 4 | AI Reasoning Layer wired to static findings, structured JSON output |
| 5 | Remediation Engine: Tier 1 auto-fix + PR generation, Tier 2 approval flow |
| 6 | Report merging, risk scoring, export (PDF/Markdown) + Frontend: live scan progress, findings UI |
| 7 | End-to-end testing against your chosen demo repo (including one real backdoor pattern to fix live), polish, rehearse |

If time runs short, cut Tier 2 approval UI polish before you cut Tier 1 auto-fix — a working "secret got auto-fixed into a real PR" moment is a strong, low-risk demo beat on its own.

---

# 7. Codex Build Process (for judge evaluation)

OpenAI Build Week judging explicitly evaluates *how* Codex accelerated the build, not just the end result. Track this as you go, don't reconstruct it after the fact:

## 7.1 What to log throughout the week
- Which components were scaffolded primarily by Codex vs. hand-written/edited by you (e.g. "Codex generated the initial FastAPI route structure and the secret-scanner regex set; we hand-tuned the entropy thresholds and rewrote the AST rules for the auth-bypass heuristic").
- Key decision points where you overrode or redirected Codex's first attempt, and why — this is exactly the kind of detail judges want ("Codex's first pass on the remediation diff logic auto-applied fixes directly to main; we redirected it to always branch + PR instead, for safety").
- Where GPT-5.6 is used in the *running product* itself (AI Reasoning Layer, Remediation fix generation) — distinct from Codex, which is your *build* tool.

## 7.2 `/feedback` Session ID
Run the majority of core functionality (detection pipeline + remediation engine) inside one continuous Codex session where possible, so the `/feedback` session ID cleanly represents your core build — rather than scattering the essential logic across many disconnected sessions.

## 7.3 Demo video narration checklist
The <3 min video must have audio explicitly covering:
- [ ] What Codex built vs. what you directed/decided
- [ ] Where GPT-5.6 runs inside the product (Reasoning Layer, Remediation Engine)
- [ ] The live detect → explain → fix flow (Tier 1 auto-fix PR + Tier 2 approve-and-fix backdoor moment)
- [ ] A moment showing judges can test it themselves (hosted URL/sandbox account)

Build order deliberately puts **zero-hallucination static detectors before the LLM layer** — this guarantees you have *something real* to demo even if AI integration runs into issues late.
