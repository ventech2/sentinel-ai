# Codex Build Notes

Running log of what Codex built, key decisions made, and anything ambiguous that came up during the build. This doc feeds directly into:
- The demo video narration (Codex + GPT-5.6 usage section)
- The README "How Codex and GPT-5.6 were used" section
- Judge evaluation of technical implementation quality

Add a new entry after every Codex session. Keep entries factual and specific — vague entries like "Codex helped with the backend" aren't useful later.

---

## Entry template

```
### Session N — [Date] — [What this session covered]

**Prompt summary:** [1-2 lines on what you asked Codex to build]

**What Codex built:**
- ...

**Decisions / overrides made:**
- [Where you redirected Codex's first attempt and why]

**Ambiguities Codex flagged:**
- ...

**Session ID:** [if this is the core-functionality session, note the /feedback ID here]
```

---

## Entry log

### Session 1 — [DATE:July 14, 2026 {WAT}] — Backend scaffolding + DB schema

**Prompt summary:** Scaffolded FastAPI backend structure and Postgres models per Technical Spec Sections 1–2 (architecture + DB schema), including API route stubs, GitHub OAuth setup, and Redis connection config. Follow-up prompt closed 4 gaps: remediations table, real route implementations, GitHub OAuth, Redis config.

**What Codex built:**
- [x] `/backend` FastAPI project structure (app/main.py, api/routes/, models/, services/, core/config.py, queue/)
- [x] SQLAlchemy models for users, projects, scans, findings, reports, **and remediations** (added in follow-up)
- [x] Alembic migration chain — two migrations, `20260714_0001_initial_schema` and `20260716_0002_add_remediations`, both apply in sequence
- [x] Real API routes for auth, projects, scans, findings, reports — service-dependent routes intentionally return `501 Not Implemented` until underlying services are built (not faked/mocked logic)
- [x] WebSocket route `/scans/{scan_id}/live` scaffolded — accepts connection, sends a scaffold status message, closes
- [x] GitHub OAuth — real implementation, not just a stub: `GET /auth/github/login` (CSRF state + redirect), `POST /auth/github/callback` (validates state, exchanges code via real HTTPX calls to GitHub, upserts user, creates signed session cookie), plus a browser-redirect-compatible `GET /auth/github/callback`
- [x] Redis connection config (`app/queue/redis.py`) — shared async client from `REDIS_URL`, `get_redis()` dependency, closes pooled connections on shutdown. No queue/worker logic yet (correctly out of scope for this session).

**Decisions / overrides made:**
- OAuth library: custom `GitHubOAuthClient` (HTTPX-based) rather than a third-party OAuth library — Codex's choice, not explicitly directed
- Remediations table wasn't in the original Section 2 SQL block (only referenced later in Section 5.4) — corrected via follow-up prompt after review caught the gap
- Chose NOT to persist OAuth access tokens in this session — flagged as a decision that needs revisiting since repo cloning will require token access later (see open item below)

**Ambiguities Codex flagged:**
- Remediations table was missing from the initial Section 2 schema block (spec inconsistency between Section 2 and 5.4) — resolved by adding it explicitly
- `PATCH /findings/{id}` was speced to accept a note, but no `notes` column exists on the findings table — route intentionally left as a 501 scaffold pending this decision
- OAuth requires real `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, a registered redirect URI, and a strong `SESSION_SECRET` before it can actually authenticate — these are placeholder/missing in local `.env` until configured

**Open items carried into next session:**
- [x] OAuth token persistence: **DONE — separate `oauth_tokens` table**, one-to-one with users, Fernet-encrypted token storage (plaintext never stored/returned), scope + timestamps. Migration `20260717_0003_add_oauth_tokens` applied.
- [x] `notes` column on findings: **DONE — skipped for MVP.** PATCH /findings/{id} only accepts `is_false_positive`; explicitly rejects a `note` field.
- [x] Migration chain fully validated against live local Postgres 18 — current revision confirmed at `20260717_0003 (head)`, all three migrations applied cleanly.
- [ ] **Action needed:** generate a Fernet key (`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`) and set `OAUTH_TOKEN_ENCRYPTION_KEY` in `.env` — OAuth callbacks currently refuse token persistence without it (safe default, not a bug).

**Session 1 status: COMPLETE.** Backend scaffold, full DB schema (users, projects, scans, findings, reports, remediations, oauth_tokens), API route stubs, GitHub OAuth (real implementation), Redis config — all verified against a live database.

**Session ID:** 019f5e9e-7a0d-7401-b0e9-ede38d28bb6b


---

### Session 2 — [DATE:July 17, 2026 {WAT}] — Static detectors

**Prompt summary:** Implemented the four static detection modules from Technical Spec Section 3.3 — secret_scanner, config_auditor, dependency_auditor, ast_rules — each independently testable, zero AI/LLM calls.

**What Codex built:**
- [x] `secret_scanner.py` — entropy analysis (3.5+ bits/char threshold) + regex signatures for AWS keys, JWTs, private keys, Stripe-style keys, generic API_KEY= assignments
- [x] `config_auditor.py` — DEBUG=True detection, wildcard CORS, committed .env without .gitignore coverage
- [x] `dependency_auditor.py` — Levenshtein distance ≤2 typosquat detection against curated popular-package list; low-confidence (0.35) heuristic for "obscure" dependency names
- [x] `ast_rules.py` — Python `ast` module walks flagging eval/exec fed by decoded/concatenated data, and hardcoded auth/token string comparisons
- [x] Shared finding contract (`detectors/models.py`) and safe file traversal utility (`detectors/file_utils.py`) skipping .git/node_modules/venv/__pycache__, binaries, and files >1MB
- [x] Test fixtures with planted issues, `pytest` added to requirements
- [x] Tests passing: `5 passed in 0.80s`

**Decisions / overrides made:**
- Entropy threshold set at 3.5 bits/char + 16 char minimum for generic secret detection (signature-based detection used for known formats instead)
- Typosquat check uses a small curated reference list, not a live package registry (correct MVP scope choice)
- `DetectorFinding` intentionally omits `scan_id`/timestamps — assigned later by orchestration layer, not the detector itself

**Ambiguities Codex flagged:**
- `ast_rules.py` is Python-only (stdlib `ast`), not multi-language via Tree-sitter as originally scoped in the spec — flagged as a known limitation, not silently narrowed
- `.env` exposure check infers risk from file presence + missing `.gitignore` entry, doesn't inspect live Git index/history

**Follow-up sent:** requesting per-signature-type test coverage confirmation for secret_scanner, explicit confirmation that Python-only AST scope is a documented decision, and a sanity-check run against `/sample-data/vulnerable-demo-app` to confirm real planted vulnerabilities are caught.

**Follow-up 2 — JS/TS regex coverage:** Added `js_pattern_rules.py` as a separate module (not folded into Python ast_rules.py) covering `.js/.jsx/.mjs/.cjs/.ts/.tsx` files. Detects eval()/new Function() dynamic execution, decoded-then-executed payloads (atob() → eval), and hardcoded auth/token/admin comparisons. Explicitly documented as lower-precision regex detection vs. Python's AST-based approach; full Tree-sitter multi-language parsing deferred to roadmap (deliberate scope decision to conserve build time/API credit). Tests added, all passing: `6 passed in 1.37s`.

**Judgment call flagged:** direct eval/new Function flagged even without visible decoding, but at lower confidence. Regex approach can produce false positives/misses on unusual formatting — source review still recommended, not a replacement for human judgment.

**Still pending:** real end-to-end sanity check — running all detectors (Python + JS) against the actual `/sample-data/vulnerable-demo-app` repo to confirm the 6 planted vulnerabilities are genuinely caught. This is the proof-of-concept step before Session 3.

**REAL-REPO VALIDATION — Round 1:** Ran all 5 detectors against `sample-data/vulnerable-demo-app/`. 4 of 6 planted issues caught (secret, auth bypass, typosquat, committed .env). **2 gaps found:**
1. `config_auditor` only checked named config files (.env, settings.py, etc.), missed `DEBUG=True`/wildcard CORS set directly in `app/main.py`
2. `ast_rules` only flagged `eval()`/`exec()`, missed the actual backdoor pattern: `subprocess.run(decoded, shell=True)` fed by a base64-decoded payload — **this was the most important miss**, since shell-command backdoors are a core pitch claim

**REAL-REPO VALIDATION — Round 2 (after fixes):** Both gaps fixed.
- `config_auditor.py` extended to scan `.py`/`.js`/`.ts` source files directly for inline DEBUG/wildcard-CORS patterns, not just named config files
- `ast_rules.py` extended to track variables assigned from base64/hex decode expressions and flag them when passed to `subprocess.run`/`call`/`Popen` or `os.system`, not just `eval`/`exec`
- New fixtures added, full suite: `7 passed in 1.25s`
- **Result: all 6 planted vulnerabilities now caught**, confirmed against the real demo repo (not just fixtures): Stripe key (main.py:40), DEBUG=True (main.py:25), wildcard CORS (main.py:29), auth bypass (main.py:68), subprocess/base64 backdoor (main.py:96), requessts typosquat (requirements.txt:10), committed .env (.env:1)

**Session 2 status: COMPLETE AND VERIFIED.** This is the strongest proof point in the build so far — real detection against a real repo, not just passing fixture tests. Worth highlighting in the demo video narration as evidence the tool actually works, not just "tests pass."

**Session ID:** 019f5e9e-7a0d-7401-b0e9-ede38d28bb6b

---

### Session 3 — [DATE:July 17, 2026{WAT}] — Backdoor heuristics module

**Prompt summary:** Built a dedicated `backdoor_heuristics.py` module (separate from `ast_rules.py`, which already handles eval/exec and subprocess/decode patterns) covering two additional backdoor categories: suspicious outbound network calls and dependency-level install-script backdoors.

**What Codex built:**
- [x] `suspicious_outbound_connection` — flags raw IPv4 targets in HTTP URLs (Python/JS/TS), `socket.connect(("IP", port))` patterns, and domains referenced exactly once across the repo (isolated/unexplained destination heuristic)
- [x] `suspicious_install_script` — flags `package.json` pre/postinstall scripts containing remote downloads (curl/wget/fetch), `node -e`/`--eval`, or shell invocation
- [x] Test fixtures + tests, full suite: `9 passed in 0.74s`

**Decisions / overrides made:**
- Confidence calibration: raw-IP connection 0.68 (medium severity, legitimate infra is possible); isolated domain 0.42 (low severity, intentionally noisy — deliberately conservative given false-positive risk); install script 0.86–0.90 for downloads/inline-eval, 0.62 for shell-only (some build flows legitimately need shell)
- Kept cleanly separate from `ast_rules.py` and `dependency_auditor.py` — no logic duplication

**Ambiguities Codex flagged:**
- Static analysis can't determine if an outbound destination is sanctioned, dynamically resolved, or benign — **Codex independently concluded these network findings should be review-required, not auto-remediated**, which matches the Tier 3 (flagged-only) design already in the Remediation Engine spec (Section 5.1). Good consistency signal between detector confidence and architecture design.

**REAL-REPO VALIDATION:** Added a 7th planted vulnerability to the demo app (hardcoded-IP `socket.create_connection()` beacon on startup) specifically to test this module against a real repo, not just fixtures. Extended `suspicious_outbound_connection` to recognize `socket.create_connection(...)` syntax after initial gap found. Full suite: `9 passed`. **All 7 planted vulnerabilities now confirmed caught in one end-to-end scan:**

| # | Vulnerability | Detector | Location | Confidence |
|---|---|---|---|---|
| 1 | Stripe-style secret key | secret_scanner | main.py:41 | 0.98 |
| 2 | Committed .env, no .gitignore | config_auditor | .env:1 | 0.88 |
| 3 | DEBUG=True (.env) | config_auditor | .env:7 | 0.90 |
| 4 | DEBUG=True (source code) | config_auditor | main.py:26 | 0.90 |
| 5 | Wildcard CORS | config_auditor | main.py:30 | 0.92 |
| 6 | Typosquatted dependency | dependency_auditor | requirements.txt:10 | 0.86 |
| 7 | Hardcoded auth bypass | ast_rules | main.py:69 | 0.84 |
| 8 | Base64/subprocess backdoor | ast_rules | main.py:97 | 0.95 |
| 9 | Hardcoded-IP network beacon | backdoor_heuristics | main.py:113 | 0.68 |

**Session 3 status: COMPLETE AND VERIFIED.** Full static detection layer (5 detector modules) now validated end-to-end against a real repo with 9 distinct planted findings across all severity/confidence ranges — a strong, evidence-backed foundation heading into the AI Reasoning Layer.

**Session ID:** 019f5e9e-7a0d-7401-b0e9-ede38d28bb6b

---

### Session 4 — [DATE:July 17, 2026{WAT}] — AI Reasoning Layer

**Prompt summary:** Implemented app/reasoning/ai_reasoning.py per Technical Spec Section 3.4 — enriches static findings with plain-language explanations, severity/confidence assessment, and fix suggestions via LLM, with structured JSON output, bounded code context, and graceful fallback on any failure.

**What Codex built:**
- [x] `ai_reasoning.py` — takes each static finding + 12-line bounded code context (capped 15 lines/12,000 chars), calls the LLM with a system prompt that explicitly treats source code as untrusted data (prompt-injection defense) and forbids introducing new findings
- [x] Structured JSON output schema: severity, confidence, explanation, fix_suggestion, exploitability_notes
- [x] Confidence only updates if it differs from the static score by ≥0.15 (prevents noisy small adjustments)
- [x] Comprehensive fallback: invalid JSON, schema mismatch, timeout, missing credentials, API errors all fall back to original static finding with `ai_explanation=null` — never crashes
- [x] Mocked tests (no real API calls in automated suite): 12 passed
- [x] Standalone manual sanity script for real API validation against 3 real demo findings

**Major deviation — provider pivot (OpenAI → Gemini):**
- OpenAI Build Week credits are Codex-only; organizers officially confirmed **no separate OpenAI API credits are provided**, and personal funding wasn't an option
- Pivoted to **Google Gemini API** (genuinely free tier, no credit card) as the runtime AI provider, while keeping Codex as the build tool — this satisfies eligibility (project built with Codex/GPT-5.6) without requiring paid API access for the live product
- Added a provider abstraction in `ai_reasoning.py` supporting both OpenAI and Gemini behind the same structured JSON contract — OpenAI can be re-enabled with zero code changes if API access becomes available later
- Model identifier required two corrections during setup: `gemini-2.5-flash` → deprecated for new users → corrected to `gemini-3-flash-preview` (current documented free-tier model as of July 2026)

**Debugging trail (for reference — all resolved):**
1. `ModuleNotFoundError: openai` → `pip install openai`
2. `insufficient_quota` (429) → confirmed OpenAI API credits not funded for this hackathon (Codex-only)
3. `ModuleNotFoundError: google` → `pip install google-genai`
4. `404 NOT_FOUND` on `gemini-2.5-flash` → corrected to `gemini-3-flash-preview`

**REAL-API VALIDATION:** Ran the manual sanity script against 3 real findings from the vulnerable demo app using the live Gemini API (not mocked). **2 of 3 succeeded with genuinely strong output:**
- Stripe secret key finding: detailed, technically accurate explanation distinguishing "placeholder key" vs. "committed-secrets practice is still a critical failure" — plus a concrete one-line code fix
- DEBUG=True finding: correctly reasoned about FastAPI/Uvicorn debug-mode risk conditional on how the flag is wired up, plus a concrete env-var-based fix
- Auth bypass finding: hit a transient `504 DEADLINE_EXCEEDED` — **fallback logic worked correctly**, returned original static finding rather than crashing

**Session 4 status: FUNCTIONALLY PROVEN.** Real LLM-generated output confirmed high quality and technically sound. The one timeout is expected transient API behavior, not a defect — worth re-running before final demo recording to get a full 3/3, but the core capability is validated.

**Second validation run:** Re-ran the sanity script. Different finding timed out this time (config_audit, not ast_rules) — confirms the 504s are transient/random, not tied to a specific finding or prompt. The two that succeeded this run were high quality again, and notably the auth-bypass finding's confidence was updated from 0.84 → 1.00 by the AI (exceeds the 0.15 threshold), with a clear justification: "highly exploitable... attacker simply needs to include the header." **This confirms the confidence-update logic works correctly in a real run, not just in mocked tests.** Across two runs, 4 of 6 total calls succeeded with strong output; the 2 timeouts both triggered the fallback path correctly with no crashes.

**Recommendation:** run the sanity script 1-2 more times before final demo recording to build confidence in the timeout rate, and consider adding a simple retry-once-on-timeout wrapper in Session 5 or as a polish item, since a live demo hitting a 504 mid-recording would be an avoidable annoyance.

**Follow-up — timeout retry added:** Implemented single-retry logic for Gemini 504/DEADLINE_EXCEEDED specifically (not other error types — auth/quota/malformed JSON still fail straight to fallback, correctly). Test confirms exactly 2 attempts on timeout then correct fallback if both fail. Suite: `13 passed`. This reduces (doesn't eliminate) the chance of a visible timeout during live demo recording.

**Session ID:** 019f5e9e-7a0d-7401-b0e9-ede38d28bb6b

**Note for demo video narration:** the OpenAI→Gemini pivot is a good, honest engineering story to include — shows resourcefulness under a real constraint (Codex-only credits), not a shortcut. Mention that Codex was used throughout the build and that the provider abstraction keeps GPT-5.6 swap-in-ready.

---

### Session 5 — [DATE:July 17, 2026{WAT}] — Remediation Engine (Tier 1 auto-fix + Tier 2 approval)

**Prompt summary:** Implemented the tiered remediation engine per Technical Spec Section 5 — tier classification, deterministic patch generation for Tier 1, AI-assisted proposal diffs for Tier 2, guidance-only Tier 3, syntax verification, and the safety-critical isolated-branch/no-direct-main-write rule.

**What Codex built:**
- [x] `app/remediation/` — tier classification, patch generation, state transitions, syntax verification
- [x] Tier 1 deterministic templates: hardcoded secrets → env var, DEBUG=True → False, wildcard CORS → explicit origins, typosquatted dependency swap, .env/.gitignore coverage
- [x] Tier 2: AI-assisted proposal diffs for auth bypass and dynamic-execution backdoors — marked pending_approval, never auto-applied
- [x] Tier 3: guidance-only, returns HTTP 422 on remediation attempt (correctly refuses to fabricate a fix for network/install-script findings)
- [x] Verification: Python `ast.parse` + JS/TS bracket/quote syntax checks before any branch/PR action
- [x] **Safety rule enforced with a real isolated Git worktree** — branch named `sentinel-fix/{scan_id}/{finding_id}`, default checkout never touched, confirmed by a dedicated test (not just documented, actually verified)
- [x] API endpoints: `POST /findings/{id}/remediate`, `POST /remediations/{id}/approve`, `GET /remediations/{id}`
- [x] OAuth token decryption validated before PR publishing step
- [x] Tests: 29 passed, using real vulnerable-demo-app fixtures (Stripe key, config, typosquat, auth backdoor) — not just synthetic test data

**Intentionally stubbed:**
- **GitHub branch push + PR creation API call — TODO, not yet implemented.** OAuth token is retrieved/decrypted correctly, but no remote GitHub API request is made yet. A remediation currently cannot reach `pr_opened` status — it records a clear, safe failure note after local branch preparation instead of pretending to succeed.

**This is the critical path item for the demo** — "auto-fix opens a real PR" and "approve backdoor fix → PR opens" are the core demo moments and both depend on this piece. Follow-up session needed to implement real GitHub API push/PR creation before this can be demoed end-to-end.

**Follow-up — real GitHub PR integration completed:**
- Pushes only the isolated `sentinel-fix/{scan_id}/{finding_id}` branch via ephemeral authenticated Git header — default branch never touched
- Opens real PR via `POST /repos/{owner}/{repo}/pulls` with finding description, AI explanation, and an explicit "generated by Sentinel AI, review before merging" warning in the PR body
- On success: stores GitHub's real `html_url`, sets status `pr_opened`
- On failure (auth/permission/rate-limit/push/network): status `failed` with safe stored error message — if branch push succeeds but PR creation fails, the remote branch is deliberately left in place for inspection rather than silently cleaned up
- **OAuth scope change:** now requests `repo` scope for new authorizations — **existing OAuth connections (including any made during earlier testing) must re-authorize** to get PR-creation permission
- Mocked tests for success/failure/status paths + a manual disposable-repo smoke test script
- Suite: `32 passed`, compile check passed
- Known limitation: GitHub Cloud only (github.com/api.github.com) — GitHub Enterprise not yet configurable (fine for MVP scope)

**Session 5 status: COMPLETE.**

**Post-frontend bug #1 — repository snapshot unavailable at remediation time:** Discovered via real UI testing that "Auto-fix" failed with "Repository snapshot is unavailable" — the scan-time repo clone wasn't available anymore when remediation was requested as a separate later action. Fixed by re-cloning on-demand using the stored OAuth token when no snapshot exists, reusing the existing snapshot when still present, with proper cleanup in both paths (including a Windows-specific fix for read-only Git object file cleanup). Frontend also updated to surface remediation failure reasons visibly instead of a bare "failed" badge — good UX fix independent of the root cause.

**Post-frontend bug #2 — default branch assumption fixed:** Discovered that ingestion hardcoded "main" as the branch to clone, failing on repos using "master" or other default branch names. Fixed properly: project import now queries GitHub's real `default_branch` via API and stores it; ingestion refreshes this before every clone (self-correcting older imports) and clones the actual stored branch, not an assumption. Added exact-repository-only metadata client (no enumeration). Suite: 24 passed, including mocked master-branch tests.

**Note:** Real live validation of the branch fix against `ventech2/vulnerable-demo-app` pending — requires re-authenticating GitHub OAuth against the new Neon database (migrated from local Postgres mid-build, so the OAuth token isn't present in the new DB yet).

**Re-verified via real UI-triggered API calls (not just a manual script):**
- Stripe key finding → [PR #2](https://github.com/ventech2/sentinel-test-repo/pull/2), `pr_opened`
- DEBUG=True finding → [PR #3](https://github.com/ventech2/sentinel-test-repo/pull/3), `pr_opened`
- Both passed syntax verification, used isolated branches, `main` untouched
- Suite: 22 passed (remediation + ingestion cleanup tests, including on-demand clone success/failure paths)

**This is strong evidence for the demo:** the full flow now works exactly as a judge would experience it — import repo → scan → click Auto-fix in browser → real PR appears on GitHub — no scripts, no manual intervention. Full remediation flow now implemented end-to-end: tier classification → fix generation → verification → isolated branch → real GitHub PR. Real-repo validation against the actual GitHub PR flow still pending (needs OAuth re-auth + a disposable test repo) — this is the next concrete step before demo rehearsal.

**LIVE END-TO-END PROOF ACHIEVED:** Re-authorized GitHub OAuth with `repo` scope against real account (`ventech2`). Created disposable test repo `ventech2/sentinel-test-repo` with a planted Stripe-style key. Ran the real smoke test end-to-end:
- Finding detected: Stripe-style key in `app.py:3`
- Tier 1 fix generated, Python AST verification passed
- Isolated branch pushed: `sentinel-fix/{scan_id}/{finding_id}`
- **Real PR opened and confirmed live:** https://github.com/ventech2/sentinel-test-repo/pull/1
- PR body correctly states "Sentinel AI never merges this change automatically" and includes the finding description
- Confirmed: default `main` branch untouched, only the isolated fix branch was created

**This is the single strongest proof point in the entire build so far** — a real, externally-verifiable artifact (a live GitHub PR) demonstrating the complete value proposition: detect → generate fix → verify → open PR for human review. This PR link itself is worth showing directly in the demo video.

**Session ID:** 019f5e9e-7a0d-7401-b0e9-ede38d28bb6b

---

### Session 6 — [DATE:July 17, 2026{WAT}] — Orchestrator (scan job lifecycle)

**Prompt summary:** Built the orchestrator wiring together repository ingestion, all 6 detector modules (5 core + JS/TS pattern extension), the AI Reasoning Layer, and finding persistence — replacing the 501-stub routes from Session 1 with real end-to-end scan logic, per Technical Spec Sections 1.2/3.2.

**What Codex built:**
- [x] `ingestion.py` — OAuth-authenticated repo cloning, size limits, text-file inventory, language detection, plus a development-only local-fixture mode (for testing against `sample-data/vulnerable-demo-app` without needing a real GitHub clone each time)
- [x] `orchestrator.py` — full lifecycle: clone → static scan → AI review → merge/persist/report → complete/failed
- [x] Redis queue (`sentinel:scan-jobs`) + Pub/Sub live events (`sentinel:scan:{id}:events`)
- [x] Separate worker process (`scan_worker.py`) — decouples scan execution from the API request/response cycle
- [x] Real routes replacing 501 stubs: `POST /projects/{id}/scans`, `GET /scans/{id}`, `GET /scans/{id}/findings`, `WS /scans/{id}/live`
- [x] All 6 detectors run, findings enriched via AI Reasoning Layer, persisted with correct `scan_id` linkage
- [x] WebSocket messages: JSON with `type: "status"` or `type: "finding"`
- [x] Resilience: Redis delivery failures don't fail the scan — DB remains source of truth for polling; a detector throwing an error doesn't crash the whole scan
- [x] Tests: 34 passed, including a fixture-based integration test running the full pipeline against real detector output
- [x] HTTP-only end-to-end smoke script (`http_scan_smoke_test.py`) — tests through the real API, not internal function calls directly; supports pointing at the local vulnerable-demo-app fixture via `INGESTION_LOCAL_REPOSITORY_ROOT`

**Judgment call flagged:** Redis queue is deliberately simple (at-most-once list-based) for MVP — a crashed worker could leave a job unfinished with no automatic retry. Acceptable for hackathon scope; noted as a production hardening item for roadmap.

**Open item:** ingestion currently restricts to public repos only (per original PRD scope). Follow-up decision made to relax this — see below.

**Follow-up — private repo support added:** Removed the public-only restriction. Ingestion clones only the specific project the authenticated user selected, using that user's own stored OAuth token — never lists, searches, or probes other repos on the account. If GitHub denies access (no permission), it surfaces as a clear `Repository clone failed` error and the scan status becomes `failed` — no pre-emptive blocking. This correctly reframes the original "public-only" MVP restriction: the real safety boundary is "only the user-selected repo, via the user's own authorized token," not "public repos only." Suite still passes: 34/34.

### Session 7 — [DATE:July 17, 2026] — Report Generation

**Prompt summary:** Implemented the Report Service that merges persisted, AI-enriched findings into a final report — risk scoring, executive summary, and Markdown export — wired into the orchestrator's "merging" lifecycle stage.

**What Codex built:**
- [x] `report_service.py` — creates `reports` rows from persisted findings
- [x] Orchestrator calls report generation during `merging`, before scan reaches `complete`
- [x] `GET /scans/{id}/report` — summary, risk score, severity counts, full findings list with each finding's latest remediation status
- [x] `GET /scans/{id}/report/export` — Markdown file generated to `exports/`, returned as download
- [x] HTTP smoke script extended to print final risk score, summary, severity counts
- [x] Tests: 36 passed (up from 34)

**Risk formula (documented in export itself, not just code):**
`min(100, Σ(severity_weight × confidence))`, rounded to 1 decimal
- Critical: 35 | High: 18 | Medium: 8 | Low: 3 | Info: 0
- One high-confidence critical = 35; five high-confidence lows = 15 — critical findings deliberately dominate the score

**Key decision — deterministic executive summary, not LLM-generated:** Explicitly avoided asking an LLM to write the summary, to prevent it from inventing or editorializing beyond persisted findings. Summary is templated: scan scope, counts, score, highest-priority existing finding only. Consistent with the "AI never introduces new findings" principle established in Session 4 — good architectural consistency across sessions.

### Session 8 — [DATE:July 18, 2026{WAT}] — Prompt Injection + Unsafe Model Deserialization Detectors

**Prompt summary:** Added two new detectors addressing current AI-era security pain points identified mid-build: prompt injection (untrusted input flowing into LLM calls) and unsafe model deserialization (pickle/torch/joblib supply-chain risk). Explicitly excluded data-poisoning and weight-manipulation detection as out of scope for a code/repo scanner.

**What Codex built:**
- [x] `prompt_injection_rules.py` — Python AST flow analysis tracking function/request/env-derived input reaching known LLM calls (OpenAI, Anthropic, Gemini SDK patterns); JS/TS regex equivalent for SDK calls and fetch/Axios LLM API requests
  - Category: `prompt_injection_risk`, severity `medium`, confidence: Python 0.62, JS/TS 0.55 (deliberately moderate — framed as "review recommended," not confirmed exploit)
  - Skips flows passing through sanitizer/validator-named functions, but honestly notes static analysis can't verify a sanitizer is actually sufficient
- [x] `model_security_rules.py` — flags `pickle.load`/`pickle.loads` (high, 0.94), `torch.load` without `weights_only=True` (medium, 0.67), `joblib.load` on dynamic/model-like artifacts (medium, 0.72)
  - Fix suggestions: safetensors format, artifact integrity validation, `weights_only=True`
  - Explicitly does NOT inspect model weights or training data — correctly scoped to code-level supply-chain risk only, not data-poisoning/weight-manipulation
- [x] Both wired into the orchestrator — **now 8 total static detectors** in the standard scan pipeline
- [x] Test fixtures + tests for both: suite now `39 passed`

**Ambiguities Codex flagged:** prompt injection is intrinsically noisy — the detector recognizes obvious source-to-prompt flows but can't prove a sanitizer is sufficient, only that one exists syntactically. JS/TS remains regex-based (consistent with the earlier `js_pattern_rules.py` scope decision), not full AST parsing.

**Session 8 status: COMPLETE.** Good example of scope discipline — added the two detectors that genuinely fit the architecture (code-level, static, deterministic) while explicitly declining data-poisoning/weight-manipulation, which require fundamentally different analysis (dataset/model-internals inspection) outside a repo scanner's scope. This distinction is worth stating clearly in the demo if asked about "AI security" broadly — shows deliberate scoping, not a gap.

**Still pending:** real-repo validation — add a planted prompt-injection example and an unsafe pickle.load example to `sample-data/vulnerable-demo-app` and confirm both are caught in an actual end-to-end scan, same rigor as Sessions 2-3.

**Session ID:** 019f5e9e-7a0d-7401-b0e9-ede38d28bb6b

---

### Session 9 — [DATE:July 18, 2026{WAT}] — Frontend (Next.js)

**Prompt summary:** Built the Next.js frontend under /frontend with Tailwind and local shadcn-style UI primitives — Login, Dashboard, Live Scan, and Report pages, connected to the real backend API via REST + WebSocket.

**What Codex built:**
- [x] Login page — GitHub OAuth entry point
- [x] Dashboard page — repository import, project list, scan launch
- [x] Live scan page — WebSocket-driven stage timeline + live finding cards as they're detected
- [x] Report page — risk score, severity groups, AI explanations, export, tiered remediation action buttons (Tier 1 auto-fix, Tier 2 approve, Tier 3 flagged-only)
- [x] API client + WebSocket URL handling (`lib/api.ts`)
- [x] OAuth browser handoff completed — backend callback now redirects to `FRONTEND_URL/dashboard` after creating the session (real end-to-end browser login flow, not just API-level)
- [x] State management: route-local React state, REST for durable state, WebSocket triggers immediate updates — no polling

**Validation:**
- Frontend TypeScript check: no source errors
- Next.js compiled all route entries (background build worker terminated before writing BUILD_ID in this workspace — noted as an environment limitation, not a code defect; worth confirming a clean production build locally)
- Backend compilation succeeded
- Minor known issue: `test_orchestrator.py` has a stale line-number assertion (expects Stripe key at line 41, actual is now line 42 after later file edits) — cosmetic test fixture mismatch, not a functional bug, left unfixed pending a quick follow-up

**Deployment note flagged:** `NEXT_PUBLIC_API_URL`, backend `ALLOWED_ORIGINS`, and backend `FRONTEND_URL` must be configured together and consistently — important to get right before final deployment/hosting for the demo.

**Session 9 status: FUNCTIONALLY COMPLETE, pending real browser walkthrough.** This is the biggest usability unlock in the build — the full detect → explain → fix flow can now be demoed through an actual UI in a browser, not just API calls/scripts.

**Session ID:** 019f5e9e-7a0d-7401-b0e9-ede38d28bb6b

---

### Session 10 — [DATE:July 18, 2026{WAT}] — Landing Page

**Prompt summary:** Built a public "deep tech" landing page at the root route, separate from the existing dashboard — hero, product flow, detector capability cards, and CTA to login, matching the existing dark/technical design language.

**What Codex built:**
- [x] Dark technical grid background, monospace data accents, sharp-edged panels, restrained sky-blue accent color
- [x] Hero: Sentinel AI wordmark, "Security, before your next deploy" tagline, product summary, `/login` CTA
- [x] 3-step product flow visual: import repo → AI-powered scan → reviewable fixes
- [x] 8 detector capability cards (one per detector category)
- [x] Repeated footer CTA
- [x] Subtle entrance motion **with reduced-motion support** — good accessibility detail
- [x] Route structure: `/` (new landing), `/login`, `/dashboard`, `/scans/[scanId]`, `/scans/[scanId]/report` — existing pages untouched
- [x] TypeScript validation passed

**Session 10 status: COMPLETE.** Good first impression now in place for judges landing on the deployed URL — matches the product's "credible security tooling" positioning rather than generic SaaS aesthetics.

**Session ID:** 019f5e9e-7a0d-7401-b0e9-ede38d28bb6b

---

---

## Production Deployment (Post-Session-10)

Deployed to Vercel (frontend), Railway (backend API + worker, two services), Neon (Postgres), Upstash (Redis).

**Live URL:** https://sentinel-ai-omega-peach.vercel.app
**Backend API:** https://sentinel-ai-production-bf22.up.railway.app

**Bugs found and fixed via real production testing (not caught by local dev or unit tests):**

1. **Missing `NEXT_PUBLIC_API_URL` on Vercel** — field appeared to have a value but was actually showing unset placeholder text (`https://api.example.com`), causing every API call from the deployed frontend to fail silently as "Failed to fetch." Root cause of the login-loop issue diagnosed as several other things first (OAuth redirect URI, cross-domain cookies) before finding the real cause. Fix: explicitly set the real Railway URL and redeployed (required since `NEXT_PUBLIC_` vars are baked in at Next.js build time).

2. **GitHub OAuth redirect URI mismatch** — `GITHUB_REDIRECT_URI` on Railway still pointed at `localhost` after the GitHub OAuth App's registered callback URL was updated to production. Fixed by syncing both to the same Railway URL.

3. **Cross-domain session cookies** — frontend (Vercel) and backend (Railway) are on different domains, so session cookies weren't being sent/accepted by default. Fixed: `SameSite=None`, `Secure=true`, confirmed `allow_credentials=True` on CORS and `credentials: "include"` on frontend fetch calls (the last two were already correct).

4. **`git` CLI missing in Railway's runtime container** — ingestion/remediation both shell out to `git`, which isn't installed by default in Railway's Python container. Fixed via `railpack.json` with `"deploy": {"aptPackages": ["git"]}`.

5. **Git commit author identity missing in fresh containers** — remediation commits failed with "Author identity unknown" since the container has no global git config. Fixed by passing `-c user.name=... -c user.email=...` explicitly per-command for remediation commits only (Sentinel AI <sentinel-ai@noreply.github.com>) — doesn't depend on or mutate global git config, safe for any fresh container.

**Full production validation achieved:** live end-to-end scan against `ventech2/vulnerable-demo-app` through the real deployed URL — 10 real findings (2 critical, 7 high, 1 medium), real AI reasoning on every finding, risk score 100/100 correctly calculated, Tier 1 Auto-fix and Tier 2 Approve-fix both functional in production.

---

## Core `/feedback` Session ID for submission

The session where the majority of core functionality (detection pipeline + remediation engine) was built, most likely Sessions 2–5 combined, representative of the core build.

**Selected Session ID for submission:** 019f5e9e-7a0d-7401-b0e9-ede38d28bb6b
**Why this one:** 
I pick this core funtionality because detection pipline act as sensory system i.e finding threat. the live progress tracker from processing respository - static code analysis to AI Scaning shows the backend is executing a delibarate pipeline rather than just runing a single generic script and remediation engine act as motor system that fix the threat, targeted code isolation where the engine doesn't just write the whole file; it generates a highly targeted git diff (+ and - lines) isolating the exact vunerablility block. This is crucial for developer trust.
