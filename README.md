# Sentinel AI
**An AI-native security scanner that detects — and fixes — vulnerabilities and backdoors in AI-generated codebases.**

Built for OpenAI Build Week 2026 · Track: Developer Tools

---

## What it does

Sentinel AI scans a GitHub repository and:
1. **Detects** hardcoded secrets, insecure configs, risky/typosquatted dependencies, backdoor patterns (obfuscated `eval`/`exec`, shell execution fed by decoded payloads, hidden auth bypasses, suspicious outbound network calls), prompt injection risk, and unsafe model deserialization (`pickle.load`, unsafe `torch.load`) — using 8 deterministic static detectors, no hallucination risk.
2. **Explains** each finding in plain language with a severity score, confidence level, and exploitability assessment, using an LLM reasoning layer.
3. **Fixes** what it finds, with tiered autonomy:
   - **Tier 1** (secrets, bad config, typosquatted dependencies): auto-patched and opened as a real GitHub pull request.
   - **Tier 2** (auth bypasses, obfuscated backdoors): a fix is generated and shown as a diff — you approve it with one click before a PR opens.
   - **Tier 3** (suspicious network calls, risky install scripts): flagged with guidance only — Sentinel doesn't guess at a fix for findings with high false-positive risk.

Sentinel never pushes directly to your default branch — every fix, even auto-generated ones, lands as a reviewable PR on an isolated branch.

---

## How Codex and GPT-5.6 were used

- **Codex** was the primary build agent for this entire project — used across 10 build sessions to scaffold the FastAPI backend, all 8 detection modules, the AI reasoning layer, the tiered remediation engine, the scan orchestrator, the Next.js frontend, and the landing page. See `codex-build-notes.md` for a session-by-session breakdown of what Codex built, key decisions, and places we redirected its first attempt (e.g. the remediation engine's first version applied fixes directly to the default branch — we had it rebuilt to always use an isolated branch + PR instead).
- **GPT-5.6** was the intended runtime provider for the AI Reasoning Layer and Remediation Engine. During the build, OpenAI API credits for this hackathon were confirmed by organizers to be Codex-only (no separate API credit pool) — so the runtime AI calls currently use **Google's Gemini API** (`gemini-3-flash-preview`) behind the same structured-output contract. The reasoning/remediation code has a provider abstraction and can be pointed back at GPT-5.6 with a config change and no code changes, once API access is available.
- `/feedback` Codex Session ID: `[INSERT SESSION ID HERE]`

---

## Try it live

- **Hosted demo:** `https://sentinel-ai-omega-peach.vercel.app`
- **Test account:** judges can sign in with their own GitHub account via the login flow — no pre-provisioned test account needed, since scans run against a repository you choose.
- **Known limitation:** the frontend (Vercel) and backend (Railway) are on different domains, so sign-in relies on a cross-domain session cookie. This works reliably in standard browser windows, but some browsers' strict privacy modes (e.g. Chrome Incognito, Safari's default tracking protection) block third-party cookies by default and may prevent sign-in from persisting. **Please test in a regular (non-private) browser window** for the smoothest experience.

---

## Running it locally

### Prerequisites
- Node.js 20+
- Python 3.11+ (tested on 3.13)
- PostgreSQL 15+ (or a free hosted instance — we used [Neon](https://neon.tech))
- Redis 7+ (or a free hosted instance — we used [Upstash](https://upstash.com), TLS/`rediss://` required)
- A Google Gemini API key ([aistudio.google.com](https://aistudio.google.com), free tier, no credit card) — or an OpenAI API key with GPT-5.6 access, if available to you
- A GitHub OAuth App ([github.com/settings/developers](https://github.com/settings/developers)) — callback URL `http://localhost:8000/auth/github/callback` for local dev

### Setup

```bash
# Clone
git clone https://github.com/ventech2/sentinel-ai.git
cd sentinel-ai

# Backend
cd backend
python -m venv venv
venv\Scripts\activate          # Windows — use `source venv/bin/activate` on macOS/Linux
pip install -r requirements.txt
copy .env.example .env         # Windows — use `cp` on macOS/Linux
# Edit .env: set DATABASE_URL, DATABASE_URL_SYNC, REDIS_URL, GEMINI_API_KEY,
# GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, OAUTH_TOKEN_ENCRYPTION_KEY, SESSION_SECRET
alembic upgrade head
uvicorn app.main:app --reload

# In a second terminal — the scan worker (required, scans run asynchronously)
cd backend
venv\Scripts\activate
python -m app.workers.scan_worker

# In a third terminal — the frontend
cd frontend
npm install
copy .env.example .env.local
# Edit .env.local: set NEXT_PUBLIC_API_URL=http://localhost:8000
npm run dev
```

App runs at `http://localhost:3000`, API at `http://localhost:8000`. Both the API server and the worker process must be running for scans to complete — the worker consumes the Redis queue the API enqueues jobs onto.

### Key environment variables

| Variable | Location | Description |
|---|---|---|
| `DATABASE_URL` / `DATABASE_URL_SYNC` | `backend/.env` | Postgres connection (async + sync driver variants — see `.env.example` for the exact `+asyncpg` / `+psycopg` and `ssl`/`sslmode` formatting) |
| `REDIS_URL` | `backend/.env` | Scan job queue (use `rediss://` if your provider requires TLS, e.g. Upstash) |
| `GEMINI_API_KEY` | `backend/.env` | Powers the AI Reasoning Layer and Remediation Engine (current default provider) |
| `OPENAI_API_KEY` | `backend/.env` | Alternate provider — set `AI_REASONING_PROVIDER=openai` to use GPT-5.6 instead of Gemini, if you have API access |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | `backend/.env` | GitHub OAuth App credentials |
| `OAUTH_TOKEN_ENCRYPTION_KEY` | `backend/.env` | Fernet key encrypting stored GitHub tokens — generate with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `SESSION_SECRET` | `backend/.env` | Long random string for session signing |
| `NEXT_PUBLIC_API_URL` | `frontend/.env.local` | Backend API base URL |

---

## Sample data for testing

`backend/sample-data/vulnerable-demo-app` is an intentionally vulnerable FastAPI sample app containing 9 real, planted issues Sentinel AI is built to catch — see that folder's own `VULNERABILITIES.md` for the full list with exact line numbers and expected detectors. It covers: a hardcoded Stripe-style secret, `DEBUG=True` and wildcard CORS (both in application code and in a committed `.env`), a hardcoded auth-bypass conditional, a base64-decoded shell-execution backdoor, a hardcoded-IP network beacon, a typosquatted dependency, prompt injection, and unsafe `pickle.load()` deserialization.

To test: push this folder to its own GitHub repository (or use our public copy, if provided), then import it via the dashboard's "Import repository" flow and trigger a scan.

---

## Supported platforms

- Web app: any modern browser (Chrome, Firefox, Safari, Edge)
- Backend: developed and tested on Windows 10/11; should run on Linux/macOS with the same setup steps (adjust shell commands accordingly)
- Deployment target: Vercel (frontend), Railway (backend), Neon (PostgreSQL), Upstash (Redis) — `[deployment status: in progress]`

---

## Architecture

See `SENTINEL_AI_TECHNICAL_SPEC.md` for full system architecture, database schema, API reference, and the remediation engine's tiered-safety design. See `codex-build-notes.md` for the session-by-session build log, including bugs found through real end-to-end testing (not just unit tests) and how each was fixed.

---

## Project structure

```
sentinel-ai/
├── README.md
├── SENTINEL_AI_PRD.md
├── SENTINEL_AI_TECHNICAL_SPEC.md
├── DEMO_VIDEO_SCRIPT.md
├── codex-build-notes.md
├── backend/
│   ├── app/
│   │   ├── api/routes/         # auth, projects, scans, findings, remediations, reports
│   │   ├── detectors/          # 8 static detectors (secrets, config, dependencies,
│   │   │                       #   AST rules, JS/TS patterns, backdoor heuristics,
│   │   │                       #   prompt injection, model deserialization)
│   │   ├── reasoning/          # AI Reasoning Layer (Gemini/OpenAI provider abstraction)
│   │   ├── remediation/        # tier classification, fix generation, GitHub PR flow
│   │   ├── services/           # ingestion, orchestrator, GitHub OAuth/repo metadata
│   │   ├── models/             # SQLAlchemy models
│   │   ├── workers/            # async scan worker (consumes the Redis queue)
│   │   └── main.py
│   ├── alembic/                # DB migrations
│   ├── sample-data/
│   │   └── vulnerable-demo-app/  # intentionally vulnerable test repo, 9 planted issues
│   ├── scripts/                # manual smoke-test scripts (AI reasoning, GitHub PR, full HTTP scan)
│   ├── tests/
│   └── requirements.txt
├── frontend/
│   ├── app/                    # Next.js app router: landing page, login, dashboard,
│   │                           #   live scan view, report view
│   ├── components/
│   └── package.json
```

---

## License
MIT — see `LICENSE` for full text.

---

## Team
Solo build.
