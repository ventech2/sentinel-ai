# Sentinel AI
**An AI-native security scanner that detects — and fixes — vulnerabilities and backdoors in AI-generated ("vibe-coded") codebases.**

Built for OpenAI Build Week 2026 · Track: Developer Tools

---

## What it does

Sentinel AI scans a GitHub repository and:
1. **Detects** hardcoded secrets, insecure configs, risky dependencies, and backdoor patterns (obfuscated `eval`/`exec`, hidden auth bypasses, suspicious outbound calls) using static analysis + AST parsing.
2. **Explains** each finding in plain language with a severity score and confidence level, using **GPT-5.6**.
3. **Fixes** what it finds:
   - Low-risk issues (secrets, bad config, bad dependencies) are auto-patched and opened as a pull request.
   - Higher-risk findings (backdoors, auth bypasses) get a generated fix that you review and approve with one click before a PR is opened.

Sentinel never pushes directly to your default branch — every fix, even auto-generated ones, lands as a reviewable PR.

---

## How Codex and GPT-5.6 were used

- **Codex** was used as the primary build agent for this project — scaffolding the FastAPI backend, the detection pipeline modules, and the remediation diff-generation logic. See `/docs/codex-build-notes.md` for a breakdown of what Codex generated vs. what we hand-tuned (e.g. entropy thresholds for secret detection, AST rules for auth-bypass heuristics).
- **GPT-5.6** powers two live parts of the running product:
  - The **AI Reasoning Layer**, which explains and scores each static/backdoor finding
  - The **Remediation Engine**, which generates the proposed fix diffs
- `/feedback` Codex Session ID: `[INSERT SESSION ID HERE]`

---

## Try it live

- **Hosted demo:** `[INSERT DEPLOYED URL HERE]`
- **Test account:** `[INSERT TEST LOGIN / SANDBOX ACCESS HERE]` — no setup required, judges can scan the sample repo below immediately.

---

## Running it locally

### Prerequisites
- Node.js 20+
- Python 3.11+
- PostgreSQL 15+
- Redis 7+
- An OpenAI API key (GPT-5.6 access)

### Setup

```bash
# Clone
git clone https://github.com/[your-org]/sentinel-ai.git
cd sentinel-ai

# Backend
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # add your OPENAI_API_KEY, DATABASE_URL, REDIS_URL
alembic upgrade head    # run DB migrations
uvicorn main:app --reload

# Frontend
cd ../frontend
npm install
cp .env.example .env.local   # add NEXT_PUBLIC_API_URL, GitHub OAuth client ID
npm run dev
```

App runs at `http://localhost:3000`, API at `http://localhost:8000`.

### Environment variables

| Variable | Location | Description |
|---|---|---|
| `OPENAI_API_KEY` | backend `.env` | GPT-5.6 access for Reasoning Layer + Remediation Engine |
| `DATABASE_URL` | backend `.env` | PostgreSQL connection string |
| `REDIS_URL` | backend `.env` | Job queue |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | backend `.env` | GitHub OAuth |
| `NEXT_PUBLIC_API_URL` | frontend `.env.local` | Backend API base URL |

---

## Sample data for testing

We include an intentionally vulnerable sample repository at `/sample-data/vulnerable-demo-app` containing real, verifiable issues Sentinel AI is built to catch:
- A hardcoded API key
- A `DEBUG=True` production config with wildcard CORS
- A typosquatted dependency in `package.json`
- An obfuscated `eval(atob(...))` backdoor payload
- A hardcoded auth-bypass conditional

To test: import `https://github.com/[your-org]/vulnerable-demo-app` (or the local copy in `/sample-data`) via the dashboard's "Import Repository" flow, and trigger a scan.

---

## Supported platforms

- Web app: any modern browser (Chrome, Firefox, Safari, Edge)
- Backend: Linux/macOS (tested on Ubuntu 22.04 and macOS 14)
- Deployment: Vercel (frontend), Railway (backend), Neon (PostgreSQL)

---

## Architecture

See `/docs/SENTINEL_AI_TECHNICAL_SPEC.md` for full system architecture, database schema, API reference, and the remediation engine design.

---

## Project structure

```
sentinel-ai/
├── backend/
│   ├── app/
│   │   ├── detectors/          # static detection modules
│   │   ├── backdoor/           # backdoor heuristics module
│   │   ├── reasoning/          # GPT-5.6 AI Reasoning Layer
│   │   ├── remediation/        # fix generation + PR flow
│   │   ├── models/             # SQLAlchemy models
│   │   └── main.py
│   ├── alembic/                # DB migrations
│   └── requirements.txt
├── frontend/
│   ├── app/                    # Next.js app router pages
│   ├── components/
│   └── package.json
├── sample-data/
│   └── vulnerable-demo-app/    # intentionally vulnerable test repo
├── docs/
│   ├── SENTINEL_AI_PRD.md
│   ├── SENTINEL_AI_TECHNICAL_SPEC.md
│   └── codex-build-notes.md
└── README.md
```

---

## License
[Insert license — MIT recommended for hackathon submissions requiring public repos]

---

## Team
[Insert team names / roles]
