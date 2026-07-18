# Planted Vulnerabilities — Reference Sheet

This document lists every intentional vulnerability in this demo app, for internal use when testing and demoing Sentinel AI. **Do not include this file's "answer key" framing in judge-facing materials if you want the live detection to feel unscripted** — but it's fine to reference during rehearsal.

| # | Vulnerability | Location | Expected Detector | Expected Tier | Confidence |
|---|---|---|---|---|---|
| 1 | Insecure config: `DEBUG=True` (source code) | `app/main.py:26` | `config_auditor.py` | Tier 1 (auto-fix) | 0.90 |
| 1b | Insecure config: wildcard CORS | `app/main.py:30` | `config_auditor.py` | Tier 1 (auto-fix) | 0.92 |
| 2 | Hardcoded secret (Stripe-shaped API key) | `app/main.py:41` | `secret_scanner.py` | Tier 1 (auto-fix) | 0.98 |
| 3 | Hardcoded auth-bypass conditional | `app/main.py:69`, `verify_admin()` | `ast_rules.py` | Tier 2 (approve-and-fix) | 0.84 |
| 4 | Obfuscated backdoor: base64-decoded payload executed via `subprocess.run(..., shell=True)` | `app/main.py:97`, `health_check()` | `ast_rules.py` | Tier 2 (approve-and-fix) | 0.95 |
| 5 | Typosquatted dependency (`requessts` vs `requests`) | `requirements.txt:10` | `dependency_auditor.py` | Tier 1 (auto-fix) | 0.86 |
| 6 | `.env` committed to version control, `.gitignore` doesn't exclude it | `.env:1` | `config_auditor.py` | Tier 1 (auto-fix) | 0.88 |
| 6b | `DEBUG=True` inside the committed `.env` | `.env:7` | `config_auditor.py` | Tier 1 (auto-fix) | 0.90 |
| 7 | Suspicious outbound network call: hardcoded-IP beacon on startup | `app/main.py:113`, `_report_usage_metrics()` | `backdoor_heuristics.py` | Tier 3 (flagged only, no auto-fix) | 0.68 |
| 8 | Prompt injection: unsanitized user input concatenated directly into an LLM prompt | `app/main.py:134`, `summarize_task()` | `prompt_injection_rules.py` | Tier 3 (flagged only, no auto-fix — review recommended) | ~0.62 |
| 9 | Unsafe model deserialization: `pickle.load()` on an attacker-controllable file path | `app/main.py:151`, `load_model()` | `model_security_rules.py` | Tier 2 (approve-and-fix) | ~0.94 |

**Note:** vulnerabilities #8 and #9 were added in Session 8 (new detector types) — not yet included in a confirmed real-repo end-to-end scan. Run the full scan against this repo once more to confirm actual detected line numbers/confidence match what's listed here, then update this table with real output, same as #1-7.

## Rehearsal notes
- Vulnerability #4 (the obfuscated backdoor) is your strongest demo moment — walk through it slowly in the video: show the encoded payload, then Sentinel AI's decoded explanation, then the approval click.
- Vulnerability #3 (auth bypass) is a good second Tier 2 example if you have time for two approve-and-fix moments.
- Vulnerability #7 (network beacon) is your Tier 3 example — flagged with an honest "review required, not auto-fixed" message. Good to show judges the system knows its own limits: not every finding gets a one-click fix.
- Vulnerabilities #1, #1b, #2, #5, #6 are your Tier 1 auto-fix montage — these should resolve in seconds and are the "wow, it just fixed it" beat.
- Vulnerability #9 (unsafe pickle load) is a strong second Tier 2 example, and a good one to mention specifically if a judge asks about "AI-era" security — it's a real, well-known ML supply-chain risk (malicious pickle files execute arbitrary code on load), distinct from your other backdoor examples.
- Vulnerability #8 (prompt injection) is your other Tier 3 example alongside #7 — good to show two different "flagged, not auto-fixed" cases with different underlying reasons (network ambiguity vs. prompt-sanitization ambiguity).
- Test the full scan-to-fix flow against this exact repo at least 3 times before recording, to confirm consistency.
