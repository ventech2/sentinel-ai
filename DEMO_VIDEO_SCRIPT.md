# Sentinel AI — Demo Video Script (Target: 2:45–2:55)

Public YouTube, unlisted-but-public or public. Must include narrated audio covering Codex + GPT-5.6 usage per submission requirements.

---

## [0:00–0:15] Hook + Problem
**Visual:** Title card, then a quick montage of AI coding assistant UIs (Copilot/Cursor-style) generating code.

**Narration:**
"AI coding tools ship an enormous amount of code today — and that code carries a predictable set of risks: hardcoded secrets, broken auth logic, and even hidden backdoors. Sentinel AI is a security scanner built specifically for AI-generated codebases — and unlike most tools, it doesn't just find these problems. It fixes them."

---

## [0:15–0:35] What it is / Track fit
**Visual:** Dashboard home screen.

**Narration:**
"This is Sentinel AI, built for OpenAI Build Week in the Developer Tools track. It scans a GitHub repo, detects vulnerabilities and backdoor patterns, explains them in plain language using GPT-5.6, and generates real fixes — from auto-patched pull requests to approved backdoor remediations."

---

## [0:35–1:10] Live Detection Demo
**Visual:** Import the intentionally vulnerable sample repo, trigger a scan, show live progress (static scan → AI review stages).

**Narration:**
"I'm importing a sample repo with real, planted issues — a hardcoded API key, an insecure config, and a hidden backdoor. Sentinel AI runs a static analysis pass first, so every finding here is verifiable, not hallucinated. Then GPT-5.6 reviews the flagged code and explains severity and impact in plain language."

**Visual:** Findings populate: secret finding, config finding, then the backdoor finding highlighted.

---

## [1:10–1:45] The Backdoor Moment
**Visual:** Click into the backdoor finding — show the obfuscated payload and GPT-5.6's decoded explanation.

**Narration:**
"Here's the interesting one: an obfuscated `eval` payload — a real backdoor pattern. GPT-5.6 decodes it and explains exactly what it does in plain English, along with a confidence score. This is a Tier 2 finding — high-risk enough that Sentinel doesn't auto-apply the fix. Instead, it proposes a diff, and I approve it myself, live."

**Visual:** Click "Approve Fix" → PR opens on GitHub.

---

## [1:45–2:05] Auto-Fix Moment (Tier 1)
**Visual:** Show the hardcoded secret finding, click "Auto-fix," show the generated PR.

**Narration:**
"For lower-risk findings like this hardcoded secret, Sentinel auto-generates the fix and opens a pull request automatically — but never merges it directly. Every fix, even automated ones, goes through a normal PR review on GitHub."

---

## [2:05–2:35] Codex + GPT-5.6 Build Narration
**Visual:** Split screen or cut to code editor / Codex session screenshots.

**Narration:**
"This entire project was built using Codex as the primary build agent — it scaffolded our FastAPI backend, the detection modules, and the initial remediation diff logic. We made key decisions along the way — for example, Codex's first version of the remediation engine applied fixes directly to the main branch, and we redirected it to always branch and open a PR instead, for safety. GPT-5.6 powers the two AI-driven parts of the live product: the Reasoning Layer that explains findings, and the Remediation Engine that generates fixes."

---

## [2:35–2:50] Close + Test Access
**Visual:** Final report screen, export button, then a card with the hosted demo URL/test account.

**Narration:**
"You can test Sentinel AI yourself right now — link and test account are in the description and README. Sentinel AI: built by AI, secured by AI."

---

## Production checklist
- [ ] Keep total runtime under 3:00 (aim for 2:45–2:55 to leave margin)
- [ ] Captions/subtitles recommended for accessibility and judge clarity
- [ ] Video set to public (not private) on YouTube
- [ ] Description includes: hosted demo URL, test account credentials, repo link, `/feedback` Codex session ID
- [ ] Confirm every claim in narration matches something actually visible on screen — don't narrate a capability you don't show working
