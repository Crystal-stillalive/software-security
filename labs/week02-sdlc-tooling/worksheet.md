# Worksheet 2 — Secure SDLC & Tooling (3 hrs)

> **Course:** Software Security (KOSEN69) · **Week 2**
> **Aligned to:** OWASP 2025 (A05 Injection [CWE-89, CWE-78], A04 Cryptographic Failures [CWE-327], A02 Security Misconfiguration [CWE-798, CWE-489]) · CWE-798, CWE-89, CWE-78, CWE-327, CWE-489
> **Signature game:** "Bug Triage Race" (scan → triage; score = true positives − misclassified)

> **Ethics note:** The scanners run only against the provided `vulnerable-repo/` on your own machine. Do not point SAST/secret scanners at third-party repos or production systems without authorization. Treat any secret you find here as fake lab data.

## Part 1 — Student Information
| Name | Student ID | Date | Group |
|---|---|---|---|
| Pyae Shunn Le Maung | 6631503084 | 4.9.2026 | |

## Part 2 — Lecture Questions
Answer in your own words (2–4 sentences each).
1. Distinguish SAST, DAST, and SCA — what does each see, and when in the SDLC does each run?
> SAST checks source code without running it, early in development. DAST tests a running app from outside, later in the pipeline. SCA checks third-party dependencies for known CVEs, usually at build time.

2. What is secret scanning, and why do hardcoded secrets keep ending up in repos?
> Secret scanning finds hardcoded credentials in code and git history. Secrets end up in repos because developers paste real keys in to get things working fast, then forget to remove them.

3. What does "shift-left / DevSecOps" mean in practice for a CI pipeline?
> Shift-left means running security checks early and automatically in CI — at every commit or PR — instead of waiting for a manual review before release.

4. Why is coverage-guided fuzzing considered the dominant modern bug-finding technique?
> Fuzzing is dominant because it actually runs the code against many inputs and tracks which paths get hit. It finds bugs that only show up at runtime, which static tools can't reason about.

5. Define true positive vs. false positive in scanner triage, and why misclassifying both directions is costly.
> A true positive is a real vulnerability correctly flagged. A false positive is a flagged issue that isn't real. Missing a true positive lets a real bug ship; too many false positives waste time and get ignored.


![A left to right SDLC pipeline showing SAST at write code, secret scanning at commit, SCA and fuzzing at build, and DAST at deploy, with what each tool cannot see written underneath it.](img/sdlc-gates.svg)

## Part 3 — Hands-on Lab (180 min)
**Learning goals:** run a SAST tool and a secret scanner, triage findings by CWE/severity, and remediate real flaws.
**Prerequisites:** Docker installed; internet to pull the Semgrep/Gitleaks images.

**Environment setup**
```bash
cd labs/week02-sdlc-tooling
cat scan.sh                 # see exactly what it runs
bash scan.sh                # Semgrep (p/default + p/owasp-top-ten) then Gitleaks on ./vulnerable-repo
```
Target under scan: `vulnerable-repo/app.py` (plus `requirements.txt`). It contains five planted flaws.

**What to submit per task:** the command/payload run + a screenshot of the finding + a 2–3 sentence mitigation.

**Task 0 — Onboarding (5 min)** · *Goal:* confirm tooling. *Steps:* run `bash scan.sh`; confirm both Semgrep and Gitleaks sections produce output. *Deliverable:* screenshot showing both tools ran.
![alt text](<Screenshot 2569-09-03 at 22.18.31.png>)

**Task 1 — SAST sweep with Semgrep (25 min)** · *Goal:* find code flaws. *Steps:* read the Semgrep output; locate the SQL injection in `/user` (CWE-89, string-formatted query), the OS command injection in `/ping` (CWE-78, `shell=True`), the weak `md5` password hash (CWE-327), and `debug=True` (CWE-489). *Deliverable:* one screenshot per finding with the file:line.
- CWE-89, string-formatted query
![alt text](<Screenshot 2569-09-03 at 22.39.02.png>)
- CWE-78, shell=True
![alt text](<Screenshot 2569-09-03 at 22.40.07.png>)
- CWE-327
![alt text](<Screenshot 2569-09-03 at 22.40.36.png>)
- CWE-489
![alt text](<Screenshot 2569-09-03 at 22.41.18.png>)

**Task 2 — Secret scan with Gitleaks (15 min)** · *Goal:* find leaked credentials. *Steps:* read the Gitleaks output; identify `AWS_SECRET_ACCESS_KEY` and `DB_PASSWORD` (CWE-798). *Deliverable:* screenshot + the rule that fired for each.
![alt text](<Screenshot 2569-09-03 at 22.43.06.png>)
- AWS_SECRET_ACCESS_KEY — CWE-798 — Rule: `generic-api-key`
- DB_PASSWORD — CWE-798 — Rule: `generic-api-key`

`Both secrets are hardcoded in source (CWE-798), recoverable by anyone with repo access, even from git history. Fix: load both from environment variables.`

**Task 3 — Bug Triage Race (30 min)** · *Goal:* triage accurately. *Steps:* build a table with columns *Tool | File:Line | CWE | Severity | TP/FP | Fix idea*; mark at least 3 true positives and 1 likely false positive and justify each. (Score = TP − misclassified.) *Deliverable:* the completed triage table.

| Tool | File:Line | CWE | Severity | TP/FP | Fix idea |
|---|---|---|---|---|---|
| Semgrep | app.py:19-20 | CWE-89 | High | TP — `sql-injection-db-cursor-execute` rule; user input directly formatted into SQL string, confirmed exploitable | Parameterized query with `?` placeholder |
| Semgrep | app.py:19-20 | CWE-89 | Low | FP — `tainted-sql-string`, `formatted-sql-query`, and `sqlalchemy-execute-raw-query` rules all fired on this exact same line/bug already captured above; counting these as 4 additional distinct findings rather than 1 bug caught 4 times over-counts the real vulnerability count | N/A — already remediated by the single fix above; this is a triage/counting issue, not a separate code fix |
| Semgrep | app.py:26 | CWE-78 | Critical | TP — `subprocess-shell-true` rule; `shell=True` + string concatenation of user input, confirmed exploitable | Pass args as list, remove `shell=True` |
| Semgrep | app.py:30 | CWE-327 | Medium | TP — MD5 confirmed used for password hashing, no salt | Replace with argon2id/bcrypt |
| Semgrep | app.py:33 | CWE-489 | Medium | TP — `debug=True` literally present, confirmed | Set `debug=False` before deploy |
| Gitleaks | app.py:11 | CWE-798 | High | TP — real-format AWS key string hardcoded in source | Move to environment variable |
| Gitleaks | app.py:12 | CWE-798 | High | TP — plaintext DB password hardcoded in source | Move to environment variable |

**Task 4 — Fuzzing intro (10 min)** · *Goal:* see coverage-guided fuzzing find a bug SAST won't. *Steps:* in the `labs/toolbox` container (Apple clang has no libFuzzer runtime), build `clang -g -fsanitize=address,fuzzer harness.c -o fuzz`, then **seed the corpus** and run it:
`mkdir -p corpus && printf 'FUZ' > corpus/seed && ./fuzz corpus`. It crashes almost immediately with an AddressSanitizer heap-buffer-overflow at `harness.c:23` (the `data[3]` read with no `size > 3` check). Seeding matters: an unseeded `./fuzz` has to rediscover the magic bytes by chance and often finds nothing for minutes — that unpredictability is itself worth a sentence in your write-up. (The deep fuzzing+exploit lab is Week 11.) *Deliverable:* the ASan crash output (or a screenshot) + a 2-sentence note on why fuzzing finds this bug when a linter/SAST pass over the same 4-line check would not.

![alt text](<Screenshot 2569-09-03 at 23.08.05.png>)
![alt text](<Screenshot 2569-09-03 at 23.08.37.png>)
![alt text](<Screenshot 2569-09-03 at 23.08.50.png>)

`Fuzzing crashed almost instantly on the seeded input. A linter can't catch data[3] because it's only a bug at runtime, with a short input — not a recognizable bad pattern on its own. Fuzzing actually runs the code and lets ASan catch the out-of-bounds read the moment it happens.`

**Task 5 — Scan the project target (40 min)** · *Goal:* apply the tools to your term project. *Steps:* run Semgrep + Gitleaks against **NoteVault** (`../../project/starter-app`); also run an SCA scan: `docker run --rm -v "$PWD/../../project/starter-app:/src" aquasec/trivy fs /src`. *Deliverable:* a findings list (tool, file:line/CVE, CWE) — reuse it in your project vuln report.
![alt text](<Screenshot 2569-09-03 at 23.21.26.png>)
![alt text](<Screenshot 2569-09-03 at 23.23.31.png>)
![alt text](<Screenshot 2569-09-03 at 23.26.05.png>)

`Semgrep found 31 issues in NoteVault: SQLi in /login and /search, JWT none-algorithm bypass, hardcoded JWT secret, XSS via string-built HTML, command injection in /export, debug mode on. Gitleaks found 0 leaks — the hardcoded secret's low entropy missed its generic detector. Trivy found 32 dependency CVEs, 12 HIGH, across Flask, PyJWT, Werkzeug, Jinja2, and urllib3.`

**Task 6 — Build a security CI gate (25 min)** · *Goal:* automate the scan (previews Week 15). *Steps:* adapt `../week15-devsecops-pipeline/security-ci.yml` into a workflow that runs Semgrep + Trivy + Gitleaks and **fails on HIGH/CRITICAL**; run it locally (`act`) or commit to your fork and read the Actions log. *Deliverable:* the workflow file + a screenshot of a failing run.

**Workflow file** (`.github/workflows/security-ci.yml`, adapted from `labs/week15-devsecops-pipeline/security-ci.yml`):

```yml
# Sandbox/teaching only; for authorized lab use.
#
# Week 15 — DevSecOps security gate (GitHub Actions LAB TEMPLATE).
# This file lives in the lab dir. To activate it, copy it to
#   .github/workflows/security-ci.yml
# in a repo (see README-pipeline.md).
#
# It runs four security tools and FAILS the build on HIGH/CRITICAL:
#   - Semgrep  (SAST)            CWE-coverage via OWASP rulesets
#   - Trivy    (SCA + image + IaC)
#   - Gitleaks (secret scanning)
# SARIF results upload to the GitHub "Security" tab even when a scan fails
# (the upload steps use `if: always()`), so reviewers still see findings.
#
# OWASP 2025: A03 (supply chain), A02 (misconfig), A09 (logging/alerting).

name: security-ci

# Run on every push and PR to main, plus manual dispatch.
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:

# Least-privilege token: read code, write security events (for SARIF upload).
permissions:
  contents: read
  security-events: write

jobs:
  # ---------------------------------------------------------------
  # 1) SAST — Semgrep scans source for insecure patterns.
  # ---------------------------------------------------------------
  semgrep:
    name: SAST (Semgrep)
    runs-on: ubuntu-latest
    container:
      image: semgrep/semgrep:latest
    steps:
      - uses: actions/checkout@v4

      - name: Semgrep scan -> SARIF
        # Produce SARIF always; do NOT fail here so the SARIF can upload.
        # The gate (fail on findings) is enforced in the next step.
        run: |
          semgrep scan \
            --config p/default \
            --config p/owasp-top-ten \
            --sarif --output semgrep.sarif \
            --error || true

      - name: Upload Semgrep SARIF
        if: always()              # upload even if a later step fails
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep.sarif
          category: semgrep

      - name: Gate — fail on Semgrep findings
        # `--error` makes Semgrep exit non-zero when findings exist.
        run: semgrep scan --config p/default --config p/owasp-top-ten --error

  # ---------------------------------------------------------------
  # 2) Trivy — filesystem (SCA) + IaC/Dockerfile config scan.
  #    Image scan is included as a commented example (needs a build).
  # ---------------------------------------------------------------
  trivy:
    name: SCA + IaC (Trivy)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # --- Filesystem / dependency (SCA) scan -> SARIF (report, no fail) ---
      - name: Trivy fs (SCA) -> SARIF
        uses: aquasecurity/trivy-action@0.24.0
        with:
          scan-type: fs
          scanners: vuln,secret
          format: sarif
          output: trivy-fs.sarif
          severity: HIGH,CRITICAL
          exit-code: "0"          # report only; the gate step enforces failure

      - name: Upload Trivy fs SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-fs.sarif
          category: trivy-fs

      # --- IaC / Dockerfile misconfiguration scan -> SARIF ---
      - name: Trivy config (IaC) -> SARIF
        uses: aquasecurity/trivy-action@0.24.0
        with:
          scan-type: config
          format: sarif
          output: trivy-config.sarif
          severity: HIGH,CRITICAL
          exit-code: "0"

      - name: Upload Trivy config SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-config.sarif
          category: trivy-config

      # --- GATE: re-scan with exit-code 1 so HIGH/CRITICAL FAILS the build ---
      - name: Gate — fail on HIGH/CRITICAL (SCA)
        uses: aquasecurity/trivy-action@0.24.0
        with:
          scan-type: fs
          scanners: vuln,secret
          severity: HIGH,CRITICAL
          ignore-unfixed: false
          exit-code: "1"          # <-- real failure semantics, not `|| true`

      - name: Gate — fail on HIGH/CRITICAL (IaC)
        uses: aquasecurity/trivy-action@0.24.0
        with:
          scan-type: config
          severity: HIGH,CRITICAL
          exit-code: "1"

      # --- OPTIONAL image scan (uncomment once the job builds an image) ---
      # - name: Build image
      #   run: docker build -t app:ci .
      # - name: Gate — fail on image CVEs
      #   uses: aquasecurity/trivy-action@0.24.0
      #   with:
      #     scan-type: image
      #     image-ref: app:ci
      #     severity: HIGH,CRITICAL
      #     exit-code: "1"

  # ---------------------------------------------------------------
  # 3) Gitleaks — secret scanning across the repo + git history.
  # ---------------------------------------------------------------
  gitleaks:
    name: Secrets (Gitleaks)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # full history so history-buried secrets are caught

      - name: Gitleaks scan -> SARIF
        run: |
          docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:latest \
            detect -s /repo \
            --report-format sarif --report-path /repo/gitleaks.sarif \
            --exit-code 0 -v || true   # report; gate step enforces failure

      - name: Upload Gitleaks SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: gitleaks.sarif
          category: gitleaks

      - name: Gate — fail if any secret found
        run: |
          docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:latest \
            detect -s /repo --exit-code 1 -v   # <-- non-zero => build fails

```
![alt text](<Screenshot 2569-09-04 at 00.17.05.png>)

**Task 7 — SAST blind spots (20 min)** · *Goal:* see what scanners miss. *Steps:* find one real bug in `vulnerable-repo/app.py` (or NoteVault) that Semgrep did **not** flag, and explain why a pattern-based tool missed it. *Deliverable:* the bug + a 2-sentence explanation.

- Bug: /api/notes/<nid> checks that a user is logged in, but never checks if they own the note. Any user can read any note by guessing the ID (CWE-639, IDOR).

- Explanation: 
  > The code uses a safe, parameterized query — no dangerous function or bad string pattern to catch. The bug is a missing authorization check, which is a logic problem, not something a pattern-matcher can see.

**Task 8 — Defend / fix it (10 min)** · *Goal:* remediate the planted flaws in `vulnerable-repo/app.py`. *Steps:* rewrite `/user` to use a parameterized query (`?` placeholder); remove `shell=True` and pass an argument list in `/ping`; move both secrets to environment variables; replace `md5` with bcrypt/argon2; set `debug=False`. *Deliverable:* a before/after diff for each fix mapped to its CWE.

```bash
"""
Deliberately INSECURE sample for Week 2 scanning practice.
Do NOT copy these patterns into real code. Find them with SAST + secret scanning.
 
--- FIXED (Task 8) ---
"""
import os
import sqlite3
import subprocess
from argon2 import PasswordHasher
from flask import Flask, request
 
app = Flask(__name__)
ph = PasswordHasher()
 
# FIX (CWE-798): secrets loaded from environment, never hardcoded in source.
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
 
 
@app.route("/user")
def user():
    name = request.args.get("name", "")
    con = sqlite3.connect("app.db")
    # FIX (CWE-89): parameterized query — user input is bound as data,
    # never concatenated/formatted into the SQL string itself.
    q = "SELECT * FROM users WHERE name = ?"
    return str(con.execute(q, (name,)).fetchall())
 
 
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # FIX (CWE-78): shell=True removed; command passed as an argument list
    # so the OS never invokes a shell that could interpret metacharacters
    # (;, |, &&, etc.) in user-controlled input.
    return subprocess.check_output(["ping", "-c", "1", host])
 
 
def store_password(pw):
    # FIX (CWE-327): argon2id — slow, memory-hard, auto-salted KDF,
    # replacing the fast, unsalted MD5 hash.
    return ph.hash(pw)
 
 
if __name__ == "__main__":
    # FIX (CWE-489): debug mode disabled.
    app.run(debug=False)
 
```

| CWE | Vulnerability | Before | After |
|---|---|---|---|
| CWE-89 | SQL Injection | `"SELECT * FROM users WHERE name = '%s'" % name` | `"SELECT * FROM users WHERE name = ?"`, bound via `(name,)` |
| CWE-78 | OS Command Injection | `check_output("ping -c 1 " + host, shell=True)` | `check_output(["ping", "-c", "1", host])` |
| CWE-798 | Hardcoded Credentials | `AWS_SECRET_ACCESS_KEY = "hK8pQ2..."` | `os.environ.get("AWS_SECRET_ACCESS_KEY")` |
| CWE-327 | Weak Password Hash | `hashlib.md5(pw.encode()).hexdigest()` | `ph.hash(pw)` (argon2id) |
| CWE-489 | Debug Mode | `app.run(debug=True)` | `app.run(debug=False)` |

![alt text](<Screenshot 2569-09-04 at 00.44.27.png>)

## Part 4 — Reflection
1. Map two of your findings to their CWE and to the matching OWASP 2025 category.
> SQL Injection = CWE-89 → OWASP A05:2025 Injection. User input changes the query itself. 
> Weak hashing = CWE-327 → OWASP A04:2025 Cryptographic Failures. MD5 is fast and unsalted, easy to crack.

2. Name a real-world breach caused by a hardcoded/leaked secret or an injection flaw, and what control would have caught it pre-release.
> The 2021 Codecov breach came from leaked credentials that let an attacker modify their upload script. Secret scanning in CI plus credential rotation would have caught it before release.

3. Which single tool (SAST vs. secret scanning) gave the highest-value findings on this repo, and why?
> SAST gave more value here. Semgrep found real, exploitable bugs across the whole app. Gitleaks only found 2 secrets in the sample repo and nothing in NoteVault.

## Grading rubric (100)
| Criterion | Points |
|---|---|
| Lecture questions (Part 2) | 20 |
| Exploitation + evidence (scan output + triage table + screenshots) | 40 |
| Defense (remediated `app.py` with before/after diffs) | 25 |
| Reflection (CWE/OWASP mapping + breach + tool value) | 15 |

---

## Evidence & Integrity (required)

- **Identity proof:** every screenshot/diagram must show a terminal running `printf '%s | %s | ' "$(whoami)" '<YOUR-STUDENT-ID>'; date '+%F %T %Z'` **in the
  same image as the evidence**. When the evidence is a browser page, a DevTools panel or a
  rendered response, put that terminal **beside the browser and capture the whole screen** — a
  cropped window carries nothing that identifies you, and the lab's own output is
  byte-identical for the whole cohort *by design*, so the stamp is the only thing that makes
  the shot yours. Generic or borrowed evidence is not accepted.
- **Personalized flag (if this lab issues one):** ____________________
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
  1. What did you do, and **why did the vulnerability work**?
  > I ran Semgrep and Gitleaks on vulnerable-repo/app.py and NoteVault. The SQL injection worked because the query used string formatting, so user input could change the query itself. The command injection worked the same way — shell=True let shell characters in the input run as real commands.

  2. **Why does your fix actually stop it** — and what could still break it?
  > I switched to parameterized queries and argument lists, so input is only ever data, never code. I moved secrets to environment variables and switched to argon2id. The re-scan proved it — 10 findings and 2 leaks became 0 and 0. What could still break it: if someone adds a new route later and goes back to string formatting instead of parameters, the same bug returns elsewhere.

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.
- Prompt given to the AI:
"Fix the SQL injection vulnerability in vulnerable-repo/app.py's /user endpoint. Use a parameterized query."

- AI's answer:
```py
@app.route("/user")
def user():
    name = request.args.get("name", "")
    con = sqlite3.connect("app.db")
    q = "SELECT * FROM users WHERE name = ?"
    return str(con.execute(q, name).fetchall())
```

2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).

`What's wrong with it:
The query itself is correct, but the parameter is passed wrong. con.execute(q, name) passes a raw string, not a tuple — sqlite3 needs a sequence. This line:

```py
return str(con.execute(q, name).fetchall())
```
should be:

```py
return str(con.execute(q, (name,)).fetchall())
```

My corrected version, and why the AI's was insufficient:

```py
@app.route("/user")
def user():
    name = request.args.get("name", "")
    con = sqlite3.connect("app.db")
    q = "SELECT * FROM users WHERE name = ?"
    return str(con.execute(q, (name,)).fetchall())
```

3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.
> The /user endpoint takes the name parameter from the URL and pastes it into a SQL query with string formatting. An attacker can put SQL code inside name, and the database runs it as part of the query instead of treating it as plain text.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*
- Final prompt:
> "Fix the SQL injection in this Flask route. Use a parameterized query with a ? placeholder, and pass the parameter as a tuple. Show the corrected code."

- Verified result:
```py
q = "SELECT * FROM users WHERE name = ?"
return str(con.execute(q, (name,)).fetchall())
```
> Re-ran the scan after applying this. Semgrep went from flagging this line to 0 findings on it. Fix confirmed working, no refinement needed.