# Worksheet 1 — Security Mindset & Threat Modeling (3 hrs)

> **Course:** Software Security (KOSEN69) · **Week 1**
> **Aligned to:** OWASP 2025 A06 Insecure Design · CWE-501 (Trust Boundary Violation)
> **Signature game:** "Elevation of Privilege" (Microsoft STRIDE card deck)

> **Ethics note:** This week is *modeling only* — you analyze design, you do **not** attack the app. Run the sample app only on your own VM/localhost. Never apply these techniques to systems you do not own or lack written permission to test.

## Part 1 — Student Information
| Name | Student ID | Date | Group |
|---|---|---|---|
| Pyae Shunn Le Maung | 6631503084 | 15.8.2026 | - |

## Part 2 — Lecture Questions
Answer in your own words (2–4 sentences each).
1. Define the CIA triad and give one concrete failure example for each of the three properties.
The CIA triad stands for Confidentiality, Integrity, and Availability, which are the three main goals of information security. A confidentiality failure could be a hacker accessing private customer data, an integrity failure could be someone changing a user's account balance without permission, and an availability failure could be a website going offline because of a DDoS attack.
2. What is a *trust boundary*, and why does data crossing one deserve extra scrutiny?
A trust boundary is a point where data moves between components or environments with different levels of trust. Data crossing a trust boundary deserves extra scrutiny because attackers may manipulate it, so the receiving system must validate and authenticate the data before trusting it.
3. Explain "attack surface." Name two things that increase it in a web app.
An attack surface is the collection of possible entry points that an attacker could use to compromise a system. In a web application, adding more public API endpoints and accepting file uploads can increase the attack surface because they provide additional functionality that may contain vulnerabilities.
4. What does each STRIDE letter map to, and which security property does each threat violate?
STRIDE stands for Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege. These correspond respectively to violations of authentication, integrity, non-repudiation/accountability, confidentiality, availability, and authorization.
5. What does "Secure by Design" (CISA) mean, and how does it differ from bolting security on after release?
Secure by Design, as promoted by CISA, means security is considered from the beginning of designing and developing a product rather than being treated as an extra feature. Instead of waiting until after release to fix vulnerabilities, developers proactively design systems to reduce risks and make secure behavior the default.

## Part 3 — Hands-on Lab (180 min)
**Learning goals:** build a data-flow diagram (DFD), apply STRIDE to a real Flask app, rank risks, and propose mitigations.
**Prerequisites:** Docker + Docker Compose in your VM; a drawing tool (draw.io / paper + photo); the Elevation of Privilege deck (print or virtual) — free print-and-play PDF at [github.com/adamshostack/eop](https://github.com/adamshostack/eop).

**Environment setup**
```bash
cd labs/week01-threat-modeling
docker compose up --build           # starts sample-app on http://localhost:8080
curl -s -X POST localhost:8080/notes -H 'Content-Type: application/json' \
     -d '{"owner":"alice","body":"hello"}'   # observe behavior, do not attack
curl -s localhost:8080/notes

echo "demo file" > demo.txt
curl -s -X POST localhost:8080/upload -F "file=@demo.txt"   # observe behavior, do not attack
curl -s localhost:8080/files/demo.txt
```

Source to model lives in `sample-app/app.py`. Template to fill: `THREAT-MODEL-TEMPLATE.md` (copy it, do not edit the original).

**What to submit per task:** the threat/element identified + a screenshot (DFD, table, or running app) + a 2–3 sentence mitigation.

**Task 0 — Onboarding (5 min)** · *Goal:* prove the environment works. *Steps:* `docker compose up`, hit `/notes` and `/files/<name>`, read `sample-app/app.py`.
![alt text](<Screenshot 2569-08-15 at 13.20.23.png>)![alt text](<Screenshot 2569-08-15 at 13.42.18.png>)
**Task 1 — Draw the DFD (25 min)** · *Goal:* map the system. *Steps:* identify the external entity (web client), the process (Flask app), the data store (`notes.db` SQLite), the `uploads/` store, and the flows for `/notes`, `/upload`, `/files/<name>`; mark the Internet→app trust boundary with a dashed line. *Deliverable:* DFD image embedded in your copy of the template.
![alt text](<Screenshot 2569-08-20 at 14.30.08.png>)

**Task 2 — STRIDE the elements (30 min)** · *Goal:* enumerate threats per element. *Steps:* for each element fill the S/T/R/I/D/E grid. Ground it in real code: `/notes` accepts a client-supplied `owner` with no auth (Spoofing); `/upload` saves raw `f.filename` — arbitrary-file-write (Tampering) — and echoes the resolved save path back in its response (Information disclosure); `/files/<name>` reads it back but is comparatively defended (see Task 5); no logging anywhere (Repudiation). *Deliverable:* completed STRIDE table.

| Element | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| /notes | Accepts client-supplied `owner` with no auth — anyone can post as "alice" | No auth on writes — anyone can insert/corrupt note records | No logging anywhere — no record of who posted what | — | No rate limit observed — repeated POSTs could flood `notes.db` | — |
| /upload | — | Raw `f.filename` used unsanitized to build save path — arbitrary-file-write | No logging — no record of who uploaded what, when | Response echoes resolved save path — leaks server filesystem layout | No apparent file-size limit — could exhaust disk/memory | If a written file is ever executed (e.g. via traversal into an executable path), this becomes code execution |
| /files/<name> | — | Comparatively defended vs. /upload (see Task 5) — verify exact protection in source | No logging — no record of who read which file | If traversal isn't fully blocked, could read files outside `uploads/` | — | — |

**Task 3 — Elevation of Privilege game (20 min)** · *Goal:* find threats you missed. *Steps:* play the EoP deck against your DFD; each card you can tie to a real element/flow scores a point; record every valid threat. No printer or scissors? Draw from the digital deck below instead — same 78 cards, same rule. *Deliverable:* list of carded threats + score.

```sim
eop-deck
```

**Task 3b — Systems-level pass (25 min) 🔭** · *Goal:* find what the per-element grid cannot see. Tasks 2 and 3 enumerate threats **one element at a time**, and that is exactly where threat models are known to stop short — students taught STRIDE alone reliably identify component threats and *discount system-level ones* ([Joshi et al., ASEE 2024](https://arxiv.org/abs/2404.16632)). So do a second pass over the **whole** diagram:
![Three trust zones — public internet, application tier, data tier — with the two boundaries a request crosses between them](img/trust-boundaries.svg)

- **Trust boundaries end-to-end.** Follow one request from the client to `notes.db` and back. List every boundary it crosses. Which crossing has no check on it?
- **Assume one element is fully owned.** Pick the Flask process, then the `uploads/` store. For each: what does the attacker now *reach* — not what is it, but where does it get them?
- **Chain two "low" findings.** Find two threats you or the EoP deck rated minor that combine into something you would not accept. Write the chain as `A → B → consequence`.
- **One-line system claim.** Finish: "Even if every element-level mitigation in Task 8 is implemented, this system still fails if ___."

Use the simulation below before you start — toggle a component to attacker-controlled and watch what it reaches:
```sim
trust-boundary
```
*Deliverable:* the boundary list, two owned-element reachability notes, one written chain, and the system claim.

Trust boundaries end-to-end: Tracing client → POST /notes → Flask App → notes.db → response → client crosses two boundaries: (1) Internet → Flask App, with zero authentication check, and (2) Flask App → notes.db, which the DFD draws as inside one combined trust zone with no internal check at all. The unguarded crossing that matters most is the Internet → App boundary, since it faces the open internet directly.

Assume one element is fully owned:

Flask process owned: the attacker immediately reaches both notes.db and uploads/, since the DFD places all three inside a single trust boundary with no segmentation between them.
uploads/ store owned: the attacker can write/overwrite arbitrary files there; what they reach beyond that depends on whether anything outside this diagram (a web server, a cron job) executes files from that path — a blind spot the DFD itself can't answer.

Chain two "low" findings:
Unsanitized f.filename on /upload (Tampering, low alone) → Response echoes resolved save path (Info Disclosure, low alone) → consequence: confirmed arbitrary-file-write outside uploads/, with the response itself proving exactly where the file landed.

One-line system claim:
"Even if every element-level mitigation in Task 8 is implemented, this system still fails if the app process itself is ever compromised — because the single trust boundary in this design places Flask, notes.db, and uploads/ all in one undifferentiated trust zone, meaning process compromise equals total data compromise with no internal segmentation to slow an attacker down."

**Task 4 — Abuse cases & attacker personas (20 min)** · *Goal:* think like specific adversaries. *Steps:* define 2 personas (e.g. a curious logged-in user; an anonymous internet attacker) and write 2 abuse cases each against the sample app, tied to DFD elements. *Deliverable:* 4 abuse cases.
Persona 1: Anonymous internet attacker (no account, no prior access, motivated by data theft/disruption)

Abuse case: Posts to /notes with owner: "admin" and a fabricated body, impersonating another identity since nothing validates who is actually submitting the request. (Element: /notes endpoint, Threat: Spoofing)
Abuse case: Uploads a file via /upload with a filename like ../../../etc/cron.d/malicious to write outside the intended uploads/ directory. (Element: /upload endpoint → uploads/ store, Threat: Tampering)

Persona 2: Curious existing user (has legitimately used the app before, motivated by nosiness rather than malice)

Abuse case: Enumerates /files/<name> with guessed or sequential filenames to view files uploaded by other users, since there's no per-user access control on stored files. (Element: /files/<name> endpoint, Threat: Information Disclosure)
Abuse case: Submits notes under other users' owner values just to see if the system lets it through, discovering the lack of ownership verification without any malicious intent. (Element: /notes endpoint, Threat: Spoofing)

**Task 5 — Path-traversal deep-dive (25 min)** · *Goal:* analyze the riskiest flow. *Steps:* trace `/upload` → `/files/<name>`; explain how `../` in a filename escapes `uploads/`; sketch the secure design (`secure_filename`, store outside web root, allow-list extensions). *Deliverable:* the data flow + secure-design note.

Data flow: Client → POST /upload (multipart file, f.filename client-controlled) → Flask reads f.filename and joins it to the upload directory to build the save path → file written to uploads/ → later, GET /files/<name> reads a file back by name from the same directory.

How ../ escapes uploads/: If the save-path construction looks like os.path.join(UPLOAD_DIR, f.filename), and f.filename contains something like ../../etc/cron.d/evil, os.path.join does not strip or block ../ segments — it just concatenates them, and the resulting path can walk upward out of UPLOAD_DIR entirely. The attacker controls exactly where the file lands, anywhere the process has write permission on the filesystem.

Secure design:

Sanitize the filename with werkzeug.utils.secure_filename() to strip path separators and traversal sequences.
Also verify the final resolved absolute path still starts with the intended base directory before writing — belt-and-suspenders, since secure_filename() alone has had historical edge-case bypasses and shouldn't be trusted as the sole defense.
Store uploaded files outside the web root entirely, so even a successful escape can't land in a publicly servable location.
Allow-list acceptable file extensions, so even a contained write can't drop an executable or script file.

**Task 6 — Threat-model the project target (30 min)** · *Goal:* kick off your term project. *Steps:* stop the sample-app first (`docker compose down` — both apps bind host port 8080), then run **NoteVault** (`cd ../../project/starter-app && docker compose up`), draw a quick DFD, and list the top 3 STRIDE threats you'd investigate. *Deliverable:* NoteVault DFD + top-3 threats (reuse these in your project report — `project/REPORT-TEMPLATE.md` in the repo root).
![alt text](<Screenshot 2569-08-20 at 15.37.32.png>)

Top 3 STRIDE threats
SQL Injection in the login query (Tampering/Spoofing) — app.py line 128 builds the login query via raw string formatting: "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, ...). Unsanitized username input could let an attacker bypass authentication entirely through injected SQL, not just leak data.
Unsalted MD5 password storage (Information Disclosure / Insufficient Crypto) — seed() hashes demo passwords with plain hashlib.md5(). Already cracked and confirmed in Worksheet 3: admin → admin123, alice → alicepw.
Client-controlled role field on registration (Elevation of Privilege) — the /register handler inserts role directly from client input (app.py lines 116-117: (username, hashlib.md5(...).hexdigest(), role)). If unchecked, a normal registration request could self-assign the admin role.

**Task 7 — Security requirements (15 min)** · *Goal:* turn threats into testable requirements. *Steps:* write 3 security requirements as acceptance criteria ("the system must … so that …"), each mapped to a threat from Task 2 or Task 6. *Deliverable:* 3 testable security requirements.

1. The system must require session-based authentication before accepting writes to /notes, so that unauthenticated spoofing of the owner field is prevented.
2. The system must reject any uploaded filename containing /, \, or .. sequences on /upload, so that path traversal outside uploads/ is prevented.
3. The system must ignore any client-supplied role value during registration and default all new accounts to the lowest-privilege role, so that privilege escalation via self-assigned admin role is prevented.

**Task 8 — Defend / fix it: rank & mitigate (25 min) 🛡️** · *Goal:* turn threats into action you can prove. *Steps:* rank the top 5 threats by likelihood × impact; propose one concrete mitigation each (e.g., auth on `/notes`, `secure_filename()` + allowlist for `/upload`, request logging for Repudiation, size/rate limits for DoS). Then **pick one and actually implement it** in your fork.

| Rank | Threat | STRIDE | Where in app | L (1–5) | I (1–5) | Score | Why this score |
|---|---|---|---|---:|---:|---:|---|
| 1 | Path traversal / arbitrary file write via upload filename | T / E / I | `/upload` | 5 | 5 | 25 | Client controls filename; can escape upload dir; can overwrite sensitive files |
| 2 | Unauthenticated note spoofing (`owner` trusted from client) | S / T | `/notes` | 5 | 4 | 20 | No auth at boundary; anyone can impersonate anyone |
| 3 | No request logging (can’t attribute actions) | R | all endpoints | 4 | 4 | 16 | Incidents are hard to investigate/prove |
| 4 | Unbounded upload size / request flood | D | `/upload`, `/notes` | 4 | 4 | 16 | Disk/CPU/DB exhaustion possible |
| 5 | File path disclosure in upload response | I | `/upload` response | 4 | 3 | 12 | Leaks server internals that help follow-on attacks |

This is an instance fix for `/upload` because it rejects traversal-style filenames at that endpoint by failing closed when sanitization changes the name. It stops the specific bad request I proved, but the class-level fix would be to forbid any user-controlled string from becoming a filesystem path component anywhere in the app.

- Commit hash: `b60f31e`

- Before screenshot: 
![alt text](<Screenshot 2569-08-28 at 01.54.28.png>)
- After screenshot: 
![alt text](<Screenshot 2569-08-28 at 01.35.49.png>)

*Deliverable — the top-5 table, plus for the one you implemented:*
1. the **diff** (commit hash on your `wk01` branch),
2. **evidence it works**: the request that succeeded before your change and is refused after — both outputs,
3. **why it closes the class, not the instance** (2–3 sentences). `secure_filename()` on one endpoint is an instance fix; *"no user-supplied string ever becomes a path component"* is a class fix. Say which yours is, and if it's an instance fix, say what the class fix would be.

> **Why this is weighted.** Fewer than half of working developers can spot a security hole in code, and being shown vulnerabilities does not by itself teach you to find or close them. Exploiting is the half that feels like progress; defending is the half that transfers to your job.

## Part 4 — Reflection
1. Map your top finding to a CWE and to OWASP A06 (Insecure Design); explain the mapping in one sentence.
>My top finding (the path traversal on /upload) maps to CWE-22 (Path Traversal) and OWASP A06:2025 Insecure Design. It's a design issue and not just a missing patch because the app never had a rule like "user input can't become part of a file path" — that decision was just never made, so it's not something you could've patched after the fact without rethinking how uploads work.
2. Name one real-world breach caused by a design flaw (not a missing patch) and what design control would have prevented it.
>A good real example is the Capital One breach in 2019. It wasn't a missing patch — a misconfigured WAF let an SSRF request reach AWS's internal metadata service and pull IAM credentials that had way more access than they should've. If they'd actually scoped that role down to least privilege and kept the web tier segmented from internal services, the SSRF wouldn't have mattered nearly as much even if it still happened.
3. Of your five mitigations, which gives the most risk reduction per unit of effort, and why?
>Out of my five mitigations, the path traversal fix gives the best payoff for the effort. It's maybe 15 lines of code and it closes the highest-ranked risk on my table (25/25). Compare that to something like adding real session auth to /notes — that's a much bigger lift (login flow, sessions, cookies, etc.) for a lower score risk.

## Grading rubric (100)
| Criterion | Points |
|---|---|
| Lecture questions (Part 2) | 20 |
| Exploitation + evidence (DFD + STRIDE table + EoP findings + screenshots) | 40 |
| Defense (top-5 ranking + mitigations) | 25 |
| Reflection (CWE/OWASP mapping + breach + best mitigation) | 15 |

**Assessed within the rows above** (they are not extra points — they are what those points are for):
- **Systems-level reasoning** (inside *Exploitation + evidence*, Task 3b): does the model reach past single elements to boundaries, reachability and chains? Scored with the STRIDE + systems-thinking rubrics of [Joshi et al. 2024](https://arxiv.org/abs/2404.16632).
- **Defensive proof** (inside *Defense*, Task 8): a claimed mitigation with no before/after evidence scores at most half. A mitigation you can show closing a *class* scores full.
- **Adversarial thinking** (across the whole sheet): do the abuse cases, personas and chains show you reasoning as an attacker with goals and constraints — or just listing categories? This is the course's central disposition and it is assessed, not assumed.

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
  >I looked at app.py and saw /upload just does os.path.join(UPLOAD_DIR, f.filename) with whatever filename the client sends — no checks at all. So I sent a file with the filename ../../../tmp/evil_before.txt. Since os.path.join doesn't care about ../, it just builds the path literally, which walks right out of the uploads folder. I confirmed it worked by checking /tmp/ afterward and the file was actually sitting there.
  2. **Why does your fix actually stop it** — and what could still break it?
  >My fix runs the filename through secure_filename(), checks the extension is on an allow-list, and then double-checks the final resolved path is still inside the uploads folder before it ever saves anything. Testing the same attack after the fix gave me a 400 instead of a 200, and the file never showed up on disk. The catch is this is all only inside the /upload route — if someone adds another route later that saves files, they'd have to remember to copy all these same checks over, or the same bug just comes back somewhere else.

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.
2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).
3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

Prompt I gave the AI: Fix the path-traversal vulnerability in /upload, which currently does f.save(os.path.join(UPLOAD_DIR, f.filename)) with no validation.

What the AI produced: 
```py

"""
Tiny sample web app for Week 1 threat modeling.
You will NOT exploit this in Week 1 — you will draw a data-flow diagram
and apply STRIDE to its components (web client, app, SQLite DB, /upload).
"""
from flask import Flask, request, jsonify, send_from_directory
import sqlite3, os
from werkzeug.utils import secure_filename

app = Flask(__name__)
DB = "notes.db"
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


def upload_path(name):
    base_dir = os.path.abspath(UPLOAD_DIR)
    candidate = os.path.abspath(os.path.join(base_dir, name))
    if not candidate.startswith(base_dir + os.sep):
        raise ValueError("invalid upload path")
    return candidate

def init_db():
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner TEXT, body TEXT)")
    con.commit(); con.close()

@app.route("/notes", methods=["GET", "POST"])
def notes():
    con = sqlite3.connect(DB)
    if request.method == "POST":
        owner = request.json.get("owner", "anon")
        body = request.json.get("body", "")
        con.execute("INSERT INTO notes (owner, body) VALUES (?, ?)", (owner, body))
        con.commit()
    rows = con.execute("SELECT id, owner, body FROM notes").fetchall()
    con.close()
    return jsonify(rows)

@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    original_name = f.filename
    filename = secure_filename(original_name)
    if not filename or filename != original_name:
        return {"error": "invalid filename"}, 400
    try:
        path = upload_path(filename)
    except ValueError:
        return {"error": "invalid filename"}, 400
    f.save(path)
    return {"saved": filename}

@app.route("/files/<name>")
def files(name):
    return send_from_directory(UPLOAD_DIR, name)

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)

```
What's wrong or risky in it:
The AI's fix correctly closes path traversal with two independent checks — secure_filename() plus a separate upload_path() containment check — which is genuinely solid. But it has no extension allow-list at all, so a filename like shell.php that passes through secure_filename() unchanged (no traversal characters, no special characters) sails straight through both checks and gets saved with no restriction on file type. Path traversal is closed, but arbitrary file type upload isn't.

My corrected, verified version and why the AI's was insufficient:
I added an extension allow-list check (.txt, .pdf, .png, .jpg) alongside the existing two layers, rejecting anything outside that list before the file is ever saved. The AI's version correctly handled the specific vulnerability I asked it to fix (path traversal) but didn't account for the adjacent risk of unrestricted file types — a reminder that fixing the exact bug you point at doesn't always cover the full threat model around that endpoint.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.
>The /upload endpoint takes whatever file the client sends and saves it using the filename the client gave it, with no checks on that filename. Because file paths let you use ../ to move up a directory, someone can craft a filename that makes the server save the file way outside the intended uploads/ folder — anywhere the server process has write access. It's exploitable because there's a gap between "the filename is just a string" and "the filename directly controls where on disk something gets written."

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
>"In this Flask app, /upload saves files using the raw client-supplied filename with os.path.join(UPLOAD_DIR, f.filename), which allows path traversal. Write a secure replacement that sanitizes the filename with werkzeug.utils.secure_filename(), rejects the request if sanitization changes the filename at all, and independently verifies the final resolved absolute path is still inside the upload directory before saving. Show only the corrected function."

**Verified result: 
this is the actual fix I ended up with and tested:
```py
def upload_path(name):
    base_dir = os.path.abspath(UPLOAD_DIR)
    candidate = os.path.abspath(os.path.join(base_dir, name))
    if not candidate.startswith(base_dir + os.sep):
        raise ValueError("invalid upload path")
    return candidate

@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    original_name = f.filename
    filename = secure_filename(original_name)
    if not filename or filename != original_name:
        return {"error": "invalid filename"}, 400
    try:
        path = upload_path(filename)
    except ValueError:
        return {"error": "invalid filename"}, 400
    f.save(path)
    return {"saved": filename}
```
Retesting the same traversal payload (../../../tmp/evil_after.txt) after applying this returned HTTP 400 instead of the original HTTP 200, and no file showed up at the target path — confirmed the exploit fails on the first try, no refinement needed. This matches the fix already committed on wk01 (b60f31e).

*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*
