# Worksheet 4 — Injection & Input Handling (3 hrs)

> **Course:** Software Security (KOSEN69) · **Week 4**
> **Aligned:** OWASP 2025 **A05 Injection** · **CWE-89** (SQLi), **CWE-78** (OS command injection), **CWE-434** (unrestricted upload)
> **Signature game:** 🐉 **SQLi Boss Fight** — each successful injection lands a "hit" on the boss; the boss falls when you dump every credential and land an RCE.

> ⚠️ **Ethics note:** All payloads here are for the provided sandbox (`vulnerable_app.py`) and your own DVWA/Juice Shop containers **only**. Never test systems you do not own or have written permission to test. Unauthorized injection is a crime under most computer-misuse laws.

## Part 1 — Student Information

| Name | Student ID | Date | Group |
|------|-----------|------|-------|
| Pyae Shunn Le Maung | 6631503084 | 11.9.26 | - |

## Part 2 — Lecture Questions

Answer in 2–4 sentences each.

1. Why does a **parameterized query** (`execute(sql, (params,))`) defeat SQL injection, while string formatting (`"... '%s'" % user`) does not? Reference how the database treats data vs. code.
`A parameterized query sends SQL and data separately — the database compiles the query first, then binds input as pure data, never as syntax. String formatting builds the final SQL text before the database sees it, so malicious input like ' OR '1'='1 just becomes part of the query itself.`


2. In the `/ping` endpoint, `subprocess.run("ping -c 1 " + host, shell=True)` is vulnerable. Explain how `shell=True` turns user input into **CWE-78**, and how an argument array (`["ping","-c","1",host]`) removes the shell.

`shell=True passes the whole string to a shell, which parses special characters like ; and |. So 127.0.0.1;id runs ping, then runs id as a separate command. An argument array skips the shell entirely — the OS runs ping directly, with host as one literal value, never interpreted as command syntax.`

3. Distinguish **input validation** (allow-list) from **output handling**. Why is validation alone insufficient defense for SQLi?

`Validation checks input matches an expected shape before use. Output handling controls how data is used at the actual sensitive point, like a parameterized query. Validation alone isn't enough for SQLi because it's easy to miss an edge case — a parameterized query guarantees safety regardless of what validation caught.`

4. The `/upload` route saves any filename to disk (**CWE-434**). What two properties must a directory and a filename have for an upload to become remote code execution, and which does `solution_app.py` remove?

`The directory needs to be web-served or executed by something, and the filename/extension needs to be something that actually runs (like .php or .py). solution_app.py fixes the second one, restricting extensions — this lab's upload directory was never served in the first place.`

5. What is a **UNION-based** SQLi, and why must the injected `SELECT` return the same number of columns as the original query? Relate to `/search?q=' UNION SELECT username,password FROM users--`.

`UNION-based SQLi appends a second SELECT to the original query, combining both results into one response. SQL requires both SELECTs to return the same number of columns, so UNION SELECT username,password FROM users-- only works if the original query also returns 2 columns — then usernames and passwords come back disguised as normal search results.`

![One untrusted request value in the Week 4 lab fans out to three interpreters — the SQL engine (CWE-89), the OS shell (CWE-78) and the filesystem (CWE-434) — with the specific control that stops it at each sink: a parameterised query, an argument vector without a shell, and an extension allow-list.](img/injection-sinks.svg)

## Part 3 — Hands-on Lab (150 min)

**Learning goals:** extract data via SQLi, achieve OS command injection, exploit an unrestricted upload, then prove each fix in `solution_app.py` blocks the payload.

**Prerequisites:** Docker + Docker Compose, `curl`, a browser. Working dir: `labs/week04-injection/`.

### Environment setup

```bash
cd labs/week04-injection
docker compose up            # builds python:3.12-slim, installs flask, runs vulnerable_app.py
# vulnerable app -> http://localhost:8080   (service name: injection-lab, port 8080)
```
Optional secondary targets:
```bash
docker run --rm -it -p 80:80 vulnerables/web-dvwa        # DVWA  -> http://localhost
docker run --rm -p 3000:3000 bkimminich/juice-shop       # Juice Shop -> http://localhost:3000
```

**What to submit per task:** the exact **payload/command**, a **screenshot** of the response proving success, and a **2–3 sentence mitigation** in your own words.

---

**Task 0 — Onboarding (5 min).** Browse to `http://localhost:8080/login?user=alice&pw=alicepw` and confirm `Welcome alice`. Note the seeded users (`alice`, `bob`). Screenshot the working app. *Deliverable: screenshot.*
![alt text](<Screenshot 2569-09-11 at 15.13.22.png>)

**Before you start — see why concatenation is the flaw** 🔬 Type any input and watch which characters the database will parse as *SQL* rather than as a name. The point is not the payload; it is that with concatenation the input becomes syntax, and with a parameterised query it structurally cannot. You will be asked to state that difference in your own words in Task 5.

```sim
sqli-parse
```

**Task 1 — Auth bypass via SQLi (25 min) 🐉 Hit #1.**
- *Goal:* log in as `alice` with **no valid password**.
- *Steps:* hit `/login?user=alice'--&pw=x`, then `/login?user=x' OR '1'='1'--&pw=x` (the trailing `--` is required: without it, SQL binds `AND` tighter than `OR`, so `... OR '1'='1' AND password='x'` matches no row). Observe the comment in the query at lines 61–63 of `vulnerable_app.py`.
- *Deliverable:* both URLs + screenshot of `Welcome alice` + explain why `--` and `OR '1'='1` work.

>First Payload - http://localhost:8080/login?user=alice%27--&pw=x
![alt text](<Screenshot 2569-09-11 at 15.15.55.png>)

>Second Payload - http://localhost:8080/login?user=x%27%20OR%20%271%27=%271%27--&pw=x
![alt text](<Screenshot 2569-09-11 at 15.19.38.png>)

`The -- starts a SQL comment, so everything after it in the query (like the AND password = '...' check) gets ignored entirely by the database.`

`OR '1'='1' is always true, so even without the trailing comment, adding this to the WHERE clause makes the condition match every row, not just the one with a correct password — but without the --, the original AND password='x' would still apply too, since AND binds tighter than OR in SQL's operator precedence, so the comment is what actually neutralizes the password check.`

**Task 2 — Credential dump via UNION SQLi (30 min) 🐉 Hit #2.**
- *Goal:* exfiltrate every username **and password** from the `users` table.
- *Steps:* request `/search?q=' UNION SELECT username,password FROM users--`. Confirm `alice:alicepw` and `bob:bobpw` appear.
- *Deliverable:* payload + screenshot of dumped credentials + note on why column count must match.
![alt text](<Screenshot 2569-09-11 at 15.21.05.png>)

`Why column count must match: The original /search query returns two columns. The injected SELECT username,password also returns two columns, so SQLite can line them up and combine both result sets with UNION. If the counts didn't match, the query would fail with an error instead of returning data.`

**Task 3 — OS command injection (30 min) 🐉 Hit #3.**
- *Goal:* run an arbitrary command through `/ping`.
- *Steps:* request `/ping?host=127.0.0.1;id` then `/ping?host=$(whoami)` (URL-encode if needed). Capture the injected command's output.
- *Deliverable:* both payloads + screenshot of `id`/`whoami` output + explanation of the `shell=True` flaw (CWE-78).

>/ping?host=127.0.0.1;id
![alt text](<Screenshot 2569-09-11 at 15.28.39.png>)

>/ping?host=$(whoami)
![alt text](<Screenshot 2569-09-11 at 15.38.51.png>)

`Why this works: shell=True runs the whole string through a shell, which reads ; as a command separator and $() as command substitution. So 127.0.0.1;id runs ping, then runs id separately — CWE-78.`

**Task 4 — Unrestricted upload (25 min) 🐉 Hit #4.**
- *Goal:* show the upload accepts a dangerous file type with no checks (CWE-434).
- *Steps:* `GET /upload` (form), then upload a file named `shell.py`. Confirm `saved to /tmp/uploads/shell.py`. Discuss: if `UPLOAD_DIR` were web-served or executed, this is the RCE chain (here the dir is **not** served, so document the missing control rather than claiming auto-RCE).
- *Deliverable:* upload command/screenshot + 2–3 sentences on why extension allow-listing matters.

![alt text](<Screenshot 2569-09-11 at 15.44.40.png>)

`Why extension allow-listing matters: without it, the server accepts any file type, including executable scripts like .py, .php, or .sh. If the upload directory is ever web-served or reached by another process, those files can run as code — turning a simple upload feature into remote code execution. An allow-list restricts uploads to safe, non-executable types (like .txt, .png, .pdf), so even a misconfigured directory can't be weaponized this way.`

**Task 5 — Defend / fix it (35 min) 🛡️ Boss defeated.**
- *Goal:* prove `solution_app.py` blocks Tasks 1–4.
- *Steps:* stop the vulnerable container (`Ctrl-C`), then run the fixed app on the same compose env:
  ```bash
  docker compose run --rm --service-ports injection-lab bash -c "pip install --no-cache-dir flask && python solution_app.py"
  ```
  Re-fire each payload from Tasks 1–4. Expected: `Login failed`, no credential dump, `invalid host` (400) on `127.0.0.1;id`, and `file type not allowed` for `shell.py`.
- *Deliverable:* screenshots of all four failures + name the fix line for each (parameterized query L52–55 login / L62–66 search, `shell=False`+regex L74–77, `secure_filename`+allow-list L86–93).

>Task 1 Re-run
![alt text](<Screenshot 2569-09-11 at 15.49.47.png>)
![alt text](<Screenshot 2569-09-11 at 16.01.44.png>)
>Task 2 Re-run
![alt text](<Screenshot 2569-09-11 at 15.53.29.png>)
>Task 3 Re-run
![alt text](<Screenshot 2569-09-11 at 15.58.55.png>)
![alt text](<Screenshot 2569-09-11 at 16.04.08.png>)
>Task 4 Re-run
![alt text](<Screenshot 2569-09-11 at 16.05.44.png>)
L52–55: parameterized query for /login
L62–66: parameterized query for /search
L74–77: shell=False + regex validation for /ping
L86–93: secure_filename + allow-list for /upload

## Part 4 — Reflection

1. **CWE/OWASP mapping:** map each of your four exploits to its CWE (89/78/434) and to OWASP 2025 **A05 Injection**.
>SQLi auth bypass = CWE-89, UNION dump = CWE-89, command injection = CWE-78, unrestricted upload = CWE-434 — all map to OWASP A05 Injection.

2. **Real breach:** the **2017 Equifax breach** exposed ~147M people after attackers exploited a known input-handling flaw (Apache Struts CVE-2017-5638). In 3–4 sentences, connect that failure to the lessons in this lab (untrusted input reaching a powerful interpreter; the cost of an unpatched/unvalidated input path).
>The 2017 Equifax breach came from an unpatched Apache Struts flaw (CVE-2017-5638) that let attackers send crafted input straight to a powerful interpreter, exposing 147M people's data. Same root cause as this lab: untrusted input reaching a system that treats it as code, not data — and an unpatched/unvalidated path left it exploitable for months.

3. **Best mitigation:** of parameterized queries, allow-list validation, least privilege, and avoiding `shell=True`, which single control would have prevented the most damage in this lab, and why?
>Parameterized queries prevented the most damage here — they close both the auth bypass and the credential dump, the two most severe findings, by making it structurally impossible for user input to become SQL syntax.

## Grading rubric (100)

| Criterion | Points |
|-----------|-------:|
| Part 2 — Lecture questions (conceptual accuracy) | 20 |
| Part 3 — Exploitation + evidence (payloads + screenshots, Tasks 1–4) | 40 |
| Part 3 — Defense (Task 5: fixes proven, lines cited) | 25 |
| Part 4 — Reflection (CWE/OWASP mapping, breach, mitigation) | 15 |
| **Total** | **100** |

---

## Evidence & Integrity (required)

- **Identity proof:** every screenshot/diagram must show a terminal running `printf '%s | %s | ' "$(whoami)" '<YOUR-STUDENT-ID>'; date '+%F %T %Z'` **in the
  same image as the evidence**. When the evidence is a browser page, a DevTools panel or a
  rendered response, put that terminal **beside the browser and capture the whole screen** — a
  cropped window carries nothing that identifies you, and the lab's own output is
  byte-identical for the whole cohort *by design*, so the stamp is the only thing that makes
  the shot yours. Generic or borrowed evidence is not accepted.
- **Personalized flag (if this lab issues one):** FLAG{sqli_demo}
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
  1. What did you do, and **why did the vulnerability work**?
  >I sent SQLi payloads to /login and /search, command injection to /ping, and an unrestricted upload to /upload. They worked because the app built SQL and shell commands by concatenating raw user input, and accepted any filename with no checks.

  2. **Why does your fix actually stop it** — and what could still break it?
  >solution_app.py uses parameterized queries, shell=False with input validation, and filename sanitization with an extension allow-list — user input can never become code in any of the four sinks. What could still break it: a future route that reuses string concatenation instead of the same safe patterns.

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.
-Prompt given: "Fix the SQL injection in the /login route."

-AI's answer:
```py
@app.route("/login")
def login():
    user = request.args.get("user", "")
    pw = request.args.get("pw", "")
    q = "SELECT * FROM users WHERE user=? AND pw=?"
    row = db.execute(q, (user, pw)).fetchone()
    return f"Welcome {user}" if row else "Login failed"
```
2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).
What's wrong: Column names are guessed (user, pw) without checking the real schema — could be username/password instead, causing a runtime error rather than a working fix.

3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.
```py
@app.route("/login")
def login():
    user = request.args.get("user", "")
    pw = request.args.get("pw", "")
    q = "SELECT * FROM users WHERE username=? AND password=?"
    row = db.execute(q, (user, pw)).fetchone()
    return f"Welcome {user}" if row else "Login failed"
```
> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.

>/login builds a SQL query by pasting the user parameter directly into the query string. Since there's no separation between code and data, an attacker can inject SQL syntax like ' OR '1'='1'-- to bypass the password check entirely.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*

>Prompt: "Rewrite /login to use a parameterized query with ? placeholders, matching the actual column names in the users table. Show the corrected route."
>Result: Query now uses ? placeholders bound via (user, pw). Re-ran the auth bypass payload — got Login failed instead of Welcome alice. Fix confirmed.
