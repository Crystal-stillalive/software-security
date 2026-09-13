# Worksheet 5 — Cross-Site Scripting & Client-Side Risks (3 hrs)

> **Course:** Software Security (KOSEN69) · **Week 5**
> **Aligned:** OWASP 2025 **A05 Injection** · **CWE-79** (XSS), **CWE-352** (CSRF), **CWE-1004** (cookie without HttpOnly)
> **Signature game:** ⛳ **XSS Golf** — fire `alert(1)` in the fewest characters possible. Lower payload length = lower score = better. Par for reflected is the `<img>` vector; can you go under par?

> ⚠️ **Ethics note:** Use only the provided `vulnerable_app.py` sandbox and your own Juice Shop container. Stealing real users' cookies or sessions is illegal. All "session theft" steps here target the sandbox cookie `session=abc123` only.

## Part 1 — Student Information

| Name | Student ID | Date | Group |
|------|-----------|------|-------|
| Pyae Shunn Le Maung | 6631503084 | 13.9.2027 | - |

## Part 2 — Lecture Questions

Answer in 2–4 sentences each.

1. Distinguish **reflected**, **stored**, and **DOM-based** XSS by *where* the untrusted data is injected and *when* it executes. Which two does our `vulnerable_app.py` implement, and at which routes?

Reflected XSS executes immediately from the request, no storage. Stored XSS saves the payload server-side and runs for every future visitor. DOM-based never touches the server — pure client-side JS. This app does reflected (/hello) and stored (/comments).

2. How does **contextual output encoding** (`markupsafe.escape`) stop `<script>` from executing? Why is HTML-context encoding different from JavaScript- or URL-context encoding?

markupsafe.escape converts <, >, " into HTML entities, so the browser renders them as text, not tags. HTML encoding differs from JS/URL encoding because each context has different special characters — using the wrong one can still leave a payload exploitable.

3. Explain how a strict **Content-Security-Policy** (`script-src 'self'`) defeats an *injected* inline script even when encoding is missing.

script-src 'self' tells the browser to only run scripts from the site's own origin, blocking any injected inline script or onerror handler even if encoding is missing.

4. What do the cookie flags **HttpOnly**, **SameSite**, and **Secure** each protect against? Map each to a concrete attack (cookie theft via XSS, CSRF, network sniffing).

HttpOnly blocks JS from reading the cookie (stops cookie theft via XSS). SameSite blocks the cookie from being sent cross-site (stops CSRF). Secure blocks the cookie over plain HTTP (stops network sniffing).

5. Why does **CSRF** (CWE-352) work even without any script injection, and how does `SameSite=Strict` plus the same-origin policy blunt it?

CSRF forges a request the victim's browser sends with their real cookie attached automatically, no script needed. SameSite=Strict blocks it by refusing to send the cookie on requests from another site.

## Part 3 — Hands-on Lab (150 min)

![Stored XSS carries the attacker's payload through the server to the victim, where it runs in the victim's origin and reads the cookie, while CSRF runs the opposite way and has the victim's own browser attach that cookie to the attacker's forged POST.](img/xss-and-csrf.svg)

**Learning goals:** land reflected + stored XSS, abuse a JS-readable cookie, build a CSRF PoC against the comment board, then prove `fixed_app.py` blocks all of it.

**Prerequisites:** Docker + Docker Compose, a browser with DevTools, a text editor. Working dir: `labs/week05-xss-client-side/`.

### Environment setup

```bash
cd labs/week05-xss-client-side
docker compose up            # python:3.12-slim + flask, runs vulnerable_app.py
# vulnerable app -> http://localhost:8080   (service name: xss-lab, port 8080)
```
Optional secondary target (for DOM XSS, which our app does not expose):
```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop       # -> http://localhost:3000
```

**What to submit per task:** the exact **payload**, a **screenshot** of the alert/effect, and a **2–3 sentence mitigation**.

---

**Task 0 — Onboarding (5 min).** Browse `http://localhost:8080/`. Open DevTools → Application → Cookies and confirm `session=abc123` is set with **no HttpOnly / SameSite**. Screenshot it. *Deliverable: screenshot.*
![alt text](<Screenshot 2569-09-13 at 15.30.48.png>)

**Task 1 — Reflected XSS + XSS Golf (30 min) ⛳.**
- *Goal:* execute JS via `/hello`, then minimize the payload.
- *Steps:* visit `/hello?name=<script>alert(1)</script>`, then the alternate `/hello?name=<img src=x onerror=alert(1)>` (useful when `<script>` tags specifically are filtered — note it's actually 3 characters longer, not shorter). Record each payload's character count for your golf score.
- *Deliverable:* both payloads + char counts + screenshot of `alert(1)` + your lowest score.

![alt text](<Screenshot 2569-09-13 at 15.33.27.png>)
![alt text](<Screenshot 2569-09-13 at 16.07.55.png>)

**Task 2 — Stored XSS (30 min) ⛳.**
- *Goal:* persist a script that runs for every visitor of `/comments`.
- *Steps:* POST a comment with body `<script>alert(document.cookie)</script>` (use the form or `curl -d 'body=...'`). Reload `/comments` and watch the cookie pop.
- *Deliverable:* payload + screenshot of the alert showing `session=abc123` + why stored XSS is more dangerous than reflected.
![alt text](<Screenshot 2569-09-13 at 19.34.55.png>)

**Task 3 — Cookie theft via XSS (25 min).**
- *Goal:* show the cookie is readable by injected JS because **HttpOnly is missing** (CWE-1004).
- *Steps:* store `<script>new Image().src='http://localhost:8080/hello?name='+document.cookie</script>` (a beacon), or simply `<img src=x onerror=alert(document.cookie)>`. Observe the cookie value being exfiltrated/displayed.
- *Deliverable:* payload + screenshot + 2–3 sentences on how HttpOnly would have stopped this.
![alt text](<Screenshot 2569-09-13 at 19.36.23.png>)

**Task 4 — CSRF PoC (30 min).**
- *Goal:* make a third-party page force a state-changing POST to `/comments`.
- *Steps:* create a local `csrf.html` with an auto-submitting form targeting the board (no token exists, cookie has no SameSite, so the browser attaches `session` cross-site):
  ```html
  <body onload="document.forms[0].submit()">
    <form action="http://localhost:8080/comments" method="POST">
      <input name="body" value="CSRF posted this comment">
    </form>
  </body>
  ```
  Open the file and confirm the comment appears on `/comments`.
- *Deliverable:* the HTML + screenshot of the forged comment + why `SameSite=Strict` blocks it.

```sim
xss-context
```
```html
<body onload="document.forms[0].submit()">
  <form action="http://localhost:8080/comments" method="POST">
    <input name="body" value="CSRF posted this comment">
  </form>
</body>
```

![alt text](<Screenshot 2569-09-13 at 19.44.53.png>)

SameSite=Strict blocks this because it prevents the browser from attaching the session cookie to any request originating from a different site — including this local csrf.html file. Without the cookie attached, the server has no way to tie the forged POST to a logged-in session.

**Task 5 — Defend / fix it (30 min) 🛡️.**
- *Goal:* prove `fixed_app.py` blocks Tasks 1–3, then show that Task 4's CSRF PoC still gets through and explain why.
- *Steps:* stop the vulnerable container (`Ctrl-C`), then:
  ```bash
  docker compose run --rm --service-ports xss-lab bash -c "pip install --no-cache-dir flask && python fixed_app.py"
  ```
  Re-fire each payload. Expected: `/hello` renders the script **as text** (escape, L21), stored comments render literally (Jinja autoescape, L30–33), a strict CSP header is now present as defense-in-depth (`Content-Security-Policy: script-src 'self'`, L12 — check DevTools → Network → Response Headers; escaping already neutralizes these payloads, so no CSP *violation* fires in the console), and the cookie now has `HttpOnly; SameSite=Strict; Secure` (L42). Then re-run Task 4's `csrf.html` PoC against `fixed_app.py`: it **still posts the forged comment** — `/comments` (L25–28) never checks the `session` cookie or a CSRF token before accepting a POST, so hardening the cookie only stops the browser from *attaching* it cross-site; it doesn't stop the request itself from being processed.
- *Deliverable:* screenshots of escaped output + the CSP response header + the hardened cookie flags + the still-successful Task 4 forgery against `fixed_app.py`, with 2–3 sentences on why cookie hardening alone doesn't close CSRF here (no server-side check tied to the cookie, and no CSRF token).
![alt text](<Screenshot 2569-09-13 at 19.51.43.png>)
![alt text](<Screenshot 2569-09-13 at 20.00.35.png>)
![alt text](<Screenshot 2569-09-13 at 20.06.46.png>)
![alt text](<Screenshot 2569-09-13 at 20.09.34.png>)
![alt text](<Screenshot 2569-09-13 at 20.12.12.png>)

fixed_app.py correctly escapes both reflected (/hello) and stored (/comments) XSS via markupsafe.escape() and Jinja autoescape — injected <script> tags render as literal text, no execution. A strict CSP (default-src 'self'; script-src 'self'; object-src 'none') is present as defense-in-depth. The session cookie now has HttpOnly, Secure, and SameSite=Strict all set (confirmed via DevTools and raw Set-Cookie header). However, re-running the Task 4 CSRF PoC against this hardened app still succeeds — /comments never checks the session cookie or a CSRF token before accepting a POST. Cookie hardening only stops the browser from attaching the cookie cross-site; it doesn't stop the server from processing an unauthenticated-looking request. Closing this fully would require a server-side CSRF token validated on every state-changing request.

## Part 4 — Reflection

1. **CWE/OWASP mapping:** map your reflected/stored XSS to **CWE-79** and your CSRF PoC to **CWE-352**, both under OWASP 2025 **A05 Injection** (CSRF historically A01/A05).
- Reflected/stored XSS = CWE-79 → OWASP A05 Injection. CSRF = CWE-352 → OWASP A05 Injection (historically A01).

2. **Real breach:** the **2018 British Airways breach** (~380k payment records) used malicious JavaScript (Magecart) injected into the site to skim card data — a client-side script-injection failure. In 3–4 sentences relate it to this lab's XSS and CSP lessons.
- The 2018 British Airways breach used injected JavaScript (Magecart) to skim card data directly from the page. This is the same class of failure as this lab's XSS — untrusted script running in a trusted origin. A strict CSP (script-src 'self') like the one in fixed_app.py would have blocked the injected skimmer from executing at all, since it only came from an unauthorized source, not the site's own scripts.

3. **Best mitigation:** between output encoding, a strict CSP, and HttpOnly+SameSite cookies, which gives the broadest defense-in-depth, and why is "encoding alone" still risky?
- A strict CSP gives the broadest defense-in-depth — it blocks script execution even if encoding is missed somewhere else in the app. Encoding alone is risky because a single missed output point (a new route, an overlooked template) silently reopens the vulnerability with no second layer of defense to catch it.

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
- **Personalized flag (if this lab issues one):** ____________________
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
  1. What did you do, and **why did the vulnerability work**?
- I injected <script> and <img onerror> payloads into /hello and /comments, and built a CSRF PoC targeting /comments. The XSS worked because user input was rendered directly into HTML with no encoding, so the browser executed it as real script. The CSRF worked because the app never checked for a token, and the cookie had no SameSite restriction, so the browser attached it automatically to a cross-origin request.

  2. **Why does your fix actually stop it** — and what could still break it?
- fixed_app.py escapes output via markupsafe.escape() and Jinja autoescape, so injected tags render as visible text, not code. The CSP adds a second layer blocking any script not from the app's own origin. The cookie now has HttpOnly, Secure, and SameSite=Strict. What still breaks: CSRF still works, since none of these fixes check whether the request itself came from a legitimate source — that requires a separate CSRF token the fixes don't add.

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.
- Prompt given to the AI: "Fix the XSS vulnerability in the /hello route."

- AI's answer:
```py
@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    name = name.replace("<script>", "").replace("</script>", "")
    return f"Hello {name}"
```
2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).
- Blacklisting the literal string <script> only blocks that one specific vector. <img src=x onerror=alert(1)> sails right through completely untouched, since it never contains the word "script."

3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.
```py
from markupsafe import escape
@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return f"Hello {escape(name)}"
```
The AI treated XSS as a specific-tag problem and tried to filter one known payload, instead of treating it as an output-encoding problem that needs to hold for any input. Blacklisting individual patterns is always incomplete; proper encoding closes the whole class of vulnerability at once.

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.
- /hello takes the name parameter and inserts it directly into the HTML response with no encoding. Since the browser can't distinguish user data from real markup, an attacker can inject a <script> tag that executes as real code the moment the page loads.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*

- Prompt: "Fix the XSS vulnerability in /hello by using markupsafe.escape() on user input before rendering it, instead of blacklisting specific tags."

Result: Re-ran <script>alert(1)</script> after applying this fix — it rendered as literal visible text on the page instead of popping an alert, confirmed working, no refinement needed.