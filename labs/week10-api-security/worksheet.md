# Worksheet 10 — API Security (3 hrs)

> **Course:** Software Security (KOSEN69) · Week 10
> **Aligned:** OWASP API Security Top 10:2023 — API1 BOLA · API3 Broken Object Property Level Auth (Mass Assignment) · API4 Unrestricted Resource Consumption
> **Signature game:** 🥷 crAPI Raid
>
> **Ethics note:** Run exploits **only** against the lab targets shipped here (`vulnerable_api.py` on `:8080`) or your own OWASP crAPI instance. Never test BOLA, mass assignment, or brute-force against systems you do not own or are not explicitly authorized to test.

## Part 1 — Student Information

| Name | Student ID | Date | Group |
|------|-----------|------|-------|
|      |           |      |       |

## Part 2 — Lecture Questions

1. Define **BOLA (API1:2023)**. Why is it the #1 API risk, and why can't a WAF reliably stop it?
2. What is **mass assignment / broken object property level authorization (API3:2023)**? Contrast a blocklist vs. an allow-list of bindable fields.
3. **API4:2023** is unrestricted resource consumption. Give two distinct impacts (security and availability) of an unthrottled `/api/login`.
4. In `vulnerable_api.py`, `current_user()` trusts the `X-User-Id` header. Why is a client-supplied header NOT authentication, and what should replace it?
5. Why does object-level authorization have to be checked **per request, per object** rather than once at login?

## Part 3 — Hands-on Lab (145 min)

**Learning goals:** Exploit BOLA, mass assignment, and a missing rate limit against a live API; then read the secure version and explain each fix.

**Prerequisites:** Docker + Docker Compose, `curl`. (Optional bonus: cloned OWASP crAPI.)

**Environment setup**
```bash
cd labs/week10-api-security
docker compose up         # INSECURE API on :8080, SECURE API on :8081
# Seeded users: alice(id 1) bob(id 2) carol(id 3, admin, balance 9999)
```

**What to submit per task:** the exact command(s) + raw response/HTTP status, a screenshot, and a 2–3 sentence mitigation note mapping the bug to its OWASP API id.

### Task 0 — Onboarding (15 min)
Confirm both APIs respond: `curl http://localhost:8080/` and `curl http://localhost:8081/`. Note which port is insecure. Record the three seeded users.
**Deliverable:** both root responses + the user table.
![alt text](<Screenshot 2569-10-24 at 00.34.07.png>)
![One REST API with three flaws — reading another user's orders by id, smuggling an admin field into user creation, and an unthrottled login — each shown at the handler where it occurs, next to its one-line fix.](img/api-flaws.svg)

### Task 1 — BOLA: read another user's orders (35 min)
**Goal:** Read carol's (admin) orders without being carol — API1:2023.
**Steps:**
1. `curl http://localhost:8080/api/users/3/orders` — note you receive the "Server rack" order with no auth.
2. Iterate the id: `curl http://localhost:8080/api/users/2/orders`.
3. On the secure API observe the ladder: `curl -i http://localhost:8081/api/users/3/orders` (401), `curl -i -H "X-User-Id: 1" http://localhost:8081/api/users/3/orders` (403), `curl -i -H "X-User-Id: 1" http://localhost:8081/api/users/1/orders` (200).
**Deliverable:** the leaked order JSON + the 401/403/200 transcript + mitigation note.
![alt text](<Screenshot 2569-10-24 at 13.57.44.png>)
GET /api/users/<id>/orders on the insecure API returns any user’s orders with zero authentication — including carol’s admin order containing FLAG{bola_demo}. The root cause (API1:2023 BOLA) is a missing per-object ownership check: the endpoint never verifies that the requester is actually authorized to view the specific <id> they’re asking about. The secure API fixes this with a three-tier check: no header → 401, authenticated but not the owner/admin → 403, owner accessing their own data → 200.

### Task 2 — Mass assignment: self-promote to admin (30 min)
**Goal:** Smuggle `is_admin` + `balance` into user creation — API3:2023.
**Steps:**
1. `curl -X POST http://localhost:8080/api/users -H "Content-Type: application/json" -d '{"username":"mallory","password":"x","is_admin":true,"balance":1000000}'`
2. Confirm the response echoes `"is_admin": true, "balance": 1000000`.
3. Repeat against `:8081` and confirm the smuggled fields are forced to `is_admin:false, balance:0`.
**Deliverable:** both responses side by side + mitigation note (allow-list in `solution_api.py`).
![alt text](<Screenshot 2569-10-24 at 14.01.14.png>)
POST /api/users on the insecure API binds the entire JSON request body directly onto the new user object, letting an attacker smuggle in is_admin and balance — fields that should only ever be set server-side. This is API3:2023 Mass Assignment. The secure API fixes this with an allow-list (ALLOWED_CREATE_FIELDS) that only accepts explicitly named safe fields (username, password), silently discarding anything else regardless of what’s in the request — confirmed by is_admin:false, balance:0 even though both were sent as true/1000000.

### Task 3 — Unrestricted resource consumption: brute-force login (25 min)
**Goal:** Show `/api/login` has no throttle — API4:2023.
**Steps:**
1. Run the brute-force loop from `attack.md` against `:8080` (guesses incl. `alice123`) — all attempts processed.
2. On `:8081` loop 7 times: `for i in $(seq 1 7); do curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8081/api/login -H "Content-Type: application/json" -d '{"username":"alice","password":"wrong"}'; done`
3. Confirm the 6th/7th attempt returns `429`.
**Deliverable:** the `401 401 401 401 401 429 429` sequence + mitigation note.
![alt text](<Screenshot 2569-10-24 at 14.06.26.png>)
/api/login on the insecure API processes every login attempt with no throttle, allowing unlimited password guesses — confirmed by brute-forcing alice’s password through 4 attempts until alice123 succeeded. This is API4:2023 Unrestricted Resource Consumption. The secure API fixes this with a rate limiter capping attempts at 5 per 60-second window; the 6th and 7th attempts both return 429 Too Many Requests instead of processing the guess.

### Task 4 — Bonus: crAPI Raid (optional, 20 min)
Against your own OWASP crAPI instance (`git clone https://github.com/OWASP/crAPI.git`), capture one BOLA or mass-assignment flag.
**Deliverable:** flag + endpoint + which API Top 10 id it maps to.

### Task 5 — Defend / fix it (20 min)
**Goal:** Explain the fixes using the secure reference `solution_api.py`.
**Steps:** Read the three `# --- FIX ...` blocks. For each, quote the line(s) that defeat your Task 1–3 exploit: the per-object ownership check (`caller["id"] != uid and not caller["is_admin"]`), `ALLOWED_CREATE_FIELDS` binding, and the `RATE_LIMIT=5 / RATE_WINDOW=60` limiter.
**Deliverable:** for each of API1/API3/API4 — the exploit that worked on `:8080`, the line in `solution_api.py` that blocks it, and the new HTTP status on `:8081`.
![alt text](<Screenshot 2569-10-24 at 15.55.44.png>)

| Finding (OWASP ID) | Exploit that worked on :8080 | Fix line in `solution_api.py` | New status on :8081 |
|---|---|---|---|
| **API1 (BOLA)** | `curl http://localhost:8080/api/users/3/orders` → leaked `FLAG{bola_demo}` | `if caller["id"] != uid and not caller["is_admin"]: return ... 403` (line 51-52) | 401 (no header) / 403 (wrong user) / 200 (owner/admin) |
| **API3 (Mass Assignment)** | `POST /api/users` with `is_admin:true` → smuggled through, got `FLAG{massassign_demo}` | `user = {k: body[k] for k in ALLOWED_CREATE_FIELDS if k in body}` (line 62) | 200, but `is_admin:false, balance:0` regardless of input |
| **API4 (Rate Limiting)** | Brute-force loop → all 4 guesses processed, `alice123` succeeded | `RATE_LIMIT = 5` / `RATE_WINDOW = 60` + `rate_limited(ip)` (lines 73-80) | 401×5 then 429×2 |

## Part 4 — Reflection

1. **Mapping:** complete a table — finding | endpoint | OWASP API id | fix applied.
   | Finding | Endpoint | OWASP API ID | Fix Applied |
   |---|---|---|---|
   | BOLA | `GET /api/users/<id>/orders` | API1:2023 | Per-object ownership check |
   | Mass assignment | `POST /api/users` | API3:2023 | Allow-list binding |
   | No rate limit | `POST /api/login` | API4:2023 | Per-IP rate limiter (5/60s) |


2. **Real breach:** research an API authorization breach (e.g., the Optus or T-Mobile BOLA/IDOR incidents). Which API Top 10 id matches, and would the `solution_api.py` ownership check have prevented it?

>The 2022 Optus breach exposed millions of customer records through an API that let identifiers be enumerated with no per-object authorization check — a textbook BOLA (API1:2023), the same class as Task 1 here. The ownership check in `solution_api.py` would have directly prevented it, since every request would have been checked against the actual authenticated caller's identity before returning data, rather than trusting whatever ID appeared in the URL.
3. **Best mitigation:** of object-level auth, allow-list binding, and rate limiting — which gives the most risk reduction for an API platform, and why?
>Object-level authorization gives the most risk reduction — even if rate limiting or allow-list binding were both missing, a correct ownership check alone stops the single most damaging outcome (one user reading or modifying another user's data) at the final point before any response leaves the server. Server-side authorization is non-negotiable because it's the only control that can't be bypassed client-side.

## Grading rubric (100)

| Criterion | Weight |
|-----------|--------|
| Lecture questions (Part 2) | 20 |
| Exploitation + evidence (Tasks 1–4: commands, output, screenshots) | 40 |
| Defense (Task 5: fixes mapped to `solution_api.py`) | 25 |
| Reflection (Part 4: mapping, breach, best mitigation) | 15 |
| **Total** | **100** |

---

## Evidence & Integrity (required)

- **Identity proof:** every screenshot/diagram must show a terminal running `printf '%s | %s | ' "$(whoami)" '<YOUR-STUDENT-ID>'; date '+%F %T %Z'` **in the
  same image as the evidence**. When the evidence is a browser page, a DevTools panel or a
  rendered response, put that terminal **beside the browser and capture the whole screen** — a
  cropped window carries nothing that identifies you, and the lab's own output is
  byte-identical for the whole cohort *by design*, so the stamp is the only thing that makes
  the shot yours. Generic or borrowed evidence is not accepted.
- **Personalized flag (if this lab issues one):** ___FLAG{bola_demo}, FLAG{massassign_demo}___
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
  1. What did you do, and **why did the vulnerability work**?
  >I read carol's admin orders via `/api/users/3/orders` with zero authentication, smuggled `is_admin:true` and `balance:1000000` into a new user via `POST /api/users`, and ran repeated login attempts against `/api/login` with no throttling. These worked because the insecure API trusted a client-supplied ID with no ownership check, bound every field from the request body directly onto the new object, and had no rate limiter at all.
  2. **Why does your fix actually stop it** — and what could still break it?
  >`solution_api.py` adds a per-object ownership check, an allow-list restricting bindable fields, and a per-IP rate limiter. Retesting confirmed all three work: 403/401 on BOLA, `is_admin:false/balance:0` on mass assignment, 429 after 5 login tries. What could still break it: if a future endpoint reused the old pattern (trusting a client-supplied ID or binding the whole request body), the same vulnerability class would reappear there.

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.
**AI's answer:**
```python
@app.route("/api/users/<int:uid>/orders")
def get_orders(uid):
    caller = current_user()
    if caller["id"] != uid:
        return jsonify(error="forbidden"), 403
    return jsonify(orders[uid])
```

2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).
>This blocks every user from viewing anyone else's orders — including a legitimate admin, who should be allowed to view any user's orders (carol is seeded as `is_admin: True` specifically to test this). It also doesn't handle `caller is None` (no auth at all), which would crash trying to index `None["id"]` instead of returning a clean 401.
3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.
**My corrected version** (matches the actual `solution_api.py`):
```python
@app.get("/api/users/<int:uid>/orders")
def get_orders(uid):
    caller = current_user()
    if caller is None:
        return jsonify({"error": "authentication required"}), 401
    if caller["id"] != uid and not caller["is_admin"]:
        return jsonify({"error": "forbidden"}), 403
```

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.
>`/api/users/<id>/orders` returns whatever order matches the ID in the URL with no check on who's asking. Since IDs are just sequential numbers, anyone can read any user's orders — including the admin's, which contains a sensitive flag — just by changing the number.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*

>Prompt: "Fix the BOLA vulnerability in `/api/users/<id>/orders` by adding a check that the authenticated caller either owns the requested user ID or is an admin, returning 401 if unauthenticated and 403 otherwise."
>Result: Re-ran the exploit after applying this fix — a request for carol's orders using alice's identity now returns 403 instead of leaking FLAG{bola_demo}, and a request with no auth header returns 401 instead of crashing. Fix confirmed against the real `solution_api.py`.