# Worksheet 6 — Authentication, Sessions & Access Control (3 hrs)

> **Course:** Software Security (KOSEN69) · **Week 6**
> **Aligned:** OWASP 2025 **A01 Broken Access Control**, **A07 Authentication Failures** · **CWE-639** (IDOR), **CWE-347** (improper signature verification), **CWE-321** (weak hardcoded key)
> **Signature games:** 🗺️ **IDOR Treasure Hunt** — walk the `oid` numbers to loot orders that aren't yours · 🔏 **JWT Forgery** — mint a token you were never given.

> ⚠️ **Ethics note:** Forging tokens and accessing other users' objects is only legal in this sandbox (`vulnerable_app.py`) and your own Juice Shop. Doing it to a real service is unauthorized access. Keep all activity inside `http://localhost:8080`.

## Part 1 — Student Information

| Name | Student ID | Date | Group |
|------|-----------|------|-------|
| Pyae Shunn Le Maung | 6631503084 | 13.9.2027 | |

![Diagram of one request passing two gates: Gate 1 authentication accepts an alg:none forgery, a weak-secret forgery, and alice's real token, then Gate 2 authorization fails to check ownership so alice's valid token reads bob's /api/orders/2 as IDOR, with the solution_app.py fixes for both.](img/authn-vs-authz.svg)

## Part 2 — Lecture Questions

Answer in 2–4 sentences each.

1. Distinguish **authentication** from **authorization**. In `vulnerable_app.py`, `get_order` calls `current_user()` but ignores its result (L63) — which of the two is missing?
- Authentication confirms who you are; authorization confirms what you're allowed to do. In get_order, calling current_user() but ignoring its result means authentication happens, but the missing piece is authorization — the code never checks whether the authenticated user actually owns the requested order.

2. What is **IDOR** (CWE-639)? Why is `/api/orders/<oid>` exploitable, and what single check in `solution_app.py` (L64) closes it?
- IDOR (Insecure Direct Object Reference) is when an app lets you access an object just by changing an ID in the request, with no check that you're allowed to see it. /api/orders/<oid> is exploitable because it fetches whatever order matches oid, regardless of who's asking. Line 64 in solution_app.py closes it by checking that the order's owner matches the authenticated user before returning it.

3. Explain the **`alg:none`** JWT attack. Why does listing `"none"` in `algorithms=[...]` (L55) let an attacker submit an *unsigned* token?
- The alg:none attack exploits JWT libraries that accept "none" as a valid signing algorithm, meaning a token with no signature at all is treated as valid. Listing "none" in algorithms=[...] tells the verification code to accept unsigned tokens, so an attacker can craft any claims they want (like {"sub": "bob"}) with zero knowledge of any secret key.

4. Why is the hardcoded HMAC secret `"secret"` (CWE-321) dangerous even if `alg:none` were disabled? How does a strong random secret + pinned algorithm defend the token?
- Even with alg:none disabled, a hardcoded, guessable secret like "secret" means an attacker can just sign a valid HS256 token themselves, since HMAC verification only checks that the signature matches — it doesn't care who generated it. A strong random secret makes brute-forcing infeasible, and pinning the algorithm (only allowing HS256, never none) closes the separate alg:none bypass entirely.

5. What do the JWT claims **`exp`** and **`aud`** add, and why does the secure version reject tokens that lack them?
- exp (expiration) limits how long a token stays valid, so a leaked or forged-but-expired token eventually stops working. aud (audience) ties a token to a specific intended recipient/service, so a token issued for one system can't be replayed against another. Rejecting tokens missing these fields prevents attackers from crafting tokens that live forever or work anywhere.

## Part 3 — Hands-on Lab (150 min)

**Learning goals:** exploit IDOR, forge JWTs two ways (`alg:none` and weak secret), then prove `solution_app.py` enforces ownership and rejects forged tokens. Steps mirror `attack.md`.

**Prerequisites:** Docker + Docker Compose, `curl`, `python3` with `pyjwt`, optionally Burp Suite. Working dir: `labs/week06-authn-authz/`.

### Environment setup

```bash
cd labs/week06-authn-authz
docker compose up            # python:3.12-slim + flask + pyjwt, runs vulnerable_app.py
# vulnerable app -> http://localhost:8080   (service name: authz-lab, port 8080)
```
Optional secondary target / proxy:
```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop       # -> http://localhost:3000
# Burp Suite: put the proxy listener AND the browser proxy on 127.0.0.1:8081.
# NOT 8080 — the lab app already owns host 8080 (docker-compose.yml, "8080:5000").
# Burp's own default listener is 8080, so you must change it: leave it there and
# either the listener refuses to start ("Address already in use") or, if it does
# bind, the browser's proxy address is the target's address and every request
# goes straight to the app instead of through Burp — you intercept nothing.
```

**What to submit per task:** the exact **command/token**, a **screenshot** of the JSON response, and a **2–3 sentence mitigation**.

---

**Task 0 — Onboarding (5 min).** Get alice's token (from `attack.md`):
```bash
TOKEN=$(curl -s -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"user":"alice","pw":"alicepw"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
echo "$TOKEN"
```
Confirm `/api/orders/1` returns alice's Laptop order. *Deliverable: screenshot of the token + order 1.*
![alt text](<Screenshot 2569-09-13 at 20.31.54.png>)

**Task 1 — IDOR Treasure Hunt (30 min) 🗺️.**
- *Goal:* read **bob's** order with **alice's** token.
- *Steps:*
  ```bash
  curl -s http://localhost:8080/api/orders/1 -H "Authorization: Bearer $TOKEN"   # yours
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $TOKEN"   # bob's — leaks!
  ```
- *Deliverable:* both responses + screenshot of bob's `Phone` order + why the missing ownership check (CWE-639) is the root cause.
![alt text](<Screenshot 2569-09-13 at 20.35.10.png>)
Both orders returned successfully despite alice's token being used for both requests. The root cause (CWE-639) is that get_order calls current_user() but never checks whether the returned user actually matches the order's owner — it only verifies who is asking, not whether they're allowed to see this specific object.
```sim
jwt-forge
```

**Task 2 — JWT Forgery via alg:none (30 min) 🔏.**
- *Goal:* impersonate bob with an **unsigned** token (no secret needed).
- *Steps:*
  ```bash
  FORGED=$(python3 - <<'PY'
  import jwt
  print(jwt.encode({"sub": "bob"}, key="", algorithm="none"))
  PY
  )
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED"
  ```
- *Deliverable:* the forged token + screenshot of the accepted response + explanation of the `none` flaw (CWE-347).
![alt text](<Screenshot 2569-09-13 at 20.37.51.png>)
The vulnerable app's jwt.decode() call includes "none" in its allowed algorithms list, so it accepts a token with no signature at all as valid. This lets an attacker forge any claims they want — here, {"sub": "bob"} — without ever needing to know the signing secret (CWE-347: improper verification of cryptographic signature).

**Task 3 — JWT Forgery via weak secret (30 min) 🔏.**
- *Goal:* sign a *valid* HS256 token because the secret is the guessable string `secret` (CWE-321).
- *Steps:*
  ```bash
  FORGED2=$(python3 - <<'PY'
  import jwt
  print(jwt.encode({"sub": "bob"}, "secret", algorithm="HS256"))
  PY
  )
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED2"
  ```
- *Deliverable:* token + screenshot + 2–3 sentences on why secret strength + key management matter.
![alt text](<Screenshot 2569-09-13 at 20.40.05.png>)
Unlike the alg:none attack, this token has a valid HS256 signature — it passes full cryptographic verification. The vulnerability is that the signing secret is the hardcoded, trivially guessable string "secret" (CWE-321) — notably, PyJWT itself flagged this as an InsecureKeyLengthWarning, since a 6-byte key falls far short of RFC 7518's recommended 32-byte minimum for HMAC-SHA256. Secret strength matters because HMAC security depends entirely on the secret being unpredictable and sufficiently long; a short or guessable secret makes the "signature" meaningless as proof of authenticity, since anyone can compute a correctly-signed token for any claims they want.

**Task 4 — Privilege/identity escalation reasoning (25 min).**
- *Goal:* combine the flaws. Using Task 2/3 you became `bob` *without his password*; using Task 1 you read objects you don't own.
- *Steps:* document the full attack chain (forge token → access any `oid`). Optionally replay the requests through **Burp Suite Repeater** and screenshot the intercepted request/response.
- *Deliverable:* a short chain diagram/paragraph + Burp (or curl) evidence.
**Task 4 — Privilege/identity escalation reasoning**

**Attack chain:**
1. Forge a token claiming to be "bob" — via `alg:none` (Task 2, no secret needed) or via the weak secret `"secret"` (Task 3, valid HS256 signature).
2. Present the forged token to `/api/orders/<oid>` — the server authenticates it as "bob" with no credentials ever provided.
3. Request any `oid`, regardless of ownership — the server never checks whether the authenticated identity (real or forged) actually owns that specific order (Task 1's IDOR).

**Result:** full impersonation of any user, plus unrestricted access to any object in the system, without ever knowing a real password.

**Why the chain matters:** the two flaws compound rather than existing independently. Broken authentication (Tasks 2/3) alone would still be limited to seeing bob's own data. Broken authorization (Task 1) alone would still require a real password first. Together, they let a single unauthenticated attacker read every order in the system.

**Evidence:** reused from Tasks 1–3 (screenshots of the forged tokens and the leaked `bob` order responses above). Burp Suite not used — curl evidence per the worksheet's alternative allowance.

**Task 5 — Defend / fix it (30 min) 🛡️.**
- *Goal:* prove `solution_app.py` blocks Tasks 1–3.
- *Steps:* stop the vulnerable container (`Ctrl-C`), then:
  ```bash
  docker compose run --rm --service-ports authz-lab bash -c "pip install --no-cache-dir flask pyjwt && python solution_app.py"
  ```
  Re-run: get a fresh alice token, then re-fire each attack. Expected: `/api/orders/2` with alice's token → **403 forbidden** (ownership check, L64); the `alg:none` token → **401 invalid token** (algorithm pinned to HS256, L50); the `"secret"` token → **401** (strong random secret + required `aud`/`exp`, L10/40).
- *Deliverable:* screenshots of the 403 and both 401s + name the fix line for each.
![alt text](<Screenshot 2569-09-13 at 20.45.32.png>)
![alt text](<Screenshot 2569-09-13 at 20.46.38.png>)
![alt text](<Screenshot 2569-09-13 at 20.47.34.png>)

## Part 4 — Reflection

1. **CWE/OWASP mapping:** map IDOR → **CWE-639 / A01**, the JWT forgeries → **CWE-347 & CWE-321 / A07**.
- IDOR → CWE-639 / OWASP A01 Broken Access Control. JWT forgeries (alg:none and weak secret) → CWE-347 & CWE-321 / OWASP A07 Authentication Failures.

2. **Real breach:** the **2022 Optus breach** exposed millions of customer records via an exposed/poorly-authorized API endpoint where identifiers could be enumerated — a textbook broken-access-control / IDOR-style failure. In 3–4 sentences connect it to Tasks 1 and 4 of this lab. 
*(Alternative: the Peloton API IDOR disclosure.)*
- The 2022 Optus breach exposed millions of customer records through an exposed API endpoint where identifiers could simply be enumerated — no proper check that the requester was authorized to see each specific record. This is the same pattern as Task 1 and Task 4 here: authentication alone (proving who you are) was treated as sufficient, when authorization (checking what that identity is allowed to access) was the actual missing control. Just like /api/orders/<oid> in this lab, sequential or guessable IDs plus no ownership check meant one valid session could pull data belonging to anyone.

3. **Best mitigation:** between deny-by-default ownership checks, pinning the JWT algorithm, and a strong managed secret, which control protects the most attack surface here, and why is server-side authorization non-negotiable?
- Deny-by-default ownership checks protect the most attack surface — even if authentication is completely broken (forged tokens, stolen credentials, anything), a proper ownership check still stops unauthorized data access at the last line of defense. Server-side authorization is non-negotiable because it's the only control that can't be bypassed client-side; pinning the algorithm and using a strong secret both matter, but they only protect the authentication layer — Task 4 proved that broken authorization compounds with broken authentication to create the worst-case outcome, and fixing authorization alone would have blocked the actual data leak even before the JWT issues were addressed.

## Grading rubric (100)

| Criterion | Points |
|-----------|-------:|
| Part 2 — Lecture questions (conceptual accuracy) | 20 |
| Part 3 — Exploitation + evidence (payloads/tokens + screenshots, Tasks 1–4) | 40 |
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
- **Personalized flag (if this lab issues one):** FLAG{idor_demo}
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
  1. What did you do, and **why did the vulnerability work**?
  - I read bob's order using alice's token (IDOR), then forged tokens claiming to be bob two ways — an unsigned alg:none token and a validly-signed token using the guessable secret "secret". The IDOR worked because the server checked who was asking but never checked whether that identity owned the specific order requested. The forgeries worked because the app trusted the alg field from the token itself (allowing "none") and used a weak, guessable signing secret.

  2. **Why does your fix actually stop it** — and what could still break it?
- solution_app.py adds a server-side ownership check comparing the authenticated user against the order's actual owner, pins the accepted algorithm to HS256 only (rejecting none entirely), and uses a strong random secret while requiring aud/exp claims. Retesting confirmed all three attacks now return 401/403. What could still break it: if the strong secret were ever hardcoded back into source control (same class of mistake as the original "secret"), or if a future endpoint forgot to include the same ownership check, the same vulnerability class would reappear elsewhere.
---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.
- Prompt given to the AI: "Fix the IDOR vulnerability in the /api/orders/<oid> endpoint."

- AI's answer:
```py
@app.route("/api/orders/<oid>")
def get_order(oid):
    user = current_user()
    order = orders.get(oid)
    if order["owner"] != user:
        return jsonify(error="forbidden"), 403
    return jsonify(order)
```
2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).
- This misses the case where current_user() returns None (no valid token at all) — if user is None and somehow order["owner"] is also None or unset, the comparison could pass incorrectly. It also doesn't handle the case where oid doesn't exist, which would crash with a KeyError/NoneType error on order["owner"] instead of returning a clean 404.
3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.
- My corrected version:
```py
@app.route("/api/orders/<oid>")
def get_order(oid):
    user = current_user()
    if not user:
        return jsonify(error="unauthorized"), 401
    order = orders.get(oid)
    if not order:
        return jsonify(error="not found"), 404
    if order["owner"] != user:
        return jsonify(error="forbidden"), 403
    return jsonify(order)
```
- The AI's fix correctly added the core ownership check, but skipped basic input validation — checking for missing authentication and missing/invalid order IDs — which are exactly the kind of edge cases that turn a clean 403 into an unhandled crash or, worse, an unintended bypass.

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.
- /api/orders/<oid> looks up whatever order matches the ID in the URL and returns it, checking only that some valid user is logged in — not whether that specific user actually owns the order. Since order IDs are just sequential numbers, anyone with a valid login can read any other user's data just by changing the number in the URL.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*
- Prompt: "Fix the IDOR vulnerability in /api/orders/<oid> by adding a server-side check that the authenticated user's identity matches the order's owner field, returning 403 if not, 401 if unauthenticated, and 404 if the order doesn't exist."

- Result: Re-ran the IDOR attempt (alice's token against bob's order) after applying this fix — got 403 forbidden instead of the leaked order data. Fix confirmed, no refinement needed.
