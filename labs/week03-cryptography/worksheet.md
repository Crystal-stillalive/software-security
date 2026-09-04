# Worksheet 3 — Cryptography Used Correctly (and Misused) (3 hrs)

> **Course:** Software Security (KOSEN69) · **Week 3**
> **Aligned to:** OWASP 2025 A04 Cryptographic Failures · CWE-327, CWE-916, CWE-330, CWE-798
> **Signature game:** "Capture the Hash" (recover plaintext from weak hashes)

> **Ethics note:** Crack only the hashes provided in `hashes.txt` on your own machine. Password-cracking against accounts or systems you don't own is illegal. Wordlists and recovered values stay inside the lab VM.

## Part 1 — Student Information
| Name | Student ID | Date | Group |
|---|---|---|---|
| Pyae Shunn Le Maung | 6631503084 | 04.09.2026 | - |

## Part 2 — Lecture Questions
Answer in your own words (2–4 sentences each).
1. Distinguish hashing, encryption, and encoding — and give one job each is the wrong tool for.
`Hashing is one-way and can't be reversed — used for password storage and integrity checks. Encryption is two-way and reversible with a key — used for protecting data you need back later. Encoding (like Base64) isn't security at all, just a format change with no key — wrong tool for hiding a password, since anyone can decode it instantly.`

2. Why is a fast hash like MD5/SHA-1 a bad choice for storing passwords, and what should be used instead?
`Fast hashes let an attacker try billions of guesses per second on cheap hardware. Password storage needs a slow, memory-hard KDF like argon2id instead, which is deliberately expensive to compute.`

3. What is a salt, what attack does it defeat, and why must it be unique per password?
`A salt is random data mixed into a password before hashing. It defeats rainbow tables, since an attacker can't use a precomputed table when every hash used different random input. It must be unique per password so two users with the same password don't get the same hash.`

4. Why does AES-ECB leak structure, and what does an authenticated mode like AES-GCM add?
`AES-ECB encrypts each block independently with the same key, so identical plaintext blocks always produce identical ciphertext — this leaks structure. AES-GCM adds a random nonce per message and an authentication tag, giving both confidentiality and integrity.`

5. What's the difference between `random` and a CSPRNG (e.g. `secrets`), and where does it matter?
`random is a deterministic PRNG, predictable if an attacker sees enough outputs. secrets is a CSPRNG built for unpredictability. It matters for anything security-related — tokens, session IDs, keys — never for values used in access control.`

![Four paired rows showing that password storage, cipher mode, randomness and key source are four separate crypto decisions: MD5 (CWE-916/327) becomes argon2id, AES-ECB with a hardcoded key (CWE-327) becomes AES-GCM with a nonce and tag, a 6-digit random.choice token (CWE-330) becomes secrets.token_urlsafe, and HARDCODED_KEY (CWE-798) becomes a key injected from the environment — so naming AES answers none of the four questions.](img/crypto-misuse.svg)

## Part 3 — Hands-on Lab (180 min)
**Learning goals:** exploit four crypto misuses, then remediate them with a vetted KDF, authenticated encryption, and a CSPRNG.
**Prerequisites:** Docker (or local Python 3.12); `hashcat` or `john`; the `rockyou.txt` wordlist.

**Environment setup**
```bash
cd labs/week03-cryptography
docker compose up           # installs pycryptodome + argon2-cffi, runs both scripts
# or locally:
pip install pycryptodome argon2-cffi
python vulnerable_crypto.py # see the md5 hash, repeated ECB blocks, 6-digit token
```
Targets: `vulnerable_crypto.py` (the misuses), `hashes.txt` (four unsalted MD5s), and `solution_skeleton.py` (the fix).

**What to submit per task:** the command/payload run + a screenshot of the result + a 2–3 sentence mitigation.

**Task 0 — Onboarding (5 min)** · *Goal:* see the misuse output. *Steps:* run `python vulnerable_crypto.py`; note the md5 digest, the identical ECB ciphertext blocks, and the short token.![alt text](<Screenshot 2569-08-16 at 12.02.37.png>)

**Task 1 — Capture the Hash (30 min)** · *Goal:* recover the passwords. *Steps:* strip the comment lines from `hashes.txt`, then run `hashcat -m 0 hashes.txt rockyou.txt` (or the `john --format=raw-md5` equivalent); recover all four plaintexts.
![alt text](<Screenshot 2569-08-16 at 14.10.13.png>)
Unsalted MD5 fell in under a second because it's a fast, unsalted hash — hashcat achieved 100.5 million hashes/sec on a single consumer GPU, and with no salt, every password maps to exactly one fixed digest, so a dictionary of 14.3 million common passwords was enough to match all four instantly (CWE-916: insufficient computational effort; CWE-327: broken/risky cryptographic algorithm).

```sim
aes-modes
```

**Task 2 — ECB structure leak (20 min)** · *Goal:* prove ECB leaks. *Steps:* call `encrypt_ecb(b"A"*16 + b"A"*16)` from `vulnerable_crypto.py` and show the two 16-byte ciphertext blocks are identical; explain how this leaks plaintext structure (CWE-327).
![alt text](<Screenshot 2569-08-16 at 14.47.47.png>)
Note: AES-ECB encrypted two identical 16-byte plaintext blocks into byte-for-byte identical ciphertext blocks (block 0 == block 1: True), because ECB encrypts each block independently with no chaining or randomization — identical input always yields identical output, leaking plaintext structure to any observer (CWE-327). Fix: use AES-GCM, which adds a random nonce per encryption so identical plaintexts never produce identical ciphertext. 

**Task 3 — Predictable token (15 min)** · *Goal:* show the reset token is guessable. *Steps:* call `reset_token()` repeatedly; argue why a 6-digit `random` token (10^6 space, non-CSPRNG) is brute-forceable (CWE-330). 
![alt text](<Screenshot 2569-08-16 at 14.59.18.png>)
A 6-digit random-based token has only 10⁶ = 1,000,000 possible values — brute-forceable in ~17 minutes at 1,000 req/sec against an unrate-limited endpoint, and random is a non-CSPRNG, so outputs may be predictable beyond brute force alone (CWE-330). Fix: use secrets.token_urlsafe() for a cryptographically secure token with a much larger space.

**Task 4 — Hardcoded key (5 min)** · *Goal:* identify the key-management flaw. *Steps:* find `HARDCODED_KEY` in `vulnerable_crypto.py`; explain why shipping a key in source is CWE-798. 
![alt text](<Screenshot 2569-08-16 at 15.10.00.png>)
This key is committed directly in source, so anyone with repo read access — including via git history, even after the line is later deleted — can recover it and decrypt anything ever encrypted with it, and it can't be rotated without a code change and redeploy. The fix is to load the key at runtime from an environment variable (e.g. os.environ["ENC_KEY_HEX"], as solution_skeleton.py does) or a secrets manager, keeping it out of source entirely and allowing independent rotation.

**Task 5 — Crack the project target's hashes (25 min)** · *Goal:* apply cracking to your term project. *Steps:* **NoteVault** stores unsalted MD5 password hashes; obtain them (via the app's `/admin` once you can reach it, or from its `seed()`), and crack them with `hashcat -m 0`. *Deliverable:* the recovered password(s) + note the CWE — record this finding for your project report (`project/REPORT-TEMPLATE.md` in the repo root).
![alt text](<Screenshot 2569-08-16 at 15.19.57.png>)

NoteVault credential storage finding: both demo accounts (alice, admin) use unsalted MD5 for password storage (app.py, seed() function). Cracked via hashcat: admin → admin123 (dictionary attack, rockyou.txt, <1 sec); alice → alicepw (mask attack, 7 lowercase letters, ~8 sec at 3+ billion H/s). CWE-916 (insufficient computational effort) / CWE-327 (broken/risky cryptographic algorithm) — same root cause as the standalone vulnerable_crypto.py exercise. Fix: migrate to argon2id per Task 6's store_password/verify_password pattern, with a rehash-on-login upgrade path for existing accounts.

**Task 6 — Password storage migration (25 min)** · *Goal:* fix it the way real apps do. *Steps:* write `store_password`/`verify_password` with **argon2id**, and a **rehash-on-login** path that upgrades a legacy MD5 record to argon2id the next time the user logs in. 
Week 3 — FIX the misuse here. Fill in the TODOs.
pip install argon2-cffi pycryptodome
"""

```bash
"""
Week 3 — FIX the misuse here. Fill in the TODOs.
pip install argon2-cffi pycryptodome
"""
import os, hashlib
from argon2 import PasswordHasher
from Crypto.Cipher import AES

ph = PasswordHasher()

def store_password(pw: str) -> str:
    # FIX: argon2id, salted automatically
    return ph.hash(pw)

def verify_password(hash_: str, pw: str) -> bool:
    try:
        return ph.verify(hash_, pw)
    except Exception:
        return False

def encrypt_gcm(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    # FIX: authenticated encryption (AES-GCM), random nonce, key from env/KMS
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data)
    return nonce, ct, tag

def decrypt_gcm(nonce: bytes, ct: bytes, tag: bytes, key: bytes) -> bytes:
    # Task 7: authenticated decryption — raises ValueError if ciphertext/tag were tampered with
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

def reset_token() -> str:
    # FIX: CSPRNG
    import secrets
    return secrets.token_urlsafe(16)

# --- Task 6: rehash-on-login migration from legacy MD5 to argon2id ---
def is_legacy_md5(stored_value: str) -> bool:
    return len(stored_value) == 32 and all(c in "0123456789abcdef" for c in stored_value.lower())

def verify_and_maybe_upgrade(stored_value: str, pw: str, save_fn) -> bool:
    if is_legacy_md5(stored_value):
        if hashlib.md5(pw.encode()).hexdigest() == stored_value:
            save_fn(store_password(pw))
            return True
        return False
    return verify_password(stored_value, pw)


if __name__ == "__main__":
    key = bytes.fromhex(os.environ.get("ENC_KEY_HEX", os.urandom(32).hex()))
    h = store_password("password123")
    print("argon2 ok:", verify_password(h, "password123"))
    print("gcm:", encrypt_gcm(b"secret", key))
    print("token:", reset_token())

    # Task 6 demo: migrate a legacy MD5 record on login
    legacy = {"value": hashlib.md5(b"alicepw").hexdigest()}

    def save(new_hash):
        legacy["value"] = new_hash
        print("Upgraded to:", new_hash)

    print("Attempt 1 (legacy MD5):", verify_and_maybe_upgrade(legacy["value"], "alicepw", save))
    print("Stored value now:", legacy["value"])
    print("Attempt 2 (now argon2id):", verify_and_maybe_upgrade(legacy["value"], "alicepw", save))

    # Task 7: authenticated encryption round-trip + tamper-fails proof
    msg = b"secret message"
    nonce, ct, tag = encrypt_gcm(msg, key)
    print("Round-trip decrypt:", decrypt_gcm(nonce, ct, tag, key))

    tampered_ct = bytearray(ct)
    tampered_ct[0] ^= 0xFF
    try:
        decrypt_gcm(nonce, bytes(tampered_ct), tag, key)
        print("TAMPER NOT DETECTED — BUG")
    except ValueError as e:
        print("Tamper correctly detected:", e)
  ```

    verify_and_maybe_upgrade detects legacy 32-char MD5 hex hashes and, on a correct password match, immediately rehashes via store_password (argon2id) and writes it back through save_fn. This works because migration can't happen in bulk offline — the plaintext password only ever exists at the moment of login — so each account upgrades transparently the next time its user authenticates, with no forced reset. Confirmed end-to-end: attempt 1 matched the legacy MD5 record and upgraded it to $argon2id$...; attempt 2 verified successfully against the new argon2id hash.


**Task 7 — Authenticated encryption round-trip (20 min)** · *Goal:* use AEAD correctly. *Steps:* encrypt+decrypt a message with **AES-GCM** using a random 12-byte nonce and a key from an env var; then flip one ciphertext byte and show decryption **fails** (tag check). *Deliverable:* the round-trip output + the tampered-fails proof.
![alt text](<Screenshot 2569-09-04 at 15.18.46.png>)

`AES-GCM authenticated the ciphertext with a tag. Round-trip decrypt returned the correct message. Flipping one byte and re-decrypting raised MAC check failed — the tag caught the tamper instead of returning corrupted plaintext.`

**Task 8 — TLS in practice (15 min)** · *Goal:* read a real cert. *Steps:* run `openssl s_client -connect example.com:443 </dev/null 2>/dev/null | tee /tmp/tls.txt | openssl x509 -noout -issuer -subject -dates` for the cert summary, then `grep -E 'Protocol|New,' /tmp/tls.txt` for the negotiated TLS version (the version line is printed by `s_client`, not by `x509`, so the plain pipe would discard it); identify issuer, validity, and that TLS version. *Deliverable:* the cert summary + one line on what TLS protects that hashing/at-rest encryption does not.
![alt text](<Screenshot 2569-09-04 at 15.29.41.png>)

- Issuer: SSL Corporation, Cloudflare TLS Issuing ECC CA 3
- Subject: example.com
- Valid: Jul 29 2026 – Oct 27 2026
- Negotiated TLS version: TLSv1.3

TLS protects data in transit — confidentiality and integrity of the connection between client and server — while hashing and at-rest encryption protect data sitting on disk; neither substitutes for the other.



**Task 9 — Defend / fix it (20 min)** · *Goal:* remediate using `solution_skeleton.py`. *Steps:* run `python solution_skeleton.py`; confirm `store_password`/`verify_password` use argon2id (auto-salted), `encrypt_gcm` uses a random 12-byte nonce + auth tag with a key from `ENC_KEY_HEX` env, and `reset_token` uses `secrets`. Map each fix to the CWE it closes. *Deliverable:* before/after table (misuse → fix → CWE closed) + screenshot of the fixed script running.

| Misuse | Fix | CWE Closed |
|---|---|---|
| Unsalted MD5 password hash | argon2id via `argon2-cffi` (auto-salted, memory-hard) | CWE-916 / CWE-327 |
| AES-ECB (structure leak) | AES-GCM (random 12-byte nonce + auth tag) | CWE-327 |
| 6-digit `random` reset token | `secrets.token_urlsafe(16)` | CWE-330 |
| `HARDCODED_KEY` in source | Key loaded from `ENC_KEY_HEX` env var | CWE-798 |

![alt text](<Screenshot 2569-09-04 at 15.18.46.png>)

## Part 4 — Reflection
1. Map each of the four misuses to its CWE and to OWASP A04, in one line each.
- MD5 password hash → CWE-916/327 → OWASP A04 Cryptographic Failures
- AES-ECB → CWE-327 → OWASP A04 Cryptographic Failures
- 6-digit random token → CWE-330 → OWASP A04 Cryptographic Failures
- Hardcoded key → CWE-798 → OWASP A04 Cryptographic Failures

2. Name a real-world breach caused by weak password hashing or hardcoded keys, and which fix here would have prevented it.
`The 2012 LinkedIn breach involved unsalted SHA-1 password hashes, which let attackers crack millions of passwords quickly once the database leaked. Argon2id (Task 6's fix) would have made cracking computationally infeasible even after a leak.`

3. Across all four fixes, which closes the largest real-world risk, and why?
`The password hashing fix (MD5 → argon2id) closes the largest real-world risk. Password reuse across sites means a cracked password here can compromise a user's accounts everywhere, making this the highest-impact fix of the four.`


## Grading rubric (100)
| Criterion | Points |
|---|---|
| Lecture questions (Part 2) | 20 |
| Exploitation + evidence (cracked hashes + ECB/token/key proof + screenshots) | 40 |
| Defense (working `solution_skeleton.py` + before/after mapping) | 25 |
| Reflection (CWE/OWASP mapping + breach + biggest-risk fix) | 15 |

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
  `I ran the vulnerable crypto script and cracked its MD5 hashes with hashcat. It worked because MD5 is fast and unsalted — hashcat tried 100+ million hashes per second, and a 14-million-word dictionary was enough to match all four instantly.`

  2. **Why does your fix actually stop it** — and what could still break it?
`Argon2id is slow and memory-hard by design, making the same attack computationally infeasible. AES-GCM adds an authentication tag, so tampering is detected. What could still break it: if the argon2 cost parameters are ever lowered for performance reasons, or if the encryption key itself leaks, none of these fixes matter.`

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.
- Prompt given to the AI:
"Fix the password hashing in vulnerable_crypto.py to use a secure algorithm."

- AI's answer:
```py
import hashlib
def store_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()
```

2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).

SHA-256 is still a fast, general-purpose hash — not designed for passwords. It has no built-in salt and no configurable work factor, so it's still crackable at high speed with a GPU, just slower than MD5. This line:
`return hashlib.sha256(pw.encode()).hexdigest()`
is the problem — swapping MD5 for SHA-256 doesn't fix the real issue.

3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.

```py
from argon2 import PasswordHasher
ph = PasswordHasher()
def store_password(pw: str) -> str:
    return ph.hash(pw)
```

The AI treated "insecure hash" as the whole problem and picked a stronger general-purpose hash, but passwords need a slow, memory-hard KDF specifically, not just a longer-digest hash. SHA-256 is still fast enough to brute-force at scale.

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.
`vulnerable_crypto.py hashes passwords with MD5, encrypts data with AES in ECB mode, and generates reset tokens with Python's regular random module. Each is exploitable because MD5 is fast enough to crack at scale, ECB leaks patterns in the ciphertext, and random is predictable, not truly random.`

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*

- Final prompt:
"Rewrite store_password to use argon2id via the argon2-cffi library, which is slow and memory-hard by design, instead of a general-purpose hash like MD5 or SHA-256. Show the corrected function."

```py
from argon2 import PasswordHasher
ph = PasswordHasher()
def store_password(pw: str) -> str:
    return ph.hash(pw)
```
Ran solution_skeleton.py after applying this — argon2 ok: True confirmed the hash/verify round-trip works correctly. Fix verified, no refinement needed.

