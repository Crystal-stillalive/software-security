# Worksheet 13 — Cloud & Container Security (4 hrs)

> **Course:** Software Security (KOSEN69) · Week 13
> **Aligned to:** OWASP 2025 **A02 Security Misconfiguration** · **CWE-732** (incorrect permission assignment), **CWE-16** (configuration), plus CWE-798, CWE-250, CWE-538, CWE-269, CWE-1104
> **Signature game:** 🔍 *Misconfig Hunt* (CloudGoat-style) — each misconfig you find **and** fix = a flag.

> ⚠️ **Ethics note:** All artifacts here are deliberately broken for teaching and are marked *"Sandbox/teaching only; for authorized lab use."* Scan, exploit, and harden **only** these lab files (or systems you own / are authorized to test). Never point Trivy or these techniques at third-party cloud accounts or images without written permission.

---

## Part 1 — Student Information

| Name | Student ID | Date | Group |
|------|-----------|------|-------|
| Pyae Shunn Le Maung | 6631503084 | 07.11.26 | - |


---

## Part 2 — Lecture Questions

**1.** The shared-responsibility model splits security duties between the cloud provider and the customer: the provider secures the underlying infrastructure (physical datacenters, hypervisors, the managed service itself), while the customer secures everything they configure and put into that service. For an S3-backed app: the provider's side is ensuring S3's storage hardware and the service's own availability/durability are secure; the customer's side is setting correct bucket policies, encryption, and access controls on the actual objects and buckets they create.

**2.** `"Action": "*"` and `"Resource": "*"` violates least privilege because it grants every possible permission on every possible resource, when any real workload only needs a small subset — if the credential leaks, the blast radius is the entire account rather than one bucket. CWE-732 (incorrect permission assignment) is about the policy itself assigning far broader access than the resource needs. CWE-269 (improper privilege management) is about the lack of any mechanism enforcing separation between roles — here there is no distinction between an app's runtime identity and an administrator; everything collapses into one all-powerful principal.

**3.** An attacker recovers `ENV API_TOKEN=sk_live_...` because environment variables set with `ENV` are baked permanently into the image's layer history, not just the running container's memory. `docker history --no-trunc <image>` shows every layer's build command including the literal `ENV API_TOKEN=...` line; `docker inspect <image>` shows the final environment variables directly. This is CWE-798 (hard-coded credentials) because the secret is embedded in the build artifact rather than injected at runtime, and CWE-200 (information exposure) because anyone who pulls or inspects the image — without ever running it — can read the secret.

**4.** `FROM python:latest` is a security and reproducibility problem because `:latest` is a moving target — the same Dockerfile can produce a different, potentially vulnerable base image on every rebuild with no record of what shipped (CWE-1104 unmaintained component, CWE-16 configuration drift). Pinning to an `@sha256:` digest locks the build to one immutable image content hash — the same digest always resolves to byte-identical content, so builds are reproducible and a security review of one build still applies to every future build using that pin.

**5.** A distroless base image removes the shell, package manager, and most general-purpose OS utilities that a normal base (like `python:3.11-slim`) still includes, leaving only the language runtime and the app's dependencies. This shrinks the attack surface because even after an RCE or escalation attempt, there is no shell to drop into, no `apt`/`pip` to pull in tools, and no auxiliary binaries (`curl`, `wget`, an editor) to abuse for lateral movement or exfiltration — the container simply lacks the tools an attacker relies on post-compromise.

---

## Part 3 — Hands-on Lab

### Task 0 — Onboarding

Command run:
```bash
cd ~/software-security/labs/week13-cloud-container
printf '%s | %s | ' "$(whoami)" '6631503084'; date '+%F %T %Z'
bash scan.sh
```

Baseline finding count against `Dockerfile.insecure`: **4 findings** (MEDIUM: 1, HIGH: 1, CRITICAL: 2) — DS-0001 MEDIUM (`:latest`), DS-0002 HIGH (root user), DS-0031 CRITICAL ×2 (secret in ENV, one per secret: API_TOKEN line 16 and AWS_SECRET_ACCESS_KEY line 17). `Dockerfile.hardened` → 0. `iam-policy-insecure.json` is reviewed manually (Trivy's config scanner does not parse standalone IAM JSON). Screenshots: `Screenshot 2569-11-07 at 04.59.05.png`, `Screenshot 2569-11-07 at 04.59.23.png`.
![alt text](<Screenshot 2569-11-07 at 04.59.05.png>)
![alt text](<Screenshot 2569-11-07 at 04.59.23.png>) 

### Task 1 — Misconfig Hunt: Container Image

| # | Defect (line in `Dockerfile.insecure`) | CWE | Trivy rule / severity |
|---|---|---|---|
| 1 | `FROM python:latest` — unpinned, mutable base | CWE-1104 / CWE-16 | DS-0001, MEDIUM |
| 2 | `ENV API_TOKEN=...` / `AWS_SECRET_ACCESS_KEY=...` — secrets baked into layer | CWE-798 / CWE-200 | DS-0031, CRITICAL (fires once per secret = 2 findings) |
| 3 | No `USER` directive — runs as root (uid 0) | CWE-250 | DS-0002, HIGH |
| 4 | `COPY . .` — copies whole build context (.git, .env, keys) | CWE-538 | manual review — no Trivy rule |
| 5 | `chmod -R 777 /app` — world-writable app dir | CWE-732 | manual review — no Trivy rule |
| 6 | `RUN pip install -r requirements.txt` — unpinned, no `--no-cache-dir` | CWE-1104 | manual review — no Trivy rule |

### Task 2 — Misconfig Hunt: IAM

| # | Problem in `iam-policy-insecure.json` | CWE | Why |
|---|---|---|---|
| 7 | `"Action": "*"` — every action allowed | CWE-269 | No privilege separation; grants admin-level power regardless of need |
| 8 | `"Resource": "*"` — every resource | CWE-732 | Permissions span the entire account, not the one bucket the app uses |
| 9 | No `Condition` block | CWE-732 | No contextual restriction (prefix, source IP, MFA) narrowing access |

**Blast radius if these creds leak:** full administrative control of the entire AWS account — read/delete every bucket, spin up resources, create backdoor users, and run up unlimited cost, because one statement grants every action on every resource with no conditions.

### Task 3 — Secrets & Storage

Secrets set with `ENV` are baked permanently into the image's layer metadata. Anyone who pulls the image can run `docker history --no-trunc <image>` to see the literal `ENV API_TOKEN=...` line, or `docker inspect <image>` to read the final environment variables — without running the container (CWE-798 / CWE-200). They belong in a secrets manager (AWS Secrets Manager / Vault), a mounted secret file, or an orchestrator secret, injected only at runtime.

`.dockerignore` entries added to stop `COPY . .` leaking sensitive files (CWE-538):
```
.git
.env
*.pem
*.key
*.crt
.aws
__pycache__
node_modules
```

### Task 4 — Hardened Dockerfile + Least-Priv IAM Defense

**Before → after finding count:** 4 findings (`Dockerfile.insecure`: MEDIUM 1, HIGH 1, CRITICAL 2) → 0 findings (`Dockerfile.hardened`).

| Task-1 Defect | Fix in `Dockerfile.hardened` |
|---|---|
| `:latest` | `FROM python:3.11-slim@sha256:cdbd05...` — digest pin |
| Unpinned pip | Multi-stage venv: `pip install --no-cache-dir -r requirements.txt` in a throwaway build stage |
| Root user | `USER 65532:65532` (distroless nonroot) |
| Secrets in ENV | No secrets in image; `ENV` only sets `PATH`/`PYTHONPATH` |
| `COPY . .` | `COPY app.py .` — only the app code (+ `.dockerignore`) |
| `chmod 777` | removed entirely; distroless runtime, non-root ownership |

**IAM rewrite** (`iam-policy-leastpriv.json`): scopes `s3:GetObject` to `arn:aws:s3:::lab-app-bucket/app/*`, and `s3:ListBucket` to the bucket with a `Condition` restricting `s3:prefix` to `app/*`.

**Extra runtime flags** (from `harden.md`): `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`.

### Task 5 — Flag Tally

9 total (6 container + 3 IAM). **Biggest-risk misconfig:** the `ENV` secrets (`sk_live_...` + `AWS_SECRET_ACCESS_KEY`) — a live credential baked into a shipped image is immediately exploitable by anyone who pulls it, needs no further foothold, and the AWS key combined with the full-admin IAM policy means instant total account compromise.

---

## Part 4 — Reflection

**1. Mapping:**

| Artifact line | CWE | OWASP 2025 | One-line fix |
|---|---|---|---|
| `FROM python:latest` | CWE-1104 | A02 Security Misconfiguration | Pin to an `@sha256:` digest |
| `ENV API_TOKEN=sk_live_...` | CWE-798 | A02 Security Misconfiguration | Inject secrets at runtime, never in a layer |
| `"Action": "*", "Resource": "*"` | CWE-732 | A02 Security Misconfiguration | Scope to `s3:GetObject` on one bucket ARN |

**2. Real incident:** In 2017 a misconfigured, publicly-readable Amazon S3 bucket exposed the personal data of ~198 million US voters held by Deep Root Analytics — no authentication was required to download it. The applicable CWE is CWE-732 (incorrect permission assignment). The single control from this lab that would have prevented it is least-privilege access scoping: a bucket policy restricting reads to a specific authorized principal instead of public/`*` access would have made the data unreadable to anonymous users.

**3. Best mitigation:** Least-privilege IAM gives the most risk reduction per unit of effort. Distroless + non-root only shrinks the blast radius *after* an attacker already has code execution inside a container — a second line of defense. Least-privilege IAM is a few lines of JSON that cap what any leaked credential or compromised workload can ever touch across the whole account, stopping the most common and most damaging cloud breach (over-permissive access leading to mass data exposure) before it happens. The effort is minimal — enumerate the handful of actions the app uses and scope them to specific ARNs — while the risk reduction covers the entire account's blast radius.

---

## Evidence & Integrity

**Personalized flag / misconfig tally:** 9 flags — 6 container defects (unpinned :latest, secrets in ENV, root user, COPY . ., chmod 777, unpinned pip) + 3 IAM problems (Action:*, Resource:*, no Condition), each found and fixed.

**1. What I did, and why the vulnerability worked:** I scanned `Dockerfile.insecure` with Trivy and found 3 flagged misconfigurations (unpinned `:latest`, root user, secrets in `ENV`), plus 3 more by manual code review (`COPY . .`, `chmod 777`, unpinned pip), and reviewed the IAM policy's `Action:*`/`Resource:*` full-admin grant. (Trivy reports 4 findings because the secret-in-ENV rule DS-0031 fires once per secret.) These worked because the image and policy were built with no least-privilege discipline: the base was a mutable tag, secrets were baked into permanent layers readable via `docker history`, the container ran as root, and the IAM principal could do anything to anything.

**2. Why the fix stops it, and what could still break it:** The hardened Dockerfile pins the base by digest, injects no secrets, runs as `USER 65532:65532` on a distroless base with only `app.py` copied; the least-privilege IAM policy scopes `s3:GetObject` to one bucket prefix with a condition. Re-scanning drops the count from 4 to 0. What could still break it: the digest pin eventually goes stale (an un-refreshed pin ships known-vulnerable base CVEs), and if a future build reintroduced `COPY . .` without the `.dockerignore`, secrets could leak again — these fixes are per-artifact, not enforced structurally.

---

## 🤖 Audit the AI

**Prompt given:** "Fix the secret-in-ENV problem in this Dockerfile."

**AI's answer:**
```dockerfile
FROM python:3.11-slim
WORKDIR /app
ARG API_TOKEN
ENV API_TOKEN=$API_TOKEN
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
```

**What's wrong with it:** Using `ARG` + `ENV` does **not** keep the secret out of the image — a value passed via `--build-arg` still ends up baked into the `ENV` layer and is recoverable with `docker history`. The AI treated "move it to a build arg" as a fix when it only changes *how* the secret enters, not whether it is embedded. It also left `COPY . .` (still leaks `.git`/`.env`) and an un-pinned base untouched.

**My corrected version:** Remove the secret from the image entirely — no `ARG`, no `ENV API_TOKEN`:
```dockerfile
FROM python:3.11-slim@sha256:cdbd05fb6f457ca275ff51ce00d93d865ca0b6a25f5ffb08262d94f6835771e5
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
USER 65532:65532
CMD ["python", "app.py"]
```
The secret is injected only at runtime (`docker run --env-file` from a secrets manager, or a mounted secret). The AI's output was insufficient because a build-arg secret is still a baked-in secret — the only real fix is for the credential never to touch any image layer.

---

## 🧠 Comprehension & Prompt

**A.** `Dockerfile.insecure` builds an image from a mutable `:latest` base, bakes two live secrets into permanent `ENV` layers, copies the entire build context in, makes everything world-writable, and runs as root. It is exploitable because anyone who obtains the image can extract the baked-in AWS/API credentials with a single `docker history` command — no running container needed — and if the container is ever breached, running as root with a 777 app directory hands the attacker full control.

**B. Prompt:** "Rewrite this Dockerfile to remove the hardcoded ENV secrets entirely (inject at runtime instead), pin the base image to a sha256 digest, copy only app.py, and run as a non-root user — then explain how to verify no secret remains in any layer."

**Result:** The rewrite removed both `ENV` secrets, pinned the digest, used `COPY app.py .`, and added `USER 65532:65532`. Verified with `docker history --no-trunc <image>` — no `sk_live_` or `AKIA` string appears in any layer. Fix confirmed.
