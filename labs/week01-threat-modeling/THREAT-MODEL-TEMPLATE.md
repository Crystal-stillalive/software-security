# Threat Model — sample-app

## 1. Data-flow diagram
![alt text](<Screenshot 2569-08-20 at 14.30.08.png>)

## 2. Elements & trust boundaries
| Element | Type (process/store/entity/flow) | Trust boundary crossed? |
|---|---|---|
| Web client | external entity | yes (Internet → app) |
| Flask app | process | yes (receives untrusted input from client across Internet → app boundary) |
| SQLite DB (`notes.db`) | data store | no (only ever written/read by the trusted Flask process, not directly by the client) |
| `uploads/` store | data store | no (only ever written/read by the trusted Flask process, not directly by the client) |

## 3. STRIDE analysis
| Element | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| /notes | Accepts client-supplied `owner` with no auth — anyone can post as "alice" | No auth on writes — anyone can insert/corrupt note records | No logging anywhere — no record of who posted what | — | No rate limit observed — repeated POSTs could flood `notes.db` | — |
| /upload | — | Raw `f.filename` used unsanitized to build save path — arbitrary-file-write | No logging — no record of who uploaded what, when | Response echoes resolved save path — leaks server filesystem layout | No apparent file-size limit — could exhaust disk/memory | If a written file is ever executed (e.g. via traversal into an executable path), this becomes code execution |
| /files/<name> | — | Comparatively defended vs. /upload (see Task 5) — verify exact protection in source | No logging — no record of who read which file | If traversal isn't fully blocked, could read files outside `uploads/` | — | — |

## 4. Top 5 risks (likelihood × impact) + mitigation
1. **No authentication on `/notes`** (Likelihood: High, Impact: Medium) — anyone can post/read notes claiming to be any `owner`. *Mitigation:* require session-based authentication before accepting writes; verify the authenticated identity matches the claimed `owner`.
2. **Unsanitized `f.filename` on `/upload`** (Likelihood: High, Impact: High) — enables arbitrary-file-write via path traversal. *Mitigation:* sanitize with `secure_filename()`, then verify the resolved path stays inside the intended upload directory; allow-list acceptable extensions.
3. **No logging anywhere in the app** (Likelihood: High, Impact: Medium) — no accountability for any action taken (Repudiation). *Mitigation:* add structured request logging (who, what, when) for every write/upload/read.
4. **Save path disclosed in `/upload` response** (Likelihood: Medium, Impact: Medium) — leaks server filesystem layout to any client. *Mitigation:* return only a generic success confirmation or an opaque file identifier, never the resolved server-side path.
5. **No rate limiting / size limiting on `/notes` and `/upload`** (Likelihood: Medium, Impact: Medium) — enables trivial denial-of-service via request flooding or oversized uploads. *Mitigation:* add per-client rate limits and a maximum upload size enforced server-side.