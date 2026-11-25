# Security implementation and scope

This is a focused educational implementation of the requested authentication controls. It is not a claim that every possible aspect of information security is covered or that the application has passed an independent security audit. Trustworthy HTTPS, secure deployment, and operational controls are part of the system, not properties a downloaded form can guarantee by itself.

## Requested controls

| Control | Implementation | Where to inspect |
| --- | --- | --- |
| HTTPS everywhere | Direct TLS 1.2+ listener by default; no plaintext application listener in direct mode. HSTS on responses. Same-machine Caddy mode retains loopback isolation. Render Free mode uses the platform HTTPS edge with its documented public-only ingress and a validated Cloudflare client address. Exact HTTPS origin and Host validation. | `server.mjs`, `lib/config.mjs`, `lib/transport.mjs`, `lib/app.mjs`, `deploy/Caddyfile` |
| CSRF protection | Random server-bound CSRF token required on every POST, including login, registration, MFA, and logout. Constant-time comparison, strict Origin check, cross-site fetch rejection, and SameSite=Strict cookies. | `lib/app.mjs`, all form templates |
| No credentials in URLs | All state-changing forms POST in bounded URL-encoded bodies. Query strings are rejected. No session IDs, setup keys, or recovery codes in URLs or browser storage. | Templates, `lib/app.mjs`, `public/js/main.js` |
| Slow salted password hashing | Argon2id v19 with a random 16-byte salt per password, 64 MiB memory, three passes, one lane, and a 32-byte output. No plaintext or reversible password storage. Async hashing has a two-operation concurrency cap. | `lib/crypto.mjs` |
| Parameterized queries | Application values use prepared SQLite/libSQL statements and bound parameters. Async transaction context and a serialized connection boundary prevent interleaved requests from entering another request’s transaction. Schema SQL is static; values are never interpolated into queries. | `lib/database.mjs`, `lib/store.mjs`, `lib/app.mjs` |
| Input limits | Passwords 15–128 Unicode code points at registration and at most 512 UTF-8 bytes, never truncated; 128 maximum at login. Email 254 characters and bounded address parts, name 80 code points, body 8 KiB, request headers 8 KiB, request timeouts. Browser limits improve usability; the server is authoritative. | `lib/crypto.mjs`, `lib/app.mjs`, `server.mjs` |
| Generic failures and timing mitigation | Same login message/status for wrong, unknown, or invalid credentials. Unknown accounts use a real dummy Argon2id hash with the same cost. Valid duplicate registrations do the same hash work and use the same redirect and confirmation. Valid credential operations have a 450–499 ms minimum response duration. | `lib/app.mjs` |
| IP and account throttling | Persistent, atomic SQLite/Turso quotas per IP and normalized account, including nonexistent accounts. Login: 8/account and 30/IP per 15 minutes. Registration: 5/account and 10/IP. MFA: 5/account and 30/IP. General requests: 180/IP/minute; new anonymous sessions: 30/IP/15 minutes. A blocked response is HTTP 429 with Retry-After. | `lib/database.mjs`, `lib/store.mjs`, `lib/app.mjs` |
| Breached-password screening | Always-on small common-password list. Optional HIBP HTTPS range check with five-character hash prefix, response padding, timeout, response size cap, and failure-closed registration. Off by default and explicitly documented. | `lib/crypto.mjs`, `.env.example`, README |
| Session regeneration | Unpredictable new 256-bit session ID after password acceptance and again after successful MFA. Previous records are deleted. Session IDs are SHA-256 hashed at rest. Anonymous, pending, and authenticated states are separate. | `lib/app.mjs`, `lib/store.mjs` |
| Hardened cookies | `__Host-548_session`, Secure, HttpOnly, SameSite=Strict, Path=/, no Domain. No tokens in localStorage/sessionStorage. Server-side expiry, idle timeout, POST logout, and Clear-Site-Data at logout. | `lib/app.mjs`, `public/js/main.js` |
| MFA | Mandatory RFC 6238 TOTP for every account. ±1 step acceptance for clock skew, persistent last-accepted counter, atomic updates to prevent replay, five-minute pending sessions, and encrypted TOTP secrets with record-bound AES-256-GCM. Enrollment cannot overwrite an existing factor. | `lib/crypto.mjs`, `lib/app.mjs` |
| Backup access | Eight random 80-bit recovery codes shown once after enrollment. Only keyed HMAC hashes remain in the recovery table. Codes are consumed atomically, work once, and require successful password verification first. Temporary display data is encrypted in the session record and removed on viewing. | `lib/crypto.mjs`, `lib/app.mjs` |
| Security logging | Persistent registration submission, password success, login failure/success, MFA events, recovery use, logout, CSRF rejection, throttling, and observed session expiration. Keyed account/IP references, bounded retention, and a local read-only CLI. No secrets or raw request data in logs. | `lib/store.mjs`, `scripts/events.mjs` |

All authentication attempts count toward quotas, including successful and concurrent requests. Quotas reset at the end of their window and are not extended by blocked requests. Account buckets remain in force across IP changes, and IP buckets remain in force across account changes. Concurrent requests cannot avoid a quota by racing a password hash. Account throttling can temporarily inconvenience a legitimate user under attack; edge defenses and monitoring are still needed for distributed abuse. No CAPTCHA or progressive sleep queue is included because temporary quotas already implement the requested throttle option.

Timing equalization reduces obvious account-existence discrepancies; it cannot guarantee statistically identical timing on all hardware and networks. Rate-limit status reveals a bucket's exhaustion, not whether an account exists. Registration deliberately does not distinguish a new account from an existing account, and a duplicate never replaces the original name, password, or MFA enrollment.

## Broader principles made concrete

| Principle | Concrete application |
| --- | --- |
| Confidentiality | HTTPS, salted password hashes, private OS file modes, encrypted authenticator secrets, protected cookies, no-store pages, no external page assets or analytics. |
| Integrity | Prepared statements, server-side validation, CSRF and Origin validation, authenticated encryption, transactional code consumption and enrollment. |
| Availability | Bounded inputs, request/handshake timeouts, connection cap, persistent quotas, two concurrent Argon2 operations, cleanup of expired records. These mitigate application abuse; they are not DDoS protection. |
| Authentication | Password plus mandatory possession factor, or a previously issued single-use recovery secret. |
| Authorization / least privilege | Protected routes check authenticated server-side state on every request; pending sessions cannot access the welcome page. No public database/log endpoints. Optional OS service runs under a restricted account. |
| Accountability | Minimal authentication event records correlated with keyed pseudonymous references and timestamps. Password resets are not logged because there is no reset feature. |
| Secure defaults / failure closed | HTTPS configuration required, missing key/certificate refuses startup, MFA required, denied routes redirect before exposing account data, optional breach check never silently bypasses an outage. |
| Defense in depth | Browser policies, escaped HTML, TLS, cookies, CSRF, quotas, hashing, encryption, and per-route state checks address different failure paths. |
| Data minimization | Only a name, normalized email identifier, password hash, encrypted MFA data, sessions, one-use code hashes, quotas, and minimal events are stored. Passwords and OTPs are discarded after validation. |
| Complete mediation | The browser's validation and hidden fields do not grant access; the server independently validates input, cookies, stage, CSRF, code freshness, and quota. |

Additional browser controls include a restrictive Content Security Policy without inline scripts/styles, frame blocking, Referrer-Policy, MIME sniffing prevention, Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy, and disabled camera/microphone/location/payment/USB permissions. HTML interpolation is escaped by default. The forms work with JavaScript disabled; JavaScript only handles password visibility, copying, local time display, and submission feedback.

## Deliberate boundaries

- TOTP is implemented; WebAuthn/passkeys are not. TOTP is not phishing-resistant. A phishing-resistant factor requires a separate WebAuthn implementation and testing.
- Email identifies accounts but is not verified. This application does not send mail or claim mailbox ownership. Production recovery and ownership verification require additional infrastructure.
- The temporary enrollment key is visible only after correct password verification. Until first enrollment is completed, a person possessing the original password can enroll a factor. Protect initial credentials and add identity-verification enrollment policy if the use case needs one.
- The small offline blocklist is intentionally limited. Enable the optional online check for a broad known-breach corpus, and assess its privacy and availability consequences.
- Database records contain name/email PII. Encrypted TOTP storage does not encrypt the whole database. Encrypt disks/backups and restrict file access on the actual deployment host. A compromise that obtains both the database and the application key can decrypt TOTP secrets.
- Local self-signed HTTPS requires a separately trusted certificate for browser identity assurance. Public deployment needs a valid trusted certificate, correct DNS, and a maintained TLS reverse proxy or direct TLS configuration.
- Log records are not tamper-proof against a host administrator or a database compromise. For stronger accountability, forward them to a separately protected logging service and monitor them.
- TLS certificates, OS permissions on Windows, filesystem backup protection, host patching, secrets management, incident response, alerting, and recovery drills require operator action. POSIX mode bits in code are not a substitute for Windows ACLs.
- Quotas and sessions share the authoritative configured database. Local mode uses SQLite; Render Free requires the external Turso database and does not silently fall back to temporary files. Multiple hosts still need a reviewed deployment/concurrency design. The Caddy configuration remains for a proxy on the same machine. Render Free mode trusts its public Cloudflare ingress; it must not be reused on a paid service accepting private-network requests or behind an arbitrary proxy chain.
- No password change/reset, MFA replacement, recovery-code regeneration, remember-me, social login, administrator console, or global session revocation UI is included. Keeping scope small avoids unaudited extra credential flows.

## Primary references consulted

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [Node.js 24 cryptography API](https://nodejs.org/docs/latest-v24.x/api/crypto.html)
- [Node.js 24 SQLite API](https://nodejs.org/docs/latest-v24.x/api/sqlite.html)
- [RFC 6238: Time-Based One-Time Password Algorithm](https://www.rfc-editor.org/rfc/rfc6238)
- [Have I Been Pwned Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords)

## Free deployment and update controls

`render.yaml` provisions only a Free web service, with no paid disk or 30-day Render Postgres database. Runtime secrets remain in the provider environment. The public origin is derived from the provider’s HTTPS URL unless explicitly set. Generated base64 and original hexadecimal 32-byte keys are accepted. Turso URLs require an encrypted protocol and a .turso.io hostname; database tokens never reach the browser. Health probes return minimal readiness only.

The pinned npm dependency and package-lock.json support reproducible installation. GitHub checks use read-only repository permissions and do not retain checkout credentials. Render waits for passing CI and repeats the test suite before deploying. The CI certificate is generated in a private temporary directory and removed; it does not generate or upload a production application key. No GitHub/Render account credentials are included.

Deployments preserve database records and the existing application key. Session rotation uses a conditional delete inside a transaction, so simultaneous password submissions cannot both upgrade one session. Concurrent recovery-page requests atomically claim the display payload once. Existing authenticator enrollment is never overwritten. Free-plan quotas, sleep behavior, and possible provider policy changes remain operational limitations; see DEPLOY-FREE.md.
