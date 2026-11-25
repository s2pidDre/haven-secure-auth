# Validation record

Performed on 25 November 2026 using Node.js 24.22.3 on Linux.

## Executed checks

- `npm run setup`: passed. Generated a fresh application key and localhost certificate pair; no real user credentials were supplied.
- `npm run ci`: **34 passed, 0 failed**. Tests use isolated temporary SQLite/libSQL databases and a temporary test certificate; they do not need a real Turso token.
- `npm run check`: passed JavaScript syntax checks, stylesheet/script references, template ID uniqueness, and CSRF form fields.
- Independent HTML parsing: all label `for` values and password-toggle targets matched existing element IDs; all form methods were POST with local actions.
- Actual `server.mjs` startup and certificate-verified HTTPS request: passed, negotiated **TLS 1.3**, returned the login page.
- Plaintext HTTP request to the direct HTTPS listener: rejected.

## Automated security cases

The test files contain the complete executable checks:

1. Protected route denial, allowed CSS/JavaScript paths, private file denial, query-string rejection, security headers, and cookie flags.
2. CSRF mismatch, missing/cross-site Origin, duplicate form parameters, wrong content type, oversized submission, invalid Host, and unsupported HTTP methods.
3. Duplicate registration produces the same public outcome and preserves the original account.
4. Invalid registration fields do not create an account.
5. Enabled breach screening rejects compromised passwords and blocks registration during a simulated service outage.
6. Wrong, unknown, oversized, and SQL-injection-shaped login inputs produce the generic failure.
7. Full first-login MFA enrollment, session rotation, old-session rejection, encrypted TOTP storage, hashed session IDs, and HTML escaping of a hostile name.
8. Recovery codes display once, work once, and cannot be reused; TOTP replay is rejected.
9. A fresh TOTP signs in an already enrolled account.
10. Account MFA quota denies excess attempts while the session remains unauthorized.
11. A competing enrollment cannot overwrite an existing authenticator.
12. IP login quota applies across different account identifiers.
13. Account login quota persists in SQLite; spoofed forwarding headers do not bypass it in direct mode.
14. Expired and idle sessions cannot access protected routes or submit a valid old form.
15. Audit records omit raw credentials, emails, IP addresses, session tokens, and authenticator secrets.
16. Password hashing uses unique Argon2id salts and verifies the correct password only.
17. AES-GCM detects altered ciphertext and incorrect record binding.
18. TOTP matches all six RFC 6238 SHA-1 test vectors.
19. TOTP rejects replay, old windows, and malformed codes.
20. Password policy checks length, predictable values, and Unicode passphrase support.
21. Recovery-code count, alphabet, and format match the intended 80-bit random secret design.
22. The HIBP protocol sends only a five-character prefix, requests padding, ignores zero-count padding entries, and rejects failed responses.

## Free deployment additions

The additional checks cover:

23. Concurrent password submissions upgrade a session at most once.
24. Simultaneous recovery-page views claim the code display only once.
25. Render Free configuration derives the correct managed HTTPS origin and requires an external database.
26. Hosting refuses a missing database/token, insecure or unexpected database URLs, weak secrets, invalid public origins, incorrect bind addresses, and unsupported platform claims.
27. Existing localhost configuration and hexadecimal keys remain compatible.
28. Render Free ingress uses a single Cloudflare-supplied client address and ignores spoofed forwarding chains; insecure/malformed ingress is rejected.
29. The same-machine Caddy mode remains restricted to loopback.
30. The actual official libSQL client adapter preserves records across reopen, rolls back failed transactions, enforces atomic quotas, and binds hostile input safely. This uses the real libSQL engine locally, not a hosted account.
31. Local async transactions cannot accidentally absorb another request's writes into a rollback.
32. Health probes expose no account data, database details, or session cookie.
33. Deployment and CI definitions select the Free plan, omit paid disks and expiring Render Postgres databases, and keep repository permissions read-only.
34. A complete registration/password/MFA/welcome/logout flow runs through the real libSQL client, and an authenticated session plus account survives closing and reopening the application and database client. Render ingress is simulated in this local test; public edge behavior is not claimed as live-tested.

Additional verification:

- `render.yaml` validated successfully against Render's live official JSON Schema, using Python jsonschema; the GitHub Actions YAML also parsed successfully.
- `npm audit --omit=dev`: **0 known vulnerabilities reported** at validation time. This is an advisory scan, not proof that dependencies contain no flaws.
- All original CSS/JavaScript assets, seven form/layout templates, and the cryptography module matched the prior ZIP byte for byte (10 retained files).
- The pinned HTTPS libSQL client import and client construction succeeded.
- The complete ZIP includes the new database adapter, initial SQL schema, locked dependency metadata, Free Blueprint, CI workflow, and deployment instructions.

## Layout review and limits

CSS and template source were reviewed for **1366 × 768**, **1024 × 768**, **768 × 1024**, and **390 × 844**. Desktop forms share one layout, tablet/mobile use a single-column layout, fields use border-box sizing and `min-width: 0`, long names/emails/keys wrap, and recovery codes use a compact two-column grid. The desktop illustration height and spacing were reduced during review to keep normal desktop pages within the intended height. Small screens may scroll vertically when necessary to preserve readable controls.

**Live browser rendering and click testing were not completed.** The execution environment did not have a usable local browser binary; its separate cloud browser could not reach the local application. Therefore this report does not claim pixel-level viewport verification, real-browser autofill/clipboard/accessibility testing, or full browser compatibility. JavaScript syntax, selectors, form endpoints, and the server-side flow were validated as described above. Check the four target viewports in your own browser after starting the application.

The public HIBP API was not contacted with a real password. Its request protocol and failure behavior were tested using controlled fake responses. No real public deployment, hosted Turso connection, executed GitHub Actions workflow, Caddy/systemd execution, Windows/macOS run, external penetration test, load test, or statistical timing-equivalence study was performed. Those results are not implied by the automated tests.

The final ZIP was checked for readable archive entries and complete required source files. Generated configuration secrets, certificates/private keys, runtime databases, and test account data are excluded.
