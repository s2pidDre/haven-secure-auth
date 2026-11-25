# Haven · Secure registration and login

A complete, small authentication project for project 548. Create an account, sign in with a password, verify an authenticator code, and arrive at a simple protected welcome page. No sample accounts, default passwords, database import, or paid services are required. Online deployment uses the pinned, free libSQL driver in package-lock.json.

The complete ZIP includes all application files, tests, documentation, and optional deployment configuration. The `data/`, `certs/`, and `.env` files are generated on your computer and are deliberately excluded. Keep those private files when installing future updates so you retain your accounts and encryption key.

## Deploy online for free

Start with **[DEPLOY-FREE.md](DEPLOY-FREE.md)**. It walks through Render Free, a persistent Turso Free database, and GitHub updates after passing tests. Online deployment does not require the localhost steps below. No paid disk or expiring Render Postgres database is configured. Accounts remain in Turso across code deployments. The free services have documented quotas and cold starts.

## Start on Windows

1. Install **Node.js 24.12 or newer within the 24.x release line** from [nodejs.org](https://nodejs.org/en/download). The built-in Argon2 API and SQLite API are used. Other Node major versions are not accepted by this project.
2. Install [Git for Windows](https://gitforwindows.org/) if OpenSSL is not already installed. Setup also detects Git's usual OpenSSL installation automatically.
3. Extract the complete ZIP into one folder. Double-click **start.bat**. Leave its terminal open.
4. Open **https://localhost:3443** in your browser. Use that exact hostname and port.

Alternatively, open a terminal in the extracted project folder and run `npm run setup`, then `npm start`. The local SQLite mode runs without downloading the hosted-database driver. Install the locked dependencies with `npm ci --ignore-scripts --no-audit --no-fund` before running the full test suite or using Turso. On macOS/Linux, install Node.js 24.x and OpenSSL, then run `sh start.sh` or the same npm commands.

**This project must run through Node.js. Live Server cannot process registration, hashing, SQLite, MFA, or server-side sessions.** Visiting HTML templates as files also does not run the application. Restart Node with Ctrl+C followed by `npm start` after replacing project files, then refresh the browser with Ctrl+F5.

## Local HTTPS certificate

Setup generates a unique, self-signed certificate and private key for **localhost only**, valid for 90 days. HTTPS is enabled immediately; your browser will show a certificate warning until the certificate is trusted. A self-signed certificate without a trusted identity does not provide the same identity assurance as a trusted production certificate. Do not use a warning bypass on a public site.

For a trusted local certificate, install [mkcert](https://github.com/FiloSottile/mkcert), run `mkcert -install` once, and run `mkcert -cert-file certs/localhost.pem -key-file certs/localhost-key.pem localhost 127.0.0.1` from this project's folder. Restart the Node server afterward. This replaces only the localhost certificate pair, not account data or application secrets. Keep mkcert's local CA private; never share its root private key.

To renew an expired self-signed localhost certificate instead, stop Node, move both `certs/localhost.pem` and `certs/localhost-key.pem` aside together, and run `npm run setup` again. Existing `.env` and `data/` remain intact.

## Use the forms

1. Choose **Create an account**, enter your name and email, and choose a unique password with **15–128 characters**. Spaces and Unicode passphrases are supported; passwords are never silently truncated or trimmed. Matching confirmation is required.
2. Sign in with your email and password. Registration always returns the same neutral confirmation, including for an existing email; an existing account's credentials are preserved.
3. On the first sign-in, add a **time-based account** in Google Authenticator, Microsoft Authenticator, 2FAS, or another TOTP app. Enter the setup key shown on the page. Then enter the app's current six-digit code. Your device's time should be automatic.
4. Save the **eight recovery codes** immediately. They appear once and disappear on refresh. Store them separately from your password. Each code can replace one authenticator code after password verification, and each works only once.
5. Continue to the protected welcome page. **Sign out** ends the server-side session. A new sign-in requires your password and a fresh authenticator or recovery code.

TOTP is mandatory for every account. There is no password-only bypass. Setup and MFA verification sessions last five minutes. An authenticated session expires after 15 minutes of inactivity or eight hours total, whichever comes first. Reloading or using the page updates activity; an idle browser tab does not keep a session alive.

If you lose both your authenticator and all recovery codes, this minimal project has no account-recovery bypass. It intentionally does not include email delivery, email verification, password reset, authenticator replacement, or passkeys. Emails are login identifiers, not verified proof of mailbox ownership. Add a properly verified recovery and email-ownership flow before using the application in a service that needs those capabilities.

## Security controls

Open **How your sign-in is protected** on the forms for a brief explanation. See **SECURITY.md** for an exact mapping from every requested control to its implementation and limitations. The UI stays focused on the forms and welcome page.

Online breached-password screening is **optional and off by default** so local registration works without an external service. A small local common-password blocklist always runs. For the broader Have I Been Pwned password corpus, set `HIBP_CHECK=true` in `.env`, then restart Node. Only a five-character SHA-1 prefix is sent to the HTTPS range endpoint, with response padding; the full password, full hash, and email are never sent. SHA-1 is used only for this lookup protocol, never for password storage. If the online check is enabled and unavailable, registration stops with a temporary error instead of bypassing the check. Login for existing users still works. The small local list is not a substitute for the online corpus.

## Verify or inspect

Install the locked dependencies with `npm ci --ignore-scripts --no-audit --no-fund`, then run `npm run ci` for the full security and deployment suite. This generates an isolated test certificate and does not need a local `.env`. Alternatively, after localhost setup, run `npm test`. Run `npm run check` for JavaScript syntax, local asset references, template ID uniqueness, and CSRF fields. Tests use a separate temporary SQLite database; they do not use or delete your real account data.

Run `npm run audit:events` on the server to display the most recent 100 authentication events. This command requires filesystem access and is not a public web endpoint. Logs contain event names, timestamps, and keyed pseudonymous account/IP references. They do not contain passwords, raw emails, raw IP addresses, cookies, OTPs, or recovery codes. They are retained for 30 days. Protect the database and backups, and forward events to a monitored central log if deployed for real users.

See **VALIDATION.md** for the checks performed on this deliverable. Test results are evidence for those cases, not a security certification.

## Production HTTPS on your own server

The ZIP supplies a same-machine Caddy reverse proxy example and an optional Linux systemd unit. Production hosting is not automatically deployed or configured by this download.

1. Use a dedicated hostname with DNS pointing to your server. Install Node.js 24.x and [Caddy](https://caddyserver.com/docs/). Put this application in `/opt/secure-auth` and run it as a dedicated, unprivileged `secureauth` user.
2. Create a fresh private `.env` using `.env.example` as the configuration template and a fresh random 32-byte hexadecimal `APP_SECRET`. You can generate that value with `node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"`. Set `APP_ORIGIN` to your exact public HTTPS origin, `TRANSPORT=proxy`, `HOST=127.0.0.1`, and `PORT=3000`. Set `DATA_DIR=/opt/secure-auth/data`. Local TLS certificate settings are unused in proxy mode. Consider enabling `HIBP_CHECK` when network access is available.
3. In `deploy/Caddyfile`, replace **both** occurrences of `auth.example.com` with your actual hostname. Run Caddy and Node on the same machine. Caddy obtains and renews a trusted public certificate and redirects public HTTP to HTTPS. Permit public ports 80 and 443; keep Node's port 3000 inaccessible externally.
4. The Caddy configuration replaces `Host`, `X-Forwarded-Proto`, and `X-Real-IP`, using the actual incoming client address. The app trusts these headers only in explicit proxy mode over loopback. Do not expose the HTTP backend, place it on a different machine, or enable proxy mode behind an arbitrary forwarding service. Direct HTTPS mode ignores spoofed forwarding headers.
5. For systemd, adjust the Node executable path in `deploy/secure-auth.service` to your installation, create the `secureauth` OS user/group, and give that user access to `.env` and the app files, plus write access to `data/`. Install/enable the service using your normal server administration process. It uses a restricted OS account and permits writes only in the application's data directory.

Back up the SQLite database using SQLite's online backup facilities or stop the application before copying `data/`. A live database may have WAL sidecar files; copying just `auth.sqlite` while the service is running is not a reliable backup. Back up `.env` separately and securely. Losing or changing `APP_SECRET` makes existing encrypted authenticator secrets unreadable. Restore the matching key with the database.

The application uses one Node process. Local and same-machine proxy mode use SQLite unless a Turso URL/token is configured; Render Free requires Turso and refuses an ephemeral fallback. For multiple hosts, put rate limiting and sessions in a shared service/database and re-evaluate concurrency and availability. Benchmark password hashing on the deployment hardware. Application controls do not replace DNS security, OS updates, certificate trust, backups, monitoring, an incident response process, or a deployment security review.

## Files to keep together

Keep `server.mjs`, `package.json`, `package-lock.json`, `lib/`, `sql/`, `templates/`, and `public/` together. Keep `.node-version`, `render.yaml`, and `.github/workflows/security-checks.yml` for the free deployment and update workflow. The remaining folders contain setup, tests, deployment examples, and documentation. Do not publish `data/`, `certs/`, or `.env` through another web server. This application's static router serves only the two explicitly allowed CSS and JavaScript files.
