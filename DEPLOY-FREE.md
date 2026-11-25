# Free online deployment and future updates

This package is prepared for **Render Free + Turso Free + GitHub Free**. No paid disk, paid database, custom domain, or ChatGPT app connection is required. Use the included `onrender.com` address. The site is **not already deployed**: the services must be created in your own accounts first.

## What each service does

| Service | Choose | Purpose |
| --- | --- | --- |
| GitHub | Free account and a private repository | Stores your source and runs the included tests on updates. |
| Render | Free web service | Runs the Node.js backend and provides HTTPS. |
| Turso | Free libSQL database | Stores accounts, sessions, rate limits, recovery-code hashes, and logs outside Render's temporary filesystem. |

Current free plans have usage limits. Render Free sleeps after 15 idle minutes, and the next request can take about a minute to wake it. It has a shared allowance of 750 instance hours per month. Turso Free currently includes 5 GB of storage, 500 million row reads, and 10 million row writes per month. GitHub private-repository automation has an included allowance. This is a practical demo or school-project setup, not an uptime guarantee.

To keep the total at **$0**, stay on Free plans, do not add a payment method, do not enable paid overages, use standard GitHub-hosted Linux runners, and use the included hostname. A limit may pause service or builds. If any account setup requires a payment or verification charge, stop before accepting it. Free-plan terms can change; review the provider's current account screens before creating anything.

## 1. Create the free accounts

Sign in or create accounts on [GitHub](https://github.com/), [Turso](https://app.turso.tech/), and [Render](https://dashboard.render.com/). You can complete the entire online setup through their websites. You do **not** need to run localhost, install OpenSSL, trust a local certificate, or run Live Server to deploy online.

Do not send account passwords, database tokens, or application keys through chat or put them in GitHub files.

## 2. Put the full project in GitHub

1. Create a **private** repository named `haven-secure-auth` with the default branch named `main`.
2. Extract the complete deployment ZIP on your computer. Upload the extracted contents into the repository's root using **Add file → Upload files**, then commit. Upload the actual files and folders, not the ZIP file itself or an extra enclosing project folder.
3. Confirm that `package.json`, `package-lock.json`, `server.mjs`, `render.yaml`, and `.node-version` are at the repository root. Keep all `lib/`, `public/`, `templates/`, `sql/`, `scripts/`, and `tests/` files.
4. Confirm that `.github/workflows/security-checks.yml` is included. Files or folders beginning with a dot may require showing hidden items in a file picker. `.env.example` is safe to upload. **Never upload `.env`, `certs/`, `data/`, `node_modules/`, or database exports.** Those private/runtime files are excluded from this ZIP.
5. Open the repository's **Actions** tab. Enable Actions for the repository if needed, and let **Security checks** finish successfully. The workflow uses read-only repository access and does not need your hosted database token.

If you prefer GitHub Desktop, add this extracted folder as a new repository and publish it as private. It will preserve the folder structure and include the dotted configuration files. The included `.gitignore` protects runtime files from normal Git commits, but check the upload list yourself before using a browser upload.

## 3. Create the Turso database

1. In the Turso dashboard, remain on the **Free** plan and create a database named `haven-auth`. Use a **libSQL-compatible** database, which is what this package's pinned `@libsql/client` driver supports. If an engine selector is shown, choose libSQL. Do not choose a rewritten-engine-only endpoint that requires a different SDK.
2. Choose a database region near Singapore when available, since the web service is configured for Render's Singapore region.
3. In the database details, copy the **database URL**. It should use `libsql://` or `https://` and a hostname ending in `.turso.io`.
4. Generate a **database-scoped read/write authentication token** for this database. Do not use an organization-wide management API token. If you choose an expiration, record the date and renew it before it expires. Update Render's token when rotating it.
5. Keep the URL and token private for the next step. The application creates the initial tables automatically on startup; you do not need to paste an SQL schema into the dashboard.

The hosted database starts empty. Existing local accounts are not automatically copied. The local `data/` folder is deliberately excluded from online uploads.

## 4. Deploy the Render Free service

1. In Render, choose **New → Blueprint** and select the GitHub repository. If prompted, authorize Render to read **only this repository**. This is the normal provider-to-repository connection used for deploying your code.
2. Select the `main` branch. Render reads the included `render.yaml`.
3. Check the resource summary: it must show **one Free web service**, with **no persistent disk and no Render Postgres database**. Do not choose a paid compute plan.
4. Supply the two values the Blueprint requests:

| Setting | Value |
| --- | --- |
| `TURSO_DATABASE_URL` | Your database URL from Turso. |
| `TURSO_AUTH_TOKEN` | Your database-scoped read/write token. |

5. Leave `APP_SECRET` set to **Generate**. Render creates and retains a random application key. The app accepts Render's base64-encoded generated secret as well as the hexadecimal key used for localhost.
6. Apply the Blueprint and wait for the initial build. It installs the pinned dependencies and runs the tests. If a required test fails, the build fails instead of deploying that version.
7. When the service is live, open the exact HTTPS URL shown by Render. The application automatically uses `RENDER_EXTERNAL_URL` as its public origin, so you do not have to guess its hostname or edit source code.
8. Create an account, sign in, finish authenticator setup, save your recovery codes, and confirm that the welcome page appears. Sign out and sign in again with a new authenticator code.

The service's `/healthz` endpoint reports only `{"status":"ok"}` when it can query the database. It exposes no accounts, database credentials, or session cookies. Render uses it for health checks. Normal application pages still require a verified HTTPS ingress path.

### Equivalent manual service settings

Use these if the Blueprint interface is unavailable. Choose a **Web Service**, not a Static Site:

| Setting | Value |
| --- | --- |
| Runtime | Node |
| Branch | `main` |
| Region | Singapore |
| Plan | **Free** |
| Root directory | Repository root; leave blank |
| Build command | `npm ci --ignore-scripts --no-audit --no-fund && npm run ci` |
| Start command | `npm start` |
| Health check path | `/healthz` |
| Auto-deploy | After CI checks pass |
| `NODE_VERSION` | `24.22.3` |
| `NODE_ENV` | `production` |
| `TRANSPORT` | `render-free` |
| `HOST` | `0.0.0.0` |
| `APP_SECRET` | Generate a random value encoding 32 bytes as base64 or 64 hexadecimal characters. |
| `TURSO_DATABASE_URL` | Your private database URL. |
| `TURSO_AUTH_TOKEN` | Your private database token. |
| `HIBP_CHECK` | `false`, or `true` if you want online breached-password screening. |

Render sets `PORT`, `RENDER`, `RENDER_SERVICE_TYPE`, and `RENDER_EXTERNAL_URL` itself. Do not enter a localhost origin. Do not run `npm run setup` in the hosted build: it is for localhost certificates/configuration only.

## 5. Update after deployment

1. Ask for the change you want. Each update can be delivered as a new **complete ZIP** with matching filenames and the current working features retained.
2. Extract the new ZIP and upload its matching files to the **same GitHub repository**, preserving their paths. For several related files, commit them together. Do not create a new Render service or a new database for a normal update.
3. GitHub runs **Security checks**. Render's `checksPass` policy waits for those checks before automatically building the new commit. The Render build runs the checks again as an additional gate.
4. Wait for Render to mark the new deployment live, then refresh the HTTPS site with Ctrl+F5.
5. Confirm that an existing account can still sign in. Account records, server-side sessions, MFA data, throttling state, and security events live in Turso, so a normal code redeployment does not replace them.

Keep the existing **`APP_SECRET`**, **database URL**, and **database**. Generating a different application key makes existing authenticator secrets unreadable. Replacing or deleting the database removes your users. Keep an encrypted backup of the application key separate from your database backups.

For UI or logic updates, leave `sql/001-auth.sql` unchanged. Future schema changes require a reviewed, additive migration; simply editing an existing `CREATE TABLE IF NOT EXISTS` definition does not alter tables already online. Code rollback also does not roll back database changes. Ask for a migration together with any new database feature.

For a bad code update, use Render's deployment rollback option, or revert the GitHub commit and let CI redeploy the known working source. Keep the same database and application key. A code rollback is not an account-data restore.

## If something fails

| Symptom | Check |
| --- | --- |
| First request takes a long time | A Free service may be waking after inactivity. Wait for its normal startup; do not add a paid plan. |
| CI fails | Read the failed test in GitHub Actions or Render's build log. Do not disable the checks to force a deploy. |
| Startup refused | Check the application key, database URL/token, Free transport settings, and Node 24.x version. Application error logs deliberately omit secrets. |
| Database requests fail | Check Turso's quota, token expiration, libSQL compatibility, and database status. The app fails closed rather than creating a temporary local user database. |
| Invalid host / form verification error | Use the exact service HTTPS URL. A custom origin must match the address visitors use. |
| Accounts disappeared after an update | Check that the same Turso database URL and `APP_SECRET` are still configured. Do not register replacement accounts until the cause is understood. |
| Provider requests a payment method or charge | Stop before accepting. This plan does not authorize payments or paid upgrades. |

No public deployment or hosted credential was created while preparing this ZIP. The package's automated tests cover the adapter and deployment configuration; the first real deployment and its public HTTPS ingress must still be verified in your accounts.

## Official references

- [Render free service limits](https://render.com/docs/free)
- [Render billing behavior on free services](https://render.com/docs/faq)
- [Render managed HTTPS](https://render.com/docs/tls)
- [Render Blueprint specification](https://render.com/docs/blueprint-spec)
- [Turso Free pricing and allowances](https://turso.tech/pricing)
- [Turso TypeScript/libSQL reference](https://docs.turso.tech/sdk/ts/reference)
- [GitHub Actions included usage and billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions)
