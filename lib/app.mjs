import { randomUUID, randomInt } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { clientIdentity } from './transport.mjs';
import { setTimeout as delay } from 'node:timers/promises';
import { createStore } from './store.mjs';
import { page } from './views.mjs';
import { hashPassword, verifyPassword, token, digest, equal, seal, unseal, fingerprint,
  newTotpSecret, verifyTotp, recoveryCodes, normalizeRecovery, passwordProblem, isBreached, BusyError } from './crypto.mjs';

export const COOKIE = '__Host-548_session';
const MINUTE = 60000;
const assets = new Map([
  ['/css/style.css', ['text/css; charset=utf-8', readFileSync(new URL('../public/css/style.css', import.meta.url))]],
  ['/js/main.js', ['text/javascript; charset=utf-8', readFileSync(new URL('../public/js/main.js', import.meta.url))]]
]);
const fields = {
  '/register': ['csrf', 'name', 'email', 'password', 'confirm_password'],
  '/login': ['csrf', 'email', 'password'], '/mfa': ['csrf', 'code'],
  '/logout': ['csrf'], '/recovery/continue': ['csrf']
};
function normalizeEmail(value) { return value.trim().toLowerCase(); }
function validEmail(value) {
  return value.length <= 254 && /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/.test(value)
    && value.split('@')[1].split('.').every(part => part.length <= 63);
}
function validPasswordSize(value) { return value.length > 0 && Array.from(value).length <= 128 && Buffer.byteLength(value) <= 512; }
function headers(res) {
  res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'");
  res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Cache-Control', 'no-store');
}
function send(res, status, html) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(html);
}
function redirect(res, location) { res.writeHead(303, { Location: location }); res.end(); }
function cookie(res, value, maxAge) {
  res.setHeader('Set-Cookie', `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`);
}
function fail(res, status, message) { send(res, status, page('error', { title: 'Unable to continue', error: message })); }
async function readForm(req, allowed) {
  if ((req.headers['content-type'] || '').split(';')[0].trim().toLowerCase() !== 'application/x-www-form-urlencoded') {
    const e = new Error('Use the form to submit your request.'); e.status = 415; throw e;
  }
  let bytes = 0; const chunks = [];
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > 8192) { const e = new Error('The submitted form is too large.'); e.status = 413; throw e; }
    chunks.push(chunk);
  }
  const values = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
  for (const key of values.keys()) {
    if (!allowed.includes(key) || values.getAll(key).length !== 1) {
      const e = new Error('Invalid form submission.'); e.status = 400; throw e;
    }
  }
  return Object.fromEntries(allowed.map(key => [key, values.get(key) || '']));
}

export async function createApp(config, options = {}) {
  const store = await createStore(config, options.database || {});
  const { prepare, transaction, audit, consume } = store;
  const dummyHash = await hashPassword(token());
  const screenPassword = options.screenPassword || isBreached;
  let lastCleanup = 0;
  async function getSession(req, res) {
    const matches = (req.headers.cookie || '').split(';').map(item => item.trim()).filter(item => item.startsWith(`${COOKIE}=`));
    const id = matches.length === 1 ? matches[0].slice(COOKIE.length + 1) : '';
    if (!/^[A-Za-z0-9_-]{43}$/.test(id)) return null;
    const row = (await prepare('SELECT * FROM sessions WHERE id_hash=?').get(digest(id)));
    const now = Date.now();
    if (!row) { cookie(res, '', 0); return null; }
    if (row.expires_at <= now || row.last_seen <= now - 15 * MINUTE) {
      (await prepare('DELETE FROM sessions WHERE id_hash=?').run(row.id_hash));
      cookie(res, '', 0);
      await audit('session_expired', req.authIp);
      return null;
    }
    (await prepare('UPDATE sessions SET last_seen=? WHERE id_hash=?').run(now, row.id_hash));
    return row;
  }
  async function rotate(res, previous, stage = 'anonymous', userId = null) {
    const id = token(); const now = Date.now();
    const lifetime = stage === 'authenticated' ? 8 * 60 * MINUTE : stage === 'anonymous' ? 15 * MINUTE : 5 * MINUTE;
    const row = { id_hash: digest(id), csrf: token(), user_id: userId, stage,
      created_at: now, last_seen: now, expires_at: now + lifetime };
    await transaction(async () => {
      if (previous) {
        const removed = await prepare('DELETE FROM sessions WHERE id_hash=? AND stage=? AND expires_at>? AND last_seen>?')
          .run(previous.id_hash, previous.stage, now, now - 15 * MINUTE);
        if (removed.changes !== 1) {
          const expired = new Error('Your session expired. Reload the sign-in form and try again.');
          expired.status = 403; throw expired;
        }
      }
      (await prepare('INSERT INTO sessions(id_hash,csrf,user_id,stage,created_at,last_seen,expires_at) VALUES(?,?,?,?,?,?,?)')
        .run(row.id_hash, row.csrf, row.user_id, row.stage, row.created_at, row.last_seen, row.expires_at));
    });
    cookie(res, id, lifetime / 1000);
    return row;
  }
  async function userFor(session) { return session?.user_id ? (await prepare('SELECT * FROM users WHERE id=?').get(session.user_id)) : null; }
  async function padded(start) { await delay(Math.max(0, 450 + randomInt(50) - (performance.now() - start))); }
  async function limited(req, res, scope, account = '') {
    const registration = scope === 'register';
    const mfa = scope === 'mfa';
    const results = [await consume(`${scope}:ip`, req.authIp, registration ? 10 : mfa ? 30 : 30, 15 * MINUTE)];
    if (account) results.push(await consume(`${scope}:account`, account, registration ? 5 : mfa ? 5 : 8, 15 * MINUTE));
    const blocked = results.filter(result => !result.allowed);
    if (!blocked.length) return false;
    await audit('authentication_throttled', req.authIp, account);
    res.setHeader('Retry-After', String(Math.max(...blocked.map(result => result.retry))));
    fail(res, 429, 'Too many attempts. Wait a little before trying again.');
    return true;
  }
  async function handler(req, res) {
    headers(res);
    try {
      // A minimal, state-free probe also works for the hosting platform's internal health checks.
      if (req.method === 'GET' && req.url === '/healthz') {
        await prepare('SELECT 1 AS ready').get();
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end('{"status":"ok"}'); return;
      }
      try { req.authIp = clientIdentity(req, config); }
      catch { fail(res, 400, 'A secure connection is required.'); return; }
      if (req.headers.host !== new URL(config.origin).host) { fail(res, 400, 'Invalid request host.'); return; }
      const url = new URL(req.url, config.origin);
      if (url.origin !== config.origin || url.search || url.hash) { fail(res, 400, 'Use the page links without query strings.'); return; }
      if (!['GET', 'POST'].includes(req.method)) {
        res.setHeader('Allow', 'GET, POST'); fail(res, 405, 'This request method is not supported.'); return;
      }
      const general = await consume('request:ip', req.authIp, 180, MINUTE);
      if (!general.allowed) { res.setHeader('Retry-After', String(general.retry)); fail(res, 429, 'Too many requests. Please wait.'); return; }
      if (Date.now() - lastCleanup > MINUTE) { lastCleanup = Date.now(); await store.cleanup(); }
      if (assets.has(url.pathname) && req.method === 'GET') {
        const [type, body] = assets.get(url.pathname);
        res.writeHead(200, { 'Content-Type': type }); res.end(body); return;
      }
      if (url.pathname === '/favicon.ico' && req.method === 'GET') { res.writeHead(204); res.end(); return; }
      let session = await getSession(req, res);
      let user = await userFor(session);
      if (session?.user_id && !user) { (await prepare('DELETE FROM sessions WHERE id_hash=?').run(session.id_hash)); session = null; }
      if (req.method === 'GET') {
        if (url.pathname === '/') {
          redirect(res, session?.stage === 'authenticated' ? '/logged-in' : '/login'); return;
        }
        if (['/login', '/register'].includes(url.pathname)) {
          if (session?.stage === 'authenticated') { redirect(res, '/logged-in'); return; }
          if (session && ['enroll', 'verify'].includes(session.stage)) { redirect(res, '/mfa'); return; }
          if (!session) {
            const allowed = await consume('anonymous:ip', req.authIp, 30, 15 * MINUTE);
            if (!allowed.allowed) { fail(res, 429, 'Too many sessions. Please wait before trying again.'); return; }
            session = await rotate(res, null);
          }
          const flash = session.flash || '';
          if (flash) (await prepare('UPDATE sessions SET flash=NULL WHERE id_hash=?').run(session.id_hash));
          const register = url.pathname === '/register';
          send(res, 200, page(register ? 'register' : 'login', {
            title: register ? 'Create your account' : 'Welcome back', csrf: session.csrf, message: flash
          })); return;
        }
        if (url.pathname === '/mfa') {
          if (!session || !['enroll', 'verify'].includes(session.stage) || !user) { redirect(res, '/login'); return; }
          const enrollment = session.stage === 'enroll';
          if (enrollment && !session.pending_secret) {
            const candidate = seal(config.secret, newTotpSecret(), `pending:${session.id_hash}`);
            const stored = await prepare('UPDATE sessions SET pending_secret=COALESCE(pending_secret,?) WHERE id_hash=? RETURNING pending_secret')
              .get(candidate, session.id_hash);
            if (!stored) { redirect(res, '/login'); return; }
            session.pending_secret = stored.pending_secret;
          }
          send(res, 200, page('mfa', { title: enrollment ? 'Set up two-step verification' : 'Verify it’s you', csrf: session.csrf,
            enrollment, setup_key: enrollment ? unseal(config.secret, session.pending_secret, `pending:${session.id_hash}`) : '',
            heading: enrollment ? 'Add a second layer.' : 'One more step.',
            description: enrollment ? 'Set up an authenticator to keep your account protected.' : 'Enter the current code from your authenticator app.',
            code_label: enrollment ? '6-digit authenticator code' : 'Authenticator or recovery code',
            button: enrollment ? 'Enable & continue' : 'Verify & sign in' })); return;
        }
        if (url.pathname === '/recovery') {
          if (session?.stage !== 'authenticated' || !user) { redirect(res, '/login'); return; }
          let codes = [];
          if (session.one_time) {
            const claimed = await prepare('UPDATE sessions SET one_time=NULL WHERE id_hash=? AND one_time=?')
              .run(session.id_hash, session.one_time);
            if (claimed.changes === 1) codes = JSON.parse(unseal(config.secret, session.one_time, `recovery:${session.id_hash}`));
          }
          send(res, 200, page('recovery', { title: 'Save your recovery codes', csrf: session.csrf, codes,
            message: codes.length ? 'Two-step verification is enabled.' : 'The codes were already displayed. Continue to your account.',
            saved_hint: codes.length ? 'Save these codes now. They will not be displayed again, even after a refresh.' : 'Keep the codes you saved in a safe place.' })); return;
        }
        if (url.pathname === '/logged-in') {
          if (session?.stage !== 'authenticated' || !user) { redirect(res, '/login'); return; }
          send(res, 200, page('logged-in', { title: 'You’re logged in', csrf: session.csrf, name: user.name, email: user.email,
            expires: new Date(session.expires_at).toISOString() })); return;
        }
        fail(res, 404, 'This page could not be found.'); return;
      }
      if (!fields[url.pathname]) { fail(res, 404, 'This page could not be found.'); return; }
      if (req.headers.origin !== config.origin || req.headers['sec-fetch-site'] === 'cross-site') {
        await audit('csrf_rejected', req.authIp); fail(res, 403, 'This request could not be verified. Reload the form and try again.'); return;
      }
      if (Number(req.headers['content-length'] || 0) > 8192) { fail(res, 413, 'The submitted form is too large.'); return; }
      const form = await readForm(req, fields[url.pathname]);
      if (!session || !equal(form.csrf, session.csrf)) {
        await audit('csrf_rejected', req.authIp); fail(res, 403, 'Your form expired or could not be verified. Reload the form and try again.'); return;
      }
      if (url.pathname === '/logout') {
        await audit('logout', req.authIp, user?.email);
        (await prepare('DELETE FROM sessions WHERE id_hash=?').run(session.id_hash));
        cookie(res, '', 0); res.setHeader('Clear-Site-Data', '"cache", "cookies", "storage"'); redirect(res, '/login'); return;
      }
      if (url.pathname === '/recovery/continue') {
        if (session.stage !== 'authenticated') { redirect(res, '/login'); return; }
        (await prepare('UPDATE sessions SET one_time=NULL WHERE id_hash=?').run(session.id_hash));
        redirect(res, '/logged-in'); return;
      }
      if (url.pathname === '/register') {
        if (session.stage !== 'anonymous') { redirect(res, '/'); return; }
        const started = performance.now();
        const email = normalizeEmail(form.email);
        const account = email.slice(0, 254);
        if (await limited(req, res, 'register', account)) return;
        const name = form.name.trim();
        let problem = !name || Array.from(name).length > 80 || /[\u0000-\u001f\u007f]/u.test(name) ? 'Enter a name with 1–80 printable characters.' : '';
        problem ||= !validEmail(email) ? 'Enter a valid email address, up to 254 characters.' : '';
        problem ||= passwordProblem(form.password, email);
        problem ||= !equal(form.password, form.confirm_password) ? 'Your passwords do not match.' : '';
        if (problem) {
          send(res, 422, page('register', { title: 'Create your account', csrf: session.csrf, name, email, error: problem })); return;
        }
        if (config.hibp) {
          try {
            if (await screenPassword(form.password)) {
              send(res, 422, page('register', { title: 'Create your account', csrf: session.csrf, name, email,
                error: 'This password has appeared in a data breach. Choose a different password.' })); return;
            }
          } catch {
            await audit('password_screen_unavailable', req.authIp);
            fail(res, 503, 'Password screening is temporarily unavailable. Please try registration later.'); return;
          }
        }
        // Hash every valid registration, including duplicates; never reveal existence.
        const hash = await hashPassword(form.password);
        await transaction(async () => {
          (await prepare('INSERT INTO users(id,name,email,password_hash,created_at) VALUES(?,?,?,?,?) ON CONFLICT(email) DO NOTHING')
            .run(randomUUID(), name, email, hash, Date.now()));
          await audit('registration_submitted', req.authIp, email);
        });
        session = await rotate(res, session);
        (await prepare('UPDATE sessions SET flash=? WHERE id_hash=?').run('Registration processed. Sign in with your credentials to continue. If you already have an account, use your existing password.', session.id_hash));
        await padded(started); redirect(res, '/login'); return;
      }
      if (url.pathname === '/login') {
        if (session.stage !== 'anonymous') { redirect(res, '/'); return; }
        const started = performance.now();
        const email = normalizeEmail(form.email);
        if (await limited(req, res, 'login', email.slice(0, 254))) return;
        const found = validEmail(email) ? (await prepare('SELECT * FROM users WHERE email=?').get(email)) : null;
        const validSize = validPasswordSize(form.password);
        const verified = await verifyPassword(validSize ? form.password : 'invalid-input', found?.password_hash || dummyHash);
        // The CSRF-bearing session must still exist after async hashing (logout/race defense).
        const current = (await prepare('SELECT stage FROM sessions WHERE id_hash=?').get(session.id_hash));
        if (!found || !validSize || !verified || current?.stage !== 'anonymous') {
          await audit('login_failed', req.authIp, email.slice(0, 254));
          await padded(started);
          send(res, 401, page('login', { title: 'Welcome back', csrf: session.csrf, email, error: 'Invalid email or password.' })); return;
        }
        session = await rotate(res, session, found.totp_secret ? 'verify' : 'enroll', found.id);
        await audit('password_verified', req.authIp, found.email);
        await padded(started); redirect(res, '/mfa'); return;
      }
      if (url.pathname === '/mfa') {
        if (!['enroll', 'verify'].includes(session.stage) || !user) { redirect(res, '/login'); return; }
        const started = performance.now();
        if (await limited(req, res, 'mfa', user.email)) return;
        const enrollment = session.stage === 'enroll';
        const submitted = form.code.trim();
        let accepted = false; let codes = [];
        await transaction(async () => {
          // Re-read the record inside the write transaction: concurrent enrollment/replay cannot bypass CAS.
          const fresh = (await prepare('SELECT * FROM users WHERE id=?').get(user.id));
          const secret = enrollment && session.pending_secret ? unseal(config.secret, session.pending_secret, `pending:${session.id_hash}`)
            : !enrollment && fresh.totp_secret ? unseal(config.secret, fresh.totp_secret, `totp:${user.id}`) : null;
          const step = secret ? verifyTotp(secret, submitted, fresh.last_totp_step) : null;
          if (enrollment && secret && step !== null && !fresh.totp_secret) {
            accepted = (await prepare('UPDATE users SET totp_secret=?,last_totp_step=? WHERE id=? AND totp_secret IS NULL')
              .run(seal(config.secret, secret, `totp:${user.id}`), step, user.id)).changes === 1;
            if (accepted) {
              codes = recoveryCodes();
              const rows = codes.flatMap(code => [fingerprint(config.secret, 'recovery-code', normalizeRecovery(code)), user.id]);
              await prepare('INSERT INTO recovery_codes(code_hash,user_id) VALUES(?,?),(?,?),(?,?),(?,?),(?,?),(?,?),(?,?),(?,?)')
                .run(...rows);
              await audit('mfa_enabled', req.authIp, user.email);
            }
          } else if (!enrollment && step !== null) {
            accepted = (await prepare('UPDATE users SET last_totp_step=? WHERE id=? AND last_totp_step<?').run(step, user.id, step)).changes === 1;
          } else if (!enrollment && /^[A-Z2-7]{16}$/.test(normalizeRecovery(submitted))) {
            accepted = (await prepare('DELETE FROM recovery_codes WHERE code_hash=? AND user_id=?')
              .run(fingerprint(config.secret, 'recovery-code', normalizeRecovery(submitted)), user.id)).changes === 1;
            if (accepted) await audit('recovery_code_used', req.authIp, user.email);
          }
        });
        if (!accepted) {
          await audit('mfa_failed', req.authIp, user.email);
          await padded(started);
          send(res, 401, page('mfa', { title: 'Verify it’s you', csrf: session.csrf, enrollment,
            setup_key: enrollment && session.pending_secret ? unseal(config.secret, session.pending_secret, `pending:${session.id_hash}`) : '',
            heading: enrollment ? 'Add a second layer.' : 'One more step.',
            description: 'Use a fresh code from your authenticator app. Your verification session lasts five minutes.',
            code_label: enrollment ? '6-digit authenticator code' : 'Authenticator or recovery code',
            button: enrollment ? 'Enable & continue' : 'Verify & sign in', error: 'Invalid or already used verification code.' })); return;
        }
        session = await rotate(res, session, 'authenticated', user.id);
        if (codes.length) (await prepare('UPDATE sessions SET one_time=? WHERE id_hash=?')
          .run(seal(config.secret, JSON.stringify(codes), `recovery:${session.id_hash}`), session.id_hash));
        await audit('login_succeeded', req.authIp, user.email);
        await padded(started); redirect(res, codes.length ? '/recovery' : '/logged-in'); return;
      }
    } catch (error) {
      if (res.headersSent || res.destroyed) return;
      if (error instanceof BusyError) {
        res.setHeader('Retry-After', '3'); fail(res, 503, 'Sign-in is busy. Please try again in a few seconds.'); return;
      }
      if (error.status) { fail(res, error.status, error.message); return; }
      // Never print request bodies, cookies, URLs, database records, or exception messages.
      console.error(JSON.stringify({ event: 'internal_error', at: new Date().toISOString() }));
      fail(res, 500, 'Something went wrong. Please try again later.');
    }
  }
  return { handler, store, close: () => store.close() };
}
