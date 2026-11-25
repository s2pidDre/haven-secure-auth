import test, { before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { randomBytes } from 'node:crypto';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp, COOKIE } from '../lib/app.mjs';
import { digest, totp, unseal, newTotpSecret, seal } from '../lib/crypto.mjs';
let app, server, config, port, folder, agent;
let screenBehavior = 'safe';
const password = 'Moonlit gardens carry 82 lanterns!';

class Browser {
  cookie = '';
  async request(path, { method = 'GET', data, origin = true, cookie = this.cookie, headers = {}, raw } = {}) {
    const body = raw ?? (data ? new URLSearchParams(data).toString() : undefined);
    const result = await new Promise((resolve, reject) => {
      const req = https.request({ hostname: '127.0.0.1', servername: 'localhost', port, path, method, agent,
        headers: { Host: `localhost:${port}`, ...(cookie ? { Cookie: cookie } : {}),
          ...(method === 'POST' && origin ? { Origin: config.origin } : {}),
          ...(body !== undefined ? { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } : {}), ...headers } }, res => {
        let text = ''; res.setEncoding('utf8'); res.on('data', chunk => { text += chunk; });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: text }));
      });
      req.on('error', reject); req.end(body);
    });
    if (result.headers['set-cookie']) this.cookie = result.headers['set-cookie'][0].split(';')[0];
    return result;
  }
  token(response) { const match = /name="csrf" value="([^"]+)"/.exec(response.body); assert.ok(match, 'CSRF field exists'); return match[1]; }
  async register(email = 'person@example.com', name = 'Ari') {
    const page = await this.request('/register');
    return this.request('/register', { method: 'POST', data: { csrf: this.token(page), name, email, password, confirm_password: password } });
  }
  async login(email = 'person@example.com', pass = password) {
    const page = await this.request('/login');
    return this.request('/login', { method: 'POST', data: { csrf: this.token(page), email, password: pass } });
  }
  async enroll() {
    const view = await this.request('/mfa');
    const secret = /id="setup-key">([^<]+)</.exec(view.body)?.[1]; assert.ok(secret);
    const response = await this.request('/mfa', { method: 'POST', data: { csrf: this.token(view), code: totp(secret, Math.floor(Date.now() / 30000)) } });
    return { secret, response };
  }
}
before(async () => {
  folder = mkdtempSync(join(tmpdir(), 'secure-auth-tests-'));
  config = { origin: 'https://localhost', transport: 'direct', secret: randomBytes(32), dataDir: folder, hibp: false };
  app = await createApp(config, { screenPassword: async () => {
    if (screenBehavior === 'offline') throw new Error('Simulated password screening outage.');
    return screenBehavior === 'breached';
  } });
  const cert = readFileSync(process.env.TEST_TLS_CERT || 'certs/localhost.pem');
  agent = new https.Agent({ ca: cert });
  server = https.createServer({ cert, key: readFileSync(process.env.TEST_TLS_KEY || 'certs/localhost-key.pem'), minVersion: 'TLSv1.2' }, app.handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  port = server.address().port; config.origin = `https://localhost:${port}`;
});
beforeEach(async () => {
  config.hibp = false;
  screenBehavior = 'safe';
  await app.store.db.exec('DELETE FROM recovery_codes; DELETE FROM sessions; DELETE FROM users; DELETE FROM rate_limits; DELETE FROM security_events;');
});
after(async () => {
  agent?.destroy();
  if (server) await new Promise(resolve => server.close(resolve));
  if (app) await app.close(); if (folder) rmSync(folder, { recursive: true, force: true });
});
test('Pages, asset references, POST forms, HTTPS headers, and cookie flags are present', async () => {
  const browser = new Browser(); const response = await browser.request('/login');
  assert.equal(response.status, 200);
  const cookie = response.headers['set-cookie'][0];
  for (const flag of ['Secure', 'HttpOnly', 'SameSite=Strict', 'Path=/']) assert.ok(cookie.includes(flag));
  assert.ok(cookie.startsWith(`${COOKIE}=`)); assert.equal(cookie.includes('Domain='), false);
  assert.equal(response.headers['cache-control'], 'no-store'); assert.match(response.headers['content-security-policy'], /frame-ancestors 'none'/);
  assert.equal(response.headers['referrer-policy'], 'same-origin', 'Native POST forms must retain their Origin without sending referrers to other sites');
  assert.match(response.headers['strict-transport-security'], /max-age/);
  for (const path of ['/register', '/css/style.css', '/js/main.js']) assert.equal((await browser.request(path)).status, 200);
  assert.equal((await browser.request('/logged-in')).headers.location, '/login');
  assert.equal((await browser.request('/data/auth.sqlite')).status, 404);
  assert.equal((await browser.request('/login?password=secret')).status, 400);
});
test('CSRF, cross-origin, duplicate fields, content type, and size are enforced server-side', async () => {
  const browser = new Browser(); const view = await browser.request('/login'); const csrf = browser.token(view);
  const data = { csrf, email: 'person@example.com', password };
  assert.equal((await browser.request('/login', { method: 'POST', data: { ...data, csrf: 'wrong' } })).status, 403);
  assert.equal((await browser.request('/login', { method: 'POST', data, origin: false })).status, 403);
  assert.equal((await browser.request('/login', { method: 'POST', data, headers: { Origin: 'null' } })).status, 403);
  assert.equal((await browser.request('/login', { method: 'POST', data, headers: { Origin: 'https://evil.example' } })).status, 403);
  assert.equal((await browser.request('/login', { method: 'POST', data, headers: { 'Sec-Fetch-Site': 'cross-site' } })).status, 403);
  assert.equal((await browser.request('/login', { method: 'POST', raw: `csrf=${csrf}&csrf=${csrf}` })).status, 400);
  assert.equal((await browser.request('/login', { method: 'POST', data, headers: { 'Content-Type': 'application/json' } })).status, 415);
  assert.equal((await browser.request('/login', { method: 'POST', raw: 'x'.repeat(9000) })).status, 413);
  assert.equal((await browser.request('/login', { headers: { Host: 'evil.example' } })).status, 400);
  assert.equal((await browser.request('/login', { method: 'PUT' })).status, 405);
});
test('Registration duplicates return the same response and preserve existing credentials', async () => {
  const a = new Browser(); const first = await a.register();
  const row = (await app.store.prepare('SELECT * FROM users').get());
  assert.equal(first.status, 303); assert.equal(first.headers.location, '/login'); assert.match(row.password_hash, /^\$argon2id\$/);
  const b = new Browser(); const second = await b.register();
  assert.equal(second.status, first.status); assert.equal(second.headers.location, first.headers.location);
  assert.equal((await app.store.prepare('SELECT COUNT(*) AS n FROM users').get()).n, 1);
  assert.equal((await app.store.prepare('SELECT password_hash FROM users').get()).password_hash, row.password_hash);
});
test('Registration validates inputs without creating a user', async () => {
  const browser = new Browser(); const view = await browser.request('/register');
  for (const change of [{ password: 'short', confirm_password: 'short' }, { email: "' OR 1=1--" }, { confirm_password: 'different' }, { name: 'a'.repeat(81) }]) {
    const result = await browser.request('/register', { method: 'POST', data: { csrf: browser.token(view), name: 'Ari', email: 'person@example.com', password, confirm_password: password, ...change } });
    assert.equal(result.status, 422);
  }
  assert.equal((await app.store.prepare('SELECT COUNT(*) AS n FROM users').get()).n, 0);
});
test('Enabled online screening rejects a breached password and fails closed during an outage', async () => {
  config.hibp = true;
  const browser = new Browser();
  screenBehavior = 'breached';
  assert.equal((await browser.register()).status, 422);
  screenBehavior = 'offline';
  assert.equal((await browser.register()).status, 503);
  assert.equal((await app.store.prepare('SELECT COUNT(*) AS n FROM users').get()).n, 0);
  screenBehavior = 'safe';
  assert.equal((await browser.register()).status, 303);
});
test('Unknown accounts, wrong passwords, oversized passwords, and injection use a generic login failure', async () => {
  const browser = new Browser(); await browser.register();
  for (const [email, pass] of [['person@example.com', 'wrong'], ['unknown@example.com', password], ["' OR 1=1--", password], ['person@example.com', 'a'.repeat(129)]]) {
    const result = await browser.login(email, pass);
    assert.equal(result.status, 401); assert.ok(result.body.includes('Invalid email or password.'));
    assert.equal(result.body.includes('account does not exist'), false);
  }
});
test('Complete enrollment rotates sessions, encrypts TOTP, escapes names, and guards the welcome page', async () => {
  const browser = new Browser(); await browser.register('person@example.com', '<script>alert(1)</script>');
  const anonymous = browser.cookie; assert.equal((await browser.login()).headers.location, '/mfa');
  const pending = browser.cookie; assert.notEqual(pending, anonymous);
  assert.equal((await browser.request('/logged-in')).headers.location, '/login');
  const { secret, response } = await browser.enroll(); assert.equal(response.headers.location, '/recovery');
  assert.notEqual(browser.cookie, pending);
  const record = (await app.store.prepare('SELECT * FROM users').get());
  assert.notEqual(record.totp_secret, secret); assert.equal(unseal(config.secret, record.totp_secret, `totp:${record.id}`), secret);
  const row = (await app.store.prepare('SELECT * FROM sessions').get());
  assert.equal(row.id_hash, digest(browser.cookie.split('=')[1])); assert.notEqual(row.id_hash, browser.cookie.split('=')[1]);
  const welcome = await browser.request('/logged-in'); assert.equal(welcome.status, 200);
  assert.ok(welcome.body.includes('&lt;script&gt;alert(1)&lt;/script&gt;')); assert.equal(welcome.body.includes('<script>alert'), false);
  assert.equal((await browser.request('/logged-in', { cookie: pending })).headers.location, '/login');
});
test('Recovery codes are shown once and accepted once; reused TOTP is rejected', async () => {
  const browser = new Browser(); await browser.register(); await browser.login();
  const { secret } = await browser.enroll();
  const recovery = await browser.request('/recovery');
  const codes = [...recovery.body.matchAll(/<li><code>([A-Z2-7-]+)<\/code><\/li>/g)].map(match => match[1]);
  assert.equal(codes.length, 8); assert.equal((await browser.request('/recovery')).body.includes(codes[0]), false);
  const view = await browser.request('/logged-in'); const loggedCookie = browser.cookie;
  await browser.request('/logout', { method: 'POST', data: { csrf: browser.token(view) } });
  assert.equal((await browser.request('/logged-in', { cookie: loggedCookie })).headers.location, '/login');
  await browser.login(); const mfa = await browser.request('/mfa');
  // Set the most recent step explicitly so this test is independent of a 30-second clock boundary.
  (await app.store.prepare('UPDATE users SET last_totp_step=?').run(Math.floor(Date.now() / 30000)));
  assert.equal((await browser.request('/mfa', { method: 'POST', data: { csrf: browser.token(mfa), code: totp(secret, Math.floor(Date.now() / 30000)) } })).status, 401);
  assert.equal((await browser.request('/mfa', { method: 'POST', data: { csrf: browser.token(mfa), code: codes[0] } })).headers.location, '/logged-in');
  assert.equal((await app.store.prepare('SELECT COUNT(*) AS n FROM recovery_codes').get()).n, 7);
  const logged = await browser.request('/logged-in'); await browser.request('/logout', { method: 'POST', data: { csrf: browser.token(logged) } });
  await browser.login(); const retry = await browser.request('/mfa');
  assert.equal((await browser.request('/mfa', { method: 'POST', data: { csrf: browser.token(retry), code: codes[0] } })).status, 401);
});
test('A fresh TOTP authenticates an already enrolled account', async () => {
  const browser = new Browser(); await browser.register();
  const record = (await app.store.prepare('SELECT * FROM users').get()); const secret = newTotpSecret();
  (await app.store.prepare('UPDATE users SET totp_secret=? WHERE id=?').run(seal(config.secret, secret, `totp:${record.id}`), record.id));
  await browser.login(); const view = await browser.request('/mfa');
  assert.equal(view.body.includes('id="setup-key"'), false);
  const result = await browser.request('/mfa', { method: 'POST', data: { csrf: browser.token(view), code: totp(secret, Math.floor(Date.now() / 30000)) } });
  assert.equal(result.headers.location, '/logged-in');
});
test('Concurrent password submissions cannot rotate the same session twice', async () => {
  const browser = new Browser(); await browser.register();
  const view = await browser.request('/login'); const original = browser.cookie;
  const options = { method: 'POST', cookie: original, data: { csrf: browser.token(view), email: 'person@example.com', password } };
  const outcomes = await Promise.all([browser.request('/login', options), browser.request('/login', options)]);
  assert.equal(outcomes.filter(result => result.status === 303).length, 1);
  assert.equal(outcomes.filter(result => [401, 403].includes(result.status)).length, 1);
  assert.equal((await app.store.prepare("SELECT COUNT(*) AS n FROM sessions WHERE stage='enroll'").get()).n, 1);
});
test('Simultaneous recovery-page requests show the code list only once', async () => {
  const browser = new Browser(); await browser.register(); await browser.login(); await browser.enroll();
  const pages = await Promise.all([browser.request('/recovery'), browser.request('/recovery')]);
  const count = pages.reduce((total, result) => total + [...result.body.matchAll(/<li><code>[A-Z2-7-]+<\/code><\/li>/g)].length, 0);
  assert.equal(count, 8);
});
test('MFA attempts are bounded per account while a pending session remains unauthorized', async () => {
  const browser = new Browser(); await browser.register(); await browser.login();
  const view = await browser.request('/mfa');
  for (let i = 0; i < 5; i++) {
    assert.equal((await browser.request('/mfa', { method: 'POST', data: { csrf: browser.token(view), code: 'invalid' } })).status, 401);
  }
  const blocked = await browser.request('/mfa', { method: 'POST', data: { csrf: browser.token(view), code: 'invalid' } });
  assert.equal(blocked.status, 429); assert.ok(Number(blocked.headers['retry-after']) > 0);
  assert.equal((await browser.request('/logged-in')).headers.location, '/login');
});
test('New MFA enrollment cannot replace an already enrolled authenticator', async () => {
  const browser = new Browser(); await browser.register(); await browser.login();
  const view = await browser.request('/mfa'); const pendingSecret = /id="setup-key">([^<]+)</.exec(view.body)[1];
  const user = (await app.store.prepare('SELECT * FROM users').get()); const original = newTotpSecret();
  const sealed = seal(config.secret, original, `totp:${user.id}`);
  // Model a second session finishing enrollment first.
  (await app.store.prepare('UPDATE users SET totp_secret=? WHERE id=?').run(sealed, user.id));
  const response = await browser.request('/mfa', { method: 'POST', data: { csrf: browser.token(view), code: totp(pendingSecret, Math.floor(Date.now() / 30000)) } });
  assert.equal(response.status, 401);
  assert.equal((await app.store.prepare('SELECT totp_secret FROM users').get()).totp_secret, sealed);
});
test('IP login quota also limits attempts across many different account identifiers', async () => {
  const browser = new Browser();
  for (let i = 0; i < 30; i++) assert.equal((await browser.login(`missing${i}@example.com`, 'incorrect')).status, 401);
  assert.equal((await browser.login('another@example.com', 'incorrect')).status, 429);
});
test('Login quota is persistent and cannot be bypassed by spoofing forwarded headers', async () => {
  const browser = new Browser();
  for (let i = 0; i < 8; i++) assert.equal((await browser.login('missing@example.com', 'incorrect')).status, 401);
  const blocked = await browser.login('missing@example.com', 'incorrect');
  assert.equal(blocked.status, 429); assert.ok(Number(blocked.headers['retry-after']) > 0);
  const view = await browser.request('/login');
  assert.equal((await browser.request('/login', { method: 'POST', data: { csrf: browser.token(view), email: 'missing@example.com', password }, headers: { 'X-Forwarded-For': '8.8.8.8', 'X-Real-IP': '8.8.8.8' } })).status, 429);
  assert.ok((await app.store.prepare('SELECT COUNT(*) AS n FROM rate_limits').get()).n > 0);
});
test('Expired, idle, and pending sessions cannot access protected resources', async () => {
  const browser = new Browser(); await browser.register(); await browser.login(); await browser.enroll();
  (await app.store.prepare('UPDATE sessions SET expires_at=?').run(Date.now() - 1));
  assert.equal((await browser.request('/logged-in')).headers.location, '/login');
  const view = await browser.request('/login');
  (await app.store.prepare('UPDATE sessions SET last_seen=?').run(Date.now() - 16 * 60000));
  assert.equal((await browser.request('/login', { method: 'POST', data: { csrf: browser.token(view), email: 'person@example.com', password } })).status, 403);
});
test('Audit events omit passwords, raw emails, IP addresses, cookies, and authenticator secrets', async () => {
  const browser = new Browser(); await browser.register(); await browser.login(); const { secret } = await browser.enroll();
  const events = JSON.stringify((await app.store.prepare('SELECT * FROM security_events').all()));
  for (const sensitive of [password, 'person@example.com', '127.0.0.1', browser.cookie.split('=')[1], secret]) assert.equal(events.includes(sensitive), false);
  for (const event of ['registration_submitted', 'password_verified', 'mfa_enabled', 'login_succeeded']) assert.ok(events.includes(event));
});
