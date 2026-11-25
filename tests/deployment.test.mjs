import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createClient } from '@libsql/client';
import { configFromEnv } from '../lib/config.mjs';
import { clientIdentity } from '../lib/transport.mjs';
import { createStore } from '../lib/store.mjs';
import { createApp } from '../lib/app.mjs';
import { totp } from '../lib/crypto.mjs';

function hostingEnv() {
  return { APP_SECRET: randomBytes(32).toString('base64'), TRANSPORT: 'render-free',
    RENDER: 'true', RENDER_SERVICE_TYPE: 'web', RENDER_EXTERNAL_URL: 'https://haven-test.onrender.com',
    TURSO_DATABASE_URL: 'libsql://haven-test-example.turso.io', TURSO_AUTH_TOKEN: 'test-database-scoped-token' };
}
function request(headers = {}, encrypted = false, remoteAddress = '10.0.0.1') {
  return { headers, socket: { encrypted, remoteAddress } };
}
test('Render Free configuration uses managed HTTPS and an external database', () => {
  const env = hostingEnv(); const config = configFromEnv(env);
  assert.equal(config.origin, env.RENDER_EXTERNAL_URL);
  assert.equal(config.host, '0.0.0.0'); assert.equal(config.port, 10000);
  assert.equal(config.secret.length, 32); assert.equal(config.databaseUrl, env.TURSO_DATABASE_URL);
  const custom = configFromEnv({ ...env, APP_ORIGIN: 'https://auth.example.com' });
  assert.equal(custom.origin, 'https://auth.example.com');
});
test('Hosting refuses ephemeral accounts, insecure database URLs, invalid secrets, and false platform claims', () => {
  const env = hostingEnv();
  for (const change of [
    { TURSO_DATABASE_URL: '', TURSO_AUTH_TOKEN: '' }, { TURSO_AUTH_TOKEN: '' },
    { TURSO_DATABASE_URL: 'http://example.com' }, { TURSO_DATABASE_URL: 'https://attacker.example/' },
    { TURSO_DATABASE_URL: 'https://name.turso.io/?token=secret' },
    { APP_SECRET: 'weak' }, { APP_SECRET: 'A'.repeat(43) + '/' },
    { APP_ORIGIN: 'http://example.com' }, { HOST: '127.0.0.1' }, { RENDER: 'false' },
    { RENDER_SERVICE_TYPE: 'pserv' }, { HIBP_CHECK: 'yes' }
  ]) assert.throws(() => configFromEnv({ ...env, ...change }));
});
test('Original localhost configuration and hexadecimal application keys remain supported', () => {
  const config = configFromEnv({ APP_SECRET: randomBytes(32).toString('hex') });
  assert.equal(config.origin, 'https://localhost:3443'); assert.equal(config.transport, 'direct');
  assert.equal(config.databaseUrl, ''); assert.equal(config.host, '127.0.0.1');
});
test('Free-host ingress uses Cloudflare identity and ignores spoofed forwarding chains', () => {
  const config = { transport: 'render-free' };
  const trusted = { 'x-forwarded-proto': 'https', 'cf-connecting-ip': '203.0.113.42',
    'x-forwarded-for': '8.8.8.8, 10.0.0.1', 'x-real-ip': '8.8.8.8' };
  assert.equal(clientIdentity(request(trusted), config), '203.0.113.42');
  for (const headers of [{}, { ...trusted, 'x-forwarded-proto': 'http' },
    { ...trusted, 'cf-connecting-ip': undefined }, { ...trusted, 'cf-connecting-ip': '8.8.8.8, 1.1.1.1' }]) {
    assert.throws(() => clientIdentity(request(headers), config));
  }
  assert.equal(clientIdentity(request(trusted, true, '192.0.2.9'), { transport: 'direct' }), '192.0.2.9');
  assert.throws(() => clientIdentity(request(trusted), { transport: 'direct' }));
});
test('Same-machine proxy mode retains its loopback-only trust boundary', () => {
  const headers = { 'x-forwarded-proto': 'https', 'x-real-ip': '203.0.113.5' };
  assert.equal(clientIdentity(request(headers, false, '127.0.0.1'), { transport: 'proxy' }), '203.0.113.5');
  assert.throws(() => clientIdentity(request(headers, false, '192.0.2.1'), { transport: 'proxy' }));
});
test('Real libSQL adapter preserves records across reopen and rolls back partial changes', async () => {
  const folder = mkdtempSync(join(tmpdir(), 'haven-libsql-'));
  const url = `file:${join(folder, 'cloud-adapter.sqlite')}`;
  const config = { secret: randomBytes(32) };
  let store;
  try {
    store = await createStore(config, { client: createClient({ url, intMode: 'number' }) });
    const insert = store.prepare('INSERT INTO users(id,name,email,password_hash,created_at) VALUES(?,?,?,?,?)');
    await insert.run('one', 'Ari', 'ari@example.com', 'test-only-hash', Date.now());
    await assert.rejects(() => store.transaction(async () => {
      await insert.run('two', 'Nico', 'nico@example.com', 'test-only-hash', Date.now());
      throw new Error('Abort the test transaction.');
    }));
    assert.equal((await store.prepare('SELECT COUNT(*) AS n FROM users').get()).n, 1);
    const attempts = await Promise.all(Array.from({ length: 12 }, () => store.consume('parallel', 'test-account', 8, 60000)));
    assert.equal(attempts.filter(attempt => attempt.allowed).length, 8);
    await store.close(); store = null;
    store = await createStore(config, { client: createClient({ url, intMode: 'number' }) });
    assert.equal((await store.prepare('SELECT email FROM users WHERE id=?').get('one')).email, 'ari@example.com');
    assert.equal((await store.consume('parallel', 'test-account', 8, 60000)).allowed, false);
    const hostile = "' OR 1=1 --";
    assert.equal(await store.prepare('SELECT * FROM users WHERE email=?').get(hostile), undefined);
  } finally {
    if (store) await store.close(); rmSync(folder, { recursive: true, force: true });
  }
});
test('Local async transactions do not absorb unrelated requests into their rollback', async () => {
  const folder = mkdtempSync(join(tmpdir(), 'haven-isolation-'));
  const store = await createStore({ secret: randomBytes(32), dataDir: folder });
  try {
    const insert = store.prepare('INSERT INTO users(id,name,email,password_hash,created_at) VALUES(?,?,?,?,?)');
    let signal; const entered = new Promise(resolve => { signal = resolve; });
    let release; const gate = new Promise(resolve => { release = resolve; });
    const rolledBack = store.transaction(async () => {
      await insert.run('rollback', 'A', 'a@example.com', 'fixture', 1); signal();
      await gate; throw new Error('Expected rollback.');
    });
    const rejected = assert.rejects(rolledBack);
    await entered;
    const unrelated = insert.run('keep', 'B', 'b@example.com', 'fixture', 2);
    release(); await rejected; await unrelated;
    assert.deepEqual((await store.prepare('SELECT id FROM users').all()).map(row => row.id), ['keep']);
  } finally { await store.close(); rmSync(folder, { recursive: true, force: true }); }
});
test('Managed ingress health checks expose no session, database details, or account data', async () => {
  const folder = mkdtempSync(join(tmpdir(), 'haven-health-'));
  const app = await createApp({ secret: randomBytes(32), dataDir: folder, origin: 'https://haven-test.onrender.com', transport: 'render-free' });
  const server = http.createServer(app.handler);
  try {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;
    const get = headers => new Promise((resolve, reject) => {
      http.get({ hostname: '127.0.0.1', port, path: '/healthz', headers }, response => {
        let body = ''; response.on('data', chunk => { body += chunk; });
        response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body }));
      }).on('error', reject);
    });
    const health = await get({ Host: 'internal-probe' });
    assert.equal(health.status, 200); assert.deepEqual(JSON.parse(health.body), { status: 'ok' });
    assert.equal(health.headers['set-cookie'], undefined);
    assert.equal((await app.store.prepare('SELECT COUNT(*) AS n FROM sessions').get()).n, 0);
  } finally {
    await new Promise(resolve => server.close(resolve)); await app.close(); rmSync(folder, { recursive: true, force: true });
  }
});
test('Free deployment and CI definitions do not provision paid or temporary databases', () => {
  const blueprint = readFileSync('render.yaml', 'utf8');
  assert.match(blueprint, /plan: free/); assert.match(blueprint, /autoDeployTrigger: checksPass/);
  assert.equal(/^\s*disk:/m.test(blueprint), false); assert.equal(/^databases:/m.test(blueprint), false);
  for (const key of ['APP_SECRET', 'TURSO_DATABASE_URL', 'TURSO_AUTH_TOKEN']) assert.ok(blueprint.includes(key));
  const workflow = readFileSync('.github/workflows/security-checks.yml', 'utf8');
  assert.match(workflow, /contents: read/); assert.match(workflow, /npm run ci/);
});
test('The full libSQL-backed hosted flow and authenticated session survive an app restart', async () => {
  const folder = mkdtempSync(join(tmpdir(), 'haven-hosted-flow-'));
  const url = `file:${join(folder, 'auth.sqlite')}`;
  const config = { secret: randomBytes(32), transport: 'render-free', origin: 'https://haven-test.onrender.com', hibp: false };
  let app, server, port, cookie = '';
  const start = async () => {
    app = await createApp(config, { database: { client: createClient({ url, intMode: 'number' }) } });
    server = http.createServer(app.handler);
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); port = server.address().port;
  };
  const stop = async () => { if (server) await new Promise(resolve => server.close(resolve)); if (app) await app.close(); server = null; app = null; };
  const visit = (path, data) => new Promise((resolve, reject) => {
    const body = data ? new URLSearchParams(data).toString() : '';
    const req = http.request({ hostname: '127.0.0.1', port, path, method: data ? 'POST' : 'GET', headers: {
      Host: 'haven-test.onrender.com', Origin: config.origin, 'X-Forwarded-Proto': 'https',
      'CF-Connecting-IP': '203.0.113.5', Cookie: cookie,
      ...(data ? { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } : {})
    } }, response => {
      let text = ''; response.on('data', chunk => { text += chunk; });
      response.on('end', () => {
        if (response.headers['set-cookie']) cookie = response.headers['set-cookie'][0].split(';')[0];
        resolve({ status: response.statusCode, headers: response.headers, body: text });
      });
    }); req.on('error', reject); req.end(body);
  });
  const csrf = view => /name="csrf" value="([^"]+)"/.exec(view.body)[1];
  try {
    await start();
    let view = await visit('/register');
    const password = 'Clear mountain lanterns float at 82!';
    assert.equal((await visit('/register', { csrf: csrf(view), name: 'Hosted Ari', email: 'hosted@example.com', password, confirm_password: password })).status, 303);
    view = await visit('/login');
    assert.equal((await visit('/login', { csrf: csrf(view), email: 'hosted@example.com', password })).headers.location, '/mfa');
    view = await visit('/mfa');
    const secret = /id="setup-key">([^<]+)</.exec(view.body)[1];
    assert.equal((await visit('/mfa', { csrf: csrf(view), code: totp(secret, Math.floor(Date.now() / 30000)) })).headers.location, '/recovery');
    assert.equal((await visit('/recovery')).status, 200);
    view = await visit('/logged-in'); assert.equal(view.status, 200); assert.ok(view.body.includes('Hosted Ari'));
    await stop(); await start();
    view = await visit('/logged-in'); assert.equal(view.status, 200); assert.ok(view.body.includes('hosted@example.com'));
    assert.equal((await visit('/logout', { csrf: csrf(view) })).headers.location, '/login');
    assert.equal((await visit('/logged-in')).headers.location, '/login');
  } finally { await stop(); rmSync(folder, { recursive: true, force: true }); }
});
