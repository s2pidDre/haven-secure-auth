import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
process.umask(0o077);
const folder = mkdtempSync(join(tmpdir(), 'haven-ci-'));
try {
  const openssl = ['openssl', 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe', 'C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe']
    .find(command => spawnSync(command, ['version'], { stdio: 'ignore' }).status === 0);
  if (!openssl) throw new Error('OpenSSL is required for the isolated HTTPS tests.');
  const cert = join(folder, 'test.pem'); const key = join(folder, 'test-key.pem');
  const generated = spawnSync(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1',
    '-keyout', key, '-out', cert, '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'], { stdio: 'ignore' });
  if (generated.status !== 0 || !existsSync(cert)) throw new Error('Test certificate creation failed.');
  const env = { ...process.env, TEST_TLS_CERT: cert, TEST_TLS_KEY: key };
  const commands = [['scripts/check.mjs'], ['--test', '--test-concurrency=1', 'tests/auth.test.mjs', 'tests/crypto.test.mjs', 'tests/deployment.test.mjs']];
  for (const args of commands) {
    const result = spawnSync(process.execPath, args, { stdio: 'inherit', env });
    if (result.status !== 0) throw new Error('A required check failed.');
  }
} catch (error) {
  console.error(error.message); process.exitCode = 1;
} finally { rmSync(folder, { recursive: true, force: true }); }
