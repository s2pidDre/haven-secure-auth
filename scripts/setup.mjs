import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync, readFileSync, chmodSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { spawnSync } from 'node:child_process';
process.umask(0o077);
if (process.versions.node.split('.')[0] !== '24' || Number(process.versions.node.split('.')[1]) < 12) {
  console.error('Install Node.js 24.12 or newer within the 24.x release line.'); process.exit(1);
}
const candidates = [process.env.OPENSSL_BIN, 'openssl',
  'C:\\Program Files\\Git\\usr\\bin\\openssl.exe', 'C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe'].filter(Boolean);
const openssl = candidates.find(candidate => spawnSync(candidate, ['version'], { stdio: 'ignore', windowsHide: true }).status === 0);
if (!existsSync('certs/localhost.pem') || !existsSync('certs/localhost-key.pem')) {
  if (existsSync('certs/localhost.pem') || existsSync('certs/localhost-key.pem')) {
    console.error('Only one TLS file exists. Restore the matching certificate/key pair or move both files aside before rerunning setup.'); process.exit(1);
  }
  if (!openssl) {
    console.error('OpenSSL is required for localhost HTTPS. Install Git for Windows (includes OpenSSL), or OpenSSL on macOS/Linux, then run setup again. You may also create certs/localhost.pem and certs/localhost-key.pem with mkcert first.'); process.exit(1);
  }
  mkdirSync('certs', { recursive: true, mode: 0o700 });
  const result = spawnSync(openssl, ['req', '-x509', '-newkey', 'rsa:3072', '-sha256', '-nodes', '-days', '90',
    '-keyout', resolve('certs/localhost-key.pem'), '-out', resolve('certs/localhost.pem'),
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
    '-addext', 'basicConstraints=critical,CA:FALSE'], { stdio: 'pipe', windowsHide: true });
  if (result.status !== 0) { console.error('Local certificate creation failed. Check your OpenSSL installation and permissions.'); process.exit(1); }
  chmodSync('certs/localhost-key.pem', 0o600);
  console.log('Created a unique, self-signed localhost certificate (90 days).');
}
if (!existsSync('.env')) {
  const sample = readFileSync('.env.example', 'utf8');
  writeFileSync('.env', sample.replace('APP_SECRET=\n', `APP_SECRET=${randomBytes(32).toString('hex')}\n`), { flag: 'wx', mode: 0o600 });
  console.log('Created private application configuration.');
} else {
  console.log('Existing .env preserved.');
}
mkdirSync(join(process.cwd(), 'data'), { recursive: true, mode: 0o700 });
console.log('Setup complete. Run npm start, then open https://localhost:3443.');
console.log('For trusted localhost HTTPS, follow README.md. Live Server cannot run this backend.');
