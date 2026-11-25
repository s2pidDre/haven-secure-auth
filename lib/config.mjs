import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

export function configFromEnv(env) {
  if (process.versions.node.split('.')[0] !== '24' || Number(process.versions.node.split('.')[1]) < 12) {
    throw new Error('Use Node.js 24.12 or newer within the 24.x release line.');
  }
  const transport = env.TRANSPORT || 'direct';
  if (!['direct', 'proxy', 'render-free'].includes(transport)) throw new Error('Invalid TRANSPORT.');
  if (transport === 'render-free' && (env.RENDER !== 'true' || env.RENDER_SERVICE_TYPE !== 'web')) {
    throw new Error('render-free transport is only for a public Render Free web service.');
  }
  const origin = new URL(env.APP_ORIGIN || (transport === 'render-free' ? env.RENDER_EXTERNAL_URL || '' : 'https://localhost:3443'));
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash) {
    throw new Error('APP_ORIGIN must be one HTTPS origin without a path, credentials, or query.');
  }
  const encodedSecret = env.APP_SECRET || '';
  let secret;
  if (/^[a-f0-9]{64}$/i.test(encodedSecret)) secret = Buffer.from(encodedSecret, 'hex');
  else if (/^[A-Za-z0-9+/]{43}=$/.test(encodedSecret)) {
    secret = Buffer.from(encodedSecret, 'base64');
    if (secret.length !== 32 || secret.toString('base64') !== encodedSecret) throw new Error('Invalid APP_SECRET.');
  } else throw new Error('APP_SECRET must encode 32 random bytes as hex or base64.');
  const databaseUrl = env.TURSO_DATABASE_URL || '';
  const databaseToken = env.TURSO_AUTH_TOKEN || '';
  if (databaseUrl || databaseToken) {
    const database = new URL(databaseUrl);
    if (!['libsql:', 'https:'].includes(database.protocol) || !database.hostname.endsWith('.turso.io') ||
      database.username || database.password || database.port || !['', '/'].includes(database.pathname) || database.search || database.hash || !databaseToken) {
      throw new Error('Use a secure Turso libSQL database URL and a database-scoped token.');
    }
  }
  if (transport === 'render-free' && (!databaseUrl || !databaseToken)) {
    throw new Error('Render Free requires Turso. Refusing to store accounts on an ephemeral filesystem.');
  }
  const host = env.HOST || (transport === 'render-free' ? '0.0.0.0' : '127.0.0.1');
  // Proxy HTTP is allowed only on loopback, behind a TLS reverse proxy on this machine.
  if (transport === 'proxy' && host !== '127.0.0.1') throw new Error('Proxy mode must bind to 127.0.0.1.');
  if (transport === 'render-free' && host !== '0.0.0.0') throw new Error('Render must bind to 0.0.0.0.');
  const port = Number(env.PORT || (transport === 'render-free' ? 10000 : 3443));
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid PORT.');
  const hibp = env.HIBP_CHECK || 'false';
  if (!['true', 'false'].includes(hibp)) throw new Error('HIBP_CHECK must be true or false.');
  return {
    origin: origin.origin, host, port, transport,
    secret, databaseUrl, databaseToken,
    dataDir: resolve(env.DATA_DIR || 'data'),
    tlsCert: resolve(env.TLS_CERT || 'certs/localhost.pem'),
    tlsKey: resolve(env.TLS_KEY || 'certs/localhost-key.pem'),
    hibp: hibp === 'true'
  };
}

export function loadConfig() {
  // Hosted settings come from the provider, never an uploaded local .env.
  if (process.env.RENDER !== 'true' && existsSync('.env')) process.loadEnvFile('.env');
  return configFromEnv(process.env);
}
