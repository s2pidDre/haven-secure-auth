import https from 'node:https';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { loadConfig } from './lib/config.mjs';
import { createApp } from './lib/app.mjs';
process.umask(0o077);
try {
  const config = loadConfig();
  const app = await createApp(config);
  const limits = { maxHeaderSize: 8192, requestTimeout: 15000, headersTimeout: 15000, keepAliveTimeout: 5000 };
  const server = config.transport === 'direct'
    ? https.createServer({ ...limits, cert: readFileSync(config.tlsCert), key: readFileSync(config.tlsKey), minVersion: 'TLSv1.2', handshakeTimeout: 10000 }, app.handler)
    : http.createServer(limits, app.handler);
  server.maxConnections = 256;
  server.maxRequestsPerSocket = 100;
  server.on('error', async () => { console.error('Unable to listen. Check the port, host, and certificate settings.'); process.exitCode = 1; await app.close(); });
  server.listen(config.port, config.host, () => console.log(`Secure Auth is available at ${config.origin}`));
  let cleaning = false;
  const cleanup = setInterval(async () => {
    if (cleaning) return;
    cleaning = true;
    try { await app.store.cleanup(); }
    catch { console.error(JSON.stringify({ event: 'cleanup_unavailable', at: new Date().toISOString() })); }
    finally { cleaning = false; }
  }, 60000); cleanup.unref();
  let stopping = false;
  function stop() {
    if (stopping) return; stopping = true;
    clearInterval(cleanup);
    server.close(async () => { await app.close(); process.exit(0); });
    server.closeIdleConnections();
    setTimeout(() => process.exit(0), 10000).unref();
  }
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
} catch {
  console.error('Startup refused. Use Node.js 24.12+ (24.x) and check the HTTPS, key, and database settings. See DEPLOY-FREE.md for hosting or README.md for localhost.');
  process.exitCode = 1;
}
