import { isIP } from 'node:net';

export function clientIdentity(req, config) {
  const remote = req.socket.remoteAddress || 'unknown';
  if (config.transport === 'direct') {
    if (!req.socket.encrypted) throw new Error('HTTPS required.');
    return remote;
  }
  if (req.headers['x-forwarded-proto'] !== 'https') throw new Error('HTTPS ingress required.');
  if (config.transport === 'proxy') {
    if (!['127.0.0.1', '::ffff:127.0.0.1'].includes(remote)) throw new Error('Loopback proxy required.');
    const value = req.headers['x-real-ip'];
    return typeof value === 'string' && isIP(value) ? value : remote;
  }
  if (config.transport === 'render-free') {
    // Render Free cannot receive private-network traffic. Public ingress passes
    // Cloudflare, which supplies/validates this single-address header.
    // Do not reuse this policy on a paid service accepting private traffic.
    const value = req.headers['cf-connecting-ip'];
    if (typeof value !== 'string' || !isIP(value)) throw new Error('Validated public ingress required.');
    return value;
  }
  throw new Error('Unknown transport.');
}
