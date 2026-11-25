import { openDatabase } from './database.mjs';
import { fingerprint } from './crypto.mjs';

export async function createStore(config, options = {}) {
  const db = await openDatabase(config, options);
  const { prepare, transaction } = db;
  async function audit(event, ip, email = '') {
    await prepare('INSERT INTO security_events(occurred_at,event,account_ref,ip_ref) VALUES(?,?,?,?)')
      .run(Date.now(), event, email ? fingerprint(config.secret, 'account-ref', email) : null,
        fingerprint(config.secret, 'ip-ref', ip));
  }
  async function consume(scope, identity, limit, windowMs, now = Date.now()) {
    const bucket = fingerprint(config.secret, `rate:${scope}`, identity);
    const result = await prepare(`INSERT INTO rate_limits(bucket,hits,reset_at) VALUES(?,1,?)
      ON CONFLICT(bucket) DO UPDATE SET
      hits=CASE WHEN reset_at<=? THEN 1 ELSE hits+1 END,
      reset_at=CASE WHEN reset_at<=? THEN excluded.reset_at ELSE reset_at END
      RETURNING hits,reset_at`).get(bucket, now + windowMs, now, now);
    return { allowed: result.hits <= limit, retry: Math.max(1, Math.ceil((result.reset_at - now) / 1000)) };
  }
  async function cleanup(now = Date.now()) {
    await transaction(async () => {
      await prepare('DELETE FROM sessions WHERE expires_at<=? OR last_seen<=?').run(now, now - 15 * 60000);
      await prepare('DELETE FROM rate_limits WHERE reset_at<=?').run(now);
      await prepare('DELETE FROM security_events WHERE occurred_at<?').run(now - 30 * 86400000);
    });
  }
  return { db, prepare, transaction, audit, consume, cleanup, close: db.close };
}
