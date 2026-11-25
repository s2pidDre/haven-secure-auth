import { loadConfig } from '../lib/config.mjs';
import { createStore } from '../lib/store.mjs';
const config = loadConfig();
const store = await createStore(config, { readOnly: true });
try {
  const rows = await store.prepare('SELECT occurred_at,event,account_ref,ip_ref FROM security_events ORDER BY id DESC LIMIT 100').all();
  console.log(JSON.stringify(rows.map(row => ({ ...row, occurred_at: new Date(row.occurred_at).toISOString() })), null, 2));
} finally { await store.close(); }
