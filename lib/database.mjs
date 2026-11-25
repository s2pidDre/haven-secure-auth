import { DatabaseSync } from 'node:sqlite';
import { AsyncLocalStorage } from 'node:async_hooks';
import { mkdirSync, chmodSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
const schema = readFileSync(new URL('../sql/001-auth.sql', import.meta.url), 'utf8');

class Mutex {
  #tail = Promise.resolve();
  async run(fn) {
    const previous = this.#tail;
    let release;
    this.#tail = new Promise(resolve => { release = resolve; });
    await previous;
    try { return await fn(); } finally { release(); }
  }
}

export async function openDatabase(config, options = {}) {
  const context = new AsyncLocalStorage();
  const lock = new Mutex();
  let local, remote;
  if (options.client) remote = options.client;
  else if (config.databaseUrl) {
    const { createClient } = await import('@libsql/client/http');
    remote = createClient({
      url: config.databaseUrl.replace(/^libsql:/, 'https:'), authToken: config.databaseToken,
      intMode: 'number', concurrency: 4,
      fetch: (input, init = {}) => fetch(input, { ...init, redirect: 'error', signal: AbortSignal.timeout(10000) })
    });
  } else {
    if (!options.readOnly) mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
    const file = join(config.dataDir, 'auth.sqlite');
    local = new DatabaseSync(file, { readOnly: Boolean(options.readOnly) });
    if (!options.readOnly) {
      chmodSync(config.dataDir, 0o700); chmodSync(file, 0o600);
      local.exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA secure_delete=ON;');
    }
  }
  const access = fn => context.getStore() ? fn(context.getStore()) : lock.run(() => fn(local || remote));
  function prepare(sql) {
    return {
      get: (...args) => access(async connection => local ? connection.prepare(sql).get(...args) : (await connection.execute({ sql, args })).rows[0]),
      all: (...args) => access(async connection => local ? connection.prepare(sql).all(...args) : (await connection.execute({ sql, args })).rows),
      run: (...args) => access(async connection => {
        if (local) return connection.prepare(sql).run(...args);
        const result = await connection.execute({ sql, args });
        return { changes: result.rowsAffected, lastInsertRowid: result.lastInsertRowid };
      })
    };
  }
  async function exec(sql) {
    return access(async connection => local ? connection.exec(sql) : connection.executeMultiple(sql));
  }
  async function transaction(fn) {
    if (context.getStore()) return fn();
    const operation = async () => {
      const connection = local || await remote.transaction('write');
      if (local) local.exec('BEGIN IMMEDIATE');
      try {
        const result = await context.run(connection, fn);
        if (local) local.exec('COMMIT'); else await connection.commit();
        return result;
      } catch (error) {
        try { if (local) local.exec('ROLLBACK'); else await connection.rollback(); } catch {}
        throw error;
      } finally { if (!local) connection.close(); }
    };
    return lock.run(operation);
  }
  try { if (!options.readOnly) await exec(schema); }
  catch (error) { if (local) local.close(); else remote.close(); throw error; }
  return { prepare, exec, transaction,
    close: async () => { if (local) await lock.run(() => local.close()); else remote.close(); } };
}
