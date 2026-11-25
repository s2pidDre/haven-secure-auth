CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL, totp_secret TEXT, last_totp_step INTEGER NOT NULL DEFAULT -1,
  created_at INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS sessions (
  id_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  stage TEXT NOT NULL CHECK(stage IN ('anonymous','enroll','verify','authenticated')),
  created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  pending_secret TEXT, one_time TEXT, flash TEXT
) STRICT;
CREATE TABLE IF NOT EXISTS recovery_codes (
  code_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE
) STRICT;
CREATE TABLE IF NOT EXISTS rate_limits (
  bucket TEXT PRIMARY KEY, hits INTEGER NOT NULL, reset_at INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS security_events (
  id INTEGER PRIMARY KEY, occurred_at INTEGER NOT NULL, event TEXT NOT NULL,
  account_ref TEXT, ip_ref TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS rate_expiry ON rate_limits(reset_at);
CREATE INDEX IF NOT EXISTS events_time ON security_events(occurred_at);
