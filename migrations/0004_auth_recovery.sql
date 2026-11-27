CREATE TABLE IF NOT EXISTS auth_challenges (
  id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  destination TEXT NOT NULL, challenge_hash TEXT NOT NULL, purpose TEXT NOT NULL,
  expires_at TEXT NOT NULL, consumed_at TEXT, attempts INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_auth_challenges_destination ON auth_challenges(destination, purpose, expires_at);
