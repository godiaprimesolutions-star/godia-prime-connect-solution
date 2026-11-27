CREATE TABLE IF NOT EXISTS sync_mutations (
  id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id), device_id TEXT NOT NULL,
  mutation_type TEXT NOT NULL, entity_id TEXT NOT NULL, payload_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'accepted', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  processed_at TEXT, error_message TEXT
);
CREATE INDEX IF NOT EXISTS idx_sync_user_created ON sync_mutations(user_id, created_at);
CREATE TABLE IF NOT EXISTS device_sync_state (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, device_id TEXT NOT NULL,
  last_synced_at TEXT, last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(user_id, device_id)
);
