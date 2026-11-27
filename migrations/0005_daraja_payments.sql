ALTER TABLE users ADD COLUMN subscription_plan TEXT;
ALTER TABLE users ADD COLUMN subscription_status TEXT NOT NULL DEFAULT 'inactive';
ALTER TABLE users ADD COLUMN subscription_expires_at TEXT;

CREATE TABLE IF NOT EXISTS payment_transactions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  order_id TEXT REFERENCES orders(id),
  purpose TEXT NOT NULL,
  plan TEXT,
  phone TEXT NOT NULL,
  amount_kes INTEGER NOT NULL CHECK(amount_kes > 0),
  merchant_request_id TEXT,
  checkout_request_id TEXT NOT NULL UNIQUE,
  mpesa_receipt TEXT UNIQUE,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','paid','failed','review')),
  result_code INTEGER,
  response_description TEXT,
  result_description TEXT,
  callback_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_payment_user_created ON payment_transactions(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_payment_status ON payment_transactions(status, created_at);
