PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, email TEXT UNIQUE, phone TEXT UNIQUE, full_name TEXT,
  password_hash TEXT, role TEXT NOT NULL DEFAULT 'customer', status TEXT NOT NULL DEFAULT 'active',
  google_sub TEXT UNIQUE, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS user_sessions (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, expires_at TEXT NOT NULL, revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id);
CREATE TABLE IF NOT EXISTS suppliers (
  id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id), business_name TEXT NOT NULL,
  phone TEXT, email TEXT, location TEXT, status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS products (
  id TEXT PRIMARY KEY, supplier_id TEXT REFERENCES suppliers(id), name TEXT NOT NULL,
  description TEXT, category TEXT, sku TEXT, image_url TEXT, unit TEXT,
  price_minor INTEGER, discount_percent REAL NOT NULL DEFAULT 0,
  stock_quantity REAL NOT NULL DEFAULT 0, is_active INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_products_active ON products(is_active, category);
CREATE INDEX IF NOT EXISTS idx_products_supplier ON products(supplier_id);
CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id), customer_name TEXT,
  customer_phone TEXT, status TEXT NOT NULL DEFAULT 'pending', payment_status TEXT NOT NULL DEFAULT 'not_paid',
  total_minor INTEGER NOT NULL DEFAULT 0, currency TEXT NOT NULL DEFAULT 'KES',
  client_order_id TEXT UNIQUE, source TEXT NOT NULL DEFAULT 'online',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS order_items (
  id TEXT PRIMARY KEY, order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  product_id TEXT REFERENCES products(id), supplier_id TEXT REFERENCES suppliers(id),
  product_name TEXT NOT NULL, variant TEXT, quantity REAL NOT NULL,
  unit_price_minor INTEGER NOT NULL DEFAULT 0, discount_percent REAL NOT NULL DEFAULT 0,
  line_total_minor INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_order_items_order ON order_items(order_id);
