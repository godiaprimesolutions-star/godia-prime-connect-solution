
PRAGMA foreign_keys = ON;

-- 1. Add fractional inventory quantity support.
-- Keep the original table and all existing records.
CREATE TABLE inventory_movements_new (
  id TEXT PRIMARY KEY,
  product_id TEXT NOT NULL,
  user_id TEXT,
  movement_type TEXT NOT NULL
    CHECK (movement_type IN (
      'stock_in',
      'stock_out',
      'adjustment',
      'sale',
      'return'
    )),
  quantity REAL NOT NULL,
  reference TEXT,
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (product_id) REFERENCES products(id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 2. Copy any existing inventory records.
INSERT INTO inventory_movements_new (
  id,
  product_id,
  user_id,
  movement_type,
  quantity,
  reference,
  notes,
  created_at
)
SELECT
  id,
  product_id,
  user_id,
  movement_type,
  quantity,
  reference,
  notes,
  created_at
FROM inventory_movements;

-- 3. Replace the old table.
DROP TABLE inventory_movements;
ALTER TABLE inventory_movements_new
RENAME TO inventory_movements;

-- 4. Recreate the inventory index.
CREATE INDEX IF NOT EXISTS idx_inventory_movements_product
ON inventory_movements(product_id);

CREATE INDEX IF NOT EXISTS idx_inventory_movements_reference
ON inventory_movements(reference);

-- 5. Add payment lookup indexes.
CREATE INDEX IF NOT EXISTS idx_payment_checkout_request
ON payment_transactions(checkout_request_id);

CREATE INDEX IF NOT EXISTS idx_payment_order
ON payment_transactions(order_id);

CREATE INDEX IF NOT EXISTS idx_payment_user_status
ON payment_transactions(user_id, status);

-- 6. Add order lookup indexes.
CREATE INDEX IF NOT EXISTS idx_orders_user_created
ON orders(user_id, created_at);

CREATE INDEX IF NOT EXISTS idx_orders_payment_status
ON orders(payment_status);

CREATE INDEX IF NOT EXISTS idx_order_items_order
ON order_items(order_id);

-- 7. Improve order event lookup.
CREATE INDEX IF NOT EXISTS idx_order_events_order_created
ON order_events(order_id, created_at);
