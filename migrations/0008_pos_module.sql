
-- GODIA PRIME POS module (additive migration only).
-- Does not alter, drop, rename, or delete existing application tables or records.

CREATE TABLE IF NOT EXISTS pos_sales (
  id TEXT PRIMARY KEY,
  seller_id TEXT NOT NULL,
  cashier_id TEXT NOT NULL,
  client_sale_id TEXT NOT NULL,
  customer_name TEXT NOT NULL DEFAULT 'Walk-in customer',
  customer_phone TEXT,
  subtotal_minor INTEGER NOT NULL CHECK (subtotal_minor >= 0),
  total_minor INTEGER NOT NULL CHECK (total_minor > 0),
  payment_method TEXT NOT NULL CHECK (payment_method IN ('cash','mpesa_till')),
  payment_status TEXT NOT NULL CHECK (payment_status IN ('paid','recorded_unverified')),
  amount_received_minor INTEGER NOT NULL CHECK (amount_received_minor >= 0),
  change_minor INTEGER NOT NULL DEFAULT 0 CHECK (change_minor >= 0),
  mpesa_receipt TEXT,
  status TEXT NOT NULL DEFAULT 'completed' CHECK (status IN ('completed','voided')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (seller_id, client_sale_id),
  FOREIGN KEY (seller_id) REFERENCES users(id) ON DELETE RESTRICT,
  FOREIGN KEY (cashier_id) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_pos_sales_seller_created
  ON pos_sales (seller_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pos_sales_created
  ON pos_sales (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pos_sales_cashier_created
  ON pos_sales (cashier_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS uq_pos_sales_mpesa_receipt
  ON pos_sales (mpesa_receipt) WHERE mpesa_receipt IS NOT NULL;

CREATE TABLE IF NOT EXISTS pos_sale_items (
  id TEXT PRIMARY KEY,
  sale_id TEXT NOT NULL,
  product_id TEXT NOT NULL,
  product_name TEXT NOT NULL,
  sku TEXT,
  quantity INTEGER NOT NULL CHECK (quantity > 0),
  unit_price_minor INTEGER NOT NULL CHECK (unit_price_minor >= 0),
  discount_percent REAL NOT NULL DEFAULT 0 CHECK (discount_percent >= 0 AND discount_percent <= 100),
  line_total_minor INTEGER NOT NULL CHECK (line_total_minor >= 0),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (sale_id) REFERENCES pos_sales(id) ON DELETE RESTRICT,
  FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_pos_sale_items_sale
  ON pos_sale_items (sale_id);
CREATE INDEX IF NOT EXISTS idx_pos_sale_items_product
  ON pos_sale_items (product_id);

-- Guard stock at the database boundary. The insert and trigger run inside the
-- D1 batch transaction: if any line cannot be fulfilled, the whole sale rolls back.
CREATE TRIGGER IF NOT EXISTS trg_pos_sale_items_stock_guard
BEFORE INSERT ON pos_sale_items
BEGIN
  SELECT CASE
    WHEN NOT EXISTS (
      SELECT 1
      FROM products p
      JOIN pos_sales s ON s.id = NEW.sale_id
      LEFT JOIN users u ON u.id = s.seller_id
      WHERE p.id = NEW.product_id
        AND p.is_active = 1
        AND p.stock_quantity >= NEW.quantity
        AND (
          p.supplier_id = s.seller_id
          OR lower(COALESCE(u.role, '')) IN ('owner','admin')
        )
    )
    THEN RAISE(ABORT, 'POS_INSUFFICIENT_STOCK')
  END;
END;

CREATE TRIGGER IF NOT EXISTS trg_pos_sale_items_stock_decrement
AFTER INSERT ON pos_sale_items
BEGIN
  UPDATE products
  SET stock_quantity = stock_quantity - NEW.quantity,
      updated_at = CURRENT_TIMESTAMP
  WHERE id = NEW.product_id
    AND is_active = 1
    AND stock_quantity >= NEW.quantity;
END;
