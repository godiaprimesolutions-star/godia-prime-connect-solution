
-- GODIA PRIME POS V2
-- Additive migration: preserves all existing tables and records.
-- Legacy pos_sales and pos_sale_items are deliberately untouched.

CREATE TABLE IF NOT EXISTS pos_sales_v2 (
  id TEXT PRIMARY KEY,
  seller_id TEXT NOT NULL,
  cashier_id TEXT NOT NULL,
  client_sale_id TEXT NOT NULL,
  customer_name TEXT NOT NULL DEFAULT 'Walk-in customer',
  customer_phone TEXT,
  subtotal_minor INTEGER NOT NULL CHECK (subtotal_minor >= 0),
  total_minor INTEGER NOT NULL CHECK (total_minor > 0),
  payment_method TEXT NOT NULL
    CHECK (payment_method IN ('cash', 'mpesa_till')),
  payment_status TEXT NOT NULL
    CHECK (payment_status IN ('paid', 'recorded_unverified')),
  amount_received_minor INTEGER NOT NULL
    CHECK (amount_received_minor >= 0),
  change_minor INTEGER NOT NULL DEFAULT 0
    CHECK (change_minor >= 0),
  mpesa_receipt TEXT,
  status TEXT NOT NULL DEFAULT 'completed'
    CHECK (status IN ('completed', 'voided')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

  UNIQUE (seller_id, client_sale_id),

  FOREIGN KEY (seller_id)
    REFERENCES users(id) ON DELETE RESTRICT,

  FOREIGN KEY (cashier_id)
    REFERENCES users(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_pos_sales_v2_seller_created
  ON pos_sales_v2 (seller_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_pos_sales_v2_created
  ON pos_sales_v2 (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_pos_sales_v2_cashier_created
  ON pos_sales_v2 (cashier_id, created_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS uq_pos_sales_v2_mpesa_receipt
  ON pos_sales_v2 (mpesa_receipt)
  WHERE mpesa_receipt IS NOT NULL;


CREATE TABLE IF NOT EXISTS pos_sale_items_v2 (
  id TEXT PRIMARY KEY,
  sale_id TEXT NOT NULL,
  product_id TEXT NOT NULL,
  product_name TEXT NOT NULL,
  sku TEXT,
  quantity INTEGER NOT NULL CHECK (quantity > 0),
  unit_price_minor INTEGER NOT NULL
    CHECK (unit_price_minor >= 0),
  discount_percent REAL NOT NULL DEFAULT 0
    CHECK (discount_percent >= 0 AND discount_percent <= 100),
  line_total_minor INTEGER NOT NULL
    CHECK (line_total_minor >= 0),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY (sale_id)
    REFERENCES pos_sales_v2(id) ON DELETE RESTRICT,

  FOREIGN KEY (product_id)
    REFERENCES products(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_pos_sale_items_v2_sale
  ON pos_sale_items_v2 (sale_id);

CREATE INDEX IF NOT EXISTS idx_pos_sale_items_v2_product
  ON pos_sale_items_v2 (product_id);


-- Verify stock and product ownership before recording each sale line.
-- Product ownership is established through suppliers.user_id,
-- not by comparing products.supplier_id directly with users.id.

CREATE TRIGGER IF NOT EXISTS trg_pos_sale_items_v2_stock_guard
BEFORE INSERT ON pos_sale_items_v2
BEGIN
  SELECT CASE
    WHEN NOT EXISTS (
      SELECT 1
      FROM products p
      JOIN pos_sales_v2 s
        ON s.id = NEW.sale_id
      JOIN users u
        ON u.id = s.seller_id
      WHERE p.id = NEW.product_id
        AND p.is_active = 1
        AND p.stock_quantity >= NEW.quantity
        AND (
          lower(COALESCE(u.role, '')) IN ('owner', 'admin')
          OR EXISTS (
            SELECT 1
            FROM suppliers sp
            WHERE sp.id = p.supplier_id
              AND sp.user_id = s.seller_id
          )
        )
    )
    THEN RAISE(ABORT, 'POS_INSUFFICIENT_STOCK_OR_ACCESS_DENIED')
  END;
END;


-- Deduct stock only after the sale line passes the stock guard.

CREATE TRIGGER IF NOT EXISTS trg_pos_sale_items_v2_stock_decrement
AFTER INSERT ON pos_sale_items_v2
BEGIN
  UPDATE products
  SET stock_quantity = stock_quantity - NEW.quantity,
      updated_at = CURRENT_TIMESTAMP
  WHERE id = NEW.product_id
    AND is_active = 1
    AND stock_quantity >= NEW.quantity;
END;
