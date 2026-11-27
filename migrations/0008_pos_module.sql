-- GODIA PRIME POS V2 (corrected)
-- Additive only. Leaves legacy pos_sales and pos_sale_items untouched.
-- Quantities are REAL to support kg, litres, metres and other fractional units.

CREATE TABLE IF NOT EXISTS pos_sales_v2 (
  id TEXT PRIMARY KEY,
  seller_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  cashier_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
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
  void_reason TEXT,
  voided_by TEXT REFERENCES users(id),
  voided_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (seller_id, client_sale_id)
);

CREATE INDEX IF NOT EXISTS idx_pos_sales_v2_seller_created ON pos_sales_v2 (seller_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pos_sales_v2_created ON pos_sales_v2 (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pos_sales_v2_cashier_created ON pos_sales_v2 (cashier_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS uq_pos_sales_v2_mpesa_receipt ON pos_sales_v2 (mpesa_receipt) WHERE mpesa_receipt IS NOT NULL;

CREATE TABLE IF NOT EXISTS pos_sale_items_v2 (
  id TEXT PRIMARY KEY,
  sale_id TEXT NOT NULL REFERENCES pos_sales_v2(id) ON DELETE RESTRICT,
  product_id TEXT NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
  product_name TEXT NOT NULL,
  sku TEXT,
  quantity REAL NOT NULL CHECK (quantity > 0),
  unit_price_minor INTEGER NOT NULL CHECK (unit_price_minor >= 0),
  discount_percent REAL NOT NULL DEFAULT 0 CHECK (discount_percent >= 0 AND discount_percent <= 100),
  line_total_minor INTEGER NOT NULL CHECK (line_total_minor >= 0),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_pos_sale_items_v2_sale ON pos_sale_items_v2 (sale_id);
CREATE INDEX IF NOT EXISTS idx_pos_sale_items_v2_product ON pos_sale_items_v2 (product_id);

DROP TRIGGER IF EXISTS trg_pos_sale_items_v2_stock_guard;
CREATE TRIGGER trg_pos_sale_items_v2_stock_guard
BEFORE INSERT ON pos_sale_items_v2
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1
    FROM products p
    JOIN pos_sales_v2 s ON s.id=NEW.sale_id AND s.status='completed'
    JOIN users u ON u.id=s.seller_id AND u.status='active'
    WHERE p.id=NEW.product_id AND p.is_active=1 AND p.stock_quantity>=NEW.quantity
      AND (
        lower(COALESCE(u.role,'')) IN ('owner','admin')
        OR EXISTS (SELECT 1 FROM suppliers sp WHERE sp.id=p.supplier_id AND sp.user_id=s.seller_id AND sp.status='active')
      )
  ) THEN RAISE(ABORT,'POS_INSUFFICIENT_STOCK_OR_ACCESS_DENIED') END;
END;

DROP TRIGGER IF EXISTS trg_pos_sale_items_v2_stock_decrement;
CREATE TRIGGER trg_pos_sale_items_v2_stock_decrement
AFTER INSERT ON pos_sale_items_v2
BEGIN
  UPDATE products SET stock_quantity=stock_quantity-NEW.quantity, updated_at=CURRENT_TIMESTAMP
  WHERE id=NEW.product_id AND is_active=1 AND stock_quantity>=NEW.quantity;
  INSERT INTO inventory_movements (id,product_id,user_id,movement_type,quantity,reference,notes)
  SELECT lower(hex(randomblob(16))),NEW.product_id,s.seller_id,'sale',NEW.quantity,s.id,'POS V2 sale stock deduction'
  FROM pos_sales_v2 s WHERE s.id=NEW.sale_id;
END;

DROP TRIGGER IF EXISTS trg_pos_sales_v2_restore_stock_on_void;
CREATE TRIGGER trg_pos_sales_v2_restore_stock_on_void
AFTER UPDATE OF status ON pos_sales_v2
WHEN OLD.status='completed' AND NEW.status='voided'
BEGIN
  UPDATE products
  SET stock_quantity=stock_quantity+COALESCE((SELECT SUM(i.quantity) FROM pos_sale_items_v2 i WHERE i.sale_id=NEW.id AND i.product_id=products.id),0),
      updated_at=CURRENT_TIMESTAMP
  WHERE id IN (SELECT product_id FROM pos_sale_items_v2 WHERE sale_id=NEW.id);
  INSERT INTO inventory_movements (id,product_id,user_id,movement_type,quantity,reference,notes)
  SELECT lower(hex(randomblob(16))),i.product_id,NEW.seller_id,'return',i.quantity,NEW.id,'POS V2 voided sale stock restoration'
  FROM pos_sale_items_v2 i WHERE i.sale_id=NEW.id;
END;
