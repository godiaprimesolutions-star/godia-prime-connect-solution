/**
 * GODIA PRIME CONNECT SOLUTIONS
 * API ENGINE V2.1 - PHONE/PASSWORD LOGIN
 * Cloudflare Workers + D1 + M-PESA Daraja
 *
 * Google sign-in is intentionally disabled.
 * Existing D1 tables and records are not modified or deleted by deployment.
 */

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store"
};

const uid = (prefix = "") => prefix + crypto.randomUUID();
const nowIso = () => new Date().toISOString();

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, ...headers }
  });
}

function corsHeaders(req, env) {
  const origin = req.headers.get("Origin");
  const allowed = String(env.FRONTEND_ORIGIN || "*").split(",").map(x => x.trim());
  return {
    "access-control-allow-origin":
      allowed.includes("*") ? "*" : (allowed.includes(origin) ? origin : "null"),
    "access-control-allow-methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "access-control-allow-headers": "Content-Type, Authorization",
    "access-control-max-age": "86400",
    "vary": "Origin"
  };
}

function b64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function fromB64url(value) {
  const s = value.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(s + "=".repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
}

async function signToken(user, env) {
  if (!env.JWT_SECRET || env.JWT_SECRET.length < 32) {
    throw new Error("JWT_SECRET must contain at least 32 characters");
  }
  const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const payload = b64url(new TextEncoder().encode(JSON.stringify({
    sub: user.id, role: user.role || "customer", email: user.email || null,
    exp: Math.floor(Date.now() / 1000) + 604800
  })));
  const data = `${header}.${payload}`;
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(env.JWT_SECRET),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return `${data}.${b64url(signature)}`;
}

async function auth(req, env) {
  try {
    if (!env.JWT_SECRET || !env.DB) return null;
    const token = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
    if (!token) return null;
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [header, payload, signature] = parts;
    const decodedHeader = JSON.parse(new TextDecoder().decode(fromB64url(header)));
    if (decodedHeader.alg !== "HS256" || decodedHeader.typ !== "JWT") return null;
    const key = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(env.JWT_SECRET),
      { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
    );
    const valid = await crypto.subtle.verify(
      "HMAC", key, fromB64url(signature), new TextEncoder().encode(`${header}.${payload}`)
    );
    if (!valid) return null;
    const data = JSON.parse(new TextDecoder().decode(fromB64url(payload)));
    if (typeof data.exp !== "number" || data.exp <= Math.floor(Date.now() / 1000) || !data.sub) return null;
    const user = await env.DB.prepare(
      "SELECT id,email,phone,full_name,role,status,subscription_plan,subscription_status,subscription_expires_at FROM users WHERE id=?"
    ).bind(data.sub).first();
    return user?.status === "active" ? user : null;
  } catch {
    return null;
  }
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2", salt, iterations: 150000, hash: "SHA-256"
  }, key, 256);
  return `${b64url(salt)}.${b64url(bits)}`;
}

async function verifyPassword(password, stored) {
  try {
    const [salt, expected] = String(stored || "").split(".");
    if (!salt || !expected) return false;
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({
      name: "PBKDF2", salt: fromB64url(salt), iterations: 150000, hash: "SHA-256"
    }, key, 256);
    const actual = fromB64url(expected);
    const calculated = new Uint8Array(bits);
    return actual.length === calculated.length && actual.every((v, i) => v === calculated[i]);
  } catch {
    return false;
  }
}

async function body(req) {
  try {
    const value = await req.json();
    return value && typeof value === "object" ? value : {};
  } catch {
    return {};
  }
}

/* Kenyan phone normalization: database values are stored as +254... */
function normalizeKenyanPhone(value) {
  let phone = String(value || "").trim().replace(/[\s()-]/g, "");
  if (phone.startsWith("00")) phone = "+" + phone.slice(2);
  if (phone.startsWith("0")) phone = "+254" + phone.slice(1);
  else if (/^[17]\d{8}$/.test(phone)) phone = "+254" + phone;
  else if (/^254[17]\d{8}$/.test(phone)) phone = "+" + phone;
  if (!/^\+254[17]\d{8}$/.test(phone)) throw new Error("Enter a valid Kenyan phone number, for example 07XX XXX XXX");
  return phone;
}

/* M-PESA DARAJA */
function normalizeMpesaPhone(value) {
  let phone = String(value || "").replace(/[\s+()-]/g, "");
  if (phone.startsWith("0")) phone = "254" + phone.slice(1);
  if (phone.startsWith("7") || phone.startsWith("1")) phone = "254" + phone;
  if (!/^254[17]\d{8}$/.test(phone)) throw new Error("Enter a valid Kenyan M-PESA phone number");
  return phone;
}

function darajaTimestamp(date = new Date()) {
  const z = n => String(n).padStart(2, "0");
  return date.getFullYear() + z(date.getMonth() + 1) + z(date.getDate()) +
    z(date.getHours()) + z(date.getMinutes()) + z(date.getSeconds());
}

async function darajaAccessToken(env) {
  if (!env.DARAJA_CONSUMER_KEY || !env.DARAJA_CONSUMER_SECRET) throw new Error("Daraja credentials are not configured");
  const credentials = btoa(`${env.DARAJA_CONSUMER_KEY}:${env.DARAJA_CONSUMER_SECRET}`);
  const response = await fetch("https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials", {
    headers: { Authorization: `Basic ${credentials}` }
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || !result.access_token) throw new Error("Daraja authentication failed");
  return result.access_token;
}

async function startDarajaStk(env, details) {
  const shortcode = String(env.DARAJA_SHORTCODE || "").trim();
  const passkey = env.DARAJA_PASSKEY;
  const callbackUrl = env.DARAJA_CALLBACK_URL;
  if (!/^\d{5,7}$/.test(shortcode) || !passkey || !callbackUrl) throw new Error("M-PESA Worker settings are incomplete");
  if (!env.DARAJA_CALLBACK_TOKEN || !callbackUrl.includes(`/api/payments/mpesa/callback/${env.DARAJA_CALLBACK_TOKEN}`)) {
    throw new Error("Invalid M-PESA callback configuration");
  }
  const timestamp = darajaTimestamp();
  const password = btoa(`${shortcode}${passkey}${timestamp}`);
  const token = await darajaAccessToken(env);
  const request = {
    BusinessShortCode: shortcode, Password: password, Timestamp: timestamp,
    TransactionType: env.DARAJA_TRANSACTION_TYPE || "CustomerPayBillOnline",
    Amount: Math.round(details.amount), PartyA: details.phone, PartyB: shortcode,
    PhoneNumber: details.phone, CallBackURL: callbackUrl,
    AccountReference: String(details.accountReference || "GODIA").slice(0, 12),
    TransactionDesc: String(details.transactionDesc || "GODIA payment").slice(0, 13)
  };
  const response = await fetch("https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(request)
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || String(result.ResponseCode) !== "0" || !result.CheckoutRequestID) {
    throw new Error(result.errorMessage || result.ResponseDescription || "M-PESA STK Push failed");
  }
  return result;
}

async function startSubscriptionPayment(req, env) {
  const user = await auth(req, env);
  if (!user) return json({ ok: false, message: "Please sign in first" }, 401);
  const b = await body(req);
  const plan = String(b.plan || "").trim().toUpperCase();
  const plans = { BASIC: "GODIA_PLAN_BASIC_KES", PRO: "GODIA_PLAN_PRO_KES", PRIME: "GODIA_PLAN_PRIME_KES" };
  const variable = plans[plan];
  if (!variable) return json({ ok: false, message: "Invalid subscription plan" }, 400);
  const amount = Number(env[variable]);
  if (!Number.isSafeInteger(amount) || amount < 1) {
    return json({ ok: false, message: `${variable} has not been configured with an approved price` }, 503);
  }
  let phone;
  try { phone = normalizeMpesaPhone(b.phone || user.phone); }
  catch (error) { return json({ ok: false, message: error.message }, 400); }
  const paymentId = uid("pay_");
  const temporaryCheckoutId = `init_${paymentId}`;
  await env.DB.prepare(`
    INSERT INTO payment_transactions
    (id,user_id,purpose,plan,phone,amount_kes,checkout_request_id,status,response_description)
    VALUES(?,?,?,?,?,?,?,?,?)
  `).bind(paymentId, user.id, "GODIA_SUBSCRIPTION", plan, phone, amount, temporaryCheckoutId, "pending", "STK request initializing").run();
  try {
    const result = await startDarajaStk(env, {
      phone, amount, accountReference: `GODIA-${plan}`, transactionDesc: `${plan} plan`
    });
    await env.DB.prepare(`
      UPDATE payment_transactions SET merchant_request_id=?,checkout_request_id=?,
      response_description=?,updated_at=CURRENT_TIMESTAMP WHERE id=?
    `).bind(result.MerchantRequestID || null, result.CheckoutRequestID, result.ResponseDescription || "STK Push sent", paymentId).run();
    return json({
      ok: true, paymentId, checkoutRequestId: result.CheckoutRequestID,
      amountKes: amount, status: "pending",
      message: result.CustomerMessage || "M-PESA prompt sent. Enter your PIN to complete payment."
    },  202);
  } catch (error) {
    await env.DB.prepare(`
      UPDATE payment_transactions SET status='failed',response_description=?,updated_at=CURRENT_TIMESTAMP WHERE id=?
    `).bind(error.message, paymentId).run();
    return json({ ok: false, paymentId, message: error.message }, 502);
  }
}

async function handleDarajaCallback(req, env) {
  const expected = `/api/payments/mpesa/callback/${env.DARAJA_CALLBACK_TOKEN || ""}`;
  if (!env.DARAJA_CALLBACK_TOKEN || new URL(req.url).pathname !== expected) return json({ ok: false }, 404);
  const b = await body(req);
  const callback = b?.Body?.stkCallback;
  if (!callback?.CheckoutRequestID) return json({ ResultCode: 0, ResultDesc: "Callback received" });
  const payment = await env.DB.prepare("SELECT * FROM payment_transactions WHERE checkout_request_id=?")
    .bind(callback.CheckoutRequestID).first();
  if (!payment) return json({ ResultCode: 0, ResultDesc: "Unknown payment" });
  if (["paid", "failed", "review"].includes(payment.status)) return json({ ResultCode: 0, ResultDesc: "Already processed" });
  const resultCode = Number(callback.ResultCode);
  const metadata = callback.CallbackMetadata?.Item || [];
  const getMeta = name => metadata.find(x => x.Name === name)?.Value ?? null;
  const receipt = getMeta("MpesaReceiptNumber");
  const paidAmount = Number(getMeta("Amount") || 0);
  const paidPhone = String(getMeta("PhoneNumber") || "");
  const expectedPhone = String(payment.phone || "").replace(/\D/g, "");
  const matches = resultCode === 0 && paidAmount === Number(payment.amount_kes) &&
    paidPhone === expectedPhone && Boolean(receipt);
  if (matches) {
    await env.DB.prepare(`
      UPDATE payment_transactions SET status='paid',result_code=?,result_description=?,
      mpesa_receipt=?,callback_json=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'
    `).bind(resultCode, String(callback.ResultDesc || "Success"), receipt, JSON.stringify(b), payment.id).run();
    if (payment.purpose === "GODIA_SUBSCRIPTION") {
      const days = Math.max(1, Math.min(365, Number(env.GODIA_SUBSCRIPTION_DAYS || 30)));
      await env.DB.prepare(`
        UPDATE users SET subscription_plan=?,subscription_status='active',
        subscription_expires_at=datetime(
          CASE WHEN subscription_status='active' AND subscription_expires_at>CURRENT_TIMESTAMP
          THEN subscription_expires_at ELSE CURRENT_TIMESTAMP END,
          '+' || ? || ' days'
        ),updated_at=CURRENT_TIMESTAMP WHERE id=?
      `).bind(payment.plan, days, payment.user_id).run();
    }
  } else {
    const status = resultCode === 0 ? "review" : "failed";
    await env.DB.prepare(`
      UPDATE payment_transactions SET status=?,result_code=?,result_description=?,
      callback_json=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'
    `).bind(status, resultCode, String(callback.ResultDesc || "Payment verification failed"), JSON.stringify(b), payment.id).run();
  }
  return json({ ResultCode: 0, ResultDesc: "Callback processed" });
}

/* MAIN API */
async function handle(req, env) {
  const url = new URL(req.url);
  const path = url.pathname;
  const method = req.method;

  if (path.startsWith("/api/payments/mpesa/callback/") && method === "POST") {
    return handleDarajaCallback(req, env);
  }

  if (path === "/api/health" && method === "GET") {
    return json({ ok: true, service: "GODIA PRIME CONNECT API", version: "2.1", time: nowIso(), database: "bound" });
  }

  /* Registration: accept both camelCase and snake_case field names. */
  if (path === "/api/auth/register" && method === "POST") {
    const b = await body(req);
    const email = String(b.email || "").trim().toLowerCase() || null;
    let phone = String(b.phone || "").trim() || null;
    const password = String(b.password || "");
    const fullName = String(b.fullName || b.full_name || b.name || "").trim().slice(0, 150);
    if (!email && !phone) return json({ ok: false, message: "Email or phone is required" }, 400);
    if (!fullName) return json({ ok: false, message: "Full name is required" }, 400);
    if (password.length < 8 || password.length > 128) return json({ ok: false, message: "Password must contain 8 to 128 characters" }, 400);
    if (phone) {
      try { phone = normalizeKenyanPhone(phone); }
      catch (error) { return json({ ok: false, message: error.message }, 400); }
    }
    const id = uid("usr_");
    try {
      const passwordHash = await hashPassword(password);
      await env.DB.prepare(`
        INSERT INTO users (id,email,phone,full_name,role,password_hash)
        VALUES(?,?,?,?,?,?)
      `).bind(id, email, phone, fullName, "customer", passwordHash).run();
      const user = await env.DB.prepare("SELECT id,email,phone,full_name,role FROM users WHERE id=?").bind(id).first();
      return json({ ok: true, token: await signToken(user, env), user }, 201);
    } catch (error) {
      console.error("Registration error:", error.message);
      return json({ ok: false, message: "An account with this email or phone may already exist" }, 409);
    }
  }

  /* Phone/email + password login. Supports old and new frontend field names. */
  if (path === "/api/auth/login" && method === "POST") {
    const b = await body(req);
    const rawIdentifier = String(b.identifier || b.phone || b.email || "").trim();
    const password = String(b.secret || b.password || "");
    if (!rawIdentifier || !password) return json({ ok: false, message: "Enter your phone number and password" }, 400);
    let identifier = rawIdentifier.toLowerCase();
    if (!identifier.includes("@")) {
      try { identifier = normalizeKenyanPhone(identifier); }
      catch { return json({ ok: false, message: "Enter a valid Kenyan phone number" }, 400); }
    }
    const user = await env.DB.prepare(`
      SELECT * FROM users WHERE lower(email)=? OR phone=?
    `).bind(identifier, identifier).first();
    if (!user || user.status !== "active" || !user.password_hash ||
        !(await verifyPassword(password, user.password_hash))) {
      return json({ ok: false, message: "Invalid login details. Check your phone number and password/PIN." }, 401);
    }
    const safe = { id: user.id, email: user.email, phone: user.phone, full_name: user.full_name, role: user.role };
    return json({ ok: true, token: await signToken(safe, env), user: safe });
  }

  /* Google authentication deliberately disabled. */
  if (path === "/api/auth/google" && method === "POST") {
    return json({ ok: false, message: "Google sign-in is disabled. Please use your phone number and password." }, 410);
  }

  if (["/api/auth/request-otp", "/api/auth/verify-otp", "/api/auth/forgot-pin"].includes(path) && method === "POST") {
    return json({ ok: false, message: "OTP delivery is not enabled. An email or SMS delivery provider must first be connected." }, 501);
  }

  /* Public product catalogue */
  if (path === "/api/products" && method === "GET") {
    const q = (url.searchParams.get("q") || "").trim();
    const query = q
      ? env.DB.prepare(`
          SELECT id,name,description,category,sku,image_url,unit,price_minor,
          discount_percent,stock_quantity,supplier_id,updated_at
          FROM products WHERE is_active=1 AND name LIKE ? ORDER BY updated_at DESC LIMIT 100
        `).bind(`%${q}%`)
      : env.DB.prepare(`
          SELECT id,name,description,category,sku,image_url,unit,price_minor,
          discount_percent,stock_quantity,supplier_id,updated_at
          FROM products WHERE is_active=1 ORDER BY updated_at DESC LIMIT 100
        `);
    const result = await query.all();
    return json({ ok: true, products: result.results || [] });
  }

  /* Create order; accept frontend field aliases while retaining the same D1 schema. */
  if (path === "/api/orders" && method === "POST") {
    const user = await auth(req, env);
    if (!user) return json({ ok: false, message: "Authentication required" }, 401);
    const b = await body(req);
    const items = Array.isArray(b.items) ? b.items : [];
    if (!items.length || items.length > 100) return json({ ok: false, message: "Order must contain between 1 and 100 items" }, 400);
    const orderId = uid("ord_");
    const clientId = b.clientOrderId || b.client_order_id ? String(b.clientOrderId || b.client_order_id).slice(0, 100) : null;
    const customerName = String(b.customerName || b.customer_name || user.full_name || "").slice(0, 150);
    let customerPhone = String(b.customerPhone || b.customer_phone || user.phone || "").trim();
    if (customerPhone) {
      try { customerPhone = normalizeKenyanPhone(customerPhone); }
      catch (error) { return json({ ok: false, message: error.message }, 400); }
    }
    let total = 0;
    const normalized = [];
    for (const item of items) {
      const qty = Number(item.quantity);
      if (!Number.isFinite(qty) || qty <= 0 || qty > 100000) return json({ ok: false, message: "Invalid item quantity" }, 400);
      const productId = String(item.productId || item.product_id || "");
      const product = await env.DB.prepare(`
        SELECT id,name,supplier_id,price_minor,discount_percent,stock_quantity,is_active
        FROM products WHERE id=?
      `).bind(productId).first();
      if (!product || !product.is_active) return json({ ok: false, message: "Product is unavailable" }, 409);
      if (qty > Number(product.stock_quantity)) return json({ ok: false, message: `Insufficient stock for ${product.name}` }, 409);
      const unit = Math.max(0, Number(product.price_minor || 0));
      const discount = Math.max(0, Math.min(100, Number(product.discount_percent || 0)));
      const line = Math.round(unit * qty * (1 - discount / 100));
      total += line;
      normalized.push({
        id: uid("itm_"), product, qty, unit, discount, line,
        variant: String(item.variant || "").slice(0, 150) || null
      });
    }
    try {
      await env.DB.prepare(`
        INSERT INTO orders
        (id,user_id,customer_name,customer_phone,status,payment_status,total_minor,client_order_id,source)
        VALUES(?,?,?,?,?,?,?,?,?)
      `).bind(orderId, user.id, customerName, customerPhone, "pending", "not_paid", total, clientId, "online-or-synced").run();
      for (const item of normalized) {
        await env.DB.prepare(`
          INSERT INTO order_items
          (id,order_id,product_id,supplier_id,product_name,variant,quantity,unit_price_minor,discount_percent,line_total_minor)
          VALUES(?,?,?,?,?,?,?,?,?,?)
        `).bind(item.id, orderId, item.product.id, item.product.supplier_id, item.product.name,
          item.variant, item.qty, item.unit, item.discount, item.line).run();
      }
      await env.DB.prepare(`
        INSERT INTO order_events (id,order_id,actor_user_id,event_type,note)
        VALUES(?,?,?,?,?)
      `).bind(uid("evt_"), orderId, user.id, "order_submitted", "Order received; payment not yet taken").run();
      return json({
        ok: true, orderId, id: orderId, status: "pending",
        paymentStatus: "not_paid", totalMinor: total, currency: "KES"
      }, 201);
    } catch (error) {
      if (clientId) {
        const existing = await env.DB.prepare(`
          SELECT id,status,payment_status,total_minor FROM orders WHERE client_order_id=?
        `).bind(clientId).first();
        if (existing) return json({
          ok: true, orderId: existing.id, id: existing.id, status: existing.status,
          paymentStatus: existing.payment_status, totalMinor: existing.total_minor, duplicate: true
        });
      }
      throw error;
    }
  }

  if (path === "/api/orders" && method === "GET") {
    const user = await auth(req, env);
    if (!user) return json({ ok: false, message: "Authentication required" }, 401);
    const result = await env.DB.prepare(`
      SELECT id,status,payment_status,total_minor,currency,created_at
      FROM orders WHERE user_id=? ORDER BY created_at DESC LIMIT 100
    `).bind(user.id).all();
    return json({ ok: true, orders: result.results || [] });
  }

  if (path === "/api/subscriptions/stk-push" && method === "POST") return startSubscriptionPayment(req, env);

  if (path === "/api/payments/mpesa/status" && method === "GET") {
    const user = await auth(req, env);
    if (!user) return json({ ok: false, message: "Authentication required" }, 401);
    const id = url.searchParams.get("paymentId");
    if (!id) return json({ ok: false, message: "paymentId is required" }, 400);
    const payment = await env.DB.prepare(`
      SELECT id,purpose,plan,amount_kes,status,mpesa_receipt,created_at,updated_at
      FROM payment_transactions WHERE id=? AND user_id=?
    `).bind(id, user.id).first();
    return payment ? json({ ok: true, payment }) : json({ ok: false, message: "Payment not found" }, 404);
  }

  if (path === "/api/sync" && method === "POST") {
    const user = await auth(req, env);
    if (!user) return json({ ok: false, message: "Authentication required" }, 401);
    const b = await body(req);
    const deviceId = String(b.deviceId || "").slice(0, 100);
    const mutations = Array.isArray(b.mutations) ? b.mutations : [];
    if (!deviceId) return json({ ok: false, message: "deviceId is required" }, 400);
    if (mutations.length > 100) return json({ ok: false, message: "Maximum 100 mutations per batch" }, 400);
    const results = [];
    for (const mutation of mutations) {
      const id = String(mutation.id || uid("mut_")).slice(0, 100);
      try {
        await env.DB.prepare(`
          INSERT OR IGNORE INTO sync_mutations
          (id,user_id,device_id,mutation_type,entity_id,payload_json,status)
          VALUES(?,?,?,?,?,?,?)
        `).bind(id, user.id, deviceId, String(mutation.type || "unknown").slice(0, 100),
          String(mutation.entityId || id).slice(0, 100), JSON.stringify(mutation.payload || {}), "accepted").run();
        results.push({ id, status: "accepted" });
      } catch {
        results.push({ id, status: "rejected" });
      }
    }
    await env.DB.prepare(`
      INSERT INTO device_sync_state (user_id,device_id,last_synced_at,last_seen_at)
      VALUES(?,?,?,?)
      ON CONFLICT(user_id,device_id) DO UPDATE SET
      last_synced_at=excluded.last_synced_at,last_seen_at=excluded.last_seen_at
    `).bind(user.id, deviceId, nowIso(), nowIso()).run();
    return json({
      ok: true, received: results.length, results, syncedAt: nowIso(),
      note: "Mutations are recorded. Business-specific replay handlers are not enabled."
    });
  }

  if (path === "/api/me" && method === "GET") {
    const user = await auth(req, env);
    return user ? json({ ok: true, user }) : json({ ok: false, message: "Authentication required" }, 401);
  }

  return json({ ok: false, message: "API endpoint not found" }, 404);
}

export default {
  async fetch(request, env, ctx) {
    const headers = corsHeaders(request, env);
    try {
      if (request.method === "OPTIONS") return new Response(null, { status: 204, headers });
      const url = new URL(request.url);
      if (url.pathname.startsWith("/api/")) {
        const response = await handle(request, env);
        const finalHeaders = new Headers(response.headers);
        for (const [key, value] of Object.entries(headers)) finalHeaders.set(key, value);
        return new Response(response.body, { status: response.status, headers: finalHeaders });
      }
      if (env.ASSETS) return env.ASSETS.fetch(request);
      return new Response("GODIA PRIME frontend is not configured", { status: 404 });
    } catch (error) {
      console.error("GODIA API error:", error.message);
      return json({ ok: false, message: "Internal server error" }, 500, headers);
    }
  }
};
