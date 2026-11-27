
/**
 * GODIA PRIME CONNECT SOLUTIONS
 * API ENGINE V2.3 - PIN LOGIN + BUSINESS APPROVAL + POS V2
 * Cloudflare Workers + D1 + M-PESA Daraja
 *
 * Google sign-in is intentionally disabled.
 * Existing D1 tables and records are preserved.
 * POS V2 uses pos_sales_v2 and pos_sale_items_v2.
 * Legacy POS tables are deliberately untouched.
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
  const allowed = String(env.FRONTEND_ORIGIN || "*")
    .split(",")
    .map(x => x.trim());

  return {
    "access-control-allow-origin":
      allowed.includes("*")
        ? "*"
        : (allowed.includes(origin) ? origin : "null"),
    "access-control-allow-methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "access-control-allow-headers": "Content-Type, Authorization",
    "access-control-max-age": "86400",
    "vary": "Origin"
  };
}

function b64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function fromB64url(value) {
  const s = value.replace(/-/g, "+").replace(/_/g, "/");

  return Uint8Array.from(
    atob(s + "=".repeat((4 - s.length % 4) % 4)),
    c => c.charCodeAt(0)
  );
}

async function signToken(user, env) {
  if (!env.JWT_SECRET || env.JWT_SECRET.length < 32) {
    throw new Error("JWT_SECRET must contain at least 32 characters");
  }

  const header = b64url(
    new TextEncoder().encode(
      JSON.stringify({ alg: "HS256", typ: "JWT" })
    )
  );

  const payload = b64url(
    new TextEncoder().encode(
      JSON.stringify({
        sub: user.id,
        role: user.role || "customer",
        email: user.email || null,
        exp: Math.floor(Date.now() / 1000) + 604800
      })
    )
  );

  const data = `${header}.${payload}`;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.JWT_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data)
  );

  return `${data}.${b64url(signature)}`;
}

async function auth(req, env) {
  try {
    if (!env.JWT_SECRET || !env.DB) return null;

    const token = (req.headers.get("authorization") || "")
      .replace(/^Bearer\s+/i, "");

    if (!token) return null;

    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const [header, payload, signature] = parts;

    const decodedHeader = JSON.parse(
      new TextDecoder().decode(fromB64url(header))
    );

    if (
      decodedHeader.alg !== "HS256" ||
      decodedHeader.typ !== "JWT"
    ) {
      return null;
    }

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(env.JWT_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      fromB64url(signature),
      new TextEncoder().encode(`${header}.${payload}`)
    );

    if (!valid) return null;

    const data = JSON.parse(
      new TextDecoder().decode(fromB64url(payload))
    );

    if (
      typeof data.exp !== "number" ||
      data.exp <= Math.floor(Date.now() / 1000) ||
      !data.sub
    ) {
      return null;
    }

    const user = await env.DB.prepare(`
      SELECT id,email,phone,full_name,role,status,
      subscription_plan,subscription_status,subscription_expires_at
      FROM users
      WHERE id=?
    `).bind(data.sub).first();

    return user?.status === "active" ? user : null;

  } catch {
    return null;
  }
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt,
    iterations: 100000,
    hash: "SHA-256"
  }, key, 256);

  return `${b64url(salt)}.${b64url(bits)}`;
}

async function verifyPassword(password, stored) {
  try {
    const [salt, expected] = String(stored || "").split(".");

    if (!salt || !expected) return false;

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits({
      name: "PBKDF2",
      salt: fromB64url(salt),
      iterations: 100000,
      hash: "SHA-256"
    }, key, 256);

    const actual = fromB64url(expected);
    const calculated = new Uint8Array(bits);

    return actual.length === calculated.length &&
      actual.every((v, i) => v === calculated[i]);

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

/* Read a POS V2 receipt and its items. */
async function readPosSale(db, saleId, sellerId = null) {
  let sale;

  if (sellerId) {
    sale = await db.prepare(`
      SELECT *
      FROM pos_sales_v2
      WHERE id=? AND seller_id=?
    `).bind(saleId, sellerId).first();

  } else {
    sale = await db.prepare(`
      SELECT *
      FROM pos_sales_v2
      WHERE id=?
    `).bind(saleId).first();
  }

  if (!sale) return null;

  const result = await db.prepare(`
    SELECT
      id,
      product_id,
      product_name,
      sku,
      quantity,
      unit_price_minor,
      discount_percent,
      line_total_minor,
      created_at
    FROM pos_sale_items_v2
    WHERE sale_id=?
    ORDER BY rowid
  `).bind(saleId).all();

  return {
    ...sale,
    items: result.results || []
  };
}

/* Kenyan phone normalization: database values are stored as +254... */
function normalizeKenyanPhone(value) {
  let phone = String(value || "")
    .trim()
    .replace(/[\s()-]/g, "");

  if (phone.startsWith("00")) {
    phone = "+" + phone.slice(2);
  }

  if (phone.startsWith("0")) {
    phone = "+254" + phone.slice(1);
  } else if (/^[17]\d{8}$/.test(phone)) {
    phone = "+254" + phone;
  } else if (/^254[17]\d{8}$/.test(phone)) {
    phone = "+" + phone;
  }

  if (!/^\+254[17]\d{8}$/.test(phone)) {
    throw new Error(
      "Enter a valid Kenyan phone number, for example 07XX XXX XXX"
    );
  }

  return phone;
}

/* M-PESA DARAJA */
function normalizeMpesaPhone(value) {
  let phone = String(value || "")
    .replace(/[\s+()-]/g, "");

  if (phone.startsWith("0")) {
    phone = "254" + phone.slice(1);
  }

  if (phone.startsWith("7") || phone.startsWith("1")) {
    phone = "254" + phone;
  }

  if (!/^254[17]\d{8}$/.test(phone)) {
    throw new Error("Enter a valid Kenyan M-PESA phone number");
  }

  return phone;
}

function darajaTimestamp(date = new Date()) {
  const z = n => String(n).padStart(2, "0");

  return date.getFullYear() +
    z(date.getMonth() + 1) +
    z(date.getDate()) +
    z(date.getHours()) +
    z(date.getMinutes()) +
    z(date.getSeconds());
}

async function darajaAccessToken(env) {
  if (!env.DARAJA_CONSUMER_KEY || !env.DARAJA_CONSUMER_SECRET) {
    throw new Error("Daraja credentials are not configured");
  }

  const credentials = btoa(
    `${env.DARAJA_CONSUMER_KEY}:${env.DARAJA_CONSUMER_SECRET}`
  );

  const response = await fetch(
    "https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
    {
      headers: {
        Authorization: `Basic ${credentials}`
      }
    }
  );

  const result = await response.json().catch(() => ({}));

  if (!response.ok || !result.access_token) {
    throw new Error("Daraja authentication failed");
  }

  return result.access_token;
}

async function startDarajaStk(env, details) {
  const shortcode = String(env.DARAJA_SHORTCODE || "").trim();
  const passkey = env.DARAJA_PASSKEY;
  const callbackUrl = env.DARAJA_CALLBACK_URL;

  if (!/^\d{5,7}$/.test(shortcode) || !passkey || !callbackUrl) {
    throw new Error("M-PESA Worker settings are incomplete");
  }

  if (
    !env.DARAJA_CALLBACK_TOKEN ||
    !callbackUrl.includes(
      `/api/payments/mpesa/callback/${env.DARAJA_CALLBACK_TOKEN}`
    )
  ) {
    throw new Error("Invalid M-PESA callback configuration");
  }

  const timestamp = darajaTimestamp();
  const password = btoa(`${shortcode}${passkey}${timestamp}`);
  const token = await darajaAccessToken(env);

  const request = {
    BusinessShortCode: shortcode,
    Password: password,
    Timestamp: timestamp,
    TransactionType:
      env.DARAJA_TRANSACTION_TYPE || "CustomerPayBillOnline",
    Amount: Math.round(details.amount),
    PartyA: details.phone,
    PartyB: shortcode,
    PhoneNumber: details.phone,
    CallBackURL: callbackUrl,
    AccountReference: String(
      details.accountReference || "GODIA"
    ).slice(0, 12),
    TransactionDesc: String(
      details.transactionDesc || "GODIA payment"
    ).slice(0, 13)
  };

  const response = await fetch(
    "https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(request)
    }
  );

  const result = await response.json().catch(() => ({}));

  if (
    !response.ok ||
    String(result.ResponseCode) !== "0" ||
    !result.CheckoutRequestID
  ) {
    throw new Error(
      result.errorMessage ||
      result.ResponseDescription ||
      "M-PESA STK Push failed"
    );
  }

  return result;
}

async function startSubscriptionPayment(req, env) {
  const user = await auth(req, env);

  if (!user) {
    return json({
      ok: false,
      message: "Please sign in first"
    }, 401);
  }

  const b = await body(req);
  const plan = String(b.plan || "").trim().toUpperCase();

  const plans = {
    BASIC: "GODIA_PLAN_BASIC_KES",
    PRO: "GODIA_PLAN_PRO_KES",
    PRIME: "GODIA_PLAN_PRIME_KES"
  };

  const variable = plans[plan];

  if (!variable) {
    return json({
      ok: false,
      message: "Invalid subscription plan"
    }, 400);
  }

  const amount = Number(env[variable]);

  if (!Number.isSafeInteger(amount) || amount < 1) {
    return json({
      ok: false,
      message: `${variable} has not been configured with an approved price`
    }, 503);
  }

  let phone;

  try {
    phone = normalizeMpesaPhone(b.phone || user.phone);
  } catch (error) {
    return json({
      ok: false,
      message: error.message
    }, 400);
  }

  const paymentId = uid("pay_");
  const temporaryCheckoutId = `init_${paymentId}`;

  await env.DB.prepare(`
    INSERT INTO payment_transactions
    (
      id,user_id,purpose,plan,phone,amount_kes,
      checkout_request_id,status,response_description
    )
    VALUES(?,?,?,?,?,?,?,?,?)
  `).bind(
    paymentId,
    user.id,
    "GODIA_SUBSCRIPTION",
    plan,
    phone,
    amount,
    temporaryCheckoutId,
    "pending",
    "STK request initializing"
  ).run();

  try {
    const result = await startDarajaStk(env, {
      phone,
      amount,
      accountReference: `GODIA-${plan}`,
      transactionDesc: `${plan} plan`
    });

    await env.DB.prepare(`
      UPDATE payment_transactions
      SET merchant_request_id=?,
      checkout_request_id=?,
      response_description=?,
      updated_at=CURRENT_TIMESTAMP
      WHERE id=?
    `).bind(
      result.MerchantRequestID || null,
      result.CheckoutRequestID,
      result.ResponseDescription || "STK Push sent",
      paymentId
    ).run();

    return json({
      ok: true,
      paymentId,
      checkoutRequestId: result.CheckoutRequestID,
      amountKes: amount,
      status: "pending",
      message:
        result.CustomerMessage ||
        "M-PESA prompt sent. Enter your PIN to complete payment."
    }, 202);

  } catch (error) {
    await env.DB.prepare(`
      UPDATE payment_transactions
      SET status='failed',
      response_description=?,
      updated_at=CURRENT_TIMESTAMP
      WHERE id=?
    `).bind(error.message, paymentId).run();

    return json({
      ok: false,
      paymentId,
      message: error.message
    }, 502);
  }
}

async function handleDarajaCallback(req, env) {
  const expected =
    `/api/payments/mpesa/callback/${env.DARAJA_CALLBACK_TOKEN || ""}`;

  if (
    !env.DARAJA_CALLBACK_TOKEN ||
    new URL(req.url).pathname !== expected
  ) {
    return json({ ok: false }, 404);
  }

  const b = await body(req);
  const callback = b?.Body?.stkCallback;

  if (!callback?.CheckoutRequestID) {
    return json({
      ResultCode: 0,
      ResultDesc: "Callback received"
    });
  }

  const payment = await env.DB.prepare(`
    SELECT *
    FROM payment_transactions
    WHERE checkout_request_id=?
  `).bind(callback.CheckoutRequestID).first();

  if (!payment) {
    return json({
      ResultCode: 0,
      ResultDesc: "Unknown payment"
    });
  }

  if (["paid", "failed", "review"].includes(payment.status)) {
    return json({
      ResultCode: 0,
      ResultDesc: "Already processed"
    });
  }

  const resultCode = Number(callback.ResultCode);
  const metadata = callback.CallbackMetadata?.Item || [];

  const getMeta = name =>
    metadata.find(x => x.Name === name)?.Value ?? null;

  const receipt = getMeta("MpesaReceiptNumber");
  const paidAmount = Number(getMeta("Amount") || 0);
  const paidPhone = String(getMeta("PhoneNumber") || "");
  const expectedPhone = String(payment.phone || "").replace(/\D/g, "");

  const matches =
    resultCode === 0 &&
    paidAmount === Number(payment.amount_kes) &&
    paidPhone === expectedPhone &&
    Boolean(receipt);

  if (matches) {
    const paymentUpdate = await env.DB.prepare(`
      UPDATE payment_transactions
      SET status='paid',
      result_code=?,
      result_description=?,
      mpesa_receipt=?,
      callback_json=?,
      updated_at=CURRENT_TIMESTAMP
      WHERE id=? AND status='pending'
    `).bind(
      resultCode,
      String(callback.ResultDesc || "Success"),
      receipt,
      JSON.stringify(b),
      payment.id
    ).run();

    // Only the callback that actually changes pending -> paid may grant the plan.
    if (Number(paymentUpdate?.meta?.changes || 0) > 0 && payment.purpose === "GODIA_SUBSCRIPTION") {
      const days = Math.max(1,Math.min(365,Number(env.GODIA_SUBSCRIPTION_DAYS || 30)));
      try {
        await env.DB.prepare(`
          UPDATE users
          SET subscription_plan=?,
          subscription_status='active',
          subscription_expires_at=datetime(
            CASE
              WHEN subscription_status='active'
              AND subscription_expires_at>CURRENT_TIMESTAMP
              THEN subscription_expires_at
              ELSE CURRENT_TIMESTAMP
            END,
            '+' || ? || ' days'
          ),
          updated_at=CURRENT_TIMESTAMP
          WHERE id=?
        `).bind(payment.plan,days,payment.user_id).run();
      } catch (error) {
        console.error("Subscription activation failed after confirmed payment:",String(error?.message || error));
        await env.DB.prepare(`UPDATE payment_transactions SET status='review',response_description='Payment received; subscription activation requires manual review',updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='paid'`).bind(payment.id).run();
      }
    }

  } else {
    const status = resultCode === 0 ? "review" : "failed";

    await env.DB.prepare(`
      UPDATE payment_transactions
      SET status=?,
      result_code=?,
      result_description=?,
      callback_json=?,
      updated_at=CURRENT_TIMESTAMP
      WHERE id=? AND status='pending'
    `).bind(
      status,
      resultCode,
      String(callback.ResultDesc || "Payment verification failed"),
      JSON.stringify(b),
      payment.id
    ).run();
  }

  return json({
    ResultCode: 0,
    ResultDesc: "Callback processed"
  });
}

/* MAIN API */
async function handle(req, env) {
  const url = new URL(req.url);
  const path = url.pathname;
  const method = req.method;

  if (
    path.startsWith("/api/payments/mpesa/callback/") &&
    method === "POST"
  ) {
    return handleDarajaCallback(req, env);
  }

  if (path === "/api/health" && method === "GET") {
    if (!env.DB) return json({ok:false,service:"GODIA PRIME CONNECT API",version:"2.3",database:"not_bound"},503);
    try {
      await env.DB.prepare("SELECT 1 AS ok").first();
      return json({ok:true,service:"GODIA PRIME CONNECT API",version:"2.3",time:nowIso(),database:"connected"});
    } catch {
      return json({ok:false,service:"GODIA PRIME CONNECT API",version:"2.3",database:"query_failed"},503);
    }
  }

  /* Safe status check for first-owner setup; never returns the bootstrap secret. */
  if (path === "/api/setup/status" && method === "GET") {
    const owner = await env.DB.prepare("SELECT id FROM users WHERE lower(role) IN ('owner','admin') LIMIT 1").first();
    return json({ok:true,ownerSetupAvailable:!owner,bootstrapEnabled:Boolean(env.GODIA_OWNER_BOOTSTRAP_SECRET)});
  }

  /* One-time first-owner bootstrap. Requires a Worker secret; never public by default. */
  if (path === "/api/auth/bootstrap-owner" && method === "POST") {
    if (!env.DB || !env.JWT_SECRET || env.JWT_SECRET.length < 32) {
      return json({ ok: false, message: "Server security or database settings are incomplete." }, 503);
    }
    if (!env.GODIA_OWNER_BOOTSTRAP_SECRET) {
      return json({ ok: false, message: "Owner setup is not enabled. Configure the one-time Worker secret first." }, 503);
    }
    const b = await body(req);
    if (String(b.bootstrapSecret || "") !== String(env.GODIA_OWNER_BOOTSTRAP_SECRET)) {
      return json({ ok: false, message: "Owner setup authorization failed." }, 403);
    }
    const fullName = String(b.fullName || b.full_name || "").trim().slice(0, 150);
    const email = String(b.email || "").trim().toLowerCase() || null;
    let phone = String(b.phone || "").trim();
    const password = String(b.password || "");
    const pin = String(b.pin || "");
    if (!fullName || (!email && !phone) || password.length < 8 || password.length > 128 || !/^\d{4,8}$/.test(pin)) {
      return json({ ok: false, message: "Provide a name, email or phone, an 8–128 character password and a 4–8 digit PIN." }, 400);
    }
    if (phone) {
      try { phone = normalizeKenyanPhone(phone); }
      catch (error) { return json({ ok: false, message: error.message }, 400); }
    }
    const existingOwner = await env.DB.prepare("SELECT id FROM users WHERE lower(role) IN ('owner','admin') LIMIT 1").first();
    if (existingOwner) return json({ ok: false, message: "An owner or administrator already exists. First-owner setup is closed." }, 409);
    const id = uid("usr_");
    try {
      const passwordHash = await hashPassword(password);
      const pinHash = await hashPassword(pin);
      await env.DB.batch([
        env.DB.prepare(`INSERT INTO users (id,email,phone,full_name,role,status,password_hash) SELECT ?,?,?,?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM users WHERE lower(role) IN ('owner','admin'))`).bind(id,email,phone,fullName,"owner","active",passwordHash),
        env.DB.prepare(`INSERT INTO user_pin_credentials (user_id,pin_hash) SELECT ?,? WHERE EXISTS (SELECT 1 FROM users WHERE id=?)`).bind(id,pinHash,id)
      ]);
      const user = await env.DB.prepare("SELECT id,email,phone,full_name,role,status FROM users WHERE id=? AND role='owner'").bind(id).first();
      if (!user) return json({ ok: false, message: "Owner setup was already completed or could not be committed." }, 409);
      return json({ ok: true, token: await signToken(user, env), user, message: "The first owner account has been created." }, 201);
    } catch (error) {
      const msg = String(error?.message || "");
      if (msg.includes("UNIQUE constraint failed")) return json({ ok: false, message: "That email or phone number is already registered." }, 409);
      console.error("Owner bootstrap failed:", msg);
      return json({ ok: false, message: "Owner setup could not be completed. Check that migration 0009 has been applied." }, 500);
    }
  }

  /* Public registration creates customers or pending business applications.
     The submitted role field is never trusted. */
  if (path === "/api/auth/register" && method === "POST") {
    const b = await body(req);
    const email = String(b.email || "").trim().toLowerCase() || null;
    let phone = String(b.phone || "").trim() || null;
    const password = String(b.password || "");
    const pin = String(b.pin || "");
    const fullName = String(b.fullName || b.full_name || b.name || "").trim().slice(0,150);
    const accountType = String(b.accountType || "customer").trim().toLowerCase();
    const allowedTypes = ["customer","agent","supplier","distributor"];
    if (!env.DB || !env.JWT_SECRET || env.JWT_SECRET.length < 32) {
      return json({ ok:false, code:"SERVER_NOT_CONFIGURED", message:"Database or login security is not configured." },503);
    }
    if (!allowedTypes.includes(accountType)) return json({ ok:false, message:"Choose a valid account type." },400);
    if (!email && !phone) return json({ ok:false, message:"Email or phone is required." },400);
    if (!fullName) return json({ ok:false, message:"Full name is required." },400);
    if (password.length < 8 || password.length > 128) return json({ ok:false, message:"Password must contain 8 to 128 characters." },400);
    if (!/^\d{4,8}$/.test(pin)) return json({ ok:false, message:"PIN must contain 4 to 8 digits." },400);
    if (phone) {
      try { phone = normalizeKenyanPhone(phone); }
      catch (error) { return json({ ok:false, message:error.message },400); }
    }
    if (accountType === "customer" && b.privacyConsent !== true) return json({ ok:false, message:"Please acknowledge the privacy notice." },400);
    const isBusiness = accountType !== "customer";
    const businessName = String(b.businessName || "").trim().slice(0,180);
    if (isBusiness && (!businessName || b.privacyConsent !== true || b.verificationConsent !== true)) {
      return json({ ok:false, message:"Complete the business details and confirm the verification declaration." },400);
    }
    const id = uid("usr_");
    const status = isBusiness ? "pending" : "active";
    const details = {
      businessName,
      businessType: String(b.businessType || "").slice(0,120),
      idType: String(b.idType || "").slice(0,40),
      idNumber: String(b.idNumber || "").trim().slice(0,100),
      kraPin: String(b.kraPin || "").trim().slice(0,40) || null,
      permitNumber: String(b.permitNumber || "").trim().slice(0,100) || null,
      businessAddress: String(b.businessAddress || "").trim().slice(0,250),
      yearsOperating: String(b.yearsOperating || "").slice(0,40),
      referencePhone: String(b.referencePhone || "").trim().slice(0,30) || null,
      productsServices: String(b.productsServices || "").trim().slice(0,1000),
      coverage: String(b.coverage || "").trim().slice(0,500),
      county: String(b.county || "").slice(0,100),
      countyCode: b.countyCode ?? null,
      constituency: String(b.constituency || "").slice(0,100),
      constituencyId: b.constituencyId ?? null,
      ward: String(b.ward || "").slice(0,100),
      wardId: b.wardId ?? null,
      locality: String(b.locality || "").slice(0,180)
    };
    if (isBusiness && (!details.idType || !details.idNumber || !details.businessAddress || !details.productsServices || !details.coverage || !details.county || !details.constituency || !details.ward || !details.locality)) {
      return json({ ok:false, message:"Complete all required identity, business and location fields." },400);
    }
    try {
      const passwordHash = await hashPassword(password);
      const pinHash = await hashPassword(pin);
      const statements = [
        env.DB.prepare(`INSERT INTO users (id,email,phone,full_name,role,status,password_hash) VALUES(?,?,?,?,?,?,?)`).bind(id,email,phone,fullName,"customer",status,passwordHash),
        env.DB.prepare(`INSERT INTO user_pin_credentials (user_id,pin_hash) VALUES(?,?)`).bind(id,pinHash)
      ];
      statements.push(env.DB.prepare(`INSERT INTO user_profiles (user_id,county,county_code,constituency,constituency_id,ward,ward_id,locality) VALUES(?,?,?,?,?,?,?,?)`).bind(id,String(b.county || "").slice(0,100) || null,b.countyCode ?? null,String(b.constituency || "").slice(0,100) || null,b.constituencyId ?? null,String(b.ward || "").slice(0,100) || null,b.wardId ?? null,String(b.locality || "").slice(0,180) || null));
      if (isBusiness) {
        statements.push(env.DB.prepare(`INSERT INTO business_application_details (user_id,account_type,business_name,details_json,status) VALUES(?,?,?,?, 'pending')`).bind(id,accountType,businessName,JSON.stringify(details)));
        if (accountType === "supplier" || accountType === "distributor") {
          statements.push(env.DB.prepare(`INSERT INTO suppliers (id,user_id,business_name,phone,email,location,status) VALUES(?,?,?,?,?,?, 'pending')`).bind(uid("sup_"),id,businessName,phone,email,[details.locality,details.county].filter(Boolean).join(", ")));
        }
        if (accountType === "agent") {
          statements.push(env.DB.prepare(`INSERT INTO agent_applications (id,user_id,status) VALUES(?,?,'pending')`).bind(uid("aga_"),id));
        } else if (accountType === "distributor") {
          statements.push(env.DB.prepare(`INSERT INTO distributor_applications (id,user_id,business_name,status) VALUES(?,?,?,'pending')`).bind(uid("dis_"),id,businessName));
        }
      }
      await env.DB.batch(statements);
      const user = await env.DB.prepare("SELECT id,email,phone,full_name,role,status FROM users WHERE id=?").bind(id).first();
      return json({
        ok:true,
        user,
        applicationStatus:isBusiness ? "pending" : "active",
        message:isBusiness ? "Your business application has been submitted for verification. You can sign in after approval." : "Your customer account has been created. Please sign in with your PIN."
      },201);
    } catch (error) {
      const msg = String(error?.message || "");
      if (msg.includes("UNIQUE constraint failed")) {
        if (msg.includes("users.email")) return json({ok:false,code:"EMAIL_EXISTS",message:"This email address is already registered."},409);
        if (msg.includes("users.phone")) return json({ok:false,code:"PHONE_EXISTS",message:"This phone number is already registered."},409);
        return json({ok:false,code:"ACCOUNT_EXISTS",message:"This account is already registered."},409);
      }
      console.error("Registration error:",msg);
      return json({ok:false,code:"REGISTRATION_ERROR",message:"Registration failed. Please try again. Confirm that migration 0009 has been applied."},500);
    }
  }

  /* PIN login; legacy password hashes remain a fallback for older accounts. */
  if (path === "/api/auth/login" && method === "POST") {
    const b = await body(req);
    const rawIdentifier = String(b.identifier || b.phone || b.email || "").trim();
    const credential = String(b.secret || b.pin || b.password || "");
    if (!rawIdentifier || !credential) return json({ok:false,message:"Enter your phone number and PIN."},400);
    let identifier = rawIdentifier.toLowerCase();
    if (!identifier.includes("@")) {
      try { identifier = normalizeKenyanPhone(identifier); }
      catch { return json({ok:false,message:"Enter a valid Kenyan phone number."},400); }
    }
    const user = await env.DB.prepare("SELECT * FROM users WHERE lower(email)=? OR phone=?").bind(identifier,identifier).first();
    if (!user || user.status !== "active") return json({ok:false,message:"Invalid login details, or your business application is still awaiting approval."},401);
    let valid = false;
    try {
      const pinRecord = await env.DB.prepare("SELECT pin_hash FROM user_pin_credentials WHERE user_id=?").bind(user.id).first();
      if (pinRecord?.pin_hash) valid = await verifyPassword(credential,pinRecord.pin_hash);
      else valid = await verifyPassword(credential,user.password_hash);
    } catch (error) {
      if (!String(error?.message || "").includes("no such table")) throw error;
      valid = await verifyPassword(credential,user.password_hash);
    }
    if (!valid) return json({ok:false,message:"Invalid login details. Check your phone number and PIN."},401);
    const safe = {id:user.id,email:user.email,phone:user.phone,full_name:user.full_name,role:user.role};
    return json({ok:true,token:await signToken(safe,env),user:safe});
  }

  /* Google authentication deliberately disabled. */
  if (path === "/api/auth/google" && method === "POST") {
    return json({
      ok: false,
      message: "Google sign-in is disabled. Please use your phone number and password."
    }, 410);
  }

  if (
    [
      "/api/auth/request-otp",
      "/api/auth/verify-otp",
      "/api/auth/forgot-pin"
    ].includes(path) &&
    method === "POST"
  ) {
    return json({
      ok: false,
      message: "OTP delivery is not enabled. An email or SMS delivery provider must first be connected."
    }, 501);
  }

  /* Public product catalogue */
  if (path === "/api/products" && method === "GET") {
    const q = (url.searchParams.get("q") || "").trim();

    const query = q
      ? env.DB.prepare(`
          SELECT
            id,name,description,category,sku,image_url,unit,
            price_minor,discount_percent,stock_quantity,
            supplier_id,updated_at
          FROM products
          WHERE is_active=1 AND name LIKE ?
          ORDER BY updated_at DESC
          LIMIT 100
        `).bind(`%${q}%`)

      : env.DB.prepare(`
          SELECT
            id,name,description,category,sku,image_url,unit,
            price_minor,discount_percent,stock_quantity,
            supplier_id,updated_at
          FROM products
          WHERE is_active=1
          ORDER BY updated_at DESC
          LIMIT 100
        `);

    const result = await query.all();

    return json({
      ok: true,
      products: result.results || []
    });
  }

  /* Create an order atomically. Stock is checked here but not deducted until fulfilment. */
  if (path === "/api/orders" && method === "POST") {
    const user = await auth(req, env);
    if (!user) return json({ok:false,message:"Authentication required"},401);
    const b = await body(req);
    const rawItems = Array.isArray(b.items) ? b.items : [];
    if (!rawItems.length || rawItems.length > 100) return json({ok:false,message:"Order must contain between 1 and 100 items."},400);
    const clientId = b.clientOrderId || b.client_order_id ? String(b.clientOrderId || b.client_order_id).trim().slice(0,100) : null;
    if (clientId) {
      const existing = await env.DB.prepare("SELECT id,status,payment_status,total_minor FROM orders WHERE client_order_id=? AND user_id=?").bind(clientId,user.id).first();
      if (existing) return json({ok:true,orderId:existing.id,id:existing.id,status:existing.status,paymentStatus:existing.payment_status,totalMinor:existing.total_minor,duplicate:true});
    }
    const customerName = String(b.customerName || b.customer_name || user.full_name || "").trim().slice(0,150);
    let customerPhone = String(b.customerPhone || b.customer_phone || user.phone || "").trim();
    if (customerPhone) {
      try { customerPhone = normalizeKenyanPhone(customerPhone); }
      catch (error) { return json({ok:false,message:error.message},400); }
    }
    const normalized = [];
    let total = 0;
    for (const item of rawItems) {
      const qtyRaw = Number(item.quantity);
      const qty = Math.round(qtyRaw * 1000) / 1000;
      const productId = String(item.productId || item.product_id || "").trim();
      if (!productId || !Number.isFinite(qtyRaw) || qty <= 0 || qty > 100000 || Math.abs(qtyRaw-qty)>1e-7) {
        return json({ok:false,message:"Each order item must have a valid positive quantity (up to 3 decimal places)."},400);
      }
      const product = await env.DB.prepare(`SELECT id,name,supplier_id,price_minor,discount_percent,stock_quantity,is_active FROM products WHERE id=?`).bind(productId).first();
      if (!product || Number(product.is_active) !== 1) return json({ok:false,message:"A selected product is unavailable."},409);
      if (qty > Number(product.stock_quantity || 0)) return json({ok:false,message:`Insufficient stock for ${product.name}.`},409);
      const unit = Number(product.price_minor || 0);
      if (!Number.isSafeInteger(unit) || unit < 0) return json({ok:false,message:`Invalid price for ${product.name}.`},409);
      const discount = Math.max(0,Math.min(100,Number(product.discount_percent || 0)));
      const line = Math.round(unit * qty * (1-discount/100));
      if (!Number.isSafeInteger(line) || line < 0) return json({ok:false,message:"Order total is outside the supported range."},400);
      total += line;
      if (!Number.isSafeInteger(total)) return json({ok:false,message:"Order total is outside the supported range."},400);
      normalized.push({id:uid("itm_"),product,qty,unit,discount,line,variant:String(item.variant || "").slice(0,150) || null});
    }
    const orderId = uid("ord_");
    const statements = [env.DB.prepare(`INSERT INTO orders (id,user_id,customer_name,customer_phone,status,payment_status,total_minor,client_order_id,source) VALUES(?,?,?,?,?,?,?,?,?)`).bind(orderId,user.id,customerName,customerPhone || null,"pending","not_paid",total,clientId,"online-or-synced")];
    for (const item of normalized) {
      statements.push(env.DB.prepare(`INSERT INTO order_items (id,order_id,product_id,supplier_id,product_name,variant,quantity,unit_price_minor,discount_percent,line_total_minor) VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(item.id,orderId,item.product.id,item.product.supplier_id,item.product.name,item.variant,item.qty,item.unit,item.discount,item.line));
    }
    statements.push(env.DB.prepare(`INSERT INTO order_events (id,order_id,actor_user_id,event_type,note) VALUES(?,?,?,?,?)`).bind(uid("evt_"),orderId,user.id,"order_submitted","Order received; payment not yet taken"));
    try {
      await env.DB.batch(statements);
      return json({ok:true,orderId,id:orderId,status:"pending",paymentStatus:"not_paid",totalMinor:total,currency:"KES"},201);
    } catch (error) {
      if (clientId) {
        const existing = await env.DB.prepare("SELECT id,status,payment_status,total_minor FROM orders WHERE client_order_id=? AND user_id=?").bind(clientId,user.id).first();
        if (existing) return json({ok:true,orderId:existing.id,id:existing.id,status:existing.status,paymentStatus:existing.payment_status,totalMinor:existing.total_minor,duplicate:true});
        const collision = await env.DB.prepare("SELECT id FROM orders WHERE client_order_id=?").bind(clientId).first();
        if (collision) return json({ok:false,message:"This order reference is already in use. Please refresh and try again."},409);
      }
      console.error("Order creation failed:",String(error?.message || error));
      return json({ok:false,message:"The order could not be saved. Please try again."},500);
    }
  }

  if (path === "/api/orders" && method === "GET") {
    const user = await auth(req, env);

    if (!user) {
      return json({
        ok: false,
        message: "Authentication required"
      }, 401);
    }

    const result = await env.DB.prepare(`
      SELECT id,status,payment_status,total_minor,currency,created_at
      FROM orders
      WHERE user_id=?
      ORDER BY created_at DESC
      LIMIT 100
    `).bind(user.id).all();

    return json({
      ok: true,
      orders: result.results || []
    });
  }

  if (
    path === "/api/subscriptions/stk-push" &&
    method === "POST"
  ) {
    return startSubscriptionPayment(req, env);
  }

  if (path === "/api/payments/mpesa/status" && method === "GET") {
    const user = await auth(req, env);

    if (!user) {
      return json({
        ok: false,
        message: "Authentication required"
      }, 401);
    }

    const id = url.searchParams.get("paymentId");

    if (!id) {
      return json({
        ok: false,
        message: "paymentId is required"
      }, 400);
    }

    const payment = await env.DB.prepare(`
      SELECT
        id,purpose,plan,amount_kes,status,mpesa_receipt,
        created_at,updated_at
      FROM payment_transactions
      WHERE id=? AND user_id=?
    `).bind(id, user.id).first();

    return payment
      ? json({ ok: true, payment })
      : json({ ok: false, message: "Payment not found" }, 404);
  }

  if (path === "/api/sync" && method === "POST") {
    const user = await auth(req, env);

    if (!user) {
      return json({
        ok: false,
        message: "Authentication required"
      }, 401);
    }

    const b = await body(req);
    const deviceId = String(b.deviceId || "").slice(0, 100);
    const mutations = Array.isArray(b.mutations) ? b.mutations : [];

    if (!deviceId) {
      return json({
        ok: false,
        message: "deviceId is required"
      }, 400);
    }

    if (mutations.length > 100) {
      return json({
        ok: false,
        message: "Maximum 100 mutations per batch"
      }, 400);
    }

    const results = [];

    for (const mutation of mutations) {
      const id = String(
        mutation.id || uid("mut_")
      ).slice(0, 100);

      try {
        await env.DB.prepare(`
          INSERT OR IGNORE INTO sync_mutations
          (
            id,user_id,device_id,mutation_type,entity_id,
            payload_json,status
          )
          VALUES(?,?,?,?,?,?,?)
        `).bind(
          id,
          user.id,
          deviceId,
          String(mutation.type || "unknown").slice(0, 100),
          String(mutation.entityId || id).slice(0, 100),
          JSON.stringify(mutation.payload || {}),
          "accepted"
        ).run();

        results.push({
          id,
          status: "accepted"
        });

      } catch {
        results.push({
          id,
          status: "rejected"
        });
      }
    }

    await env.DB.prepare(`
      INSERT INTO device_sync_state
      (user_id,device_id,last_synced_at,last_seen_at)
      VALUES(?,?,?,?)
      ON CONFLICT(user_id,device_id) DO UPDATE SET
      last_synced_at=excluded.last_synced_at,
      last_seen_at=excluded.last_seen_at
    `).bind(
      user.id,
      deviceId,
      nowIso(),
      nowIso()
    ).run();

    return json({
      ok: true,
      received: results.length,
      results,
      syncedAt: nowIso(),
      note: "Mutations are recorded. Business-specific replay handlers are not enabled."
    });
  }

  /* ---------------------------------------------------------
   * GODIA PRIME POS V2
   * Uses pos_sales_v2 and pos_sale_items_v2 only.
   * --------------------------------------------------------- */

  const posAllowedRoles = [
    "owner",
    "admin",
    "supplier",
    "distributor",
    "retailer",
    "shopkeeper"
  ];

  /* POS product list */
  if (path === "/api/pos/products" && method === "GET") {
    const user = await auth(req, env);

    if (!user) {
      return json({
        ok: false,
        message: "Authentication required"
      }, 401);
    }

    const role = String(user.role || "").toLowerCase();

    if (!posAllowedRoles.includes(role)) {
      return json({
        ok: false,
        message: "Your account is not authorized to use the cashier POS."
      }, 403);
    }

    let result;

    if (role === "owner" || role === "admin") {
      result = await env.DB.prepare(`
        SELECT
          p.id,p.name,p.description,p.category,p.sku,p.image_url,
          p.unit,p.price_minor,p.discount_percent,p.stock_quantity,
          p.supplier_id
        FROM products p
        WHERE p.is_active=1
        ORDER BY p.name
        LIMIT 500
      `).all();

    } else {
      result = await env.DB.prepare(`
        SELECT
          p.id,p.name,p.description,p.category,p.sku,p.image_url,
          p.unit,p.price_minor,p.discount_percent,p.stock_quantity,
          p.supplier_id
        FROM products p
        INNER JOIN suppliers sp
          ON sp.id=p.supplier_id
        WHERE p.is_active=1
          AND sp.user_id=?
        ORDER BY p.name
        LIMIT 500
      `).bind(user.id).all();
    }

    return json({
      ok: true,
      products: result.results || []
    });
  }

  /* Record a POS sale */
  if (path === "/api/pos/sales" && method === "POST") {
    const user = await auth(req, env);

    if (!user) {
      return json({
        ok: false,
        message: "Authentication required"
      }, 401);
    }

    const role = String(user.role || "").toLowerCase();

    if (!posAllowedRoles.includes(role)) {
      return json({
        ok: false,
        message: "Your account is not authorized to record POS sales."
      }, 403);
    }

    const b = await body(req);
    const rawItems = Array.isArray(b.items) ? b.items : [];

    if (!rawItems.length || rawItems.length > 100) {
      return json({
        ok: false,
        message: "A sale must contain between 1 and 100 product lines."
      }, 400);
    }

    const paymentMethod = String(
      b.paymentMethod || ""
    ).toLowerCase();

    if (!["cash", "mpesa_till"].includes(paymentMethod)) {
      return json({
        ok: false,
        message: "Choose cash or M-PESA Till payment."
      }, 400);
    }

    const clientSaleId = String(
      b.clientSaleId || ""
    ).trim().slice(0, 100);

    if (!clientSaleId) {
      return json({
        ok: false,
        message: "Sale reference is missing. Please try again."
      }, 400);
    }

    /* Idempotency check: prevent duplicate sale submissions. */
    const prior = await env.DB.prepare(`
      SELECT id
      FROM pos_sales_v2
      WHERE seller_id=? AND client_sale_id=?
    `).bind(user.id, clientSaleId).first();

    if (prior) {
      const saved = await readPosSale(
        env.DB,
        prior.id,
        user.id
      );

      return json({
        ok: true,
        duplicate: true,
        sale: saved,
        message: "This sale was already recorded."
      });
    }

    const customerName = String(
      b.customerName || "Walk-in customer"
    ).trim().slice(0, 150) || "Walk-in customer";

    let customerPhone = String(
      b.customerPhone || ""
    ).trim();

    if (customerPhone) {
      try {
        customerPhone = normalizeKenyanPhone(customerPhone);
      } catch (error) {
        return json({
          ok: false,
          message: error.message
        }, 400);
      }
    }

    const mpesaReceipt = paymentMethod === "mpesa_till"
      ? String(b.mpesaReceipt || "")
          .trim()
          .toUpperCase()
          .replace(/[^A-Z0-9]/g, "")
          .slice(0, 30) || null
      : null;

    if (paymentMethod === "mpesa_till" && !mpesaReceipt) {
      return json({
        ok: false,
        message: "Enter the M-PESA transaction code. It will be recorded as unverified until checked."
      }, 400);
    }

    /* Merge duplicate product lines and validate quantities. */
    const merged = new Map();

    for (const line of rawItems) {
      const productId = String(
        line.productId || line.product_id || ""
      ).trim();

      const quantity = Number(line.quantity);

      if (
        !productId ||
        !Number.isFinite(quantity) ||
        quantity <= 0 ||
        quantity > 100000 ||
        Math.abs(quantity * 1000 - Math.round(quantity * 1000)) > 1e-7
      ) {
        return json({
          ok: false,
          message: "Each product must have a positive quantity with no more than 3 decimal places."
        }, 400);
      }

      const combined = (merged.get(productId) || 0) + quantity;

      if (!Number.isFinite(combined) || combined > 100000 || Math.abs(combined * 1000 - Math.round(combined * 1000)) > 1e-7) {
        return json({
          ok: false,
          message: "Product quantity is outside the supported range."
        }, 400);
      }

      merged.set(productId, combined);
    }

    if (merged.size > 100) {
      return json({
        ok: false,
        message: "Too many different products in one sale."
      }, 400);
    }

    const items = [];
    let subtotalMinor = 0;
    let totalMinor = 0;

    for (const [productId, quantity] of merged) {
      const product = await env.DB.prepare(`
        SELECT
          id,name,sku,supplier_id,price_minor,
          discount_percent,stock_quantity,is_active
        FROM products
        WHERE id=?
      `).bind(productId).first();

      if (!product || Number(product.is_active) !== 1) {
        return json({
          ok: false,
          message: "One of the selected products is unavailable."
        }, 409);
      }

      /* Verify seller ownership through suppliers.user_id. */
      if (role !== "owner" && role !== "admin") {
        const ownership = await env.DB.prepare(`
          SELECT id
          FROM suppliers
          WHERE id=? AND user_id=?
          LIMIT 1
        `).bind(
          product.supplier_id,
          user.id
        ).first();

        if (!ownership) {
          return json({
            ok: false,
            message: "You can only sell products assigned to your own business."
          }, 403);
        }
      }

      if (quantity > Number(product.stock_quantity || 0)) {
        return json({
          ok: false,
          message: `Not enough stock for ${product.name}. Available: ${Number(product.stock_quantity || 0)}.`
        }, 409);
      }

      const unit = Number(product.price_minor || 0);

      if (!Number.isSafeInteger(unit) || unit < 0) {
        return json({
          ok: false,
          message: `Invalid price for ${product.name}.`
        }, 409);
      }

      const discount = Math.max(
        0,
        Math.min(100, Number(product.discount_percent || 0))
      );

      const lineSubtotal = Math.round(unit * quantity);
      const lineTotal = Math.round(lineSubtotal * (1 - discount / 100));

      if (
        !Number.isSafeInteger(lineSubtotal) ||
        !Number.isSafeInteger(lineTotal) ||
        lineTotal < 0
      ) {
        return json({
          ok: false,
          message: "Sale total is outside the supported range."
        }, 400);
      }

      subtotalMinor += lineSubtotal;
      totalMinor += lineTotal;

      if (
        !Number.isSafeInteger(subtotalMinor) ||
        !Number.isSafeInteger(totalMinor)
      ) {
        return json({
          ok: false,
          message: "Sale total is outside the supported range."
        }, 400);
      }

      items.push({
        product,
        quantity,
        unit,
        discount,
        lineTotal
      });
    }

    if (
      !Number.isSafeInteger(subtotalMinor) ||
      subtotalMinor < 0 ||
      !Number.isSafeInteger(totalMinor) ||
      totalMinor <= 0
    ) {
      return json({
        ok: false,
        message: "The sale total is outside the supported range or is zero."
      }, 400);
    }

    const amountReceivedMinor =
      paymentMethod === "cash"
        ? Number(b.amountReceivedMinor)
        : totalMinor;

    if (
      !Number.isSafeInteger(amountReceivedMinor) ||
      amountReceivedMinor < totalMinor
    ) {
      return json({
        ok: false,
        message: "Amount received must be equal to or greater than the sale total."
      }, 400);
    }

    const changeMinor =
      paymentMethod === "cash"
        ? amountReceivedMinor - totalMinor
        : 0;

    const paymentStatus =
      paymentMethod === "cash"
        ? "paid"
        : "recorded_unverified";

    const saleId = uid("pos_");

    /*
     * D1 batch executes the sale header and all sale lines
     * as one transaction. The database triggers validate and
     * deduct stock when the sale lines are inserted.
     */
    const statements = [
      env.DB.prepare(`
        INSERT INTO pos_sales_v2
        (
          id,seller_id,cashier_id,client_sale_id,
          customer_name,customer_phone,subtotal_minor,total_minor,
          payment_method,payment_status,amount_received_minor,
          change_minor,mpesa_receipt,status
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      `).bind(
        saleId,
        user.id,
        user.id,
        clientSaleId,
        customerName,
        customerPhone || null,
        subtotalMinor,
        totalMinor,
        paymentMethod,
        paymentStatus,
        amountReceivedMinor,
        changeMinor,
        mpesaReceipt,
        "completed"
      )
    ];

    for (const item of items) {
      statements.push(
        env.DB.prepare(`
          INSERT INTO pos_sale_items_v2
          (
            id,sale_id,product_id,product_name,sku,
            quantity,unit_price_minor,discount_percent,
            line_total_minor
          )
          VALUES(?,?,?,?,?,?,?,?,?)
        `).bind(
          uid("psi_"),
          saleId,
          item.product.id,
          item.product.name,
          item.product.sku || null,
          item.quantity,
          item.unit,
          item.discount,
          item.lineTotal
        )
      );
    }

    try {
      await env.DB.batch(statements);

    } catch (error) {
      const msg = String(error?.message || "");

      if (
        msg.includes("POS_INSUFFICIENT_STOCK") ||
        msg.includes("POS_INSUFFICIENT_STOCK_OR_ACCESS_DENIED")
      ) {
        return json({
          ok: false,
          message: "Stock changed or product access was denied while this sale was being processed. Refresh the products and try again."
        }, 409);
      }

      if (
        msg.includes("UNIQUE constraint failed") &&
        msg.includes("mpesa_receipt")
      ) {
        return json({
          ok: false,
          message: "This M-PESA receipt code has already been used. Check the Till statement before retrying."
        }, 409);
      }

      if (msg.includes("UNIQUE constraint failed")) {
        const duplicate = await env.DB.prepare(`
          SELECT id
          FROM pos_sales_v2
          WHERE seller_id=? AND client_sale_id=?
        `).bind(
          user.id,
          clientSaleId
        ).first();

        if (duplicate) {
          const saved = await readPosSale(
            env.DB,
            duplicate.id,
            user.id
          );

          return json({
            ok: true,
            duplicate: true,
            sale: saved,
            message: "This sale was already recorded."
          });
        }
      }

      console.error("POS V2 sale failed:", msg);

      return json({
        ok: false,
        message: "The sale could not be saved. No receipt was issued; please refresh and check the sales list."
      }, 500);
    }

    const saved = await readPosSale(
      env.DB,
      saleId,
      user.id
    );

    return json({
      ok: true,
      sale: saved,
      message:
        paymentMethod === "cash"
          ? "Cash sale recorded and stock updated."
          : "M-PESA Till reference recorded. Verify the payment separately before treating it as confirmed."
    }, 201);
  }

  /* Void a completed POS sale. The database trigger restores stock and logs returns. */
  if (path.startsWith("/api/pos/sales/") && path.endsWith("/void") && method === "POST") {
    const user = await auth(req, env);
    if (!user) return json({ok:false,message:"Authentication required"},401);
    const role = String(user.role || "").toLowerCase();
    if (!["owner","admin"].includes(role)) return json({ok:false,message:"Only an owner or administrator can void a sale."},403);
    const saleId = decodeURIComponent(path.slice("/api/pos/sales/".length,-"/void".length));
    const sale = await env.DB.prepare("SELECT id,status FROM pos_sales_v2 WHERE id=?").bind(saleId).first();
    if (!sale) return json({ok:false,message:"Sale not found."},404);
    if (sale.status !== "completed") return json({ok:false,message:"Only completed sales can be voided."},409);
    const b = await body(req);
    const reason = String(b.reason || "Owner-authorised POS void").trim().slice(0,300);
    try {
      await env.DB.prepare("UPDATE pos_sales_v2 SET status='voided',void_reason=?,voided_by=?,voided_at=CURRENT_TIMESTAMP WHERE id=? AND status='completed'").bind(reason,user.id,saleId).run();
      const updated = await env.DB.prepare("SELECT status FROM pos_sales_v2 WHERE id=?").bind(saleId).first();
      if (updated?.status !== "voided") return json({ok:false,message:"Sale could not be voided."},409);
      return json({ok:true,saleId,status:"voided",reason,message:"Sale voided. Stock was restored and inventory movements were recorded."});
    } catch (error) {
      console.error("POS void failed:",String(error?.message || error));
      return json({ok:false,message:"The sale could not be voided."},500);
    }
  }

  /* POS daily sales report */
  if (path === "/api/pos/sales" && method === "GET") {
    const user = await auth(req, env);

    if (!user) {
      return json({
        ok: false,
        message: "Authentication required"
      }, 401);
    }

    const role = String(user.role || "").toLowerCase();

    if (!posAllowedRoles.includes(role)) {
      return json({
        ok: false,
        message: "Your account is not authorized to view POS reports."
      }, 403);
    }

    const date = String(
      url.searchParams.get("date") ||
      new Date().toLocaleDateString("en-CA", {
        timeZone: "Africa/Nairobi"
      })
    );

    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return json({
        ok: false,
        message: "Use a date in YYYY-MM-DD format."
      }, 400);
    }

    const ownerScope =
      role === "owner" || role === "admin";

    const scopeSql = ownerScope
      ? "date(datetime(created_at,'+3 hours'))=?"
      : "seller_id=? AND date(datetime(created_at,'+3 hours'))=?";

    const parameters = ownerScope
      ? [date]
      : [user.id, date];

    const summary = await env.DB.prepare(`
      SELECT
        COUNT(*) AS sale_count,
        COALESCE(
          SUM(
            CASE
              WHEN payment_method='cash'
              THEN total_minor
              ELSE 0
            END
          ),0
        ) AS cash_total_minor,
        COALESCE(
          SUM(
            CASE
              WHEN payment_method='mpesa_till'
              THEN total_minor
              ELSE 0
            END
          ),0
        ) AS mpesa_till_total_minor,
        COALESCE(SUM(total_minor),0) AS daily_total_minor
      FROM pos_sales_v2
      WHERE ${scopeSql}
        AND status='completed'
    `).bind(...parameters).first();

    const sales = await env.DB.prepare(`
      SELECT
        id,customer_name,customer_phone,total_minor,
        payment_method,payment_status,amount_received_minor,
        change_minor,mpesa_receipt,created_at
      FROM pos_sales_v2
      WHERE ${scopeSql}
        AND status='completed'
      ORDER BY created_at DESC
      LIMIT 200
    `).bind(...parameters).all();

    return json({
      ok: true,
      date,
      summary: summary || {},
      sales: sales.results || [],
      currency: "KES",
      timezone: "Africa/Nairobi"
    });
  }

  /* POS receipt lookup */
  if (
    path.startsWith("/api/pos/sales/") &&
    method === "GET"
  ) {
    const user = await auth(req, env);

    if (!user) {
      return json({
        ok: false,
        message: "Authentication required"
      }, 401);
    }

    const role = String(user.role || "").toLowerCase();

    if (!posAllowedRoles.includes(role)) {
      return json({
        ok: false,
        message: "Your account is not authorized to view POS receipts."
      }, 403);
    }

    let saleId;

    try {
      saleId = decodeURIComponent(
        path.slice("/api/pos/sales/".length)
      );
    } catch {
      return json({
        ok: false,
        message: "Invalid receipt reference."
      }, 400);
    }

    if (!saleId || saleId.includes("/")) {
      return json({
        ok: false,
        message: "Invalid receipt reference."
      }, 400);
    }

    const ownerScope =
      role === "owner" || role === "admin";

    const sale = await readPosSale(
      env.DB,
      saleId,
      ownerScope ? null : user.id
    );

    if (!sale) {
      return json({
        ok: false,
        message: "Receipt not found."
      }, 404);
    }

    return json({
      ok: true,
      sale
    });
  }

  /* Owner/admin business-application review. Sensitive identity data is never public. */
  if (path === "/api/admin/applications" && method === "GET") {
    const user = await auth(req, env);
    if (!user) return json({ok:false,message:"Authentication required"},401);
    if (!["owner","admin"].includes(String(user.role || "").toLowerCase())) return json({ok:false,message:"Administrator access required."},403);
    const status = String(url.searchParams.get("status") || "pending").toLowerCase();
    if (!["pending","approved","rejected","all"].includes(status)) return json({ok:false,message:"Invalid application status."},400);
    const result = status === "all"
      ? await env.DB.prepare(`SELECT d.user_id,d.account_type,d.business_name,d.details_json,d.status,d.notes,d.created_at,u.full_name,u.email,u.phone FROM business_application_details d JOIN users u ON u.id=d.user_id ORDER BY d.created_at DESC LIMIT 200`).all()
      : await env.DB.prepare(`SELECT d.user_id,d.account_type,d.business_name,d.details_json,d.status,d.notes,d.created_at,u.full_name,u.email,u.phone FROM business_application_details d JOIN users u ON u.id=d.user_id WHERE d.status=? ORDER BY d.created_at DESC LIMIT 200`).bind(status).all();
    const applications = (result.results || []).map(row => {
      let details = {};
      try { details = JSON.parse(row.details_json || "{}"); } catch {}
      return {...row,details,details_json:undefined};
    });
    return json({ok:true,applications});
  }

  if (path.startsWith("/api/admin/applications/") && method === "PATCH") {
    const user = await auth(req, env);
    if (!user) return json({ok:false,message:"Authentication required"},401);
    if (!["owner","admin"].includes(String(user.role || "").toLowerCase())) return json({ok:false,message:"Administrator access required."},403);
    const targetId = decodeURIComponent(path.slice("/api/admin/applications/".length));
    if (!targetId || targetId.includes("/")) return json({ok:false,message:"Invalid application reference."},400);
    const b = await body(req);
    const decision = String(b.decision || "").toLowerCase();
    if (!["approve","reject"].includes(decision)) return json({ok:false,message:"Decision must be approve or reject."},400);
    const app = await env.DB.prepare("SELECT account_type,status FROM business_application_details WHERE user_id=?").bind(targetId).first();
    if (!app) return json({ok:false,message:"Application not found."},404);
    if (app.status !== "pending") return json({ok:false,message:"This application has already been reviewed."},409);
    const approved = decision === "approve";
    const nextStatus = approved ? "approved" : "rejected";
    const userStatus = approved ? "active" : "rejected";
    const nextRole = approved ? app.account_type : "customer";
    const notes = String(b.notes || "").trim().slice(0,500) || null;
    const statements = [
      env.DB.prepare("UPDATE business_application_details SET status=?,notes=?,reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP WHERE user_id=? AND status='pending'").bind(nextStatus,notes,user.id,targetId),
      env.DB.prepare("UPDATE users SET role=?,status=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'").bind(nextRole,userStatus,targetId)
    ];
    if (["supplier","distributor"].includes(app.account_type)) statements.push(env.DB.prepare("UPDATE suppliers SET status=? WHERE user_id=?").bind(approved ? "active" : "rejected",targetId));
    if (app.account_type === "agent") statements.push(env.DB.prepare("UPDATE agent_applications SET status=?,notes=?,reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP WHERE user_id=? AND status='pending'").bind(nextStatus,notes,user.id,targetId));
    if (app.account_type === "distributor") statements.push(env.DB.prepare("UPDATE distributor_applications SET status=?,notes=?,reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP WHERE user_id=? AND status='pending'").bind(nextStatus,notes,user.id,targetId));
    try {
      await env.DB.batch(statements);
      const changed = await env.DB.prepare("SELECT status,role FROM users WHERE id=?").bind(targetId).first();
      if (!changed || changed.status !== userStatus) return json({ok:false,message:"Application status changed before this review could be completed."},409);
      return json({ok:true,userId:targetId,status:nextStatus,role:changed.role,message:approved ? "Business application approved." : "Business application rejected."});
    } catch (error) {
      console.error("Application review failed:",String(error?.message || error));
      return json({ok:false,message:"Application review failed. No approval was confirmed."},500);
    }
  }

  if (path === "/api/me" && method === "GET") {
    const user = await auth(req, env);

    return user
      ? json({ ok: true, user })
      : json({
          ok: false,
          message: "Authentication required"
        }, 401);
  }

  return json({
    ok: false,
    message: "API endpoint not found"
  }, 404);
}

export default {
  async fetch(request, env, ctx) {
    const headers = corsHeaders(request, env);

    try {
      if (request.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers
        });
      }

      const url = new URL(request.url);

      if (url.pathname.startsWith("/api/")) {
        const response = await handle(request, env);
        const finalHeaders = new Headers(response.headers);

        for (const [key, value] of Object.entries(headers)) {
          finalHeaders.set(key, value);
        }

        return new Response(response.body, {
          status: response.status,
          headers: finalHeaders
        });
      }

      if (env.ASSETS) {
        return env.ASSETS.fetch(request);
      }

      return new Response(
        "GODIA PRIME frontend is not configured",
        { status: 404 }
      );

    } catch (error) {
      console.error("GODIA API error:", error.message);

      return json({
        ok: false,
        message: "Internal server error"
      }, 500, headers);
    }
  }
};
