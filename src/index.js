const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' };
const json = (data, status=200) => new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
const uid = (prefix='') => prefix + crypto.randomUUID();
const nowIso = () => new Date().toISOString();
const b64url = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
const fromB64url = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/') + '='.repeat((4-s.length%4)%4)), c=>c.charCodeAt(0));
async function signToken(user, env) {
  if (!env.JWT_SECRET || env.JWT_SECRET.length < 32) throw new Error('JWT_SECRET must be configured as a 32+ character secret');
  const header=b64url(new TextEncoder().encode(JSON.stringify({alg:'HS256',typ:'JWT'})));
  const payload=b64url(new TextEncoder().encode(JSON.stringify({sub:user.id,role:user.role||'customer',email:user.email||null,exp:Math.floor(Date.now()/1000)+60*60*24*7})));
  const data=`${header}.${payload}`; const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(env.JWT_SECRET),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const sig=await crypto.subtle.sign('HMAC',key,new TextEncoder().encode(data)); return `${data}.${b64url(sig)}`;
}
async function auth(req, env) {
  const token=(req.headers.get('authorization')||'').replace(/^Bearer\s+/i,''); if(!token) return null;
  try { const [h,p,s]=token.split('.'); const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(env.JWT_SECRET),{name:'HMAC',hash:'SHA-256'},false,['verify']);
    const valid=await crypto.subtle.verify('HMAC',key,fromB64url(s),new TextEncoder().encode(`${h}.${p}`)); if(!valid)return null;
    const payload=JSON.parse(new TextDecoder().decode(fromB64url(p))); if(payload.exp<Date.now()/1000)return null;
    const user=await env.DB.prepare('SELECT id,email,phone,full_name,role,status FROM users WHERE id=?').bind(payload.sub).first(); return user?.status==='active'?user:null;
  } catch { return null; }
}
async function hashPassword(password) {
  const salt=crypto.getRandomValues(new Uint8Array(16)); const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveBits']);
  const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:150000,hash:'SHA-256'},key,256);
  return `${b64url(salt)}.${b64url(bits)}`;
}
async function verifyPassword(password, stored) { try { const [s,h]=stored.split('.'); const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveBits']); const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt:fromB64url(s),iterations:150000,hash:'SHA-256'},key,256); const a=fromB64url(h),b=new Uint8Array(bits); return a.length===b.length && a.every((v,i)=>v===b[i]); } catch { return false; } }
async function body(req) { try { return await req.json(); } catch { return {}; } }
async function googleUser(credential, env) {
  if(!env.GOOGLE_CLIENT_ID) throw new Error('Google sign-in is not configured. Set GOOGLE_CLIENT_ID.');
  const r=await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(credential)}`); if(!r.ok) throw new Error('Google credential could not be verified');
  const g=await r.json(); if(g.aud!==env.GOOGLE_CLIENT_ID || g.email_verified!=='true') throw new Error('Google account verification failed');
  let user=await env.DB.prepare('SELECT * FROM users WHERE google_sub=? OR email=?').bind(g.sub,g.email).first();
  if(!user){ const id=uid('usr_'); await env.DB.prepare('INSERT INTO users(id,email,full_name,google_sub,role) VALUES(?,?,?,?,?)').bind(id,g.email,g.name||'',g.sub,'customer').run(); user=await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(id).first(); }
  return user;
}

function normalizeMpesaPhone(value) {
  let phone=String(value||'').replace(/[\s+()-]/g,'');
  if(phone.startsWith('0')) phone='254'+phone.slice(1);
  if(phone.startsWith('7')||phone.startsWith('1')) phone='254'+phone;
  if(!/^254[17]\d{8}$/.test(phone)) throw new Error('Enter a valid Kenyan M-PESA number, for example 2547XXXXXXXX');
  return phone;
}
function darajaTimestamp(d=new Date()) {
  const z=n=>String(n).padStart(2,'0');
  return d.getFullYear()+z(d.getMonth()+1)+z(d.getDate())+z(d.getHours())+z(d.getMinutes())+z(d.getSeconds());
}
async function darajaAccessToken(env) {
  const key=env.DARAJA_CONSUMER_KEY, secret=env.DARAJA_CONSUMER_SECRET;
  if(!key||!secret) throw new Error('Production Daraja Consumer Key and Consumer Secret are not configured as Worker secrets');
  const authHeader=btoa(`${key}:${secret}`);
  const response=await fetch('https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials',{headers:{Authorization:`Basic ${authHeader}`}});
  const payload=await response.json().catch(()=>({}));
  if(!response.ok||!payload.access_token) throw new Error('Safaricom Daraja could not issue an access token');
  return payload.access_token;
}
async function startDarajaStk(env,{phone,amount,accountReference,transactionDesc}) {
  const shortcode=String(env.DARAJA_SHORTCODE||'').trim(), passkey=env.DARAJA_PASSKEY, callbackUrl=env.DARAJA_CALLBACK_URL;
  if(!/^\d{5,7}$/.test(shortcode)||!passkey||!callbackUrl) throw new Error('Configure DARAJA_SHORTCODE, DARAJA_PASSKEY and DARAJA_CALLBACK_URL in Worker settings');
  if(!env.DARAJA_CALLBACK_TOKEN||!callbackUrl.includes(`/api/payments/mpesa/callback/${env.DARAJA_CALLBACK_TOKEN}`)) throw new Error('Callback URL must include the configured callback token path');
  const timestamp=darajaTimestamp(), password=btoa(`${shortcode}${passkey}${timestamp}`), token=await darajaAccessToken(env);
  const request={BusinessShortCode:shortcode,Password:password,Timestamp:timestamp,TransactionType:env.DARAJA_TRANSACTION_TYPE||'CustomerPayBillOnline',Amount:Math.round(amount),PartyA:phone,PartyB:shortcode,PhoneNumber:phone,CallBackURL:callbackUrl,AccountReference:String(accountReference||env.DARAJA_ACCOUNT_REFERENCE||'GODIA').slice(0,12),TransactionDesc:String(transactionDesc||'GODIA payment').slice(0,13)};
  const response=await fetch('https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest',{method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:JSON.stringify(request)});
  const payload=await response.json().catch(()=>({}));
  if(!response.ok||String(payload.ResponseCode)!=='0'||!payload.CheckoutRequestID) throw new Error(payload.errorMessage||payload.ResponseDescription||'Safaricom rejected the STK Push request');
  return payload;
}
async function startSubscriptionPayment(req,env) {
  const user=await auth(req,env); if(!user) return json({ok:false,message:'Sign in before paying for a GODIA plan'},401);
  const b=await body(req), plan=String(b.plan||'').trim().toUpperCase();
  const planEnv={BASIC:'GODIA_PLAN_BASIC_KES',PRO:'GODIA_PLAN_PRO_KES',PRIME:'GODIA_PLAN_PRIME_KES'}[plan];
  if(!planEnv) return json({ok:false,message:'Choose a valid plan: Basic, Pro or Prime'},400);
  const amount=Number(env[planEnv]);
  if(!Number.isSafeInteger(amount)||amount<1) return json({ok:false,message:`Set ${planEnv} to the approved subscription price in KES before accepting payments`},503);
  let phone; try { phone=normalizeMpesaPhone(b.phone||user.phone); } catch(e) { return json({ok:false,message:e.message},400); }
  const paymentId=uid('pay_');
  try {
    const payload=await startDarajaStk(env,{phone,amount,accountReference:`GODIA-${plan}`,transactionDesc:`${plan} plan`});
    await env.DB.prepare(`INSERT INTO payment_transactions(id,user_id,purpose,plan,phone,amount_kes,merchant_request_id,checkout_request_id,status,response_description) VALUES(?,?,?,?,?,?,?,?,?,?)`)
      .bind(paymentId,user.id,'GODIA_SUBSCRIPTION',plan,phone,amount,payload.MerchantRequestID,payload.CheckoutRequestID,'pending',payload.ResponseDescription||'STK Push sent').run();
    return json({ok:true,paymentId,checkoutRequestId:payload.CheckoutRequestID,merchantRequestId:payload.MerchantRequestID,amountKes:amount,status:'pending',message:payload.CustomerMessage||'M-PESA prompt sent. Enter your M-PESA PIN to complete payment.'},202);
  } catch(e) { return json({ok:false,message:e.message||'Could not start M-PESA payment'},502); }
}
async function handleDarajaCallback(req,env) {
  const expected=`/api/payments/mpesa/callback/${env.DARAJA_CALLBACK_TOKEN||'__not_configured__'}`;
  if(!env.DARAJA_CALLBACK_TOKEN||new URL(req.url).pathname!==expected) return json({ok:false},404);
  const b=await body(req), callback=b?.Body?.stkCallback;
  if(!callback?.CheckoutRequestID) return json({ResultCode:0,ResultDesc:'Callback received'});
  const payment=await env.DB.prepare('SELECT * FROM payment_transactions WHERE checkout_request_id=?').bind(callback.CheckoutRequestID).first();
  if(!payment) return json({ResultCode:0,ResultDesc:'Unknown checkout request'});
  if(payment.status==='paid'||payment.status==='failed') return json({ResultCode:0,ResultDesc:'Callback already processed'});
  const resultCode=Number(callback.ResultCode), metadata=callback.CallbackMetadata?.Item||[];
  const getMeta=name=>metadata.find(x=>x.Name===name)?.Value??null;
  const receipt=getMeta('MpesaReceiptNumber'), paidAmount=Number(getMeta('Amount')||0), paidPhone=getMeta('PhoneNumber');
  if(resultCode===0 && paidAmount===Number(payment.amount_kes) && String(paidPhone||'')===String(payment.phone)) {
    await env.DB.prepare(`UPDATE payment_transactions SET status='paid',result_code=?,result_description=?,mpesa_receipt=?,callback_json=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`)
      .bind(resultCode,String(callback.ResultDesc||'Success'),receipt,JSON.stringify(b),payment.id).run();
    if(payment.purpose==='GODIA_SUBSCRIPTION') {
      const days=Math.max(1,Math.min(365,Number(env.GODIA_SUBSCRIPTION_DAYS||30)));
      await env.DB.prepare(`UPDATE users SET subscription_plan=?,subscription_status='active',subscription_expires_at=datetime(CASE WHEN subscription_status='active' AND subscription_expires_at>CURRENT_TIMESTAMP THEN subscription_expires_at ELSE CURRENT_TIMESTAMP END, '+' || ? || ' days'),updated_at=CURRENT_TIMESTAMP WHERE id=?`)
        .bind(payment.plan,days,payment.user_id).run();
    }
  } else {
    const status=resultCode===0?'review':'failed';
    await env.DB.prepare(`UPDATE payment_transactions SET status=?,result_code=?,result_description=?,callback_json=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`)
      .bind(status,resultCode,String(callback.ResultDesc||'Payment result did not match expected amount/phone'),JSON.stringify(b),payment.id).run();
  }
  return json({ResultCode:0,ResultDesc:'Callback processed'});
}

async function handle(req, env) {
  const url=new URL(req.url), path=url.pathname, method=req.method;
  if(path.startsWith('/api/payments/mpesa/callback/') && method==='POST') return handleDarajaCallback(req,env);
  if(path==='/api/subscriptions/stk-push' && method==='POST') return startSubscriptionPayment(req,env);
  if(path==='/api/payments/mpesa/status' && method==='GET') { const user=await auth(req,env); if(!user)return json({ok:false,message:'Authentication required'},401); const id=url.searchParams.get('paymentId'); if(!id)return json({ok:false,message:'paymentId is required'},400); const p=await env.DB.prepare('SELECT id,purpose,plan,amount_kes,status,mpesa_receipt,created_at,updated_at FROM payment_transactions WHERE id=? AND user_id=?').bind(id,user.id).first(); return p?json({ok:true,payment:p}):json({ok:false,message:'Payment not found'},404); }
  if(path==='/api/health' && method==='GET') return json({ok:true,service:'GODIA PRIME CONNECT API',time:nowIso(),database:'bound'});
  if(path==='/api/products' && method==='GET') { const q=(url.searchParams.get('q')||'').trim(); const rows=q?await env.DB.prepare("SELECT id,name,description,category,sku,image_url,unit,price_minor,discount_percent,stock_quantity,supplier_id,updated_at FROM products WHERE is_active=1 AND name LIKE ? ORDER BY updated_at DESC LIMIT 100").bind(`%${q}%`).all():await env.DB.prepare('SELECT id,name,description,category,sku,image_url,unit,price_minor,discount_percent,stock_quantity,supplier_id,updated_at FROM products WHERE is_active=1 ORDER BY updated_at DESC LIMIT 100').all(); return json({ok:true,products:rows.results||[]}); }
  if(path==='/api/auth/register' && method==='POST') { const b=await body(req); const email=(b.email||'').trim().toLowerCase()||null, phone=(b.phone||'').trim()||null, password=String(b.password||''); if(!email&&!phone)return json({ok:false,message:'Email or phone is required'},400); if(password.length<8)return json({ok:false,message:'Password must be at least 8 characters'},400); const id=uid('usr_'); try { const hash=await hashPassword(password); await env.DB.prepare('INSERT INTO users(id,email,phone,full_name,role,password_hash) VALUES(?,?,?,?,?,?)').bind(id,email,phone,b.fullName||b.name||'',b.role==='supplier'?'supplier':'customer',hash).run(); const user=await env.DB.prepare('SELECT id,email,phone,full_name,role FROM users WHERE id=?').bind(id).first(); return json({ok:true,token:await signToken(user,env),user}); } catch(e) { return json({ok:false,message:'An account with that email or phone may already exist'},409); } }
  if(path==='/api/auth/login' && method==='POST') { const b=await body(req), id=(b.identifier||'').trim().toLowerCase(), secret=String(b.secret||''); const user=await env.DB.prepare('SELECT * FROM users WHERE lower(email)=? OR phone=?').bind(id,id).first(); if(!user?.password_hash || !(await verifyPassword(secret,user.password_hash)))return json({ok:false,message:'Invalid login details'},401); const safe={id:user.id,email:user.email,phone:user.phone,full_name:user.full_name,role:user.role}; return json({ok:true,token:await signToken(safe,env),user:safe}); }
  if(path==='/api/auth/google' && method==='POST') { const b=await body(req); if(!b.credential)return json({ok:false,message:'Google credential is required'},400); try { const user=await googleUser(b.credential,env); return json({ok:true,token:await signToken(user,env),user:{id:user.id,email:user.email,full_name:user.full_name,role:user.role}}); } catch(e) { return json({ok:false,message:e.message},401); } }
  if(['/api/auth/request-otp','/api/auth/verify-otp','/api/auth/forgot-pin'].includes(path) && method==='POST') return json({ok:false,message:'OTP delivery and recovery are not enabled yet. Configure an SMS/email provider before using this endpoint.'},501);
  if(path==='/api/orders' && method==='POST') { const user=await auth(req,env); if(!user)return json({ok:false,message:'Authentication required'},401); const b=await body(req), items=Array.isArray(b.items)?b.items:[]; if(!items.length)return json({ok:false,message:'Order must contain at least one item'},400); const orderId=uid('ord_'), clientId=b.clientOrderId||null; let total=0; const normalized=[]; for(const item of items){ const qty=Number(item.quantity); if(!Number.isFinite(qty)||qty<=0)return json({ok:false,message:'Invalid item quantity'},400); const product=await env.DB.prepare('SELECT id,name,supplier_id,price_minor,discount_percent,stock_quantity,is_active FROM products WHERE id=?').bind(String(item.productId||'')).first(); if(!product||!product.is_active)return json({ok:false,message:`Product unavailable: ${item.productName||item.productId}`},409); if(qty>Number(product.stock_quantity))return json({ok:false,message:`Insufficient stock for ${product.name}`},409); const unit=Math.max(0,Number(product.price_minor||0)); const line=Math.round(unit*qty*(1-Number(product.discount_percent||0)/100)); total+=line; normalized.push({id:uid('itm_'),product,qty,unit,line,variant:item.variant||null}); }
    try { await env.DB.prepare('INSERT INTO orders(id,user_id,customer_name,customer_phone,status,payment_status,total_minor,client_order_id,source) VALUES(?,?,?,?,?,?,?,?,?)').bind(orderId,user.id,user.full_name,user.phone,'pending','not_paid',total,clientId,'online-or-synced').run(); for(const x of normalized){ await env.DB.prepare('INSERT INTO order_items(id,order_id,product_id,supplier_id,product_name,variant,quantity,unit_price_minor,discount_percent,line_total_minor) VALUES(?,?,?,?,?,?,?,?,?,?)').bind(x.id,orderId,x.product.id,x.product.supplier_id,x.product.name,x.variant,x.qty,x.unit,x.product.discount_percent||0,x.line).run(); } await env.DB.prepare('INSERT INTO order_events(id,order_id,actor_user_id,event_type,note) VALUES(?,?,?,?,?)').bind(uid('evt_'),orderId,user.id,'order_submitted','Order request received; payment not taken').run(); return json({ok:true,orderId,status:'pending',paymentStatus:'not_paid',totalMinor:total,currency:'KES'} ,201); } catch(e) { if(clientId){ const existing=await env.DB.prepare('SELECT id,status,payment_status,total_minor FROM orders WHERE client_order_id=?').bind(clientId).first(); if(existing)return json({ok:true,orderId:existing.id,status:existing.status,paymentStatus:existing.payment_status,totalMinor:existing.total_minor,duplicate:true}); } throw e; } }
  if(path==='/api/orders' && method==='GET') { const user=await auth(req,env); if(!user)return json({ok:false,message:'Authentication required'},401); const rows=await env.DB.prepare('SELECT id,status,payment_status,total_minor,currency,created_at FROM orders WHERE user_id=? ORDER BY created_at DESC LIMIT 100').bind(user.id).all(); return json({ok:true,orders:rows.results||[]}); }
  if(path==='/api/sync' && method==='POST') { const user=await auth(req,env); if(!user)return json({ok:false,message:'Authentication required'},401); const b=await body(req), deviceId=String(b.deviceId||'').slice(0,100), mutations=Array.isArray(b.mutations)?b.mutations:[]; if(!deviceId)return json({ok:false,message:'deviceId is required'},400); if(mutations.length>100)return json({ok:false,message:'Maximum 100 mutations per sync batch'},400); const results=[]; for(const m of mutations){ const id=String(m.id||uid('mut_')); try { await env.DB.prepare('INSERT OR IGNORE INTO sync_mutations(id,user_id,device_id,mutation_type,entity_id,payload_json,status) VALUES(?,?,?,?,?,?,?)').bind(id,user.id,deviceId,String(m.type||'unknown'),String(m.entityId||id),JSON.stringify(m.payload||{}),'accepted').run(); results.push({id,status:'accepted'}); } catch { results.push({id,status:'rejected'}); } } await env.DB.prepare('INSERT INTO device_sync_state(user_id,device_id,last_synced_at,last_seen_at) VALUES(?,?,?,?) ON CONFLICT(user_id,device_id) DO UPDATE SET last_synced_at=excluded.last_synced_at,last_seen_at=excluded.last_seen_at').bind(user.id,deviceId,nowIso(),nowIso()).run(); return json({ok:true,received:results.length,results,syncedAt:nowIso(),note:'Mutation envelopes are recorded. Business-specific replay handlers must be enabled before queued mutations are applied.'}); }
  if(path==='/api/me' && method==='GET') { const user=await auth(req,env); return user?json({ok:true,user}):json({ok:false,message:'Authentication required'},401); }
  return json({ok:false,message:'Not found'},404);
}
export default { 
  async fetch(request, env, ctx) { 
    try { 
      const url = new URL(request.url);
      if (url.pathname.startsWith('/api/')) return await handle(request, env);
      const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GODIA PRIME</title><style>body{font-family:sans-serif;background:#0f172a;color:#fff;text-align:center;padding:20px}h1{color:#facc15}.card{background:#fff;color:#111;border-radius:16px;padding:20px;max-width:520px;margin:20px auto}.btn{display:block;background:#22c55e;color:#fff;padding:14px;border-radius:10px;text-decoration:none;font-weight:bold;margin-top:12px}.btn2{background:#2563eb}</style></head><body><h1>GODIA PRIME</h1><p>Connect Solution - Kisii, Kenya</p><p>✅ API + M-PESA + D1 Connected</p><div class="card"><h2>Karibu GODIA Prime</h2><p>Marketplace • POS • Supply Chain</p><a class="btn" href="https://wa.me/254700000000">WhatsApp Sasa</a><a class="btn btn2" href="/api/health">Test API Health</a></div><p>© 2026 GODIA Prime</p></body></html>`;
      return new Response(html, { headers: { "Content-Type": "text/html" } });
    } catch(e) { 
      return json({ok:false,message:'Internal server error'},500); 
    } 
  } 
};
