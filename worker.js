const COOKIE = "ghh_session";
const ADMIN_COOKIE = "ghh_admin";
const SESSION_DAYS = 7;
const ROOM_TERM_DAYS = 30;
const REFERRAL_LEVELS = [25, 2, 1];
const WITHDRAWAL_TAX_PERCENT = 15;
const DAILY_CHECKIN_BONUS = 400;

const json = (data, status=200, extra={}) => Response.json(data, { status, headers: { "Cache-Control": "no-store", ...extra } });

function b64(bytes) { return btoa(String.fromCharCode(...new Uint8Array(bytes))); }
function unb64(s) { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
async function digest(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return b64(buf);
}
async function passwordHash(password, salt) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name:"PBKDF2", salt:unb64(salt), iterations:120000, hash:"SHA-256" }, key, 256);
  return b64(bits);
}
async function makePasswordRecord(password) {
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const salt = b64(saltBytes);
  return { salt, hash: await passwordHash(password, salt) };
}
async function verifyPassword(password, hash, salt) {
  return (await passwordHash(password, salt)) === hash;
}
function cookie(request, name) {
  const raw = request.headers.get("Cookie") || "";
  for (const part of raw.split(";")) {
    const [k,...rest] = part.trim().split("=");
    if (k === name) return rest.join("=");
  }
  return null;
}
function setCookie(name, value, maxAge) {
  return name + "=" + encodeURIComponent(value) + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=" + maxAge;
}
function clearCookie(name) { return setCookie(name, "", 0); }
async function body(request) { try { return await request.json(); } catch { return {}; } }
function now() { return Date.now(); }
function eatDateKey(ms=Date.now()) {
  return new Date(ms + 3 * 60 * 60 * 1000).toISOString().slice(0,10);
}
function dateKey() { return eatDateKey(); }

function normalizePhone(value) {
  let p=String(value||"").trim().replace(/[\s-]/g,"");
  if (p.startsWith("00")) p="+"+p.slice(2);
  if (p.startsWith("0")) p="+256"+p.slice(1);
  if (/^256\d{9}$/.test(p)) p="+"+p;
  return p;
}

function marzConfigured(env) {
  return !!(env.MARZPAY_API_KEY && env.MARZPAY_API_SECRET);
}

function marzAuthorization(env) {
  return "Basic " + btoa(String(env.MARZPAY_API_KEY)+":"+String(env.MARZPAY_API_SECRET));
}

async function marzRequest(env, endpoint, payload) {
  if (!marzConfigured(env)) throw new Error("MarzPay is not configured. Set MARZPAY_API_KEY and MARZPAY_API_SECRET.");
  const response=await fetch("https://wallet.wearemarz.com/api/v1"+endpoint,{
    method:"POST",
    headers:{
      "Authorization":marzAuthorization(env),
      "Content-Type":"application/json",
      "Accept":"application/json"
    },
    body:JSON.stringify(payload)
  });
  const data=await response.json().catch(()=>({}));
  if (!response.ok || data?.status==="error") {
    throw new Error(data?.message || "MarzPay request failed.");
  }
  return data;
}

async function verifyMarzSignature(request, env, rawBody) {
  const secret=env.MARZPAY_WEBHOOK_SECRET;
  if (!secret) return true;
  const timestamp=request.headers.get("X-MarzPay-Timestamp")||"";
  const header=request.headers.get("X-MarzPay-Signature")||"";
  const match=header.match(/(?:^|,)v1=([a-f0-9]+)/i);
  if (!timestamp || !match) return false;
  const expectedBytes=await crypto.subtle.sign(
    "HMAC",
    await crypto.subtle.importKey("raw",new TextEncoder().encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]),
    new TextEncoder().encode(timestamp+"."+rawBody)
  );
  const expected=[...new Uint8Array(expectedBytes)].map(b=>b.toString(16).padStart(2,"0")).join("");
  const received=match[1].toLowerCase();
  if (expected.length!==received.length) return false;
  let diff=0;
  for(let i=0;i<expected.length;i++) diff |= expected.charCodeAt(i)^received.charCodeAt(i);
  return diff===0;
}

async function marzWebhook(request,env) {
  const raw=await request.text();
  if (!(await verifyMarzSignature(request,env,raw))) return json({error:"Invalid MarzPay signature."},401);
  let payload;
  try { payload=JSON.parse(raw); } catch { return json({error:"Invalid webhook payload."},400); }
  const event=String(payload?.event_type||"").toLowerCase();
  const reference=String(payload?.transaction?.reference||"");
  if (!reference) return json({ok:true});
  const tx=await env.DB.prepare("SELECT * FROM transactions WHERE reference=? LIMIT 1").bind(reference).first();
  if (!tx) return json({ok:true});
  const status=String(payload?.transaction?.status||"").toLowerCase();
  const finalSuccess=event.endsWith(".completed") || status==="completed" || status==="successful";
  const finalFailure=event.endsWith(".failed") || event.endsWith(".cancelled") || ["failed","cancelled"].includes(status);
  const providerUuid=payload?.transaction?.uuid||null;
  const providerReference=payload?.transaction?.provider_reference||payload?.collection?.provider_transaction_id||payload?.disbursement?.provider_transaction_id||null;
  await env.DB.prepare("INSERT INTO marzpay_transactions (local_transaction_id,provider_uuid,provider_reference,direction,phone,updated_at) VALUES (?,?,?,?,?,?) ON CONFLICT(local_transaction_id) DO UPDATE SET provider_uuid=excluded.provider_uuid,provider_reference=excluded.provider_reference,updated_at=excluded.updated_at")
    .bind(tx.id,providerUuid,providerReference,tx.type==="deposit"?"collection":"disbursement",normalizePhone(payload?.transaction?.phone_number||payload?.collection?.phone_number||payload?.disbursement?.phone_number||""),now()).run();

  if (tx.type==="deposit" && tx.status==="pending" && finalSuccess) {
    const chain=await referralChain(env,tx.user_id);
    const ts=now();
    const statements=[
      env.DB.prepare("UPDATE transactions SET status='completed' WHERE id=? AND status='pending'").bind(tx.id),
      env.DB.prepare("UPDATE users SET balance=balance+? WHERE id=?").bind(tx.amount,tx.user_id),
      env.DB.prepare("INSERT INTO deposit_funds (user_id,available_amount,updated_at) VALUES (?,?,?) ON CONFLICT(user_id) DO UPDATE SET available_amount=available_amount+excluded.available_amount,updated_at=excluded.updated_at").bind(tx.user_id,tx.amount,ts)
    ];
    for(const item of chain){
      const rate=REFERRAL_LEVELS[item.level-1], bonus=Math.floor(Number(tx.amount)*rate/100);
      if(bonus>0) statements.push(
        env.DB.prepare("UPDATE users SET balance=balance+?,total_earnings=total_earnings+? WHERE id=?").bind(bonus,bonus,item.userId),
        env.DB.prepare("INSERT OR IGNORE INTO referral_rewards (deposit_transaction_id,beneficiary_id,source_user_id,level,rate_percent,bonus_amount,created_at) VALUES (?,?,?,?,?,?,?)").bind(tx.id,item.userId,tx.user_id,item.level,rate,bonus,ts)
      );
    }
    await env.DB.batch(statements);
  } else if (tx.type==="deposit" && tx.status==="pending" && finalFailure) {
    await env.DB.prepare("UPDATE transactions SET status='failed' WHERE id=? AND status='pending'").bind(tx.id).run();
  } else if (tx.type==="withdrawal" && tx.status==="processing" && finalSuccess) {
    await env.DB.prepare("UPDATE transactions SET status='completed' WHERE id=? AND status='processing'").bind(tx.id).run();
  } else if (tx.type==="withdrawal" && tx.status==="processing" && finalFailure) {
    await env.DB.batch([
      env.DB.prepare("UPDATE transactions SET status='failed' WHERE id=? AND status='processing'").bind(tx.id),
      env.DB.prepare("UPDATE users SET balance=balance+? WHERE id=?").bind(tx.amount,tx.user_id)
    ]);
  }
  return json({ok:true});
}

function refCode() { return "GHH-" + crypto.randomUUID().replaceAll("-", "").slice(0,8).toUpperCase(); }

async function createSession(env, userId, admin=false) {
  const token = crypto.randomUUID() + crypto.randomUUID();
  const tokenHash = await digest(token);
  const expires = now() + SESSION_DAYS * 86400000;
  if (admin) {
    const id = crypto.randomUUID();
    await env.DB.prepare("INSERT INTO admin_sessions (id,admin_id,token_hash,expires_at) VALUES (?,?,?,?)")
      .bind(id, "owner", tokenHash, new Date(expires).toISOString()).run();
  } else {
    await env.DB.prepare("INSERT INTO sessions (user_id,token_hash,expires_at,created_at) VALUES (?,?,?,?)")
      .bind(userId, tokenHash, expires, now()).run();
  }
  return token;
}

async function currentUser(request, env) {
  const token = cookie(request, COOKIE);
  if (!token) return null;
  const hash = await digest(token);
  const row = await env.DB.prepare("SELECT u.id,u.login,u.referral_code,u.balance,u.total_earnings FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?").bind(hash, now()).first();
  return row || null;
}

async function requireAdmin(request, env) {
  const token = cookie(request, ADMIN_COOKIE);
  if (!token) return false;
  const hash = await digest(token);
  const row = await env.DB.prepare("SELECT id FROM admin_sessions WHERE token_hash=? AND expires_at>?").bind(hash, new Date().toISOString()).first();
  return !!row;
}

async function adminConfigured(env) {
  return !!env.ADMIN_PASSWORD;
}

async function ensureRulesTables(env) {
  await env.DB.batch([
    env.DB.prepare("CREATE TABLE IF NOT EXISTS deposit_funds (user_id INTEGER PRIMARY KEY, available_amount INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS referral_rewards (id INTEGER PRIMARY KEY AUTOINCREMENT, deposit_transaction_id INTEGER NOT NULL, beneficiary_id INTEGER NOT NULL, source_user_id INTEGER NOT NULL, level INTEGER NOT NULL, rate_percent INTEGER NOT NULL, bonus_amount INTEGER NOT NULL, created_at INTEGER NOT NULL, UNIQUE(deposit_transaction_id,beneficiary_id,level))"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS product_earnings (id INTEGER PRIMARY KEY AUTOINCREMENT, investment_id INTEGER NOT NULL, user_id INTEGER NOT NULL, earning_date TEXT NOT NULL, amount INTEGER NOT NULL, created_at INTEGER NOT NULL, UNIQUE(investment_id,earning_date))"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS withdrawal_details (transaction_id INTEGER PRIMARY KEY, tax_percent INTEGER NOT NULL, tax_amount INTEGER NOT NULL, net_amount INTEGER NOT NULL)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS marzpay_transactions (local_transaction_id INTEGER PRIMARY KEY, provider_uuid TEXT, provider_reference TEXT, direction TEXT NOT NULL, phone TEXT NOT NULL, updated_at INTEGER NOT NULL)"),
    env.DB.prepare("INSERT OR IGNORE INTO deposit_funds (user_id,available_amount,updated_at) SELECT u.id, MAX(0, COALESCE((SELECT SUM(t.amount) FROM transactions t WHERE t.user_id=u.id AND t.type='deposit' AND t.status='completed'),0)-COALESCE((SELECT SUM(t2.amount) FROM transactions t2 WHERE t2.user_id=u.id AND t2.type='room_purchase' AND t2.status='completed'),0)), ? FROM users u").bind(now())
  ]);
}

async function referralChain(env, userId) {
  const chain = [];
  let current = userId;
  for (let level=0; level<3; level++) {
    const row = await env.DB.prepare("SELECT referrer_id FROM referrals WHERE referred_user_id=? ORDER BY id ASC LIMIT 1").bind(current).first();
    if (!row) break;
    chain.push({ userId: row.referrer_id, level: level + 1 });
    current = row.referrer_id;
  }
  return chain;
}

async function creditDailyEarnings(env, targetDate=eatDateKey()) {
  await ensureRulesTables(env);
  const nowTs = now();
  const investments = await env.DB.prepare("SELECT id,user_id,daily_return,started_at,status FROM investments WHERE status='active' AND started_at < ? AND started_at >= ?")
    .bind(nowTs, nowTs - ROOM_TERM_DAYS * 86400000).all();
  for (const inv of investments.results || []) {
    const startDate = eatDateKey(inv.started_at);
    if (startDate >= targetDate) continue;
    const exists = await env.DB.prepare("SELECT id FROM product_earnings WHERE investment_id=? AND earning_date=?").bind(inv.id,targetDate).first();
    if (exists) continue;
    const statements = [
      env.DB.prepare("INSERT INTO product_earnings (investment_id,user_id,earning_date,amount,created_at) VALUES (?,?,?,?,?)").bind(inv.id,inv.user_id,targetDate,inv.daily_return,nowTs),
      env.DB.prepare("UPDATE users SET balance=balance+?,total_earnings=total_earnings+? WHERE id=?").bind(inv.daily_return,inv.daily_return,inv.user_id),
      env.DB.prepare("INSERT INTO transactions (user_id,type,amount,status,reference,created_at) VALUES (?, 'earning', ?, 'completed', ?, ?)").bind(inv.user_id,inv.daily_return,"EARN-"+inv.id+"-"+targetDate,nowTs)
    ];
    await env.DB.batch(statements);
  }
}

async function ensureSettings(env) {
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)").run();
  await env.DB.prepare("INSERT OR IGNORE INTO app_settings (key,value) VALUES ('withdrawals_open','1')").run();
}

async function withdrawalsOpen(env) {
  await ensureSettings(env);
  const row = await env.DB.prepare("SELECT value FROM app_settings WHERE key='withdrawals_open'").first();
  return row?.value !== "0";
}

async function ensureAdmin(env) {
  const existing = await env.DB.prepare("SELECT id FROM admin_users WHERE id='owner'").first();
  if (!existing) {
    const rec = await makePasswordRecord(env.ADMIN_PASSWORD);
    await env.DB.prepare("INSERT INTO admin_users (id,phone,password_hash,password_salt,status) VALUES ('owner',?,?,?,'active')")
      .bind(env.ADMIN_EMAIL || "owner", rec.hash, rec.salt).run();
  }
}

function normalizeAuthPhone(value) {
  let p=String(value||"").trim().replace(/[\s().-]/g,"");
  if(p.startsWith("00")) p="+"+p.slice(2);
  if(p.startsWith("0")) p="+256"+p.slice(1);
  if(p.startsWith("256")) p="+"+p;
  return p;
}

function isValidAuthPhone(value) {
  return /^\+2567\d{8}$/.test(value);
}

async function register(request, env) {
  try {
    let stage="request";
    const { phone, password, referralCode } = await body(request);
    stage="validate";
    const normalized = normalizeAuthPhone(phone);
    if (!isValidAuthPhone(normalized) || !password || password.length < 8) return json({error:"Use a valid Ugandan telephone number and a password of at least 8 characters."},400);
    const exists = await env.DB.prepare("SELECT id FROM users WHERE login=?").bind(normalized).first();
    if (exists) return json({error:"An account with that telephone number already exists."},409);
    let referrer = null;
    if (referralCode) referrer = await env.DB.prepare("SELECT id FROM users WHERE referral_code=?").bind(String(referralCode).trim().toUpperCase()).first();
    stage="password";
    const rec = await makePasswordRecord(password);
    const code = refCode();
    const created = now();
    stage="insert";
    await env.DB.prepare("INSERT INTO users (login,password_hash,password_salt,referral_code,created_at) VALUES (?,?,?,?,?)")
      .bind(normalized,rec.hash,rec.salt,code,created).run();
    const createdUser = await env.DB.prepare("SELECT id,login,referral_code FROM users WHERE login=? LIMIT 1").bind(normalized).first();
    if (!createdUser) throw new Error("Registration could not create the customer record.");
    const userId = createdUser.id;
    stage="referral";
    if (referrer) {
      await env.DB.prepare("INSERT INTO referrals (referrer_id,referred_user_id,rate_percent,created_at) VALUES (?,?,?,?)")
        .bind(referrer.id,userId,25,created).run();
    }
    stage="welcome";
    await grantWelcomeBonus(env,userId);
    stage="session";
    const token = await createSession(env,userId);
    return json({ok:true,user:{id:userId,login:normalized,referralCode:createdUser.referral_code,balance:5000,totalEarnings:5000},welcomeBonus:5000},200,{"Set-Cookie":setCookie(COOKIE,token,SESSION_DAYS*86400)});
  } catch (e) {
    console.error("Registration error", e?.message || e);
    return json({error:"Registration failed at "+stage+". Please try again."},500);
  }
}
async function grantWelcomeBonus(env, userId) {
  const existing = await env.DB.prepare("SELECT id FROM transactions WHERE user_id=? AND type='earning' AND reference=? LIMIT 1")
    .bind(userId, "WELCOME-"+userId).first();
  if (existing) return false;
  const bonus = 5000;
  const ts = now();
  await env.DB.batch([
    env.DB.prepare("UPDATE users SET balance=balance+?,total_earnings=total_earnings+? WHERE id=?").bind(bonus,bonus,userId),
    env.DB.prepare("INSERT INTO transactions (user_id,type,amount,status,reference,created_at) VALUES (?, 'earning', ?, 'completed', ?, ?)").bind(userId,bonus,"WELCOME-"+userId,ts)
  ]);
  return true;
}

async function login(request, env) {
  const { phone, password } = await body(request);
  const normalized = normalizeAuthPhone(phone);
  if (!isValidAuthPhone(normalized)) return json({error:"Enter a valid Ugandan telephone number."},400);
  const row = await env.DB.prepare("SELECT * FROM users WHERE login=?").bind(normalized).first();
  if (!row || !(await verifyPassword(String(password||""),row.password_hash,row.password_salt))) return json({error:"Invalid login details."},401);
  await grantWelcomeBonus(env,row.id);
  const fresh = await env.DB.prepare("SELECT id,login,referral_code,balance,total_earnings FROM users WHERE id=?").bind(row.id).first();
  const token = await createSession(env,row.id);
  return json({ok:true,user:{id:fresh.id,login:fresh.login,referralCode:fresh.referral_code,balance:fresh.balance,totalEarnings:fresh.total_earnings},welcomeBonus:5000},200,{"Set-Cookie":setCookie(COOKIE,token,SESSION_DAYS*86400)});
}

async function logout(request, env) {
  const token=cookie(request,COOKIE);
  if(token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await digest(token)).run();
  return json({ok:true},200,{"Set-Cookie":clearCookie(COOKIE)});
}

async function checkin(request, env) {
  const user=await currentUser(request,env); if(!user) return json({error:"Please sign in."},401);
  const d=dateKey();
  try {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO daily_checkins (user_id,checkin_date,bonus_amount,created_at) VALUES (?,?,?,?)").bind(user.id,d,DAILY_CHECKIN_BONUS,now()),
      env.DB.prepare("UPDATE users SET balance=balance+?,total_earnings=total_earnings+? WHERE id=?").bind(DAILY_CHECKIN_BONUS,DAILY_CHECKIN_BONUS,user.id),
      env.DB.prepare("INSERT INTO transactions (user_id,type,amount,status,reference,created_at) VALUES (?, 'earning', ?, 'completed', ?, ?)").bind(user.id,DAILY_CHECKIN_BONUS,"CHECKIN-"+user.id+"-"+d,now())
    ]);
  } catch { return json({error:"Daily check-in has already been claimed today."},409); }
  return json({ok:true,bonus:DAILY_CHECKIN_BONUS});
}

async function deposit(request, env) {
  const user=await currentUser(request,env); if(!user) return json({error:"Please sign in."},401);
  await ensureRulesTables(env);
  if(!marzConfigured(env)) return json({error:"Payments are not configured yet. Add the MarzPay API secrets in Cloudflare."},503);
  const {amount,method,phone}=await body(request); const value=Math.floor(Number(amount));
  if(!Number.isFinite(value)||value<20000) return json({error:"Minimum deposit is UGX 20,000."},400);
  if(!["MTN Mobile Money","Airtel Money"].includes(method)) return json({error:"Choose MTN Mobile Money or Airtel Money."},400);
  const normalizedPhone=normalizePhone(phone);
  if(!/^\+256\d{9}$/.test(normalizedPhone)) return json({error:"Enter a valid Uganda mobile-money number."},400);
  const reference=crypto.randomUUID();
  const created=now();
  const result=await env.DB.prepare("INSERT INTO transactions (user_id,type,amount,method,status,reference,created_at) VALUES (?, 'deposit', ?, ?, 'pending', ?, ?)")
    .bind(user.id,value,method,reference,created).run();
  try {
    const data=await marzRequest(env,"/collect-money",{
      amount:value,phone_number:normalizedPhone,country:"UG",reference,
      description:"Grand Horizon Hotels deposit",
      callback_url:new URL("/api/marzpay/webhook",request.url).toString(),
      metadata:[{orderId:"GHH-"+result.meta.last_row_id}]
    });
    const providerUuid=data?.data?.transaction?.uuid||null;
    const providerReference=data?.data?.transaction?.provider_reference||null;
    await env.DB.prepare("INSERT INTO marzpay_transactions (local_transaction_id,provider_uuid,provider_reference,direction,phone,updated_at) VALUES (?,?,?,?,?,?)")
      .bind(result.meta.last_row_id,providerUuid,providerReference,"collection",normalizedPhone,now()).run();
    return json({ok:true,status:"processing",reference,providerUuid,message:"Payment request sent. Approve the mobile-money prompt on your phone."});
  } catch(e) {
    await env.DB.prepare("UPDATE transactions SET status='failed' WHERE id=? AND status='pending'").bind(result.meta.last_row_id).run();
    return json({error:e.message||"Unable to start the payment."},502);
  }
}

async function withdrawal(request, env) {
  const user=await currentUser(request,env); if(!user) return json({error:"Please sign in."},401);
  await ensureRulesTables(env);
  if(!await withdrawalsOpen(env)) return json({error:"Withdrawals are currently closed by the administrator."},503);
  if(!marzConfigured(env)) return json({error:"Payments are not configured yet. Add the MarzPay API secrets in Cloudflare."},503);
  const {amount,method,phone}=await body(request); const value=Math.floor(Number(amount));
  if(!Number.isFinite(value)||value<5000) return json({error:"Minimum withdrawal is UGX 5,000."},400);
  if(!["MTN Mobile Money","Airtel Money"].includes(method)) return json({error:"Choose MTN Mobile Money or Airtel Money."},400);
  const normalizedPhone=normalizePhone(phone);
  if(!/^\+256\d{9}$/.test(normalizedPhone)) return json({error:"Enter a valid Uganda mobile-money number."},400);
  const fresh=await env.DB.prepare("SELECT balance FROM users WHERE id=?").bind(user.id).first();
  const eligibility=await env.DB.prepare("SELECT (SELECT COUNT(*) FROM transactions WHERE user_id=? AND type='deposit' AND status='completed') deposit_count,(SELECT COUNT(*) FROM investments WHERE user_id=? AND status='active' AND started_at >= ?) active_rooms")
    .bind(user.id,user.id,now()-ROOM_TERM_DAYS*86400000).first();
  if(Number(eligibility.deposit_count)<1 || Number(eligibility.active_rooms)<1) return json({error:"Withdrawals require at least one successful deposit and an active purchased product."},403);
  if(Number(fresh.balance)<value) return json({error:"Insufficient balance."},400);
  const tax=Math.floor(value*WITHDRAWAL_TAX_PERCENT/100);
  const net=value-tax;
  const reference="WDR-"+crypto.randomUUID().replaceAll("-","").slice(0,18).toUpperCase();
  const ts=now();
  const result=await env.DB.prepare("INSERT INTO transactions (user_id,type,amount,method,status,reference,created_at) VALUES (?, 'withdrawal', ?, ?, 'pending', ?, ?)")
    .bind(user.id,value,method,reference,ts).run();
  try {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO withdrawal_details (transaction_id,tax_percent,tax_amount,net_amount) VALUES (?,?,?,?)").bind(result.meta.last_row_id,WITHDRAWAL_TAX_PERCENT,tax,net),
      env.DB.prepare("INSERT INTO marzpay_transactions (local_transaction_id,provider_uuid,provider_reference,direction,phone,updated_at) VALUES (?,?,?,?,?,?)").bind(result.meta.last_row_id,null,null,"disbursement",normalizedPhone,ts),
      env.DB.prepare("UPDATE users SET balance=balance-? WHERE id=? AND balance>=?").bind(value,user.id,value)
    ]);
    const after=await env.DB.prepare("SELECT balance FROM users WHERE id=?").bind(user.id).first();
    if(Number(after.balance)<0) throw new Error("Unable to reserve withdrawal balance.");
  } catch(e) {
    await env.DB.prepare("DELETE FROM withdrawal_details WHERE transaction_id=?").bind(result.meta.last_row_id).run();
    await env.DB.prepare("DELETE FROM marzpay_transactions WHERE local_transaction_id=?").bind(result.meta.last_row_id).run();
    await env.DB.prepare("DELETE FROM transactions WHERE id=? AND status='pending'").bind(result.meta.last_row_id).run();
    return json({error:e.message||"Unable to create withdrawal."},409);
  }
  return json({ok:true,status:"pending",reference,grossAmount:value,taxAmount:tax,taxPercent:WITHDRAWAL_TAX_PERCENT,netAmount:net,message:"Withdrawal request created. It will be paid after administrator approval."});
}

async function rent(request, env) {
  const user=await currentUser(request,env); if(!user) return json({error:"Please sign in."},401);
  await ensureRulesTables(env);
  const {packageId}=await body(request);
  const room=await env.DB.prepare("SELECT id,price_ugx,daily_figure_ugx FROM rooms WHERE id=? AND enabled=1").bind(Number(packageId)).first();
  if(!room) return json({error:"Room package is not available."},400);
  const p=Number(room.price_ugx), daily=Number(room.daily_figure_ugx);
  const depositRow=await env.DB.prepare("SELECT available_amount FROM deposit_funds WHERE user_id=?").bind(user.id).first();
  if(Number(depositRow?.available_amount||0)<p) return json({error:"This product can only be purchased after a successful deposit. Deposit funds are required for the room purchase."},403);
  const fresh=await env.DB.prepare("SELECT balance FROM users WHERE id=?").bind(user.id).first();
  if(Number(fresh.balance)<p) return json({error:"Insufficient balance. Please deposit funds."},400);
  const started=now();
  const investment=await env.DB.prepare("INSERT INTO investments (user_id,package_id,price,daily_return,started_at,status) VALUES (?,?,?,?,?,'active')")
    .bind(user.id,packageId,p,daily,started).run();
  await env.DB.batch([
    env.DB.prepare("UPDATE users SET balance=balance-? WHERE id=?").bind(p,user.id),
    env.DB.prepare("UPDATE deposit_funds SET available_amount=available_amount-?,updated_at=? WHERE user_id=?").bind(p,started,user.id),
    env.DB.prepare("INSERT INTO transactions (user_id,type,amount,status,reference,created_at) VALUES (?, 'room_purchase', ?, 'completed', ?, ?)").bind(user.id,p,"ROOM-"+investment.meta.last_row_id,started)
  ]);
  return json({ok:true,investmentId:investment.meta.last_row_id,expiresAt:started+ROOM_TERM_DAYS*86400000});
}

async function me(request,env){
  const user=await currentUser(request,env); if(!user) return json({authenticated:false});
  await ensureRulesTables(env);
  await creditDailyEarnings(env);
  const fresh=await env.DB.prepare("SELECT id,login,referral_code,balance,total_earnings FROM users WHERE id=?").bind(user.id).first();
  const rooms=await env.DB.prepare("SELECT id,package_id,price,daily_return,started_at,status FROM investments WHERE user_id=? ORDER BY id DESC").bind(user.id).all();
  const direct=await env.DB.prepare("SELECT COUNT(*) count FROM referrals WHERE referrer_id=?").bind(user.id).first();
  const rewards=await env.DB.prepare("SELECT COALESCE(SUM(bonus_amount),0) total FROM referral_rewards WHERE beneficiary_id=?").bind(user.id).first();
  const levels=[];
  for(let level=1;level<=3;level++){
    const row=await env.DB.prepare("SELECT COUNT(*) count,COALESCE(SUM(bonus_amount),0) total FROM referral_rewards WHERE beneficiary_id=? AND level=?").bind(user.id,level).first();
    levels.push({level,count:Number(row?.count||0),total:Number(row?.total||0),ratePercent:REFERRAL_LEVELS[level-1]});
  }
  const todayEarnings=await env.DB.prepare("SELECT COALESCE(SUM(amount),0) total FROM product_earnings WHERE user_id=? AND earning_date=?").bind(user.id,eatDateKey()).first();
  const referrer=await env.DB.prepare("SELECT u.login,u.referral_code FROM referrals r JOIN users u ON u.id=r.referrer_id WHERE r.referred_user_id=? LIMIT 1").bind(user.id).first();
  return json({authenticated:true,user:fresh,rooms:rooms.results||[],todayEarnings:Number(todayEarnings?.total||0),referral:{code:fresh.referral_code,link:new URL("/?ref="+encodeURIComponent(fresh.referral_code),"https://grand-horizon-hotels.investmentreal95.workers.dev").toString(),directCustomers:Number(direct?.count||0),totalBonuses:Number(rewards?.total||0),levels,referrer}});
}

async function adminLogin(request,env){
  if(!await adminConfigured(env)) return json({error:"Admin security is not configured yet. Set ADMIN_PASSWORD in Cloudflare Worker secrets."},503);
  const {email,password}=await body(request);
  if(String(email||"").trim().toLowerCase() !== String(env.ADMIN_EMAIL||"owner").trim().toLowerCase() || String(password||"") !== String(env.ADMIN_PASSWORD)) return json({error:"Invalid administrator credentials."},401);
  await ensureAdmin(env);
  const token=await createSession(env,"owner",true);
  return json({ok:true},200,{"Set-Cookie":setCookie(ADMIN_COOKIE,token,SESSION_DAYS*86400)});
}

async function adminLogout(request,env){
  const token=cookie(request,ADMIN_COOKIE);
  if(token) await env.DB.prepare("DELETE FROM admin_sessions WHERE token_hash=?").bind(await digest(token)).run();
  return json({ok:true},200,{"Set-Cookie":clearCookie(ADMIN_COOKIE)});
}

async function adminSummary(request,env){
  if(!await requireAdmin(request,env)) return json({error:"Administrator login required."},401);
  const stats = await env.DB.prepare(`
    SELECT
      (SELECT COUNT(*) FROM users) AS users,
      (SELECT COUNT(*) FROM transactions WHERE type='deposit' AND status='completed') AS depositCount,
      (SELECT COALESCE(SUM(amount),0) FROM transactions WHERE type='deposit' AND status='completed') AS totalDeposits,
      (SELECT COUNT(*) FROM transactions WHERE type='withdrawal' AND status='completed') AS withdrawalCount,
      (SELECT COALESCE(SUM(COALESCE(wd.net_amount,t.amount)),0) FROM transactions t LEFT JOIN withdrawal_details wd ON wd.transaction_id=t.id WHERE t.type='withdrawal' AND t.status='completed') AS totalWithdrawals
  `).first();
  return json({...stats, withdrawalsOpen: await withdrawalsOpen(env)});
}

async function approveWithdrawal(request,env,id){
  if(!await requireAdmin(request,env)) return json({error:"Administrator login required."},401);
  await ensureRulesTables(env);
  if(!marzConfigured(env)) return json({error:"MarzPay is not configured. Add MARZPAY_API_KEY and MARZPAY_API_SECRET."},503);
  const tx=await env.DB.prepare("SELECT * FROM transactions WHERE id=? AND type='withdrawal'").bind(id).first();
  if(!tx) return json({error:"Withdrawal not found."},404);
  if(tx.status!=="pending") return json({error:"This withdrawal has already been processed or is already being paid."},409);
  const detail=await env.DB.prepare("SELECT net_amount FROM withdrawal_details WHERE transaction_id=?").bind(id).first();
  const mp=await env.DB.prepare("SELECT * FROM marzpay_transactions WHERE local_transaction_id=?").bind(id).first();
  if(!mp?.phone) return json({error:"Withdrawal phone number is missing."},409);
  try {
    const data=await marzRequest(env,"/send-money",{
      amount:Number(detail?.net_amount||tx.amount),
      phone_number:mp.phone,
      country:"UG",
      reference:tx.reference,
      description:"Grand Horizon Hotels withdrawal",
      callback_url:new URL("/api/marzpay/webhook",request.url).toString(),
      metadata:[{orderId:"GHH-WDR-"+id}]
    });
    await env.DB.batch([
      env.DB.prepare("UPDATE transactions SET status='processing' WHERE id=? AND status='pending'").bind(id),
      env.DB.prepare("UPDATE marzpay_transactions SET provider_uuid=?,provider_reference=?,updated_at=? WHERE local_transaction_id=?")
        .bind(data?.data?.transaction?.uuid||null,data?.data?.transaction?.provider_reference||null,now(),id)
    ]);
    return json({ok:true,status:"processing",paid:Number(detail?.net_amount||tx.amount),tax:Number(tx.amount)-Number(detail?.net_amount||tx.amount)});
  } catch(e) {
    return json({error:e.message||"MarzPay payout could not be started. The reserved balance remains protected."},502);
  }
}
async function approveDeposit(request,env,id){
  if(!await requireAdmin(request,env)) return json({error:"Administrator login required."},401);
  await ensureRulesTables(env);
  const tx=await env.DB.prepare("SELECT * FROM transactions WHERE id=? AND type='deposit'").bind(id).first();
  if(!tx) return json({error:"Deposit not found."},404);
  if(tx.status!=="pending") return json({error:"This deposit has already been processed."},409);
  const providerTx=await env.DB.prepare("SELECT local_transaction_id FROM marzpay_transactions WHERE local_transaction_id=? AND direction='collection'").bind(id).first();
  if(providerTx) return json({error:"This deposit is connected to MarzPay and is credited automatically by its callback."},409);
  const ts=now();
  const chain=await referralChain(env,tx.user_id);
  const statements=[
    env.DB.prepare("UPDATE transactions SET status='completed' WHERE id=?").bind(id),
    env.DB.prepare("UPDATE users SET balance=balance+? WHERE id=?").bind(tx.amount,tx.user_id),
    env.DB.prepare("INSERT INTO deposit_funds (user_id,available_amount,updated_at) VALUES (?,?,?) ON CONFLICT(user_id) DO UPDATE SET available_amount=available_amount+excluded.available_amount,updated_at=excluded.updated_at").bind(tx.user_id,tx.amount,ts)
  ];
  for(const item of chain){
    const rate=REFERRAL_LEVELS[item.level-1];
    const bonus=Math.floor(Number(tx.amount)*rate/100);
    if(bonus>0){
      statements.push(
        env.DB.prepare("UPDATE users SET balance=balance+?,total_earnings=total_earnings+? WHERE id=?").bind(bonus,bonus,item.userId),
        env.DB.prepare("INSERT OR IGNORE INTO referral_rewards (deposit_transaction_id,beneficiary_id,source_user_id,level,rate_percent,bonus_amount,created_at) VALUES (?,?,?,?,?,?,?)").bind(id,item.userId,tx.user_id,item.level,rate,bonus,ts)
      );
    }
  }
  await env.DB.batch(statements);
  return json({ok:true,credited:tx.amount,referralLevels:chain.map(x=>x.level)});
}
async function setWithdrawalStatus(request,env) {
  if(!await requireAdmin(request,env)) return json({error:"Administrator login required."},401);
  const {open} = await body(request);
  if(typeof open !== "boolean") return json({error:"Choose whether withdrawals should be open or closed."},400);
  await ensureSettings(env);
  await env.DB.prepare("UPDATE app_settings SET value=? WHERE key='withdrawals_open'").bind(open ? "1" : "0").run();
  return json({ok:true,withdrawalsOpen:open});
}

async function adminRoute(request,env,url){
  if(url.pathname==="/api/marzpay/webhook" && request.method==="POST") return marzWebhook(request,env);
  if(url.pathname==="/api/admin/login" && request.method==="POST") return adminLogin(request,env);
  if(url.pathname==="/api/admin/logout" && request.method==="POST") return adminLogout(request,env);
  if(url.pathname==="/api/admin/summary" && request.method==="GET") return adminSummary(request,env);
  if(url.pathname==="/api/admin/withdrawals/status" && request.method==="POST") return setWithdrawalStatus(request,env);
  const m=url.pathname.match(/^\/api\/admin\/deposits\/(\d+)\/approve$/);
  if(m && request.method==="POST") return approveDeposit(request,env,Number(m[1]));
  const w=url.pathname.match(/^\/api\/admin\/withdrawals\/(\d+)\/approve$/);
  if(w && request.method==="POST") return approveWithdrawal(request,env,Number(w[1]));
  return null;
}

async function runDailyEarnings(env) {
  await ensureRulesTables(env);
  const target=eatDateKey();
  await creditDailyEarnings(env,target);
}

export default {
  async scheduled(controller, env) {
    if (controller.cron === "0 21 * * *") await runDailyEarnings(env);
  },
  async fetch(request, env) {
    const url=new URL(request.url);
    try {
      await ensureRulesTables(env);
      if(url.pathname.startsWith("/api/")){
        if(url.pathname==="/api/health") return json({ok:true,service:"Grand Horizon Hotels",database:"D1"});
        const admin=await adminRoute(request,env,url); if(admin) return admin;
        if(url.pathname==="/api/auth/register" && request.method==="POST") return await register(request,env);
        if(url.pathname==="/api/auth/login" && request.method==="POST") return await login(request,env);
        if(url.pathname==="/api/auth/logout" && request.method==="POST") return await logout(request,env);
        if(url.pathname==="/api/me" && request.method==="GET") return await me(request,env);
        if(url.pathname==="/api/checkin" && request.method==="POST") return await checkin(request,env);
        if(url.pathname==="/api/deposits" && request.method==="POST") return await deposit(request,env);
        if(url.pathname==="/api/withdrawals" && request.method==="POST") return await withdrawal(request,env);
        if(url.pathname==="/api/rent" && request.method==="POST") return await rent(request,env);
        return json({error:"API route not found."},404);
      }
      if(url.pathname==="/admin" || url.pathname==="/admin/") {
        const assetUrl = new URL("/admin.html", request.url);
        return env.ASSETS.fetch(new Request(assetUrl.toString(), { method:"GET", headers: request.headers }));
      }
      if(url.pathname==="/login" || url.pathname==="/login/" || url.pathname==="/register" || url.pathname==="/register/") {
        const assetUrl = new URL("/index.html", request.url);
        return env.ASSETS.fetch(new Request(assetUrl.toString(), { method:"GET", headers: request.headers }));
      }
      return env.ASSETS.fetch(request);
    } catch(e) {
      console.error(e);
      return json({error:"Server error. Please try again."},500);
    }
  }
};