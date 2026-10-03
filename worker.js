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
    env.DB.prepare("CREATE TABLE IF NOT EXISTS withdrawal_details (transaction_id INTEGER PRIMARY KEY, tax_percent INTEGER NOT NULL, tax_amount INTEGER NOT NULL, net_amount INTEGER NOT NULL)")
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

async function register(request, env) {
  const { login, password, referralCode } = await body(request);
  const normalized = String(login || "").trim().toLowerCase();
  if (!normalized || !password || password.length < 8) return json({error:"Use a valid login and a password of at least 8 characters."},400);
  const exists = await env.DB.prepare("SELECT id FROM users WHERE login=?").bind(normalized).first();
  if (exists) return json({error:"An account with that login already exists."},409);
  let referrer = null;
  if (referralCode) referrer = await env.DB.prepare("SELECT id FROM users WHERE referral_code=?").bind(String(referralCode).trim().toUpperCase()).first();
  const rec = await makePasswordRecord(password);
  const code = refCode();
  const created = now();
  const result = await env.DB.prepare("INSERT INTO users (login,password_hash,password_salt,referral_code,created_at) VALUES (?,?,?,?,?)")
    .bind(normalized,rec.hash,rec.salt,code,created).run();
  const userId = result.meta.last_row_id;
  if (referrer) {
    await env.DB.prepare("INSERT INTO referrals (referrer_id,referred_user_id,rate_percent,created_at) VALUES (?,?,?,?)")
      .bind(referrer.id,userId,25,created).run();
  }
  await grantWelcomeBonus(env,userId);
  const token = await createSession(env,userId);
  return json({ok:true,user:{id:userId,login:normalized,referralCode:code,balance:5000,totalEarnings:5000},welcomeBonus:5000},200,{"Set-Cookie":setCookie(COOKIE,token,SESSION_DAYS*86400)});
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
  const { login, password } = await body(request);
  const row = await env.DB.prepare("SELECT * FROM users WHERE login=?").bind(String(login||"").trim().toLowerCase()).first();
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
  const {amount,method}=await body(request); const value=Math.floor(Number(amount));
  if(!Number.isFinite(value)||value<20000) return json({error:"Minimum deposit is UGX 20,000."},400);
  if(!["MTN Mobile Money","Airtel Money"].includes(method)) return json({error:"Choose MTN Mobile Money or Airtel Money."},400);
  const reference="DEP-"+crypto.randomUUID().replaceAll("-","").slice(0,18).toUpperCase();
  await env.DB.prepare("INSERT INTO transactions (user_id,type,amount,method,status,reference,created_at) VALUES (?, 'deposit', ?, ?, 'pending', ?, ?)")
    .bind(user.id,value,method,reference,now()).run();
  return json({ok:true,status:"pending",reference,message:"Deposit request recorded. It will be credited after payment confirmation."});
}

async function withdrawal(request, env) {
  const user=await currentUser(request,env); if(!user) return json({error:"Please sign in."},401);
  await ensureRulesTables(env);
  if(!await withdrawalsOpen(env)) return json({error:"Withdrawals are currently closed by the administrator."},503);
  const {amount,method}=await body(request); const value=Math.floor(Number(amount));
  if(!Number.isFinite(value)||value<5000) return json({error:"Minimum withdrawal is UGX 5,000."},400);
  if(!["MTN Mobile Money","Airtel Money"].includes(method)) return json({error:"Choose MTN Mobile Money or Airtel Money."},400);
  const fresh=await env.DB.prepare("SELECT balance FROM users WHERE id=?").bind(user.id).first();
  const eligibility=await env.DB.prepare("SELECT (SELECT COUNT(*) FROM transactions WHERE user_id=? AND type='deposit' AND status='completed') deposit_count,(SELECT COUNT(*) FROM investments WHERE user_id=? AND status='active' AND started_at >= ?) active_rooms")
    .bind(user.id,user.id,now()-ROOM_TERM_DAYS*86400000).first();
  if(Number(eligibility.deposit_count)<1 || Number(eligibility.active_rooms)<1) return json({error:"Withdrawals require at least one successful deposit and an active purchased product."},403);
  if(Number(fresh.balance)<value) return json({error:"Insufficient balance."},400);
  const tax=Math.floor(value*WITHDRAWAL_TAX_PERCENT/100);
  const net=value-tax;
  const reference="WDR-"+crypto.randomUUID().replaceAll("-","").slice(0,18).toUpperCase();
  const result=await env.DB.prepare("INSERT INTO transactions (user_id,type,amount,method,status,reference,created_at) VALUES (?, 'withdrawal', ?, ?, 'pending', ?, ?)")
    .bind(user.id,value,method,reference,now()).run();
  await env.DB.prepare("INSERT INTO withdrawal_details (transaction_id,tax_percent,tax_amount,net_amount) VALUES (?,?,?,?)").bind(result.meta.last_row_id,WITHDRAWAL_TAX_PERCENT,tax,net).run();
  return json({ok:true,status:"pending",reference,grossAmount:value,taxAmount:tax,taxPercent:WITHDRAWAL_TAX_PERCENT,netAmount:net,message:"Withdrawal request recorded."});
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
  const tx=await env.DB.prepare("SELECT * FROM transactions WHERE id=? AND type='withdrawal'").bind(id).first();
  if(!tx) return json({error:"Withdrawal not found."},404);
  if(tx.status!=="pending") return json({error:"This withdrawal has already been processed."},409);
  const detail=await env.DB.prepare("SELECT net_amount FROM withdrawal_details WHERE transaction_id=?").bind(id).first();
  const result=await env.DB.prepare("UPDATE users SET balance=balance-? WHERE id=? AND balance>=?").bind(tx.amount,tx.user_id,tx.amount).run();
  if(!result.meta.changes) return json({error:"Customer no longer has enough available balance."},409);
  await env.DB.prepare("UPDATE transactions SET status='completed' WHERE id=?").bind(id).run();
  return json({ok:true,paid:Number(detail?.net_amount||tx.amount),tax:Number(tx.amount)-Number(detail?.net_amount||tx.amount)});
}

async function approveDeposit(request,env,id){
  if(!await requireAdmin(request,env)) return json({error:"Administrator login required."},401);
  await ensureRulesTables(env);
  const tx=await env.DB.prepare("SELECT * FROM transactions WHERE id=? AND type='deposit'").bind(id).first();
  if(!tx) return json({error:"Deposit not found."},404);
  if(tx.status!=="pending") return json({error:"This deposit has already been processed."},409);
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
  if(url.pathname==="/api/admin/login" && request.method==="POST") return adminLogin(request,env);
  if(url.pathname==="/api/admin/logout" && request.method==="POST") return adminLogout(request,env);
  if(url.pathname==="/api/admin/summary" && request.method==="GET") return adminSummary(request,env);
  if(url.pathname==="/api/admin/withdrawals/status" && request.method==="POST") return setWithdrawalStatus(request,env);
  const m=url.pathname.match(/^\/api\/admin\/deposits\/(\d+)\/approve$/);
  if(m && request.method==="POST") return approveDeposit(request,env,Number(m[1]));
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
        if(url.pathname==="/api/auth/register" && request.method==="POST") return register(request,env);
        if(url.pathname==="/api/auth/login" && request.method==="POST") return login(request,env);
        if(url.pathname==="/api/auth/logout" && request.method==="POST") return logout(request,env);
        if(url.pathname==="/api/me" && request.method==="GET") return me(request,env);
        if(url.pathname==="/api/checkin" && request.method==="POST") return checkin(request,env);
        if(url.pathname==="/api/deposits" && request.method==="POST") return deposit(request,env);
        if(url.pathname==="/api/withdrawals" && request.method==="POST") return withdrawal(request,env);
        if(url.pathname==="/api/rent" && request.method==="POST") return rent(request,env);
        return json({error:"API route not found."},404);
      }
      if(url.pathname==="/admin" || url.pathname==="/admin/") {
        const assetUrl = new URL("/admin.html", request.url);
        return env.ASSETS.fetch(new Request(assetUrl.toString(), { method:"GET", headers: request.headers }));
      }
      return env.ASSETS.fetch(request);
    } catch(e) {
      console.error(e);
      return json({error:"Server error. Please try again."},500);
    }
  }
};