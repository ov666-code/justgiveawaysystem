// server.js — TG verify + UA/EN + site linking + Kick OAuth (user+admin in one callback) + idempotent tickets + wallets + SSE + Admin
require('dotenv').config();
const express   = require('express');
const axios     = require('axios');
const sqlite3   = require('sqlite3').verbose();
const geoip     = require('geoip-lite');
const basicAuth = require('express-basic-auth');
const crypto    = require('crypto');

const app = express();

axios.defaults.headers.common['User-Agent'] = axios.defaults.headers.common['User-Agent']
  || 'Francuz1kBot/1.0 (+https://francuz1k.com)';
axios.defaults.headers.common['Accept'] = axios.defaults.headers.common['Accept']
  || 'application/json, text/plain, */*';
app.set('trust proxy', true);
app.use(express.json({
  // сохраняем сырое тело для проверки подписи вебхука Kick (если включено)
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

// ===== ENV =====
const PORT       = Number(process.env.PORT || 4000);
const TG_TOKEN   = process.env.TG_BOT_TOKEN || '';
const TG_CHANNEL = process.env.TG_CHANNEL || '@francua000';
const DB_PATH    = process.env.DB_PATH || '/srv/app/data.sqlite';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'adminpass';
const TG_API     = `https://api.telegram.org/bot${TG_TOKEN}`;

const KICK_CLIENT_ID     = process.env.KICK_CLIENT_ID || '';
const KICK_CLIENT_SECRET = process.env.KICK_CLIENT_SECRET || '';
const KICK_REDIRECT_URI  = (process.env.KICK_REDIRECT_URI || '').replace(/\/$/, ''); // единый callback для user+admin
const KICK_OAUTH_BASE    = (process.env.KICK_OAUTH_BASE || 'https://id.kick.com').replace(/\/$/,'');
const KICK_API_BASE      = (process.env.KICK_API_BASE   || 'https://api.kick.com').replace(/\/$/,'');
const KICK_CHANNEL_SLUG  = process.env.KICK_CHANNEL_SLUG || '';
const KICK_USER_SCOPE    = (process.env.KICK_USER_SCOPE  || 'user:read user:email').trim();
const KICK_ADMIN_SCOPE   = (process.env.KICK_ADMIN_SCOPE || 'user:read events:subscribe user:email').trim();
const KICK_VERIFY_SIGNATURE = String(process.env.KICK_VERIFY_SIGNATURE||'0') === '1';
const KICK_BROADCASTER_USER_ID = Number(process.env.KICK_BROADCASTER_USER_ID || 0) || 0;
const KICK_WEBHOOK_URL   = (process.env.KICK_WEBHOOK_URL || '').trim();
const KICK_WEBHOOK_SECRET= process.env.KICK_WEBHOOK_SECRET || '';
const DEFAULT_IDENTITY_TTL = 12*60*60*1000;
const envIdentityTtl = Number(process.env.KICK_IDENTITY_CACHE_TTL);
const KICK_IDENTITY_CACHE_TTL = (Number.isFinite(envIdentityTtl) && envIdentityTtl > 0)
  ? Math.max(envIdentityTtl, 5*60*1000)
  : DEFAULT_IDENTITY_TTL;

let dynamicKickSlug = KICK_CHANNEL_SLUG || '';
let lastKickIdentityRefresh = 0;

// ===== DB =====
const db = new sqlite3.Database(DB_PATH);
const dbAll = (s,p=[])=>new Promise((res,rej)=>db.all(s,p,(e,r)=>e?rej(e):res(r)));
const dbGet = (s,p=[])=>new Promise((res,rej)=>db.get(s,p,(e,r)=>e?rej(e):res(r)));
const dbRun = (s,p=[])=>new Promise((res,rej)=>db.run(s,p,function(e){e?rej(e):res(this)}));
const dbExec= (s)=>new Promise((res,rej)=>db.exec(s,(e)=>e?rej(e):res()));

async function ensureTableColumn(table, column, definition){
  try{
    const cols = await dbAll(`PRAGMA table_info(${table})`);
    const exists = Array.isArray(cols) && cols.some(c=>String(c.name)===column);
    if (!exists){
      await dbExec('BEGIN IMMEDIATE;');
      await dbRun(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
      await dbExec('COMMIT;');
      console.log(`${table}: added column ${column}`);
    }
  }catch(e){
    try{ await dbExec('ROLLBACK;'); }catch(_){ }
    const msg = e?.message || String(e||'');
    if (!/duplicate column/i.test(msg)){
      console.error(`ensure column error for ${table}.${column}:`, msg);
    }
  }
}

// --- helper: гарантируем актуальную схему oauth_states (вызываем на старте и перед вставками) ---
async function ensureOAuthStatesTable(){
  try{
    const cols = await dbAll(`PRAGMA table_info(oauth_states)`);
    const need = new Set(['state','participant_id','verifier','created_at']);
    const have = new Set((cols||[]).map(c=>c.name));
    let ok = cols && cols.length>0;
    if (ok) for (const k of need){ if(!have.has(k)){ ok=false; break; } }
    if (!ok){
      await dbExec('BEGIN IMMEDIATE;');
      await dbRun('DROP TABLE IF EXISTS oauth_states');
      await dbRun(`CREATE TABLE oauth_states(
        state TEXT PRIMARY KEY,
        participant_id INTEGER,
        verifier TEXT,
        created_at INTEGER
      )`);
      await dbExec('COMMIT;');
      console.log('oauth_states: recreated (migrated to new schema)');
    }
  }catch(e){
    try{ await dbExec('ROLLBACK;') }catch(_){}
    console.error('ensureOAuthStatesTable error:', e.message);
  }
}

db.serialize(async ()=>{
  db.exec('PRAGMA journal_mode=WAL;');

  db.run(`CREATE TABLE IF NOT EXISTS participants(
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    tg_id              TEXT UNIQUE,
    tg_username        TEXT,
    tg_verified        INTEGER DEFAULT 0,
    kick_verified      INTEGER DEFAULT 0,
    kick_verified_by   TEXT,
    ticket_no          INTEGER UNIQUE,
    lang               TEXT,
    ip_country         TEXT,
    created_at         INTEGER,
    updated_at         INTEGER,
    ticket_sent_at     INTEGER,
    wallet_trc20       TEXT,
    wallet_updated_at  INTEGER,
    wallet_pending     INTEGER DEFAULT 0,
    -- Kick identity
    kick_user_id       TEXT,
    kick_username      TEXT,
    kick_email         TEXT,
    kick_verified_at   INTEGER
  )`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_p_created ON participants(created_at)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_p_ticket  ON participants(ticket_no)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_p_user    ON participants(tg_username)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_p_country ON participants(ip_country)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_p_kick_un ON participants(kick_username)`);
  db.run(`CREATE UNIQUE INDEX IF NOT EXISTS uq_p_kick_user
          ON participants(kick_user_id)
          WHERE kick_user_id IS NOT NULL AND kick_user_id<>''`);

  db.run(`CREATE TABLE IF NOT EXISTS tg_link_tokens(
    token TEXT PRIMARY KEY,
    participant_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    used INTEGER DEFAULT 0
  )`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_link_pid ON tg_link_tokens(participant_id)`);

  db.run(`CREATE TABLE IF NOT EXISTS winners(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    participant_id INTEGER NOT NULL UNIQUE,
    ticket_no INTEGER UNIQUE,
    prize TEXT,
    noted_at INTEGER,
    paid INTEGER DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS seq_ticket(last INTEGER NOT NULL DEFAULT 0)`, async ()=>{
    const have = await dbGet(`SELECT last FROM seq_ticket LIMIT 1`);
    if (!have) {
      const m = (await dbGet(`SELECT MAX(ticket_no) AS m FROM participants`))?.m || 0;
      await dbRun(`INSERT INTO seq_ticket(last) VALUES(?)`, [m]);
    }
  });

  db.run(`CREATE TABLE IF NOT EXISTS kick_event_log(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT UNIQUE,
    event_type TEXT,
    payload_json TEXT,
    received_at INTEGER,
    handled_ok INTEGER DEFAULT 0
  )`);

  // oauth_states создадим/мигрируем через helper (устойчиво к старым БД)
  await ensureOAuthStatesTable();

  await ensureTableColumn('participants','kick_verified_by','TEXT');

  db.run(`CREATE TABLE IF NOT EXISTS kv_store(
    k TEXT PRIMARY KEY,
    v TEXT,
    updated_at INTEGER
  )`);
});

// ===== Helpers =====
function pickLang(code){
  const c=(code||'').toLowerCase();
  return (c.startsWith('uk')||c.startsWith('ua')||c.startsWith('ru')||c.startsWith('be'))?'ua':'en';
}
function getClientIp(req){
  const cf = req.headers['cf-connecting-ip'];
  if (typeof cf === 'string' && cf.length) return cf.trim();
  const xf=req.headers['x-forwarded-for'];
  if (typeof xf==='string' && xf.length) return xf.split(',')[0].trim();
  return (req.socket?.remoteAddress||'').replace('::ffff:','');
}
function countryByIp(ip){ try{ return geoip.lookup(ip)?.country || null; }catch{ return null; } }

async function tgCall(method, params){
  try{
    const {data}=await axios.post(`${TG_API}/${method}`,params);
    return data;
  }catch(e){
    const code = e?.response?.data?.error_code;
    const desc = e?.response?.data?.description || e.message || '';
    if (code === 403 && /blocked by the user/i.test(desc)) {
      console.warn('TG: user blocked the bot');
      return { ok:false, blocked:true, error: desc };
    }
    if (/message is not modified/i.test(desc)) return { ok:false, skipped:true };
    console.error('TG API error:', e?.response?.data || e.message);
    return { ok:false, error: desc };
  }
}
function b64url(buf){ return buf.toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function makePkce(){
  const verifier  = b64url(crypto.randomBytes(32));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
  return { verifier, challenge };
}
function delay(ms){ return new Promise(res=>setTimeout(res,Math.max(0,ms||0))); }
// TTL для висячих oauth-состояний
setInterval(async ()=>{
  try{
    const th = Date.now() - 30*60*1000;
    await dbRun(`DELETE FROM oauth_states WHERE created_at<?`,[th]);
  }catch(_){}
}, 10*60*1000);

// I18N
const I18N={
  ua:{
    hi:n=>`Привіт, ${n||''}!`,
    start_line:ch=>`Натисни кнопку, щоб перевірити підписку на ${ch} і отримати галочку на сайті.`,
    btn_verify:'✅ Перевірити підписку',
    btn_wallet:'💳 Вказати USDT TRC20',
    btn_lang:'🌐 Мова',
    lang_title:'Оберіть мову',
    lang_ua:'🇺🇦 Українська',
    lang_en:'🇬🇧 English',
    btn_back:'⬅ Назад',
    not_member_alert:ch=>`Не бачу підписки на ${ch}. Підпишись і натисни ще раз.`,
    verified_msg:'✅ Telegram перевірено!\nПовернись на сайт, щоб завершити наступний крок.',
    toast_verified:'Перевірено',
    toast_lang_set:'Мову змінено',
    ticket_msg:t=>`🎟 Ваш номер квитка: **${t}**\nУспіхів у розіграші!`,
    ask_wallet:'Надішли, будь ласка, **USDT (TRC20)** адресу одним повідомленням.\nВона має починатися на `T` і мати 34 символи.',
    wallet_saved:'✅ Гаманець збережено. Дякую!',
    wallet_invalid:'❌ Це не схоже на TRC20-адресу. Приклад: `T...` (34 символи). Спробуй ще раз.'
  },
  en:{
    hi:n=>`Hi, ${n||''}!`,
    start_line:ch=>`Tap to verify your subscription to ${ch} and get a checkmark on the site.`,
    btn_verify:'✅ Verify subscription',
    btn_wallet:'💳 Add USDT TRC20',
    btn_lang:'🌐 Language',
    lang_title:'Choose your language',
    lang_ua:'🇺🇦 Ukrainian',
    lang_en:'🇬🇧 English',
    btn_back:'⬅ Back',
    not_member_alert:ch=>`I don’t see a subscription to ${ch}. Please subscribe and try again.`,
    verified_msg:'✅ Telegram verified!\nReturn to the website to finish the next step.',
    toast_verified:'Verified',
    toast_lang_set:'Language updated',
    ticket_msg:t=>`🎟 Your ticket number: **${t}**\nGood luck!`,
    ask_wallet:'Please send your **USDT (TRC20)** address in one message.\nIt should start with `T` and be 34 characters long.',
    wallet_saved:'✅ Wallet saved. Thanks!',
    wallet_invalid:'❌ Not a TRC20 address. Example: `T...` (34 chars). Try again.'
  }
};

async function getUserLang(tg_id){ try{ return (await dbGet(`SELECT lang FROM participants WHERE tg_id=?`,[String(tg_id)]))?.lang || null; }catch{ return null; } }
async function saveUserLang(tg_id,username,lang){
  const now=Date.now();
  await dbRun(
    `INSERT INTO participants(tg_id,tg_username,lang,tg_verified,created_at,updated_at)
     VALUES(?,?,?,?,?,?)
     ON CONFLICT(tg_id) DO UPDATE SET tg_username=excluded.tg_username, lang=excluded.lang, updated_at=excluded.updated_at`,
    [String(tg_id),(username||'').toLowerCase(),lang,0,now,now]
  );
}
async function getT(user){ const fromDb=await getUserLang(user.id); const lang=fromDb||pickLang(user.language_code); return { T:I18N[lang]||I18N.ua, lang }; }
const startMarkup=(T)=>({inline_keyboard:[
  [{text:T.btn_verify, callback_data:'check_sub'}],
  [{text:T.btn_wallet, callback_data:'wallet:start'}],
  [{text:T.btn_lang,   callback_data:'lang_menu'}]
]});
const langMarkup=(T,cur)=>({inline_keyboard:[
  [{text:T.lang_ua+(cur==='ua'?' ✓':''), callback_data:'lang:set:ua'},
   {text:T.lang_en+(cur==='en'?' ✓':''), callback_data:'lang:set:en'}],
  [{text:T.btn_back, callback_data:'back_to_menu'}]
]});
async function safeEdit(cbq,text,markup){
  try{
    const old=cbq?.message?.text||'';
    const om=JSON.stringify(cbq?.message?.reply_markup||{});
    const nm=JSON.stringify(markup||{});
    if(old===text && om===nm) return {ok:true,skipped:true};
    return await tgCall('editMessageText',{
      chat_id:cbq.message.chat.id,
      message_id:cbq.message.message_id,
      text, reply_markup:markup, parse_mode:'Markdown'
    });
  }catch(_){ return {ok:false}; }
}

// ===== KV helpers =====
async function kvGet(key){ try{ const r=await dbGet(`SELECT v FROM kv_store WHERE k=?`,[key]); return r?.v?JSON.parse(r.v):null; }catch(_){ return null; } }
async function kvSet(key,val){ try{ await dbRun(`INSERT INTO kv_store(k,v,updated_at) VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated_at=excluded.updated_at`,[key,JSON.stringify(val||null),Date.now()]); }catch(_){ } }

// ===== Tokens =====
function randToken(){ return crypto.randomBytes(24).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
async function createLinkToken(pid){
  const token = randToken();
  await dbRun(`INSERT INTO tg_link_tokens(token,participant_id,created_at,used) VALUES(?,?,?,0)`, [token,pid,Date.now()]);
  return token;
}
async function consumeLinkToken(token){
  const r=await dbGet(`SELECT * FROM tg_link_tokens WHERE token=? AND used=0`,[token]);
  if(!r) return null;
  await dbRun(`UPDATE tg_link_tokens SET used=1 WHERE token=?`,[token]);
  return r.participant_id;
}

// ===== Tickets (идемпотентность по личности) =====
const pad7 = (n)=> String(n).padStart(7,'0');

async function nextTicket(){
  await dbExec('BEGIN IMMEDIATE;');
  const row = await dbGet(`SELECT last FROM seq_ticket LIMIT 1`);
  const t = (row?.last||0)+1;
  await dbRun(`UPDATE seq_ticket SET last=?`,[t]);
  await dbExec('COMMIT;');
  return t;
}
async function findExistingTicketByIdentity(tg_id, kick_user_id){
  if(!tg_id && !kick_user_id) return null;
  const row = await dbGet(`
    SELECT ticket_no FROM participants
    WHERE ticket_no IS NOT NULL
      AND (
            (? IS NOT NULL AND tg_id=?)
         OR (? IS NOT NULL AND kick_user_id=?)
      )
    ORDER BY ticket_no ASC LIMIT 1
  `,[tg_id||null,tg_id||null,kick_user_id||null,kick_user_id||null]);
  return row?.ticket_no || null;
}
async function sendTicket(pid,ticket,langHint){
  const row=await dbGet(`SELECT tg_id,lang FROM participants WHERE id=?`,[pid]);
  if(!row?.tg_id) return false;
  const lang=langHint||row.lang||'ua', T=I18N[lang]||I18N.ua;
  const r=await tgCall('sendMessage',{chat_id:row.tg_id,text:T.ticket_msg(pad7(ticket)),parse_mode:'Markdown'});
  if(r?.ok) await dbRun(`UPDATE participants SET ticket_sent_at=? WHERE id=?`,[Date.now(),pid]);
  broadcastStatus(pid).catch(()=>{});
  return !!r?.ok;
}
async function issueTicketIfReady(pid){
  const u=await dbGet(`SELECT id,tg_verified,kick_verified,ticket_no,ip_country,lang,tg_id,kick_user_id,ticket_sent_at FROM participants WHERE id=?`,[pid]);
  if(!u) return;
  if(u.ip_country==='RU') return; // блок РФ
  if(!(u.tg_verified && u.kick_verified)) return;

  if(u.ticket_no){
    if(!u.ticket_sent_at){ await sendTicket(u.id,u.ticket_no,u.lang); }
    return;
  }
  const existing = await findExistingTicketByIdentity(u.tg_id, u.kick_user_id);
  if (existing){
    await dbRun(`UPDATE participants SET ticket_no=?, updated_at=? WHERE id=?`,[existing,Date.now(),u.id]);
    await sendTicket(u.id,existing,u.lang);
    return;
  }
  const t=await nextTicket();
  await dbRun(`UPDATE participants SET ticket_no=?, updated_at=? WHERE id=?`,[t,Date.now(),u.id]);
  await sendTicket(u.id,t,u.lang);
}

// ===== SSE =====
const sse = new Map(); // pid -> Set(res)
app.get('/api/status/stream', async (req,res)=>{
  const pid=Number(req.query.pid); if(!pid) return res.status(400).end('bad pid');
  res.setHeader('Content-Type','text/event-stream');
  res.setHeader('Cache-Control','no-cache');
  res.setHeader('Connection','keep-alive');
  res.flushHeaders?.();
  const send = async ()=>{
    const r = await dbGet(`SELECT tg_verified,kick_verified,ticket_no FROM participants WHERE id=?`,[pid]);
    res.write('data: ' + JSON.stringify({ok:!!r, ...(r||{})}) + '\n\n');
  };
  await send();
  let set=sse.get(pid); if(!set){ set=new Set(); sse.set(pid,set); }
  set.add(res);
  req.on('close', ()=>{ set.delete(res); if(!set.size) sse.delete(pid); });
});
async function broadcastStatus(pid){
  const set=sse.get(Number(pid)); if(!set||!set.size) return;
  const r = await dbGet(`SELECT tg_verified,kick_verified,ticket_no FROM participants WHERE id=?`,[pid]);
  const payload = 'data: ' + JSON.stringify({ok:!!r, ...(r||{})}) + '\n\n';
  for(const res of set){ try{ res.write(payload); }catch{} }
}

// ===== Health & Site API =====
app.get('/api/health', (_req,res)=>res.json({ok:true,time:Date.now(),db:DB_PATH}));

app.post('/api/join/start', async (req,res)=>{
  try{
    const now=Date.now(), ip=getClientIp(req), country=countryByIp(ip);
    const ins=await dbRun(`INSERT INTO participants(created_at,updated_at,ip_country) VALUES(?,?,?)`,[now,now,country||null]);
    const pid=ins.lastID;
    const token=await createLinkToken(pid);
    res.json({ ok:true, participant_id: pid, tg_start: token });
  }catch(e){ res.status(500).json({ ok:false, error:e.message }); }
});
app.get('/api/status', async (req,res)=>{
  try{
    const pid=Number(req.query.pid || req.query.participant_id); if(!pid) return res.json({ok:false});
    const r=await dbGet(`SELECT tg_verified,kick_verified,ticket_no,ip_country FROM participants WHERE id=?`,[pid]);
    if(!r) return res.json({ok:false});
    res.json({ ok:true, ...r });
  }catch(e){ res.status(500).json({ ok:false, error:e.message }); }
});

// ===== Kick: helpers (admin token, ensure follow sub) =====
async function kvJsonGet(key){ return kvGet(key); }
async function kvJsonSet(key,val){ return kvSet(key,val); }

function pickNumberCandidate(...values){
  for (const value of values.flat(Infinity)){
    const n = Number(value);
    if (Number.isFinite(n) && n>0) return n;
  }
  return 0;
}
function pickStringCandidate(...values){
  for (const value of values.flat(Infinity)){
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return null;
}
function collectKickObjects(sources){
  const stack = [...sources];
  const out = [];
  const seen = new Set();
  while(stack.length){
    const current = stack.pop();
    if (!current || typeof current !== 'object') continue;
    if (seen.has(current)) continue;
    seen.add(current);
    out.push(current);
    for (const val of Object.values(current)){
      if (!val) continue;
      if (Array.isArray(val)){
        for (const item of val){ if (item && typeof item === 'object') stack.push(item); }
      }else if (typeof val === 'object'){
        stack.push(val);
      }
    }
  }
  return out;
}
function withKickHeaders(base){
  const headers = { ...(base||{}) };
  if (headers.Authorization && typeof headers.Authorization === 'string'){
    headers.Authorization = headers.Authorization.trim();
  }
  if (KICK_CLIENT_ID){
    const hasClientId = Object.keys(headers).some(k => k && k.toLowerCase() === 'client-id');
    if (!hasClientId){
      headers['Client-Id'] = KICK_CLIENT_ID;
    }
  }
  if (!headers.Accept){
    headers.Accept = 'application/json, text/plain, */*';
  }
  return headers;
}
function normalizeKickIdentity(...sources){
  const objects = collectKickObjects(sources.filter(Boolean));
  if (!objects.length) return null;
  const broadcasterCandidates = [];
  const channelCandidates = [];
  const slugCandidates = [];
  const usernameCandidates = [];
  const emailCandidates = [];
  const cachedAtCandidates = [];
  const remoteUpdatedCandidates = [];
  let updatedAt = 0;
  for (const obj of objects){
    broadcasterCandidates.push(obj?.broadcaster_user_id, obj?.broadcasterUserId, obj?.owner_id, obj?.ownerId, obj?.user_id, obj?.userId, obj?.id);
    channelCandidates.push(obj?.channel_id, obj?.channelId, obj?.id, obj?.primary_channel_id, obj?.primaryChannelId);
    slugCandidates.push(obj?.channel_slug, obj?.slug, obj?.slug_name);
    usernameCandidates.push(obj?.username, obj?.name, obj?.display_name, obj?.displayName);
    emailCandidates.push(obj?.email, obj?.user?.email);
    cachedAtCandidates.push(obj?.cached_at, obj?.cachedAt, obj?.cache_at, obj?.cacheAt, obj?.refreshed_at, obj?.refreshedAt, obj?.fetched_at, obj?.fetchedAt);
    remoteUpdatedCandidates.push(obj?.remote_updated_at, obj?.remoteUpdatedAt);
    if (!updatedAt && Number(obj?.updated_at||0)>0){
      updatedAt = Number(obj.updated_at);
    }
  }
  const broadcaster_user_id = pickNumberCandidate(broadcasterCandidates);
  const channel_id = pickNumberCandidate(channelCandidates);
  const slug = pickStringCandidate(slugCandidates) || null;
  const username = pickStringCandidate(usernameCandidates) || null;
  const email = pickStringCandidate(emailCandidates) || null;
  const cached_at = pickNumberCandidate([cachedAtCandidates, updatedAt].flat());
  const remote_updated_at = pickNumberCandidate([remoteUpdatedCandidates, updatedAt].flat());
  if (!updatedAt) updatedAt = cached_at || Date.now();
  if (!broadcaster_user_id && !channel_id && !slug && !username && !email) return null;
  return {
    broadcaster_user_id: broadcaster_user_id || channel_id || 0,
    channel_id: channel_id || broadcaster_user_id || 0,
    slug,
    username,
    email,
    updated_at: updatedAt,
    cached_at: cached_at || null,
    remote_updated_at: remote_updated_at || null
  };
}
async function cacheKickIdentity(...sources){
  const identity = normalizeKickIdentity(...sources);
  if (!identity) return null;
  if (!identity.slug && KICK_CHANNEL_SLUG) identity.slug = KICK_CHANNEL_SLUG;
  if (KICK_BROADCASTER_USER_ID && !identity.broadcaster_user_id){
    identity.broadcaster_user_id = KICK_BROADCASTER_USER_ID;
  }
  const now = Date.now();
  const remoteUpdated = Number(identity.updated_at || 0);
  if (remoteUpdated && remoteUpdated > 0){
    identity.remote_updated_at = remoteUpdated;
  }
  identity.cached_at = now;
  identity.updated_at = now;
  if (identity.slug) dynamicKickSlug = identity.slug;
  lastKickIdentityRefresh = now;
  await kvJsonSet('kick_broadcaster_info', identity);
  if (identity.broadcaster_user_id){
    await kvJsonSet('kick_broadcaster_user_id', identity.broadcaster_user_id);
  }
  return identity;
}
async function getCachedKickIdentity(){
  const info = await kvJsonGet('kick_broadcaster_info');
  if (info && typeof info === 'object'){
    const normalized = normalizeKickIdentity(info);
    if (normalized){
      if (!normalized.slug && KICK_CHANNEL_SLUG) normalized.slug = KICK_CHANNEL_SLUG;
      if (KICK_BROADCASTER_USER_ID && !normalized.broadcaster_user_id){
        normalized.broadcaster_user_id = KICK_BROADCASTER_USER_ID;
      }
      if (normalized.slug) dynamicKickSlug = normalized.slug;
      const cachedAt = Number(normalized.cached_at || 0);
      const updated = Number(normalized.updated_at || 0);
      const reference = Number.isFinite(cachedAt) && cachedAt>0
        ? cachedAt
        : (Number.isFinite(updated) && updated>0 ? updated : 0);
      if (reference){
        normalized.cached_at = reference;
        normalized.updated_at = reference;
        normalized.cache_age_ms = Math.max(Date.now() - reference, 0);
        if ((Date.now() - reference) > KICK_IDENTITY_CACHE_TTL){
          normalized.stale = true;
          if (Date.now() - lastKickIdentityRefresh > 60*1000){
            lastKickIdentityRefresh = Date.now();
            fetchKickChannelInfo().then(r=>{
              if (r?.raw) cacheKickIdentity(r.raw).catch(()=>{});
              else if (r?.id) cacheKickIdentity({ channel_id:r.id }).catch(()=>{});
            }).catch(()=>{});
          }
        }
      }
      const remoteUpdated = Number(normalized.remote_updated_at || 0);
      if (Number.isFinite(remoteUpdated) && remoteUpdated>0){
        normalized.remote_updated_at = remoteUpdated;
      }else{
        normalized.remote_updated_at = null;
      }
      return normalized;
    }
  }
  if (KICK_BROADCASTER_USER_ID){
    if (KICK_CHANNEL_SLUG) dynamicKickSlug = KICK_CHANNEL_SLUG;
    const now = Date.now();
    return {
      broadcaster_user_id: KICK_BROADCASTER_USER_ID,
      channel_id: KICK_BROADCASTER_USER_ID,
      slug: KICK_CHANNEL_SLUG || null,
      username: null,
      email: null,
      cached_at: now,
      updated_at: now
    };
  }
  return null;
}

async function fetchKickChannelInfo(headersOverride){
  const slug = dynamicKickSlug || KICK_CHANNEL_SLUG;
  if (!slug) return { id:0, raw:null };
  const endpoints = [
    `${KICK_API_BASE}/public/v1/channels/${encodeURIComponent(slug)}`,
    `${KICK_API_BASE}/public/v1/channels/${encodeURIComponent(slug)}/profile`,
    `https://kick.com/api/v2/channels/${encodeURIComponent(slug)}`,
    `https://kick.com/api/v1/channels/${encodeURIComponent(slug)}`
  ];

  const headerVariants = [];
  if (headersOverride){
    headerVariants.push(withKickHeaders(headersOverride));
  }else{
    const adminAuthorization = await adminAuthHeader();
    if (adminAuthorization){
      headerVariants.push(withKickHeaders({ Authorization: adminAuthorization }));
    }
    headerVariants.push(withKickHeaders({}));
  }

  for (const headers of headerVariants){
    for (const endpoint of endpoints){
      try{
        const hdrs = headers && Object.keys(headers).length ? headers : withKickHeaders({});
        const options = hdrs ? { headers: hdrs } : undefined;
        const res = await axios.get(endpoint, options);
        const data = res?.data || {};
        const id = Number(data?.channel?.user_id || data?.channel?.id || data?.user_id || data?.user?.id || data?.id || 0);
        if (id) return { id, raw:data };
        if (data?.channel){
          const nested = Number(data.channel?.user?.id || data.channel?.user_id || 0);
          if (nested) return { id:nested, raw:data.channel };
        }
      }catch(err){
        const status = err?.response?.status;
        if (status && status !== 404 && status !== 401 && status !== 403){
          console.warn('fetchKickChannelInfo attempt failed:', status, err?.message);
        }
      }
    }
  }
  return { id:0, raw:null };
}

async function fetchKickMe(headers){
  const urls = [
    `${KICK_API_BASE}/public/v1/users/me`,
    `${KICK_API_BASE}/public/v1/users/@me`,
    `${KICK_API_BASE}/public/v1/users`
  ];
  for (const url of urls){
    try{
      const data = await axios.get(url, { headers: withKickHeaders(headers) }).then(r=>r.data);
      if (data) return data;
    }catch(err){
      const status = err?.response?.status;
      if (status && [401,403,404].includes(status)) continue;
    }
  }
  return null;
}

function matchKickFollowPayload(payload, broadcasterId){
  if (!payload) return false;
  if (payload === true) return true;
  if (Array.isArray(payload)){
    return payload.some(item => matchKickFollowPayload(item, broadcasterId));
  }
  if (typeof payload === 'string'){
    const slug = dynamicKickSlug || KICK_CHANNEL_SLUG;
    if (slug && payload.toLowerCase() === slug.toLowerCase()) return true;
    return false;
  }
  if (typeof payload === 'object'){
    if (payload.following === true || payload.followed === true || payload.is_following === true) return true;
    if (payload.state && String(payload.state).toLowerCase() === 'following') return true;
    if (payload.channel && matchKickFollowPayload(payload.channel, broadcasterId)) return true;
    if (payload.data && matchKickFollowPayload(payload.data, broadcasterId)) return true;
    if (payload.channel_id && broadcasterId && String(payload.channel_id) === String(broadcasterId)) return true;
    if (payload.broadcaster_user_id && broadcasterId && String(payload.broadcaster_user_id) === String(broadcasterId)) return true;
    if (payload.id && broadcasterId && String(payload.id) === String(broadcasterId)) return true;
    const slug = dynamicKickSlug || KICK_CHANNEL_SLUG;
    if (payload.slug && slug && String(payload.slug).toLowerCase() === slug.toLowerCase()) return true;
  }
  return false;
}

async function getBroadcasterUserId(){
  if (KICK_BROADCASTER_USER_ID) return KICK_BROADCASTER_USER_ID;
  const cachedIdentity = await getCachedKickIdentity();
  if (cachedIdentity?.broadcaster_user_id){
    return Number(cachedIdentity.broadcaster_user_id) || 0;
  }
  const cachedRaw = await kvJsonGet('kick_broadcaster_user_id');
  const cached = Number(cachedRaw||0);
  if (cached) return cached;
  if (!KICK_CHANNEL_SLUG) return 0;
  try{
    const { id, raw } = await fetchKickChannelInfo();
    if (id){
      await cacheKickIdentity({ channel_id: id }, raw);
      await kvJsonSet('kick_broadcaster_user_id', id);
    }
    return id||0;
  }catch(e){
    const status = e?.response?.status;
    console.warn('getBroadcasterUserId fail:', status || '', e?.message);
    return 0;
  }
}
async function adminTokenGet(){
  const tok = await kvJsonGet('kick_admin_token');
  if (!tok) return null;
  if (tok.expires_at && Date.now() < (tok.expires_at - 120*1000)) return tok;
  if (!tok.refresh_token) return tok;
  try{
    const form = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: tok.refresh_token,
      client_id: KICK_CLIENT_ID,
      client_secret: KICK_CLIENT_SECRET
    });
    const r = await axios.post(`${KICK_OAUTH_BASE}/oauth/token`, form, { headers:{'Content-Type':'application/x-www-form-urlencoded'} }).then(r=>r.data);
    const nt = {
      access_token: r.access_token,
      token_type:   r.token_type || 'Bearer',
      refresh_token:r.refresh_token || tok.refresh_token,
      expires_at:   Date.now() + (Number(r.expires_in||3600)*1000)
    };
    await kvJsonSet('kick_admin_token', nt);
    return nt;
  }catch(e){ console.warn('adminToken refresh fail:', e?.message); return tok; }
}
async function adminAuthHeader(){
  const tok = await adminTokenGet();
  if (!tok?.access_token) return null;
  return `${tok.token_type||'Bearer'} ${tok.access_token}`;
}

async function checkKickFollowWithUser(headers, broadcasterId){
  if (!headers?.Authorization) return false;
  const H = withKickHeaders(headers);
  const identity = await getCachedKickIdentity();
  const slug = identity?.slug || dynamicKickSlug || KICK_CHANNEL_SLUG || '';
  const channelId = Number(identity?.channel_id || 0) || (broadcasterId || 0);
  const attempts = [];
  if (broadcasterId){
    attempts.push(async ()=>{
      const { status, data } = await axios.get(`${KICK_API_BASE}/public/v1/users/me/follows/channels/${encodeURIComponent(broadcasterId)}`, { headers:H }).then(r=>({ status:r.status, data:r.data }));
      if (matchKickFollowPayload(data, broadcasterId)) return true;
      if (status === 200 && Object.keys(data||{}).length === 0) return true;
      return false;
    });
  }
  if (channelId){
    attempts.push(async ()=>{
      const { data } = await axios.get(`${KICK_API_BASE}/public/v1/users/me/follows/channels/${encodeURIComponent(channelId)}`, { headers:H }).then(r=>({ status:r.status, data:r.data }));
      return matchKickFollowPayload(data, broadcasterId || channelId);
    });
  }
  if (slug){
    attempts.push(async ()=>{
      const { data } = await axios.get(`${KICK_API_BASE}/public/v1/users/me/follows/channels/${encodeURIComponent(slug)}`, { headers:H }).then(r=>({ status:r.status, data:r.data }));
      return matchKickFollowPayload(data, broadcasterId || channelId);
    });
    attempts.push(async ()=>{
      const info = await fetchKickChannelInfo(H);
      if (info?.raw && matchKickFollowPayload(info.raw, broadcasterId || channelId)){
        await cacheKickIdentity(info.raw);
        return true;
      }
      if (info?.raw?.is_following === true) return true;
      return false;
    });
  }
  attempts.push(async ()=>{
    const resp = await axios.get(`${KICK_API_BASE}/public/v1/users/me/follows/channels`, { headers:H, params:{ limit:200 } }).then(r=>r.data);
    return matchKickFollowPayload(resp, broadcasterId);
  });

  for (const attempt of attempts){
    try{
      const ok = await attempt();
      if (ok) return true;
    }catch(err){
      const status = err?.response?.status;
      if (status === 200) return true;
      if (status && [401,403,404].includes(status)) continue;
    }
  }
  return false;
}

async function followKickChannel(headers, broadcasterId){
  if (!headers?.Authorization) return false;
  const identity = await getCachedKickIdentity();
  const channelId = Number(identity?.channel_id || 0) || (broadcasterId || 0);
  const slug = identity?.slug || dynamicKickSlug || KICK_CHANNEL_SLUG || '';
  if (!channelId && !slug && !broadcasterId) return false;
  const H = withKickHeaders({ ...headers, 'Content-Type':'application/json' });
  const payloads = [];
  if (channelId){
    payloads.push({ channel_id: channelId });
  }
  if (broadcasterId){
    payloads.push({ channel_id: channelId || broadcasterId, broadcaster_user_id: broadcasterId });
  }
  if (slug){
    payloads.push({ channel_id: channelId || broadcasterId || undefined, slug });
  }
  if (!payloads.length){
    payloads.push({});
  }
  const endpointSet = new Set([
    `${KICK_API_BASE}/public/v1/users/me/follows/channels`,
    channelId ? `${KICK_API_BASE}/public/v1/users/me/follows/channels/${encodeURIComponent(channelId)}` : null,
    broadcasterId ? `${KICK_API_BASE}/public/v1/users/me/follows/channels/${encodeURIComponent(broadcasterId)}` : null,
    slug ? `${KICK_API_BASE}/public/v1/users/me/follows/channels/${encodeURIComponent(slug)}` : null,
    slug ? `https://kick.com/api/v1/channels/${encodeURIComponent(slug)}/follow` : null
  ].filter(Boolean));

  for (const endpoint of endpointSet){
    for (const body of payloads){
      const payload = { ...body };
      if (payload.channel_id) payload.channel_id = Number(payload.channel_id);
      if (payload.broadcaster_user_id) payload.broadcaster_user_id = Number(payload.broadcaster_user_id);
      if (!payload.channel_id && channelId) payload.channel_id = channelId;
      if (!payload.slug && slug && endpoint.includes('/channels/')) payload.slug = slug;
      try{
        const resp = await axios.post(endpoint, endpoint.includes('kick.com/api/') ? {} : payload, { headers:H });
        if (resp?.status && resp.status >=200 && resp.status<300) return true;
      }catch(err){
        const status = err?.response?.status;
        if (status && [200,201,204,208,409].includes(status)) return true;
      }
    }
  }
  return false;
}

async function reconcileKickFollowFromLog(participantId, { kickUserId, kickUsername }={}){
  try{
    const kid = kickUserId ? String(kickUserId) : '';
    const kun = kickUsername ? String(kickUsername).trim().toLowerCase() : '';
    if (!kid && !kun) return false;
    const since = Date.now() - 24*60*60*1000;
    const rows = await dbAll(`SELECT id,payload_json,received_at FROM kick_event_log WHERE event_type='channel.followed' AND received_at>=? ORDER BY received_at DESC`, [since]);
    let match = null;
    for (const row of rows){
      let payload=null;
      try{ payload = JSON.parse(row.payload_json||'{}'); }catch(_){ payload=null; }
      if(!payload) continue;
      const follower = payload?.follower || {};
      const rowKid = follower?.user_id ? String(follower.user_id) : '';
      const rowKun = follower?.username ? String(follower.username).trim().toLowerCase() : '';
      const kidMatch = kid && rowKid && rowKid===kid;
      const kunMatch = kun && rowKun && rowKun===kun;
      if (kidMatch || kunMatch){
        match = {
          row,
          kid: rowKid || kid,
          kun: rowKun || kun
        };
        break;
      }
    }
    if (!match) return false;
    const now = Date.now();
    const updates = {
      kick_verified: 1,
      kick_verified_at: match.row?.received_at || now,
      kick_verified_by: 'webhook',
      updated_at: now
    };
    if (match.kid) updates.kick_user_id = match.kid;
    if (match.kun) updates.kick_username = match.kun;
    const keys = Object.keys(updates);
    const setSql = keys.map(k=>`${k}=?`).join(', ');
    const vals = keys.map(k=>updates[k]);
    await dbRun(`UPDATE participants SET ${setSql} WHERE id=?`, [...vals, participantId]);
    await issueTicketIfReady(participantId);
    await broadcastStatus(participantId);
    if (match.row?.id){
      await dbRun(`UPDATE kick_event_log SET handled_ok=1 WHERE id=?`, [match.row.id]);
    }
    return true;
  }catch(e){
    console.error('reconcileKickFollowFromLog error:', e?.message || e);
    return false;
  }
}
async function ensureKickFollowSubscription(){
  try{
    const Authorization = await adminAuthHeader();
    if (!Authorization) return {ok:false, error:'no_admin_token'};
    if (!KICK_WEBHOOK_URL) return {ok:false, error:'no_webhook_url'};
    const H = withKickHeaders({ Authorization });

    let broadcaster_user_id = await getBroadcasterUserId();
    if (!broadcaster_user_id){
      const profile = await fetchKickMe(H);
      const cached = await cacheKickIdentity(profile);
      if (cached?.broadcaster_user_id) broadcaster_user_id = cached.broadcaster_user_id;
      if (!broadcaster_user_id){
        const { id, raw } = await fetchKickChannelInfo(H);
        if (id){
          const cachedInfo = await cacheKickIdentity({ channel_id: id }, raw);
          broadcaster_user_id = cachedInfo?.broadcaster_user_id || id;
        }
      }
    }
    if (!broadcaster_user_id) return {ok:false, error:'no_broadcaster'};

    const list = await axios.get(`${KICK_API_BASE}/public/v1/events/subscriptions`, { headers:H })
                            .then(r=>r.data?.data || [])
                            .catch(()=>[]);
    const hasFollow = list.some(s => String(s.event||s.name)==='channel.followed' &&
                                     String(s.broadcaster_user_id)===String(broadcaster_user_id) &&
                                     (!KICK_WEBHOOK_URL || String(s.callback||s.url||s.webhook_url||'').replace(/\/$/,'')===KICK_WEBHOOK_URL.replace(/\/$/,'')));
    if (!hasFollow){
      await axios.post(`${KICK_API_BASE}/public/v1/events/subscriptions`, {
        events: [{ name:'channel.followed', version:1 }],
        method: 'webhook',
        broadcaster_user_id,
        callback_url: KICK_WEBHOOK_URL,
        webhook_url: KICK_WEBHOOK_URL,
        url: KICK_WEBHOOK_URL,
        secret: KICK_WEBHOOK_SECRET || undefined
      }, { headers: { ...withKickHeaders(H), 'Content-Type':'application/json' } });
    }
    return {ok:true};
  }catch(e){
    console.error('ensureKickFollowSubscription error:', e?.response?.data || e?.message);
    return {ok:false, error: e?.message || 'ensure_failed'};
  }
}

// ===== Kick OAuth =====

// Admin Connect — единый redirect_uri, другой state-префикс
app.get('/api/kick/connect-admin', async (req,res)=>{
  try{
    if(!KICK_CLIENT_ID || !KICK_REDIRECT_URI) return res.status(500).send('kick oauth not configured');

    await ensureOAuthStatesTable(); // авто‑миграция на лету (важно для старых БД)

    const {verifier, challenge} = makePkce();
    const state = `admin:${crypto.randomBytes(8).toString('hex')}`;
    await dbRun(
      `INSERT OR IGNORE INTO oauth_states(state,participant_id,verifier,created_at) VALUES(?,?,?,?)`,
      [state, null, verifier, Date.now()]
    );
    const u = new URL(`${KICK_OAUTH_BASE}/oauth/authorize`);
    u.searchParams.set('client_id', KICK_CLIENT_ID);
    u.searchParams.set('redirect_uri', KICK_REDIRECT_URI); // единый callback
    u.searchParams.set('response_type','code');
    u.searchParams.set('scope', KICK_ADMIN_SCOPE || 'user:read events:subscribe user:email'); // права для подписок
    u.searchParams.set('code_challenge', challenge);
    u.searchParams.set('code_challenge_method', 'S256');
    u.searchParams.set('state', state);
    res.redirect(u.toString());
  }catch(e){
    console.error('connect-admin failed:', e?.message||e);
    res.status(500).send('oauth_admin_connect_failed');
  }
});

// User Connect — как было (но с ensure перед вставкой)
app.get('/api/kick/connect', async (req,res)=>{
  try{
    const pid = Number(req.query.pid); if(!pid) return res.status(400).send('bad pid');
    if(!KICK_CLIENT_ID || !KICK_REDIRECT_URI) return res.status(500).send('kick oauth not configured');

    await ensureOAuthStatesTable(); // авто‑миграция на лету

    const {verifier, challenge} = makePkce();
    const state = `pid:${pid}:${crypto.randomBytes(8).toString('hex')}`;
    await dbRun(
      `INSERT OR IGNORE INTO oauth_states(state,participant_id,verifier,created_at) VALUES(?,?,?,?)`,
      [state,pid,verifier,Date.now()]
    );
    const u = new URL(`${KICK_OAUTH_BASE}/oauth/authorize`);
    u.searchParams.set('client_id', KICK_CLIENT_ID);
    u.searchParams.set('redirect_uri', KICK_REDIRECT_URI);
    u.searchParams.set('response_type','code');
    u.searchParams.set('scope', KICK_USER_SCOPE || 'user:read user:email'); // пользователю лишнее не показываем
    u.searchParams.set('code_challenge', challenge);
    u.searchParams.set('code_challenge_method', 'S256');
    u.searchParams.set('state', state);
    res.redirect(u.toString());
  }catch(e){ res.status(500).send('error'); }
});

// ЕДИНЫЙ callback для admin+user
app.get('/api/kick/oauth', async (req,res)=>{
  try{
    const code  = String(req.query.code||'');
    const state = String(req.query.state||'');
    if(!code || !state) return res.status(400).send('bad state/code');

    // достаём verifier из oauth_states по state
    const row = await dbGet(`SELECT * FROM oauth_states WHERE state=?`, [state]);
    if(!row) return res.status(400).send('bad state/code');

    // одноразовый state
    await dbRun(`DELETE FROM oauth_states WHERE state=?`, [state]);

    // обмен code->token
    const form = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: KICK_REDIRECT_URI,
      client_id: KICK_CLIENT_ID,
      code_verifier: row.verifier
    });
    if (KICK_CLIENT_SECRET) form.set('client_secret', KICK_CLIENT_SECRET);

    const tok = await axios.post(`${KICK_OAUTH_BASE}/oauth/token`, form, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    }).then(r=>r.data);

    const headers = { Authorization: `${tok.token_type||'Bearer'} ${tok.access_token}` };

    const isAdmin = state.startsWith('admin:');
    if (isAdmin){
      // ADMIN FLOW
      const at = {
        access_token: tok.access_token,
        token_type:   tok.token_type || 'Bearer',
        refresh_token: tok.refresh_token || null,
        expires_at:   Date.now() + (Number(tok.expires_in||3600)*1000)
      };
      await kvSet('kick_admin_token', at);
      try{
        const profile = await fetchKickMe(headers);
        let cached = null;
        if (profile){
          cached = await cacheKickIdentity(profile);
        }
        if (!cached){
          const { raw, id } = await fetchKickChannelInfo(headers);
          if (raw || id){
            await cacheKickIdentity({ channel_id: id }, raw);
          }
        }
      }catch(err){
        console.warn('admin identity cache fail:', err?.message);
      }
      await ensureKickFollowSubscription(); // гарантируем подписку на follow
      return res.redirect('/admin?kick_connected=1');
    }

    // USER FLOW
    const pidStr = state.split(':')[1] || '';
    const pid = Number(pidStr||0);
    if (!pid) return res.status(400).send('bad pid');

    const me = await fetchKickMe(headers);

    const kid = String(me?.id || me?.user_id || me?.user?.id || '');
    const kunSrc = me?.username || me?.user?.username || me?.name || '';
    const kun = kunSrc ? String(kunSrc).trim().toLowerCase() : '';
    const kem = me?.email ? String(me.email).toLowerCase()
              : (me?.user?.email ? String(me.user.email).toLowerCase() : null);

    if (kid || kun || kem) {
      await dbRun(`UPDATE participants SET kick_user_id=?, kick_username=?, kick_email=?, updated_at=? WHERE id=?`,
                  [kid||null,kun||null,kem,Date.now(),pid]);
    }

    if (me){
      await cacheKickIdentity(me);
    }
    const participantState = await dbGet(`SELECT kick_verified,kick_verified_by FROM participants WHERE id=?`,[pid]);
    let followVerified = !!participantState?.kick_verified;
    let verifiedByWebhook = false;
    const needsWebhookReconcile = !participantState?.kick_verified || !participantState?.kick_verified_by;
    if (needsWebhookReconcile){
      verifiedByWebhook = await reconcileKickFollowFromLog(pid, { kickUserId:kid, kickUsername:kun });
      if (verifiedByWebhook){
        followVerified = true;
      }
    }

    const broadcasterId = await getBroadcasterUserId();
    if (!followVerified){
      followVerified = await checkKickFollowWithUser(headers, broadcasterId);
      if (!followVerified){
        const autoFollowed = await followKickChannel(headers, broadcasterId);
        if (autoFollowed){
          followVerified = await checkKickFollowWithUser(headers, broadcasterId);
        }
      }
      if (!followVerified){
        await delay(800);
        followVerified = await checkKickFollowWithUser(headers, broadcasterId);
      }
    }

    if (participantState?.kick_verified && !participantState?.kick_verified_by && !verifiedByWebhook) {
      await dbRun(`UPDATE participants SET kick_verified_by=?, updated_at=? WHERE id=?`, ['oauth-check', Date.now(), pid]);
    }

    if (followVerified && !participantState?.kick_verified && !verifiedByWebhook) {
      const now = Date.now();
      const updates = {
        kick_verified: 1,
        kick_verified_at: now,
        kick_verified_by: 'oauth-check',
        updated_at: now
      };
      if (kid) updates.kick_user_id = kid;
      if (kun) updates.kick_username = kun;
      const keys = Object.keys(updates);
      const sql = keys.map(k=>`${k}=?`).join(', ');
      const vals = keys.map(k=>updates[k]);
      await dbRun(`UPDATE participants SET ${sql} WHERE id=?`, [...vals, pid]);
      await issueTicketIfReady(pid);
      await broadcastStatus(pid);
    }

    ensureKickFollowSubscription().catch(()=>{});

    if (KICK_CHANNEL_SLUG) {
      return res.redirect(`https://kick.com/${encodeURIComponent(KICK_CHANNEL_SLUG)}`);
    }
    res.send('Kick connected. Please follow the channel and return to the website.');
  }catch(e){
    console.error('oauth error:', e?.response?.data || e?.message);
    res.status(500).send('oauth_error');
  }
});

// ===== Kick webhook (channel.followed) =====
let KICK_PUBLIC_KEY_PEM = null;
async function loadKickPublicKey(){
  try{
    const r = await axios.get(`${KICK_API_BASE}/public/v1/public-key`);
    KICK_PUBLIC_KEY_PEM = r?.data?.public_key || null;
  }catch(e){ /* ignore */ }
}
if (KICK_VERIFY_SIGNATURE) { loadKickPublicKey(); setInterval(loadKickPublicKey, 6*60*60*1000); }

app.post('/api/kick/webhook', async (req,res)=>{
  try{
    const evType = String(req.headers['kick-event-type']||'');
    const mid    = String(req.headers['kick-event-message-id']||'');
    const ts     = String(req.headers['kick-event-message-timestamp']||'');
    const sig    = String(req.headers['kick-event-signature']||'');

    if (KICK_VERIFY_SIGNATURE && KICK_PUBLIC_KEY_PEM){
      try{
        const base = `${mid}.${ts}.${(req.rawBody||Buffer.from('')).toString()}`;
        const ok = crypto.createVerify('RSA-SHA256').update(base).verify(KICK_PUBLIC_KEY_PEM, sig, 'base64');
        if(!ok){ console.warn('Kick webhook signature invalid'); return res.json({ok:true}); }
      }catch(_){ return res.json({ok:true}); }
    }

    if (mid) {
      try{ await dbRun(`INSERT INTO kick_event_log(message_id,event_type,payload_json,received_at,handled_ok) VALUES(?,?,?,?,0)`,
        [mid,evType,JSON.stringify(req.body||{}),Date.now()]); }catch(_){}
    }

    let handledOk = false;
    if (evType === 'channel.followed') {
      const follower = req.body?.follower || {};
      const kid = follower?.user_id ? String(follower.user_id) : '';
      const kun = follower?.username ? String(follower.username).trim().toLowerCase() : '';
      const now = Date.now();
      const updates = {
        kick_verified: 1,
        kick_verified_at: now,
        kick_verified_by: 'webhook',
        updated_at: now
      };
      if (kid) updates.kick_user_id = kid;
      if (kun) updates.kick_username = kun;
      const keys = Object.keys(updates);
      const setSql = keys.map(k=>`${k}=?`).join(', ');
      const vals = keys.map(k=>updates[k]);
      const processed = new Set();
      if (kid){
        const list = await dbAll(`SELECT id FROM participants WHERE kick_user_id=?`,[kid]);
        for (const row of list||[]){
          processed.add(row.id);
          await dbRun(`UPDATE participants SET ${setSql} WHERE id=?`, [...vals,row.id]);
          await broadcastStatus(row.id);
          await issueTicketIfReady(row.id);
          handledOk = true;
        }
      }
      if (!handledOk && kun){
        const listByName = await dbAll(`SELECT id FROM participants WHERE LOWER(kick_username)=?`,[kun]);
        for (const row of listByName||[]){
          if (processed.has(row.id)) continue;
          await dbRun(`UPDATE participants SET ${setSql} WHERE id=?`, [...vals,row.id]);
          await broadcastStatus(row.id);
          await issueTicketIfReady(row.id);
          handledOk = true;
        }
      }
    }

    if (mid && handledOk) await dbRun(`UPDATE kick_event_log SET handled_ok=1 WHERE message_id=?`,[mid]);
    res.json({ok:true});
  }catch(e){
    console.error('kick webhook err:', e.message);
    res.json({ok:true});
  }
});

// ===== Telegram webhook =====
app.post('/api/tg/webhook', async (req,res)=>{
  res.json({ok:true});
  try{
    if(!TG_TOKEN) return;
    const u=req.body||{}, msg=u.message, cb=u.callback_query;
    const chatId=msg?.chat?.id || cb?.message?.chat?.id;
    const user  =msg?.from       || cb?.from;
    if(!user||!chatId) return;

    if (msg && msg.chat?.type==='private' && msg.text && /^\/start/.test(msg.text)) {
      const parts=msg.text.trim().split(/\s+/,2);
      const payload=parts[1]||'';
      const lang=pickLang(user.language_code);
      await saveUserLang(user.id,user.username,lang);

      if (payload) {
        const pid=await consumeLinkToken(payload);
        if(pid){
          const now=Date.now();
          try{
            await dbExec('BEGIN IMMEDIATE;');
            await dbRun(`UPDATE participants SET tg_id=NULL, tg_username=NULL, updated_at=? WHERE tg_id=? AND id<>?`,
                        [now,String(user.id),pid]);
            await dbRun(`UPDATE participants SET tg_id=?, tg_username=?, updated_at=? WHERE id=?`,
                        [String(user.id),(user.username||'').toLowerCase(),now,pid]);
            await dbExec('COMMIT;');
          }catch(e){ try{await dbExec('ROLLBACK;');}catch{} }
          await broadcastStatus(pid);
        }
      }
      const T=I18N[lang]||I18N.ua;
      await tgCall('sendMessage',{chat_id:chatId,text:`${T.hi(user.first_name)}\n${T.start_line(TG_CHANNEL)}`,reply_markup:startMarkup(T),parse_mode:'Markdown'});
      return;
    }

    if (cb) {
      const data=cb.data||'';
      const {T,lang}=await getT(user);

      if (data==='lang_menu'){ await safeEdit(cb,T.lang_title,langMarkup(T,lang)); await tgCall('answerCallbackQuery',{callback_query_id:cb.id}); return; }
      if (data.startsWith('lang:set:')){ const newL = data.endsWith(':en')?'en':'ua'; await saveUserLang(user.id,user.username,newL);
        const T2=I18N[newL]; await tgCall('answerCallbackQuery',{callback_query_id:cb.id,text:T2.toast_lang_set});
        await safeEdit(cb, `${T2.hi(user.first_name)}\n${T2.start_line(TG_CHANNEL)}`, startMarkup(T2)); return; }
      if (data==='back_to_menu'){ await safeEdit(cb, `${T.hi(user.first_name)}\n${T.start_line(TG_CHANNEL)}`, startMarkup(T)); await tgCall('answerCallbackQuery',{callback_query_id:cb.id}); return; }

      if (data==='check_sub'){
        let member=false;
        try{
          const r=await tgCall('getChatMember',{chat_id:TG_CHANNEL,user_id:user.id});
          const st=r?.result?.status;
          member=['creator','administrator','member'].includes(st);
        }catch{}
        if(!member){
          await tgCall('answerCallbackQuery',{callback_query_id:cb.id,text:T.not_member_alert(TG_CHANNEL),show_alert:true});
          return;
        }
        const now=Date.now();
        await dbRun(
          `INSERT INTO participants(tg_id,tg_username,tg_verified,created_at,updated_at)
           VALUES(?,?,?,?,?)
           ON CONFLICT(tg_id) DO UPDATE SET tg_username=excluded.tg_username, tg_verified=1, updated_at=excluded.updated_at`,
          [String(user.id),(user.username||'').toLowerCase(),1,now,now]
        );
        const p=await dbGet(`SELECT id FROM participants WHERE tg_id=? ORDER BY id DESC LIMIT 1`,[String(user.id)]);
        if(p?.id){ await issueTicketIfReady(p.id); await broadcastStatus(p.id); }
        await safeEdit(cb,T.verified_msg,startMarkup(T));
        await tgCall('answerCallbackQuery',{callback_query_id:cb.id,text:T.toast_verified});
        return;
      }

      if (data==='wallet:start'){
        await dbRun(`UPDATE participants SET wallet_pending=1 WHERE tg_id=?`,[String(user.id)]);
        await tgCall('sendMessage',{chat_id:chatId,text:T.ask_wallet,parse_mode:'Markdown'});
        await tgCall('answerCallbackQuery',{callback_query_id:cb.id});
        return;
      }
    }

    if (msg && msg.chat?.type==='private' && msg.text){
      const row=await dbGet(`SELECT wallet_pending FROM participants WHERE tg_id=?`,[String(user.id)]);
      if (row?.wallet_pending){
        const {T}=await getT(user);
        const addr=msg.text.trim();
        if (/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(addr)){
          await dbRun(`UPDATE participants SET wallet_trc20=?, wallet_updated_at=?, wallet_pending=0 WHERE tg_id=?`,
                      [addr,Date.now(),String(user.id)]);
          await tgCall('sendMessage',{chat_id:chatId,text:T.wallet_saved});
        }else{
          await tgCall('sendMessage',{chat_id:chatId,text:T.wallet_invalid,parse_mode:'Markdown'});
        }
      }
    }
  }catch(e){ console.error('Webhook err:',e.message); }
});

// ===== Admin (BasicAuth) =====
const adminAuth = basicAuth({ users: { [ADMIN_USER]: ADMIN_PASS }, challenge: true });
app.use('/admin/api', adminAuth);

app.get('/admin/api/users', async (req,res)=>{
  try{
    const q = String(req.query.q||'').trim();
    const tg = req.query.tg;     // '1'|'0'
    const k  = req.query.kick;   // '1'|'0'
    const t  = req.query.has_ticket; // '1'
    const c  = String(req.query.country||'').toUpperCase();
    const sort = String(req.query.sort||'id_desc');
    const limit  = Math.min(Math.max(parseInt(req.query.limit||300,10),1),2000);
    const offset = Math.max(parseInt(req.query.offset||0,10),0);

    const where=[]; const p=[];
    if(q){
      where.push('(id LIKE ? OR tg_username LIKE ? OR tg_id LIKE ? OR ticket_no LIKE ? OR ip_country LIKE ? OR wallet_trc20 LIKE ? OR kick_username LIKE ? OR kick_email LIKE ?)');
      p.push(`%${q}%`,`%${q}%`,`%${q}%`,`%${q}%`,`%${q}%`,`%${q}%`,`%${q}%`,`%${q}%`);
    }
    if(tg==='1') where.push('tg_verified=1');
    if(tg==='0') where.push('tg_verified=0');
    if(k==='1')  where.push('kick_verified=1');
    if(k==='0')  where.push('kick_verified=0');
    if(t==='1')  where.push('ticket_no IS NOT NULL');
    if(c) { where.push('ip_country=?'); p.push(c); }

    const ws=where.length?('WHERE '+where.join(' AND ')):'';
    let order='ORDER BY id DESC';
    if (sort==='id_asc') order='ORDER BY id ASC';
    else if (sort==='created_desc') order='ORDER BY created_at DESC';
    else if (sort==='created_asc')  order='ORDER BY created_at ASC';
    else if (sort==='ticket_desc')  order='ORDER BY ticket_no DESC';
    else if (sort==='ticket_asc')   order='ORDER BY ticket_no ASC';

    const rows=await dbAll(`
      SELECT id,tg_id,tg_username,tg_verified,
             kick_verified,kick_verified_by,kick_user_id,kick_username,kick_email,
             ticket_no,ip_country,lang,created_at,updated_at,ticket_sent_at,wallet_trc20,wallet_updated_at,wallet_pending
      FROM participants
      ${ws} ${order}
      LIMIT ? OFFSET ?`,[...p,limit,offset]);

    const next = rows.length===limit ? (offset+rows.length) : null;
    res.json({ok:true,rows,next_offset:next});
  }catch(e){ res.status(500).json({ok:false,error:e.message}); }
});

app.get('/admin/api/stats', async (_req,res)=>{
  try{
    const a = await dbGet(`SELECT COUNT(1) AS c FROM participants WHERE ticket_no IS NOT NULL`);
    const b = await dbGet(`SELECT COUNT(1) AS c FROM participants WHERE tg_verified=1`);
    const c = await dbGet(`SELECT COUNT(1) AS c FROM participants WHERE kick_verified=1`);
    res.json({ok:true,tickets:a.c|0,tg:b.c|0,kick:c.c|0});
  }catch(e){ res.status(500).json({ok:false}); }
});

app.post('/admin/api/message', async (req,res)=>{
  try{
    const {pid,text}=req.body||{}; if(!pid||!text) return res.status(400).json({ok:false,error:'bad_args'});
    const r=await dbGet(`SELECT tg_id FROM participants WHERE id=?`,[Number(pid)]);
    if(!r?.tg_id) return res.status(404).json({ok:false,error:'no_tg'});
    const s=await tgCall('sendMessage',{chat_id:r.tg_id,text:String(text)});
    res.json({ok:!!s?.ok, error:s?.error});
  }catch(e){ res.status(500).json({ok:false,error:e.message}); }
});

app.post('/admin/api/wallet/request', async (req,res)=>{
  try{
    const pid=Number(req.body?.pid); if(!pid) return res.status(400).json({ok:false,error:'pid required'});
    const r=await dbGet(`SELECT tg_id,lang FROM participants WHERE id=?`,[pid]); if(!r?.tg_id) return res.status(404).json({ok:false,error:'no_tg'});
    const T=I18N[r.lang||'ua']||I18N.ua;
    await dbRun(`UPDATE participants SET wallet_pending=1 WHERE id=?`,[pid]);
    const sent=await tgCall('sendMessage',{chat_id:r.tg_id,text: T.ask_wallet, parse_mode:'Markdown'});
    res.json({ok:!!sent?.ok});
  }catch(e){ res.status(500).json({ok:false,error:e.message}); }
});
app.post('/admin/api/wallet/clear', async (req,res)=>{
  try{
    const pid=Number(req.body?.pid); if(!pid) return res.status(400).json({ok:false,error:'pid required'});
    await dbRun(`UPDATE participants SET wallet_trc20=NULL, wallet_updated_at=NULL, wallet_pending=0 WHERE id=?`,[pid]);
    res.json({ok:true});
  }catch(e){ res.status(500).json({ok:false,error:e.message}); }
});

app.post('/admin/api/ticket/resend', async (req,res)=>{
  try{
    const pid=Number(req.body?.pid); if(!pid) return res.status(400).json({ok:false,error:'pid required'});
    const u=await dbGet(`SELECT ticket_no,lang FROM participants WHERE id=?`,[pid]); if(!u?.ticket_no) return res.json({ok:false,error:'no_ticket'});
    const ok=await sendTicket(pid,u.ticket_no,u.lang); res.json({ok});
  }catch(e){ res.status(500).json({ok:false,error:e.message}); }
});

app.post('/admin/api/cleanup', async (req,res)=>{
  try{
    const older= Math.max(Number(req.body?.older_than_m||240),1);
    const max  = Math.min(Math.max(Number(req.body?.max_rows||5000),1),50000);
    const th = Date.now()-older*60*1000;
    const ids=await dbAll(`
      SELECT id FROM participants
      WHERE tg_verified=0 AND kick_verified=0
        AND ticket_no IS NULL
        AND (tg_id IS NULL OR tg_id='')
        AND created_at IS NOT NULL AND created_at < ?
      LIMIT ?`,[th,max]);
    if(!ids.length) return res.json({ok:true,deleted:0});
    const list=ids.map(r=>r.id); const ph=list.map(_=>'?').join(',');
    await dbRun(`DELETE FROM tg_link_tokens WHERE participant_id IN (${ph})`,list);
    const r=await dbRun(`DELETE FROM participants WHERE id IN (${ph})`,list);
    res.json({ok:true,deleted:r?.changes||0});
  }catch(e){ res.status(500).json({ok:false,error:e.message}); }
});

app.post('/admin/api/wipe', async (req,res)=>{
  try{
    const phrase = String(req.body?.phrase||'');
    if (phrase !== 'WIPE-ALL-YES') return res.status(400).json({ok:false,error:'bad_phrase'});
    await dbExec('BEGIN IMMEDIATE;');
    const w1 = await dbRun(`DELETE FROM winners`);
    const w2 = await dbRun(`DELETE FROM tg_link_tokens`);
    const w3 = await dbRun(`DELETE FROM participants`);
    await dbRun(`UPDATE seq_ticket SET last=0`);
    await dbExec('COMMIT;');
    res.json({ok:true, winners_deleted:w1?.changes||0, tokens_deleted:w2?.changes||0, users_deleted:w3?.changes||0});
  }catch(e){ try{await dbExec('ROLLBACK;');}catch{} res.status(500).json({ok:false,error:e.message}); }
});

app.delete('/admin/api/users/:id', async (req,res)=>{
  try{
    const id=Number(req.params.id); if(!id) return res.status(400).json({ok:false,error:'bad_id'});
    await dbRun(`DELETE FROM tg_link_tokens WHERE participant_id=?`,[id]);
    const r=await dbRun(`DELETE FROM participants WHERE id=?`,[id]);
    res.json({ok:(r?.changes||0)>0,deleted:r?.changes||0});
  }catch(e){ res.status(500).json({ok:false,error:e.message}); }
});

app.get('/admin/api/winners', async (req,res)=>{
  try{
    const q=String(req.query.q||'').trim();
    const limit=Math.min(Math.max(parseInt(req.query.limit||300,10),1),2000);
    const offset=Math.max(parseInt(req.query.offset||0,10),0);
    const where=[]; const p=[];
    if(q){ where.push('(w.ticket_no LIKE ? OR p.tg_username LIKE ? OR p.wallet_trc20 LIKE ?)'); p.push(`%${q}%`,`%${q}%`,`%${q}%`); }
    const ws=where.length?('WHERE '+where.join(' AND ')):'';
    const rows=await dbAll(`
      SELECT w.id,w.prize,w.paid,w.noted_at,w.ticket_no,
             p.id AS participant_id,p.tg_username,p.ip_country,p.wallet_trc20
      FROM winners w
      JOIN participants p ON p.id=w.participant_id
      ${ws}
      ORDER BY w.id DESC
      LIMIT ? OFFSET ?`,[...p,limit,offset]);
    res.json({ok:true,rows});
  }catch(e){ res.status(500).json({ok:false,error:e.message}); }
});
app.post('/admin/api/winners/add', async (req,res)=>{
  try{
    const ticket=Number(req.body?.ticket_no); const prize=String(req.body?.prize||'');
    if(!ticket) return res.status(400).json({ok:false,error:'ticket required'});
    const p=await dbGet(`SELECT id FROM participants WHERE ticket_no=?`,[ticket]); if(!p?.id) return res.status(404).json({ok:false,error:'ticket_not_found'});
    await dbRun(`INSERT INTO winners(participant_id,ticket_no,prize,noted_at,paid) VALUES(?,?,?,?,0)`,[p.id,ticket,prize,Date.now()]);
    res.json({ok:true});
  }catch(e){ res.status(500).json({ok:false,error:e.message}); }
});
app.post('/admin/api/winners/pay', async (req,res)=>{
  try{
    const id=Number(req.body?.id), paid=Number(req.body?.paid?1:0);
    if(!id) return res.status(400).json({ok:false,error:'id required'});
    await dbRun(`UPDATE winners SET paid=? WHERE id=?`,[paid,id]);
    res.json({ok:true});
  }catch(e){ res.status(500).json({ok:false,error:e.message}); }
});
app.delete('/admin/api/winners/:id', async (req,res)=>{
  try{
    const id=Number(req.params.id); if(!id) return res.status(400).json({ok:false,error:'bad_id'});
    const r=await dbRun(`DELETE FROM winners WHERE id=?`,[id]);
    res.json({ok:(r?.changes||0)>0});
  }catch(e){ res.status(500).json({ok:false,error:e.message}); }
});

app.get('/admin/api/export/wallets.csv', adminAuth, async (_req,res)=>{
  try{
    const rows=await dbAll(`SELECT ticket_no,tg_username,ip_country,wallet_trc20 FROM participants WHERE ticket_no IS NOT NULL AND wallet_trc20 IS NOT NULL ORDER BY ticket_no ASC`);
    res.setHeader('Content-Type','text/csv; charset=utf-8');
    res.setHeader('Content-Disposition','attachment; filename="wallets.csv"');
    res.write('ticket,username,country,wallet\n');
    for(const r of rows){ res.write(`${pad7(r.ticket_no)},${r.tg_username||''},${r.ip_country||''},${r.wallet_trc20||''}\n`); }
    res.end();
  }catch(_){ res.status(500).end('error'); }
});

// ===== Admin UI (Kick Username/Email + панель Kick Webhooks) =====
function buildAdminHtml(){
  return String.raw`<!doctype html>
<html lang="uk">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Francuz1k • Admin</title>
<style>
:root{
  --bg:#040b0d;
  --bg-panel:#0d1d21;
  --bg-panel-soft:rgba(10,26,30,0.8);
  --border:rgba(0,255,170,0.18);
  --accent:#00ffaa;
  --accent-2:#39ffb6;
  --text:#d8ffef;
  --text-muted:#82b6a5;
  --danger:#ff7d7d;
  --success:#4cffb5;
}
*{box-sizing:border-box;font-family:"Segoe UI",system-ui,sans-serif;}
body{margin:0;background:radial-gradient(circle at top,#0f2d2d 0%,rgba(4,11,13,0.92) 45%,#030708 100%);color:var(--text);min-height:100vh;}
a{color:inherit;text-decoration:none;}
button{font:inherit;}
input,select,button{border-radius:10px;border:1px solid rgba(0,255,170,0.2);background:rgba(8,24,27,0.85);color:var(--text);padding:10px 12px;}
input:focus,select:focus,button:focus{outline:none;box-shadow:0 0 0 2px rgba(0,255,170,0.25);}
.button{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:10px 16px;border-radius:10px;border:1px solid rgba(0,255,170,0.3);background:linear-gradient(135deg,rgba(0,255,170,0.25),rgba(0,255,170,0.08));color:var(--text);cursor:pointer;transition:transform .2s ease,box-shadow .2s ease;}
.button:hover{transform:translateY(-1px);box-shadow:0 8px 20px rgba(0,255,170,0.2);}
.button.secondary{background:rgba(0,255,170,0.1);}
.button.ghost{background:transparent;border-color:rgba(0,255,170,0.2);}
.button.danger{border-color:var(--danger);color:var(--danger);background:rgba(255,80,80,0.08);}
.button.small{padding:6px 10px;font-size:13px;}
.button.xs{padding:4px 8px;font-size:12px;}
.button:disabled{opacity:.5;cursor:not-allowed;transform:none;box-shadow:none;}
.app{max-width:1400px;margin:0 auto;padding:24px 20px 40px;display:flex;flex-direction:column;gap:20px;}
.topbar{display:grid;gap:18px;background:rgba(5,19,22,0.7);border:1px solid var(--border);border-radius:18px;padding:20px;backdrop-filter:blur(12px);}
.brand h1{margin:0;font-size:28px;letter-spacing:0.02em;}
.brand p{margin:4px 0 0;font-size:14px;color:var(--text-muted);}
.stats{display:flex;flex-wrap:wrap;gap:12px;}
.stat-card{min-width:120px;flex:1;display:flex;flex-direction:column;gap:6px;background:rgba(9,27,29,0.9);padding:14px 18px;border:1px solid rgba(0,255,170,0.18);border-radius:14px;box-shadow:0 10px 30px rgba(0,0,0,0.25) inset;}
.stat-card .label{font-size:13px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.08em;}
.stat-card .value{font-size:28px;font-weight:600;}
.kick-badge{display:flex;flex-direction:column;gap:6px;}
.badge{display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:999px;font-size:13px;font-weight:600;background:rgba(0,255,170,0.12);border:1px solid rgba(0,255,170,0.3);width:max-content;}
.badge.success{color:var(--success);border-color:rgba(76,255,181,0.4);background:rgba(76,255,181,0.12);}
.badge.warn{color:#ffd166;border-color:rgba(255,209,102,0.4);background:rgba(255,209,102,0.12);}
.badge.danger{color:var(--danger);border-color:rgba(255,125,125,0.4);background:rgba(255,125,125,0.12);}
.badge-muted{color:var(--text-muted);}
.small{font-size:13px;}
.muted{color:var(--text-muted);}
.tabs{display:flex;flex-wrap:wrap;gap:10px;background:rgba(5,19,22,0.6);border:1px solid var(--border);border-radius:18px;padding:12px 16px;}
.tab{border:none;background:rgba(0,255,170,0.08);padding:10px 16px;border-radius:12px;color:var(--text);cursor:pointer;font-weight:600;transition:background .2s ease,box-shadow .2s ease;}
.tab.active{background:linear-gradient(135deg,rgba(0,255,170,0.4),rgba(0,255,170,0.15));box-shadow:0 4px 14px rgba(0,255,170,0.25);}
.tab-link{display:inline-flex;align-items:center;padding:10px 16px;border-radius:12px;background:rgba(0,255,170,0.05);border:1px solid rgba(0,255,170,0.12);font-weight:600;}
.content{display:flex;flex-direction:column;gap:20px;}
.view{display:none;flex-direction:column;gap:20px;}
.view.active{display:flex;}
.panel{background:rgba(7,23,26,0.72);border:1px solid rgba(0,255,170,0.14);border-radius:16px;padding:18px;backdrop-filter:blur(10px);}
.filters{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));align-items:end;}
.filters .field{display:flex;flex-direction:column;gap:6px;}
.filters label{font-size:13px;color:var(--text-muted);}
.filters .toggle-row{display:flex;flex-wrap:wrap;gap:10px;grid-column:1/-1;}
.toggle{display:inline-flex;align-items:center;gap:8px;font-size:13px;color:var(--text-muted);}
.table-panel{display:flex;flex-direction:column;gap:16px;}
.table-wrap{overflow:auto;border-radius:14px;border:1px solid rgba(0,255,170,0.1);}
table{width:100%;border-collapse:collapse;min-width:900px;}
th,td{padding:12px 14px;font-size:14px;text-align:left;border-bottom:1px solid rgba(0,255,170,0.08);}
th{color:var(--text-muted);font-size:13px;text-transform:uppercase;letter-spacing:0.06em;background:rgba(0,255,170,0.04);}
tr:nth-child(even){background:rgba(0,255,170,0.03);}
.nowrap{white-space:nowrap;}
.actions-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;}
.actions-row input.wide{flex:1;min-width:240px;}
.hint{color:var(--text-muted);font-size:13px;}
.pagination{display:flex;align-items:center;gap:12px;}
.cards-grid{display:grid;gap:18px;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));}
.card{background:rgba(7,23,26,0.78);border:1px solid rgba(0,255,170,0.14);border-radius:16px;padding:18px;display:flex;flex-direction:column;gap:12px;}
.card h2{margin:0;font-size:18px;}
.card p{margin:0;font-size:14px;color:var(--text-muted);line-height:1.4;}
.card .button-row{display:flex;flex-wrap:wrap;gap:10px;}
.danger-card{border-color:rgba(255,125,125,0.35);background:rgba(47,6,11,0.4);}
.flag{display:inline-flex;align-items:center;gap:6px;}
.badge-inline{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;border:1px solid rgba(0,255,170,0.18);font-size:12px;background:rgba(0,255,170,0.08);}
@media (max-width:720px){
  .filters{grid-template-columns:1fr;}
  .stat-card{flex:1 1 100%;}
  table{min-width:700px;}
}
</style>
</head>
<body>
<div class="app">
  <header class="topbar">
    <div class="brand">
      <h1>Francuz1k Admin</h1>
      <p>Керуйте всіма учасниками розіграшу в одному місці</p>
    </div>
    <div class="stats" role="status">
      <div class="stat-card">
        <span class="label">Tickets</span>
        <span class="value" id="statTickets">—</span>
      </div>
      <div class="stat-card">
        <span class="label">TG verified</span>
        <span class="value" id="statTg">—</span>
      </div>
      <div class="stat-card">
        <span class="label">Kick verified</span>
        <span class="value" id="statKick">—</span>
      </div>
    </div>
    <div class="kick-badge">
      <span id="kickStatusBadge" class="badge badge-muted">Kick: перевірка…</span>
      <span id="kickStatusText" class="muted small"></span>
    </div>
  </header>
  <nav class="tabs">
    <button class="tab active" data-tab="users">Учасники</button>
    <button class="tab" data-tab="winners">Переможці</button>
    <button class="tab" data-tab="advanced">Advanced</button>
    <a class="tab-link" href="/admin/stream" target="_blank">Stream mode</a>
  </nav>
  <main class="content">
    <section id="view-users" class="view active">
      <div class="panel filters">
        <div class="field">
          <label for="filter-search">Пошук</label>
          <input id="filter-search" placeholder="id / @username / ticket / wallet / email" autocomplete="off">
        </div>
        <div class="field">
          <label for="filter-sort">Сортування</label>
          <select id="filter-sort">
            <option value="id_desc">newest</option>
            <option value="id_asc">oldest</option>
            <option value="created_desc">created ↓</option>
            <option value="created_asc">created ↑</option>
            <option value="ticket_desc">ticket ↓</option>
            <option value="ticket_asc">ticket ↑</option>
          </select>
        </div>
        <div class="field">
          <label for="filter-limit">Кількість на сторінці</label>
          <select id="filter-limit">
            <option value="300">300</option>
            <option value="500">500</option>
            <option value="1000">1000</option>
            <option value="2000">2000</option>
          </select>
        </div>
        <div class="field">
          <label for="filter-country">Країна</label>
          <input id="filter-country" placeholder="UA, PL, ..." maxlength="3" autocomplete="off">
        </div>
        <div class="toggle-row">
          <label class="toggle"><input type="checkbox" id="filter-ticket"> лише з квитком</label>
          <label class="toggle"><input type="checkbox" id="filter-tg"> TG ✅</label>
          <label class="toggle"><input type="checkbox" id="filter-kick"> Kick ✅</label>
          <label class="toggle"><input type="checkbox" id="filter-wallet"> повний wallet</label>
          <label class="toggle"><input type="checkbox" id="filter-stream"> Mask PII</label>
        </div>
        <div class="actions-row">
          <button id="btnApplyFilters" class="button">Застосувати</button>
          <button id="btnResetFilters" class="button ghost">Скинути</button>
          <a id="linkExport" class="button ghost" href="/admin/api/export/wallets.csv">Export wallets CSV</a>
        </div>
      </div>
      <div class="panel table-panel">
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Telegram</th>
                <th>TG</th>
                <th>Kick Username</th>
                <th>Kick Email</th>
                <th>Kick</th>
                <th>Ticket</th>
                <th>Country</th>
                <th>Wallet</th>
                <th>Created</th>
                <th>Дії</th>
              </tr>
            </thead>
            <tbody id="usersTableBody"></tbody>
          </table>
        </div>
        <div class="pagination">
          <button id="usersPrev" class="button ghost small">← Назад</button>
          <button id="usersNext" class="button ghost small">Далі →</button>
          <span id="usersHint" class="hint"></span>
        </div>
      </div>
    </section>
    <section id="view-winners" class="view">
      <div class="panel actions-row">
        <input id="winners-search" class="wide" placeholder="Пошук: ticket / @username / wallet" autocomplete="off">
        <button id="btnWinnersSearch" class="button">Шукати</button>
        <input id="winners-ticket" placeholder="ticket №" style="max-width:140px" autocomplete="off">
        <input id="winners-prize" placeholder="приз" style="max-width:200px" autocomplete="off">
        <button id="btnAddWinner" class="button secondary">Додати переможця</button>
        <span id="winnersHint" class="hint"></span>
      </div>
      <div class="panel table-panel">
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>Ticket</th>
                <th>Username</th>
                <th>Country</th>
                <th>Wallet</th>
                <th>Prize</th>
                <th>Paid</th>
                <th>Дії</th>
              </tr>
            </thead>
            <tbody id="winnersTableBody"></tbody>
          </table>
        </div>
      </div>
    </section>
    <section id="view-advanced" class="view">
      <div class="cards-grid">
        <article class="card">
          <h2>Kick інтеграція</h2>
          <p id="kickStatusDetails" class="muted">Авторизуйтеся через кнопку нижче, щоб отримувати webhook про нових підписників.</p>
          <div class="button-row">
            <a id="kickConnectLink" class="button secondary" href="/api/kick/connect-admin">Connect (admin)</a>
            <button id="btnKickStatus" class="button ghost small">Оновити статус</button>
            <button id="btnKickEnsure" class="button ghost small">Ensure follow webhook</button>
            <button id="btnKickList" class="button ghost small">List subs</button>
          </div>
        </article>
        <article class="card danger-card">
          <h2>Очистка / Danger zone</h2>
          <p>Видаляйте ботів та сміття обережно. Перед wipe обов'язково зробіть резервну копію бази.</p>
          <div class="actions-row">
            <label class="toggle">Старше (хв): <input id="cleanup-minutes" type="number" min="1" value="240" style="width:100px"></label>
            <label class="toggle">Максимум записів: <input id="cleanup-max" type="number" min="1" value="5000" style="width:120px"></label>
            <button id="btnCleanup" class="button ghost small">Запустити cleanup</button>
          </div>
          <button id="btnWipeAll" class="button danger">Wipe ALL</button>
          <span id="advancedHint" class="hint"></span>
        </article>
      </div>
      <div class="panel table-panel">
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>tg_id</th>
                <th>@username</th>
                <th>Lang</th>
                <th>Country</th>
                <th>TG</th>
                <th>Kick</th>
                <th>Kick User ID</th>
                <th>Kick Username</th>
                <th>Kick Email</th>
                <th>Ticket</th>
                <th>Wallet</th>
                <th>Created</th>
                <th>Updated</th>
                <th>Ticket sent</th>
              </tr>
            </thead>
            <tbody id="advancedTableBody"></tbody>
          </table>
        </div>
      </div>
    </section>
  </main>
</div>
<script>
(function(){
  'use strict';
  function $(sel){ return document.querySelector(sel); }
  function $all(sel){ return Array.from(document.querySelectorAll(sel)); }
  function ts(x){ if(!x) return ''; var d=new Date(x); return d.toISOString().replace('T',' ').slice(0,19); }
  function mask(s){ if(!s) return ''; s=String(s); return s.length<=8 ? '••••' : (s.slice(0,4)+'…'+s.slice(-4)); }
  function maskEmail(e){ if(!e) return ''; var i=e.indexOf('@'); if(i<1) return e; var n=e.slice(0,i), d=e.slice(i); return (n.length<=3? '***':(n.slice(0,3)+'***'))+d; }
  var ESC_MAP = {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"};
  function escHtml(str){ if(str==null) return ''; return String(str).replace(/[&<>"']/g, function(ch){ return ESC_MAP[ch] || ch; }); }
  function flag(cc){ if(!cc || cc.length!==2) return ''; var A=127462; return String.fromCodePoint(A+cc.charCodeAt(0)-65, A+cc.charCodeAt(1)-65); }
  var filtersKey='adminFiltersV2';
  var state={ q:'', limit:300, offset:0, next:null, sort:'id_desc', ticket:false, tg:false, kick:false, country:'', wallet:false, stream:false };
  var els={
    tabs:$all('.tab'),
    views:{ users:$('#view-users'), winners:$('#view-winners'), advanced:$('#view-advanced') },
    filter:{
      q:$('#filter-search'), sort:$('#filter-sort'), limit:$('#filter-limit'), country:$('#filter-country'),
      ticket:$('#filter-ticket'), tg:$('#filter-tg'), kick:$('#filter-kick'), wallet:$('#filter-wallet'), stream:$('#filter-stream'),
      apply:$('#btnApplyFilters'), reset:$('#btnResetFilters')
    },
    users:{
      body:$('#usersTableBody'), prev:$('#usersPrev'), next:$('#usersNext'), hint:$('#usersHint')
    },
    winners:{
      body:$('#winnersTableBody'), search:$('#winners-search'), btnSearch:$('#btnWinnersSearch'), ticket:$('#winners-ticket'), prize:$('#winners-prize'), btnAdd:$('#btnAddWinner'), hint:$('#winnersHint')
    },
    advanced:{
      body:$('#advancedTableBody'), hint:$('#advancedHint'), cleanupMinutes:$('#cleanup-minutes'), cleanupMax:$('#cleanup-max'), btnCleanup:$('#btnCleanup'), btnWipe:$('#btnWipeAll')
    },
    kick:{
      badge:$('#kickStatusBadge'), text:$('#kickStatusText'), details:$('#kickStatusDetails'), btnStatus:$('#btnKickStatus'), btnEnsure:$('#btnKickEnsure'), btnList:$('#btnKickList')
    },
    stats:{ tickets:$('#statTickets'), tg:$('#statTg'), kick:$('#statKick') }
  };
  function restoreFilters(){
    try{
      var saved=localStorage.getItem(filtersKey);
      if(saved){ var parsed=JSON.parse(saved); if(parsed && typeof parsed==='object'){ Object.assign(state, parsed); } }
    }catch(e){}
    els.filter.q.value=state.q||'';
    els.filter.sort.value=state.sort||'id_desc';
    els.filter.limit.value=String(state.limit||300);
    els.filter.country.value=state.country||'';
    els.filter.ticket.checked=!!state.ticket;
    els.filter.tg.checked=!!state.tg;
    els.filter.kick.checked=!!state.kick;
    els.filter.wallet.checked=!!state.wallet;
    els.filter.stream.checked=!!state.stream;
  }
  function persistFilters(){
    try{ localStorage.setItem(filtersKey, JSON.stringify(state)); }catch(e){}
  }
  function syncFromInputs(){
    state.q=els.filter.q.value.trim();
    state.sort=els.filter.sort.value;
    state.limit=Number(els.filter.limit.value)||300;
    state.country=els.filter.country.value.trim();
    state.ticket=els.filter.ticket.checked;
    state.tg=els.filter.tg.checked;
    state.kick=els.filter.kick.checked;
    state.wallet=els.filter.wallet.checked;
    state.stream=els.filter.stream.checked;
  }
  function setTab(tab){
    els.tabs.forEach(function(btn){ btn.classList.toggle('active', btn.dataset.tab===tab); });
    Object.keys(els.views).forEach(function(name){ els.views[name].classList.toggle('active', name===tab); });
    if(tab==='winners'){ loadWinners(); }
    if(tab==='advanced'){ loadAdvanced(); updateKickStatus(); }
  }
  els.tabs.forEach(function(btn){ btn.addEventListener('click', function(){ setTab(btn.dataset.tab); }); });
  function onFiltersChange(){ syncFromInputs(); state.offset=0; loadUsers(); }
  els.filter.apply.addEventListener('click', onFiltersChange);
  els.filter.reset.addEventListener('click', function(){ state={ q:'', limit:300, offset:0, next:null, sort:'id_desc', ticket:false, tg:false, kick:false, country:'', wallet:false, stream:false }; restoreFilters(); onFiltersChange(); });
  [els.filter.q, els.filter.sort, els.filter.limit, els.filter.country].forEach(function(ctrl){ if(!ctrl) return; ctrl.addEventListener('change', onFiltersChange); ctrl.addEventListener('keyup', function(e){ if(e.key==='Enter') onFiltersChange(); }); });
  [els.filter.ticket, els.filter.tg, els.filter.kick, els.filter.wallet, els.filter.stream].forEach(function(ctrl){ if(!ctrl) return; ctrl.addEventListener('change', onFiltersChange); });
  async function refreshStats(){
    try{
      var r=await fetch('/admin/api/stats'); if(!r.ok) return; var j=await r.json(); if(!j.ok) return;
      if(els.stats.tickets) els.stats.tickets.textContent=j.tickets;
      if(els.stats.tg) els.stats.tg.textContent=j.tg;
      if(els.stats.kick) els.stats.kick.textContent=j.kick;
    }catch(e){}
  }
  function buildUserRow(x){
    var tg = x.tg_username ? '@'+x.tg_username : (x.tg_id||'—');
    var tgShow = state.stream ? '***' : tg;
    var cc = x.ip_country ? '<span class="badge-inline">'+flag(x.ip_country)+' '+x.ip_country+'</span>' : '';
    var wallet = x.wallet_trc20 ? (state.wallet ? x.wallet_trc20 : mask(x.wallet_trc20)) : (x.wallet_pending?'(pending)':'—');
    var walletShow = state.stream ? '***' : wallet;
    var kickUser = x.kick_username ? '@'+x.kick_username : '—';
    var kickEmail = x.kick_email ? maskEmail(x.kick_email) : '—';
    if(state.stream){ kickUser='***'; kickEmail='***'; }
    var kickBadge = x.kick_verified ? '✅' : '—';
    if (x.kick_verified && x.kick_verified_by){ kickBadge += ' '+escHtml(x.kick_verified_by); }
    var kickStatus = '<span class="badge-inline">'+kickBadge+'</span>';
    var tgStatus = x.tg_verified ? '<span class="badge-inline">✅</span>' : '<span class="badge-inline">—</span>';
    var ticket = x.ticket_no ? String(x.ticket_no).padStart(7,'0') : '—';
    return '<tr>'
      + '<td class="nowrap">'+x.id+'</td>'
      + '<td>'+tgShow+'</td>'
      + '<td>'+tgStatus+'</td>'
      + '<td>'+kickUser+'</td>'
      + '<td>'+kickEmail+'</td>'
      + '<td>'+kickStatus+'</td>'
      + '<td>'+ticket+'</td>'
      + '<td>'+cc+'</td>'
      + '<td class="nowrap">'+walletShow+'</td>'
      + '<td class="nowrap">'+ts(x.created_at)+'</td>'
      + '<td class="nowrap actions">'
      +   '<button class="button xs ghost" data-action="msg" data-id="'+x.id+'">Message</button>'
      +   '<button class="button xs ghost" data-action="reqw" data-id="'+x.id+'">Request wallet</button>'
      +   (x.wallet_trc20 ? '<button class="button xs ghost" data-action="clearw" data-id="'+x.id+'">Clear wallet</button>' : '')
      +   (x.ticket_no ? '<button class="button xs ghost" data-action="resend" data-id="'+x.id+'">Resend ticket</button>' : '')
      +   '<button class="button xs danger" data-action="del" data-id="'+x.id+'">Delete</button>'
      + '</td>'
      + '</tr>';
  }
  async function loadUsers(){
    try{
      var url=new URL('/admin/api/users', location.origin);
      url.searchParams.set('limit', state.limit);
      url.searchParams.set('offset', state.offset);
      url.searchParams.set('sort', state.sort);
      if(state.q) url.searchParams.set('q', state.q);
      if(state.ticket) url.searchParams.set('has_ticket','1');
      if(state.tg) url.searchParams.set('tg','1');
      if(state.kick) url.searchParams.set('kick','1');
      if(state.country) url.searchParams.set('country', state.country.toUpperCase());
      var r=await fetch(url);
      if(r.status===401){ alert('Auth required'); return; }
      var j=await r.json();
      if(!j.ok){ alert('Load error'); return; }
      var rows=j.rows||[];
      var html='';
      rows.forEach(function(row){ html+=buildUserRow(row); });
      els.users.body.innerHTML=html;
      state.next=j.next_offset;
      els.users.prev.disabled=(state.offset===0);
      els.users.next.disabled=(state.next==null);
      if(els.users.hint) els.users.hint.textContent='Показано '+rows.length+' • offset '+state.offset;
      persistFilters();
      refreshStats();
    }catch(e){ console.error(e); }
  }
  $('#usersTableBody').addEventListener('click', async function(e){
    var btn=e.target.closest('button'); if(!btn) return;
    var pid=Number(btn.dataset.id); var act=btn.dataset.action;
    if(!pid || !act) return;
    if(act==='msg'){
      var text=prompt('Текст повідомлення','Привіт! Вкажи USDT TRC20 гаманець.');
      if(!text) return;
      var r=await fetch('/admin/api/message',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pid:pid,text:text})});
      var j=await r.json(); alert(j.ok?'Надіслано ✅':'Помилка: '+(j.error||''));
    }
    if(act==='reqw'){
      var r1=await fetch('/admin/api/wallet/request',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pid:pid})});
      var j1=await r1.json(); alert(j1.ok?'Запит відправлено ✅':'Помилка');
    }
    if(act==='clearw'){
      if(!confirm('Очистити гаманець?')) return;
      var r2=await fetch('/admin/api/wallet/clear',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pid:pid})});
      var j2=await r2.json(); if(j2.ok) loadUsers();
    }
    if(act==='resend'){
      var r3=await fetch('/admin/api/ticket/resend',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pid:pid})});
      var j3=await r3.json(); alert(j3.ok?'Надіслано ✅':'Помилка');
    }
    if(act==='del'){
      if(!confirm('Видалити учасника?')) return;
      var r4=await fetch('/admin/api/users/'+pid,{method:'DELETE'});
      var j4=await r4.json(); if(j4.ok) loadUsers();
    }
  });
  els.users.prev.addEventListener('click', function(){ state.offset=Math.max(0, state.offset-state.limit); loadUsers(); });
  els.users.next.addEventListener('click', function(){ if(state.next!=null){ state.offset=state.next; loadUsers(); } });
  async function loadWinners(){
    try{
      var url=new URL('/admin/api/winners', location.origin);
      var q=els.winners.search.value.trim(); if(q) url.searchParams.set('q', q);
      var r=await fetch(url);
      var j=await r.json();
      var rows=j.rows||[];
      var html='';
      rows.forEach(function(w){
        html += '<tr>'
          + '<td>'+w.id+'</td>'
          + '<td>'+String(w.ticket_no).padStart(7,'0')+'</td>'
          + '<td>'+(w.tg_username?'@'+w.tg_username:'—')+'</td>'
          + '<td>'+(w.ip_country||'')+'</td>'
          + '<td>'+(w.wallet_trc20||'—')+'</td>'
          + '<td>'+(w.prize||'')+'</td>'
          + '<td>'+(w.paid?'✅':'—')+'</td>'
          + '<td>'
          +   '<button class="button xs ghost" data-wa="pay" data-id="'+w.id+'" data-paid="'+(w.paid?0:1)+'">'+(w.paid?'Unpay':'Mark paid')+'</button>'
          +   '<button class="button xs danger" data-wa="del" data-id="'+w.id+'">Delete</button>'
          + '</td>'
          + '</tr>';
      });
      els.winners.body.innerHTML=html;
      if(els.winners.hint) els.winners.hint.textContent='Всього: '+rows.length;
    }catch(e){ console.error(e); }
  }
  $('#winnersTableBody').addEventListener('click', async function(e){
    var btn=e.target.closest('button'); if(!btn) return;
    var id=Number(btn.dataset.id); var wa=btn.dataset.wa;
    if(!id || !wa) return;
    if(wa==='pay'){
      var paid=Number(btn.dataset.paid);
      var r=await fetch('/admin/api/winners/pay',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id,paid:paid})});
      var j=await r.json(); if(j.ok) loadWinners();
    }
    if(wa==='del'){
      if(!confirm('Видалити переможця?')) return;
      var r2=await fetch('/admin/api/winners/'+id,{method:'DELETE'});
      var j2=await r2.json(); if(j2.ok) loadWinners();
    }
  });
  els.winners.btnSearch.addEventListener('click', loadWinners);
  els.winners.btnAdd.addEventListener('click', async function(){
    var ticket=Number(els.winners.ticket.value);
    var prize=els.winners.prize.value.trim();
    if(!ticket){ alert('Введіть ticket №'); return; }
    var r=await fetch('/admin/api/winners/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ticket_no:ticket,prize:prize})});
    var j=await r.json();
    alert(j.ok?'Додано ✅':'Помилка: '+(j.error||''));
    if(j.ok){ els.winners.ticket.value=''; els.winners.prize.value=''; loadWinners(); }
  });
  async function loadAdvanced(){
    try{
      var url=new URL('/admin/api/users', location.origin);
      url.searchParams.set('limit','1000');
      url.searchParams.set('sort','id_desc');
      var r=await fetch(url);
      var j=await r.json();
      var rows=j.rows||[];
      var html='';
      rows.forEach(function(x){
        var tgId = state.stream ? '***' : (x.tg_id||'—');
        var tgUser = state.stream ? '***' : (x.tg_username?'@'+x.tg_username:'—');
        var wallet = x.wallet_trc20 ? (state.wallet?x.wallet_trc20:mask(x.wallet_trc20)) : (x.wallet_pending?'(pending)':'—');
        var walletShow = state.stream ? '***' : wallet;
        var kick = x.kick_verified ? '✅' : '—';
        var kid = state.stream ? '***' : (x.kick_user_id||'');
        var kun = state.stream ? '***' : (x.kick_username?'@'+x.kick_username:'—');
        var kem = state.stream ? '***' : (x.kick_email?maskEmail(x.kick_email):'—');
        html += '<tr>'
          + '<td class="nowrap">'+x.id+'</td>'
          + '<td class="nowrap">'+tgId+'</td>'
          + '<td>'+tgUser+'</td>'
          + '<td>'+(x.lang||'')+'</td>'
          + '<td>'+(x.ip_country||'')+'</td>'
          + '<td>'+ (x.tg_verified?'✅':'—') +'</td>'
          + '<td>'+kick+'</td>'
          + '<td class="nowrap">'+kid+'</td>'
          + '<td>'+kun+'</td>'
          + '<td class="nowrap">'+kem+'</td>'
          + '<td>'+(x.ticket_no?String(x.ticket_no).padStart(7,'0'):'—')+'</td>'
          + '<td class="nowrap">'+walletShow+'</td>'
          + '<td class="nowrap">'+ts(x.created_at)+'</td>'
          + '<td class="nowrap">'+ts(x.updated_at)+'</td>'
          + '<td class="nowrap">'+(x.ticket_sent_at?ts(x.ticket_sent_at):'—')+'</td>'
          + '</tr>';
      });
      els.advanced.body.innerHTML=html;
    }catch(e){ console.error(e); }
  }
  async function updateKickStatus(){
    try{
      var r=await fetch('/admin/api/kick/status');
      if(r.status===401){
        els.kick.badge.textContent='Kick: auth required';
        els.kick.badge.className='badge danger';
        return;
      }
      var j=await r.json();
      if(!j.ok){
        els.kick.badge.textContent='Kick: error';
        els.kick.badge.className='badge danger';
        return;
      }
      if(j.connected){
        els.kick.badge.textContent='Kick: connected';
        els.kick.badge.className='badge success';
      }else{
        els.kick.badge.textContent='Kick: not connected';
        els.kick.badge.className='badge warn';
      }
      var follow=j.follow_subscribed?'✓':'—';
      var channel=j.channel||'—';
      var bid=j.broadcaster_user_id||'—';
      var cid=j.channel_id||'';
      var webhook=j.webhook_url||'—';
      var pieces=['Subs: '+j.subs, 'follow webhook: '+follow, 'channel: '+channel+(cid?(' (#'+cid+')'):'')];
      pieces.push('user id: '+bid);
      pieces.push('webhook: '+webhook);
      if(j.username) pieces.push('username: '+j.username);
      if(j.email) pieces.push('email: '+j.email);
      if(j.identity_cached_at){
        pieces.push('cached: '+ts(j.identity_cached_at));
        if(typeof j.identity_cache_age_ms==='number'){
          var ageMin = Math.max(Math.round(j.identity_cache_age_ms/60000),0);
          pieces.push('cache age: '+ageMin+'m');
        }
      }else if(j.identity_updated_at){
        pieces.push('cached: '+ts(j.identity_updated_at));
      }
      if(j.identity_remote_updated_at){
        pieces.push('channel updated: '+ts(j.identity_remote_updated_at));
      }
      if(j.identity_cache_ttl_ms){
        pieces.push('TTL: '+Math.round(j.identity_cache_ttl_ms/60000)+'m');
      }
      if(j.identity_stale) pieces.push('identity cache stale, refreshing…');
      els.kick.text.textContent=pieces.join(' • ');
      if(els.kick.details){
        if(!j.webhook_url){
          els.kick.details.textContent='Додайте KICK_WEBHOOK_URL у .env та натисніть Ensure follow webhook.';
        }else{
          if(j.identity_stale){
            els.kick.details.textContent='Оновлюємо інформацію про канал Kick… Перевірте за хвилину.';
          }else if(j.identity_cached_at){
            els.kick.details.textContent='Kick кешовано: '+ts(j.identity_cached_at)+'. '+(j.connected?'Webhook готовий.':'Авторизуйтеся в Kick, щоб активувати webhook підписок.');
          }else{
            els.kick.details.textContent = j.connected ? 'Webhook готовий. Нові фоловери з\'являться автоматично.' : 'Авторизуйтеся в Kick, щоб активувати webhook підписок.';
          }
        }
      }
    }catch(e){
      els.kick.badge.textContent='Kick: error';
      els.kick.badge.className='badge danger';
    }
  }
  if(els.kick.btnStatus) els.kick.btnStatus.addEventListener('click', function(){ updateKickStatus(); });
  if(els.kick.btnEnsure) els.kick.btnEnsure.addEventListener('click', async function(){
    els.kick.text.textContent='Ensuring…';
    try{ var r=await fetch('/admin/api/kick/subscriptions/ensure',{method:'POST'}); var j=await r.json(); els.kick.text.textContent=j.ok?'Follow webhook ensured ✅':'Помилка: '+(j.error||''); updateKickStatus(); }
    catch(e){ els.kick.text.textContent='Помилка'; }
  });
  if(els.kick.btnList) els.kick.btnList.addEventListener('click', async function(){
    els.kick.text.textContent='Loading list…';
    try{ var r=await fetch('/admin/api/kick/subscriptions/list'); var j=await r.json(); els.kick.text.textContent=j.ok?'Subscriptions: '+((j.data&&j.data.data)?j.data.data.length:0):'Помилка: '+(j.error||''); }
    catch(e){ els.kick.text.textContent='Помилка'; }
  });
  if(els.advanced.btnCleanup) els.advanced.btnCleanup.addEventListener('click', async function(){
    var older=Math.max(Number(els.advanced.cleanupMinutes.value)||0,1);
    var max=Math.max(Number(els.advanced.cleanupMax.value)||0,1);
    els.advanced.hint.textContent='Running cleanup…';
    try{
      var r=await fetch('/admin/api/cleanup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({older_than_m:older,max_rows:max})});
      var j=await r.json();
      els.advanced.hint.textContent=j.ok?'Deleted: '+j.deleted:'Помилка: '+(j.error||'');
      if(j.ok) loadUsers();
    }catch(e){ els.advanced.hint.textContent='Помилка'; }
  });
  if(els.advanced.btnWipe) els.advanced.btnWipe.addEventListener('click', async function(){
    var phrase=prompt('Щоб підтвердити, введіть WIPE-ALL-YES');
    if(phrase!=='WIPE-ALL-YES') return;
    els.advanced.hint.textContent='Wiping…';
    try{
      var r=await fetch('/admin/api/wipe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phrase:phrase})});
      var j=await r.json();
      els.advanced.hint.textContent=j.ok?'Готово. Видалено '+j.users_deleted+' учасників.':'Помилка: '+(j.error||'');
      if(j.ok) loadUsers();
    }catch(e){ els.advanced.hint.textContent='Помилка'; }
  });
  restoreFilters();
  setTab('users');
  loadUsers();
  refreshStats();
  updateKickStatus();
  setInterval(refreshStats, 20000);
  setInterval(updateKickStatus, 60000);
  var qs=new URLSearchParams(location.search);
  if(qs.get('kick_connected')==='1'){
    setTab('advanced');
    updateKickStatus();
    try{ history.replaceState({},'',location.pathname); }catch(e){}
  }
})();
</script>
</body>
</html>`;
}


function buildStreamHtml(){
  return '<!doctype html><html lang="uk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
  + '<title>Stream • Francuz1k</title>'
  + '<style>body{margin:0;background:#000;color:#ccffe8;font-family:system-ui,Segoe UI,sans-serif;text-align:center}.wrap{padding:28px}h1{margin:0 0 6px;font-size:28px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-top:20px}.card{background:#061311;border:1px solid rgba(0,255,170,.3);border-radius:12px;padding:16px}.num{font-size:44px;letter-spacing:.06em}.muted{color:#86b5a5}</style>'
  + '</head><body><div class="wrap"><h1>Stream mode</h1><div class="grid">'
  + '<div class="card"><div class="muted">З квитком</div><div id="c1" class="num">—</div></div>'
  + '<div class="card"><div class="muted">TG verified</div><div id="c2" class="num">—</div></div>'
  + '<div class="card"><div class="muted">Kick verified</div><div id="c3" class="num">—</div></div>'
  + '</div></div>'
  + '<script>'
  + 'async function load(){ var r=await fetch("/admin/api/stats"); if(r.status===401){return} var j=await r.json(); if(!j.ok) return; document.getElementById("c1").textContent=j.tickets; document.getElementById("c2").textContent=j.tg; document.getElementById("c3").textContent=j.kick; }'
  + 'setInterval(load,3000); load();'
  + '</script></body></html>';
}

const ADMIN_HTML = buildAdminHtml();
const STREAM_HTML = buildStreamHtml();

// Admin helper endpoints for Kick status/subs
app.get('/admin/api/kick/status', adminAuth, async (_req,res)=>{
  try{
    const tok = await adminTokenGet();
    const auth = !!(tok?.access_token);
    const Authorization = await adminAuthHeader();
    const broadcaster_user_id = await getBroadcasterUserId();
    const identity = await getCachedKickIdentity();
    let subsCount = 0, hasFollow=false;
    const H = Authorization ? withKickHeaders({ Authorization }) : null;
    if (H){
      try{
        const list = await axios.get(`${KICK_API_BASE}/public/v1/events/subscriptions`, { headers:H })
                                .then(r=>r.data?.data || []);
        subsCount = list.length|0;
        hasFollow = list.some(s => String(s.event||s.name)==='channel.followed' &&
                                   String(s.broadcaster_user_id)===String(broadcaster_user_id));
      }catch(_){}
    }
    res.json({
      ok:true,
      connected:auth,
      subs:subsCount,
      follow_subscribed:hasFollow,
      broadcaster_user_id,
      channel: identity?.slug || KICK_CHANNEL_SLUG,
      channel_id: identity?.channel_id || null,
      webhook_url:KICK_WEBHOOK_URL,
      username: identity?.username || null,
      email: identity?.email || null,
      identity_updated_at: identity?.cached_at || identity?.updated_at || null,
      identity_cached_at: identity?.cached_at || identity?.updated_at || null,
      identity_remote_updated_at: identity?.remote_updated_at || null,
      identity_cache_age_ms: typeof identity?.cache_age_ms === 'number' ? Math.round(identity.cache_age_ms) : null,
      identity_cache_ttl_ms: KICK_IDENTITY_CACHE_TTL,
      identity_stale: !!identity?.stale
    });
  }catch(e){ res.status(500).json({ok:false}); }
});
app.get('/admin/api/kick/subscriptions/list', adminAuth, async (_req,res)=>{
  try{
    const Authorization = await adminAuthHeader();
    if(!Authorization) return res.status(400).json({ok:false,error:'not_connected'});
    const list = await axios.get(`${KICK_API_BASE}/public/v1/events/subscriptions`, { headers: withKickHeaders({ Authorization }) })
                            .then(r=>r.data);
    res.json({ok:true, data:list});
  }catch(e){ res.status(500).json({ok:false,error:e?.message}); }
});
app.post('/admin/api/kick/subscriptions/ensure', adminAuth, async (_req,res)=>{
  try{
    const r = await ensureKickFollowSubscription();
    res.json(r);
  }catch(e){ res.status(500).json({ok:false,error:e?.message}); }
});

// ===== Admin UI routes =====
app.get(/^\/(admin|адмін)\/?$/i, basicAuth({ users: { [ADMIN_USER]: ADMIN_PASS }, challenge: true }), (_req,res)=>{
  res.setHeader('Content-Type','text/html; charset=utf-8'); res.send(ADMIN_HTML);
});
app.get(/^\/admin\/stream\/?$/i, basicAuth({ users: { [ADMIN_USER]: ADMIN_PASS }, challenge: true }), (_req,res)=>{
  res.setHeader('Content-Type','text/html; charset=utf-8'); res.send(STREAM_HTML);
});

// ===== bootstrap =====
app.listen(PORT, ()=>{
  console.log(`Francuz1k portal listening on :${PORT}`);
  ensureKickFollowSubscription().catch(()=>{}); // поддерживаем подписку, если админ уже подключён
});
