// سيرفر لعبة "حرامي الغسيل" — بدون أي مكتبات خارجية (Node 18+)
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = +process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const TRUST_PROXY = process.env.TRUST_PROXY === '1'; // فعّلها لو ورا nginx/Cloudflare/منصة استضافة
const PUB = path.join(__dirname, 'public');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const SESSION_MS = 90 * 24 * 3600e3;
fs.mkdirSync(DATA_DIR, { recursive: true });

// تخزين: لو DATABASE_URL موجود بيتخزن في Postgres (مناسب للاستضافة المجانية)، وإلا في ملف db.json
const DATABASE_URL = process.env.DATABASE_URL;
const pool = DATABASE_URL ? new (require('pg').Pool)({ connectionString: DATABASE_URL, max: 3 }) : null;
let db = { users: {}, sessions: {} };
async function init() {
  if (pool) {
    await pool.query('create table if not exists kv (k text primary key, v text not null)');
    const r = await pool.query("select v from kv where k='db'");
    if (r.rows[0]) db = JSON.parse(r.rows[0].v);
  } else {
    try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) {}
  }
}
let saving = false, again = false;
function persist() {
  if (saving) { again = true; return; }
  saving = true;
  const done = () => { saving = false; if (again) { again = false; persist(); } };
  if (pool) {
    pool.query("insert into kv (k, v) values ('db', $1) on conflict (k) do update set v = excluded.v", [JSON.stringify(db)])
      .catch(e => console.error('db save failed:', e.message)).then(done);
    return;
  }
  const tmp = DB_FILE + '.tmp';
  fs.writeFile(tmp, JSON.stringify(db), err => {
    if (!err) fs.renameSync(tmp, DB_FILE);
    done();
  });
}
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const scrypt = (pw, salt) => new Promise((res, rej) =>
  crypto.scrypt(pw, salt, 64, (e, k) => e ? rej(e) : res(k.toString('hex'))));

// تحديد معدل المحاولات: 10 في الدقيقة لكل IP على الدخول والتسجيل
const hits = new Map();
function limited(ip) {
  const now = Date.now(), a = (hits.get(ip) || []).filter(t => now - t < 60e3);
  a.push(now); hits.set(ip, a);
  return a.length > 10;
}
setInterval(() => { const n = Date.now(); for (const [k, v] of hits) if (!v.some(t => n - t < 60e3)) hits.delete(k); }, 60e3).unref();

const send = (res, code, obj) => {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
};
function body(req) {
  return new Promise((res, rej) => {
    let n = 0; const c = [];
    req.on('data', d => { n += d.length; if (n > 65536) { rej(new Error('big')); req.destroy(); } else c.push(d); });
    req.on('end', () => { try { res(JSON.parse(Buffer.concat(c).toString() || '{}')); } catch (e) { rej(e); } });
    req.on('error', rej);
  });
}
function authUser(req) {
  const m = /^Bearer ([a-f0-9]{64})$/.exec(req.headers.authorization || '');
  if (!m) return null;
  const s = db.sessions[sha(m[1])];
  if (!s || Date.now() - s.t > SESSION_MS || !db.users[s.u]) return null;
  return db.users[s.u];
}
function newSession(key) {
  const tok = crypto.randomBytes(32).toString('hex');
  db.sessions[sha(tok)] = { u: key, t: Date.now() };
  const mine = Object.entries(db.sessions).filter(([, s]) => s.u === key).sort((a, b) => a[1].t - b[1].t);
  while (mine.length > 10) delete db.sessions[mine.shift()[0]]; // أقصى 10 أجهزة
  return tok;
}
const num = (v, max) => Math.max(0, Math.min(max, Math.floor(+v) || 0));

async function api(req, res, url) {
  const ip = (TRUST_PROXY && (req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress;
  const r = url.pathname.slice(5), M = req.method;

  if (M === 'POST' && (r === 'register' || r === 'login')) {
    if (limited(ip)) return send(res, 429, { error: 'محاولات كتير، استنى دقيقة وجرب تاني' });
    const { username, password } = await body(req);
    if (typeof username !== 'string' || typeof password !== 'string') return send(res, 400, { error: 'بيانات ناقصة' });
    const key = username.trim().toLowerCase();
    if (r === 'register') {
      if (!/^[\p{L}\p{N}_-]{3,20}$/u.test(username.trim())) return send(res, 400, { error: 'اسم المستخدم 3 لـ 20 حرف أو رقم (بدون مسافات)' });
      if (password.length < 6 || password.length > 100) return send(res, 400, { error: 'كلمة السر لازم تكون 6 حروف على الأقل' });
      if (db.users[key]) return send(res, 409, { error: 'الاسم ده مستخدم قبل كده' });
      const salt = crypto.randomBytes(16).toString('hex');
      db.users[key] = { name: username.trim(), salt, hash: await scrypt(password, salt), progress: null, best: 0, created: Date.now() };
      const token = newSession(key); persist();
      return send(res, 200, { token, username: db.users[key].name, progress: null });
    }
    const u = db.users[key];
    const ok = u && crypto.timingSafeEqual(Buffer.from(await scrypt(password, u.salt), 'hex'), Buffer.from(u.hash, 'hex'));
    if (!ok) return send(res, 401, { error: 'اسم المستخدم أو كلمة السر غلط' });
    const token = newSession(key); persist();
    return send(res, 200, { token, username: u.name, progress: u.progress });
  }

  if (M === 'GET' && r === 'leaderboard') {
    const top = Object.values(db.users).filter(u => u.best > 0)
      .sort((a, b) => b.best - a.best).slice(0, 20).map(u => ({ name: u.name, best: u.best }));
    return send(res, 200, { top });
  }

  const u = authUser(req);
  if (!u) return send(res, 401, { error: 'لازم تسجل دخول' });

  if (M === 'GET' && r === 'me') return send(res, 200, { username: u.name, progress: u.progress });
  if (M === 'PUT' && r === 'progress') {
    const { progress } = await body(req);
    if (!progress || typeof progress !== 'object' || Array.isArray(progress) || JSON.stringify(progress).length > 20000)
      return send(res, 400, { error: 'تقدم غير صالح' });
    u.progress = progress; u.best = num(progress.best, 10000000); u.updated = Date.now(); persist();
    return send(res, 200, { ok: true });
  }
  if (M === 'POST' && r === 'logout') {
    const m = /^Bearer ([a-f0-9]{64})$/.exec(req.headers.authorization);
    delete db.sessions[sha(m[1])]; persist();
    return send(res, 200, { ok: true });
  }
  send(res, 404, { error: 'مش موجود' });
}

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.webmanifest': 'application/manifest+json', '.json': 'application/json' };
const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
  "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'";

const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  try {
    const url = new URL(req.url, 'http://x');
    if (url.pathname.startsWith('/api/')) return await api(req, res, url);
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
    let p = decodeURIComponent(url.pathname); if (p.endsWith('/')) p += 'index.html';
    const f = path.normalize(path.join(PUB, p));
    if (!f.startsWith(PUB + path.sep)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, data) => {
      if (err) { res.writeHead(404); return res.end('404'); }
      const ext = path.extname(f);
      res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream', 'Content-Security-Policy': CSP,
        'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=3600' });
      res.end(req.method === 'HEAD' ? undefined : data);
    });
  } catch (e) { if (!res.headersSent) send(res, 400, { error: 'طلب غير صالح' }); else res.end(); }
});
init().then(() => server.listen(PORT, () => console.log('Game server on port ' + PORT + (pool ? ' (Postgres)' : ' (file db)'))))
  .catch(e => { console.error('startup failed:', e.message); process.exit(1); });
