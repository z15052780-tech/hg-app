// API لعبة "حرامي الغسيل" — دالة Vercel + Postgres (Neon). بيانات كل لاعب في صف مستقل.
const crypto = require('crypto');
const { Pool } = require('pg');

let pool, ready;
const pg = () => pool || (pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 1 }));
const q = (text, params) => pg().query(text, params);
const init = () => ready || (ready = q(
  `create table if not exists users (k text primary key, name text not null, salt text not null, hash text not null,
     progress text, best bigint not null default 0, created bigint not null);
   create table if not exists sessions (h text primary key, u text not null references users(k) on delete cascade, t bigint not null);
   create index if not exists sessions_u on sessions(u)`).catch(e => { ready = null; throw e; }));

const SESSION_MS = 90 * 24 * 3600e3;
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const scrypt = (pw, salt) => new Promise((res, rej) => crypto.scrypt(pw, salt, 64, (e, k) => e ? rej(e) : res(k.toString('hex'))));
const send = (res, code, obj) => {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(obj));
};
async function readBody(req) {
  if (req.body !== undefined && req.body !== null) return typeof req.body === 'string' ? JSON.parse(req.body || '{}') : req.body;
  return new Promise((res, rej) => {
    let n = 0; const c = [];
    req.on('data', d => { n += d.length; if (n > 65536) rej(new Error('big')); else c.push(d); });
    req.on('end', () => { try { res(JSON.parse(Buffer.concat(c).toString() || '{}')); } catch (e) { rej(e); } });
    req.on('error', rej);
  });
}
// تحديد محاولات الدخول (على مستوى النسخة الواحدة من الدالة، حماية أساسية)
const hits = new Map();
function limited(ip) {
  const now = Date.now(), a = (hits.get(ip) || []).filter(t => now - t < 60e3); a.push(now); hits.set(ip, a);
  return a.length > 10;
}
const tokenOf = req => { const m = /^Bearer ([a-f0-9]{64})$/.exec(req.headers.authorization || ''); return m && m[1]; };
async function authUser(req) {
  const t = tokenOf(req); if (!t) return null;
  const r = await q('select u.* from sessions s join users u on u.k = s.u where s.h = $1 and s.t > $2', [sha(t), Date.now() - SESSION_MS]);
  return r.rows[0] || null;
}
async function newSession(key) {
  const tok = crypto.randomBytes(32).toString('hex');
  await q('insert into sessions (h, u, t) values ($1, $2, $3)', [sha(tok), key, Date.now()]);
  await q('delete from sessions where h in (select h from sessions where u = $1 order by t desc limit 1000 offset 10)', [key]); // أقصى 10 أجهزة
  return tok;
}
const parseP = s => { try { return s ? JSON.parse(s) : null; } catch (e) { return null; } };
const num = (v, max) => Math.max(0, Math.min(max, Math.floor(+v) || 0));

module.exports = async (req, res) => {
  try {
    if (!process.env.DATABASE_URL) return send(res, 500, { error: 'السيرفر مش متظبط (DATABASE_URL ناقص)' });
    await init();
    const r = new URL(req.url, 'http://x').pathname.replace(/^\/api\/?/, '').replace(/\/$/, ''), M = req.method;
    const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || (req.socket && req.socket.remoteAddress) || '?';

    if (M === 'POST' && (r === 'register' || r === 'login')) {
      if (limited(ip)) return send(res, 429, { error: 'محاولات كتير، استنى دقيقة وجرب تاني' });
      const { username, password } = await readBody(req);
      if (typeof username !== 'string' || typeof password !== 'string') return send(res, 400, { error: 'بيانات ناقصة' });
      const key = username.trim().toLowerCase();
      if (r === 'register') {
        if (!/^[\p{L}\p{N}_-]{3,20}$/u.test(username.trim())) return send(res, 400, { error: 'اسم المستخدم 3 لـ 20 حرف أو رقم (بدون مسافات)' });
        if (password.length < 6 || password.length > 100) return send(res, 400, { error: 'كلمة السر لازم تكون 6 حروف على الأقل' });
        const salt = crypto.randomBytes(16).toString('hex');
        const ins = await q('insert into users (k, name, salt, hash, created) values ($1, $2, $3, $4, $5) on conflict (k) do nothing returning k',
          [key, username.trim(), salt, await scrypt(password, salt), Date.now()]);
        if (!ins.rows.length) return send(res, 409, { error: 'الاسم ده مستخدم قبل كده' });
        return send(res, 200, { token: await newSession(key), username: username.trim(), progress: null });
      }
      const u = (await q('select * from users where k = $1', [key])).rows[0];
      const ok = u && crypto.timingSafeEqual(Buffer.from(await scrypt(password, u.salt), 'hex'), Buffer.from(u.hash, 'hex'));
      if (!ok) return send(res, 401, { error: 'اسم المستخدم أو كلمة السر غلط' });
      return send(res, 200, { token: await newSession(key), username: u.name, progress: parseP(u.progress) });
    }

    if (M === 'GET' && r === 'leaderboard') {
      const t = await q('select name, best from users where best > 0 order by best desc limit 20');
      return send(res, 200, { top: t.rows.map(x => ({ name: x.name, best: Number(x.best) })) });
    }

    const u = await authUser(req);
    if (!u) return send(res, 401, { error: 'لازم تسجل دخول' });
    if (M === 'GET' && r === 'me') return send(res, 200, { username: u.name, progress: parseP(u.progress) });
    if (M === 'PUT' && r === 'progress') {
      const { progress } = await readBody(req);
      if (!progress || typeof progress !== 'object' || Array.isArray(progress) || JSON.stringify(progress).length > 20000)
        return send(res, 400, { error: 'تقدم غير صالح' });
      await q('update users set progress = $2, best = $3 where k = $1', [u.k, JSON.stringify(progress), num(progress.best, 10000000)]);
      return send(res, 200, { ok: true });
    }
    if (M === 'POST' && r === 'logout') {
      await q('delete from sessions where h = $1', [sha(tokenOf(req))]);
      return send(res, 200, { ok: true });
    }
    send(res, 404, { error: 'مش موجود' });
  } catch (e) {
    console.error(e);
    if (!res.writableEnded) send(res, 500, { error: 'خطأ في السيرفر' });
  }
};
