// চ্যাট অ্যাপ - ব্যাকএন্ড (কোনো বাইরের প্যাকেজ লাগে না, শুধু Node.js 22+)
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
// অনলাইনে চালালে DATA_DIR এমন ফোল্ডারে দাও যেটা স্থায়ী (ডিস্ক/ভলিউম), নইলে রিস্টার্টে ডাটা মুছে যাবে
const DATA_DIR = process.env.DATA_DIR || __dirname;
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'data.db'));
const SESSION_MAX_AGE = 30 * 24 * 60 * 60 * 1000; // ৩০ দিন

db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    code TEXT UNIQUE NOT NULL,
    salt TEXT NOT NULL,
    pass_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS contacts (
    user_id INTEGER NOT NULL,
    contact_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, contact_id)
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_id INTEGER NOT NULL,
    to_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_msg_to ON messages(to_id, id);
  CREATE INDEX IF NOT EXISTS idx_msg_pair ON messages(from_id, to_id, id);
`);

// ---------- সাহায্যকারী ফাংশন ----------
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // গুলিয়ে যায় এমন অক্ষর (O,0,I,1) বাদ

function generateCode() {
  for (let attempt = 0; attempt < 50; attempt++) {
    const bytes = crypto.randomBytes(8);
    let s = '';
    for (let i = 0; i < 8; i++) s += ALPHABET[bytes[i] % ALPHABET.length];
    const code = s.slice(0, 4) + '-' + s.slice(4);
    if (!db.prepare('SELECT 1 FROM users WHERE code = ?').get(code)) return code;
  }
  throw new Error('কোড তৈরি করা গেল না');
}

function normalizePhone(p) {
  return String(p || '').replace(/[\s\-()]/g, '');
}
function normalizeCode(c) {
  const raw = String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  return raw.length === 8 ? raw.slice(0, 4) + '-' + raw.slice(4) : '';
}
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
function publicUser(u) {
  return { id: u.id, name: u.name, code: u.code };
}

const loginAttempts = new Map(); // সহজ ব্রুট-ফোর্স সুরক্ষা
function tooManyAttempts(key) {
  const now = Date.now();
  const rec = (loginAttempts.get(key) || []).filter((t) => now - t < 10 * 60 * 1000);
  loginAttempts.set(key, rec);
  return rec.length >= 10;
}
function noteAttempt(key) {
  const rec = loginAttempts.get(key) || [];
  rec.push(Date.now());
  loginAttempts.set(key, rec);
}

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)').run(token, userId, Date.now());
  return token;
}

function authUser(req) {
  const h = req.headers['authorization'] || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!token) return null;
  return (
    db
      .prepare('SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.created_at > ?')
      .get(token, Date.now() - SESSION_MAX_AGE) || null
  );
}

// প্রক্সির (যেমন Render) পেছনে আসল ক্লায়েন্ট IP: প্রক্সি যে IP শেষে যোগ করে সেটাই বিশ্বাসযোগ্য
function clientIp(req) {
  const xff = String(req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean);
  return xff.length ? xff[xff.length - 1] : req.socket.remoteAddress;
}

// পুরনো সেশন ঘণ্টায় একবার মুছে ফেলা
setInterval(() => {
  try { db.prepare('DELETE FROM sessions WHERE created_at < ?').run(Date.now() - SESSION_MAX_AGE); } catch {}
}, 60 * 60 * 1000).unref();

function readJson(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (data.length > 1e6) {
        reject(new Error('too big'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch {
        reject(new Error('bad json'));
      }
    });
  });
}

function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(body);
}

// ---------- API ----------
async function handleApi(req, res, url) {
  const route = req.method + ' ' + url.pathname;

  if (route === 'POST /api/register') {
    const b = await readJson(req);
    const name = String(b.name || '').trim().slice(0, 40);
    const phone = normalizePhone(b.phone);
    const password = String(b.password || '');
    if (!name) return send(res, 400, { error: 'নাম দাও' });
    if (!/^\+?\d{6,15}$/.test(phone)) return send(res, 400, { error: 'সঠিক নাম্বার দাও (৬-১৫ ডিজিট)' });
    if (password.length < 6) return send(res, 400, { error: 'পাসওয়ার্ড কমপক্ষে ৬ অক্ষরের হতে হবে' });
    if (db.prepare('SELECT 1 FROM users WHERE phone = ?').get(phone))
      return send(res, 409, { error: 'এই নাম্বার দিয়ে আগেই অ্যাকাউন্ট আছে' });

    const salt = crypto.randomBytes(16).toString('hex');
    const code = generateCode();
    const r = db
      .prepare('INSERT INTO users (phone, name, code, salt, pass_hash, created_at) VALUES (?,?,?,?,?,?)')
      .run(phone, name, code, salt, hashPassword(password, salt), Date.now());
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(r.lastInsertRowid));
    return send(res, 200, { token: createSession(user.id), user: publicUser(user) });
  }

  if (route === 'POST /api/login') {
    const b = await readJson(req);
    const phone = normalizePhone(b.phone);
    const key = phone + '|' + clientIp(req);
    if (tooManyAttempts(key)) return send(res, 429, { error: 'অনেকবার ভুল হয়েছে, ১০ মিনিট পর চেষ্টা করো' });
    const user = db.prepare('SELECT * FROM users WHERE phone = ?').get(phone);
    const ok =
      user &&
      crypto.timingSafeEqual(
        Buffer.from(hashPassword(String(b.password || ''), user.salt), 'hex'),
        Buffer.from(user.pass_hash, 'hex')
      );
    if (!ok) {
      noteAttempt(key);
      return send(res, 401, { error: 'নাম্বার বা পাসওয়ার্ড ভুল' });
    }
    return send(res, 200, { token: createSession(user.id), user: publicUser(user) });
  }

  // এখান থেকে নিচের সব API-তে লগইন লাগবে
  const me = authUser(req);
  if (!me) return send(res, 401, { error: 'আবার লগইন করো' });

  if (route === 'GET /api/me') return send(res, 200, { user: publicUser(me) });

  if (route === 'POST /api/logout') {
    const token = (req.headers['authorization'] || '').slice(7);
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    return send(res, 200, { ok: true });
  }

  // কোড দিয়ে বন্ধু যোগ (দুই পাশেই যোগ হয়)
  if (route === 'POST /api/contacts') {
    const b = await readJson(req);
    const code = normalizeCode(b.code);
    if (!code) return send(res, 400, { error: 'কোড ৮ অক্ষরের হতে হবে (যেমন: ABCD-2345)' });
    const other = db.prepare('SELECT * FROM users WHERE code = ?').get(code);
    if (!other) return send(res, 404, { error: 'এই কোডে কোনো ব্যবহারকারী পাওয়া যায়নি' });
    if (other.id === me.id) return send(res, 400, { error: 'এটা তোমার নিজের কোড 🙂' });
    const ins = db.prepare('INSERT OR IGNORE INTO contacts (user_id, contact_id, created_at) VALUES (?,?,?)');
    const now = Date.now();
    ins.run(me.id, other.id, now);
    ins.run(other.id, me.id, now);
    return send(res, 200, { contact: publicUser(other) });
  }

  // কন্টাক্ট লিস্ট + শেষ মেসেজ + না-পড়া সংখ্যা
  if (route === 'GET /api/contacts') {
    const rows = db
      .prepare(
        `SELECT u.id, u.name, u.code,
          (SELECT text FROM messages m WHERE (m.from_id = u.id AND m.to_id = ?1) OR (m.from_id = ?1 AND m.to_id = u.id) ORDER BY m.id DESC LIMIT 1) AS last_text,
          (SELECT created_at FROM messages m WHERE (m.from_id = u.id AND m.to_id = ?1) OR (m.from_id = ?1 AND m.to_id = u.id) ORDER BY m.id DESC LIMIT 1) AS last_at
         FROM contacts c JOIN users u ON u.id = c.contact_id
         WHERE c.user_id = ?1`
      )
      .all(me.id);
    rows.sort((a, b) => (b.last_at || 0) - (a.last_at || 0));
    return send(res, 200, { contacts: rows });
  }

  // একজনের সাথে চ্যাট (after = এই আইডির পরের মেসেজ)
  if (route === 'GET /api/messages') {
    const withId = Number(url.searchParams.get('with'));
    const after = Number(url.searchParams.get('after') || 0);
    if (!db.prepare('SELECT 1 FROM contacts WHERE user_id = ? AND contact_id = ?').get(me.id, withId))
      return send(res, 403, { error: 'এই ব্যক্তি তোমার কন্টাক্টে নেই' });
    const msgs = db
      .prepare(
        `SELECT id, from_id, to_id, text, created_at FROM messages
         WHERE id > ? AND ((from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?))
         ORDER BY id ASC LIMIT 500`
      )
      .all(after, me.id, withId, withId, me.id);
    return send(res, 200, { messages: msgs });
  }

  if (route === 'POST /api/messages') {
    const b = await readJson(req);
    const to = Number(b.to);
    const text = String(b.text || '').trim().slice(0, 4000);
    if (!text) return send(res, 400, { error: 'খালি মেসেজ পাঠানো যায় না' });
    if (!db.prepare('SELECT 1 FROM contacts WHERE user_id = ? AND contact_id = ?').get(me.id, to))
      return send(res, 403, { error: 'এই ব্যক্তি তোমার কন্টাক্টে নেই' });
    const now = Date.now();
    const r = db
      .prepare('INSERT INTO messages (from_id, to_id, text, created_at) VALUES (?,?,?,?)')
      .run(me.id, to, text, now);
    return send(res, 200, {
      message: { id: Number(r.lastInsertRowid), from_id: me.id, to_id: to, text, created_at: now },
    });
  }

  // নতুন আসা সব মেসেজ (পোলিং) - after = শেষ দেখা আইডি
  if (route === 'GET /api/poll') {
    const after = Number(url.searchParams.get('after') || 0);
    const msgs = db
      .prepare('SELECT id, from_id, to_id, text, created_at FROM messages WHERE id > ? AND to_id = ? ORDER BY id ASC LIMIT 500')
      .all(after, me.id);
    return send(res, 200, { messages: msgs });
  }

  return send(res, 404, { error: 'পাওয়া যায়নি' });
}

// ---------- স্ট্যাটিক ফাইল ----------
const PUBLIC = path.join(__dirname, 'public');
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css', '.json': 'application/json', '.webmanifest': 'application/manifest+json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };

function serveStatic(req, res, url) {
  let p = url.pathname === '/' ? '/index.html' : url.pathname;
  const file = path.normalize(path.join(PUBLIC, p));
  if (!file.startsWith(PUBLIC + path.sep)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }
  fs.readFile(file, (err, data) => {
    if (err) {
      res.writeHead(404);
      return res.end('Not found');
    }
    const isShell = ['.html', '.js', '.webmanifest'].includes(path.extname(file)); // আপডেট যেন সহজে পৌঁছায়
    res.writeHead(200, {
      'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream',
      'Cache-Control': isShell ? 'no-cache' : 'public, max-age=86400',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  try {
    if (url.pathname === '/healthz') { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('ok'); }
    if (url.pathname.startsWith('/api/')) return await handleApi(req, res, url);
    return serveStatic(req, res, url);
  } catch (e) {
    console.error(e);
    if (!res.headersSent) send(res, 500, { error: 'সার্ভারে সমস্যা হয়েছে' });
  }
});

server.listen(PORT, '0.0.0.0', () => console.log('চ্যাট অ্যাপ চালু, পোর্ট ' + PORT + ', ডাটা: ' + DATA_DIR));
