// שרת ללא תלויות חיצוניות: מגיש את האתר ושומר הזמנות בקובץ JSON.
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const FILE = path.join(DATA_DIR, 'data.json');
fs.mkdirSync(DATA_DIR, { recursive: true });
let db = {};
try { db = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (e) {}
// קובץ משתמשים נפרד: כל מי שנרשם נשמר כאן וזמין גם אחרי הפעלה מחדש של השרת
const USERS_FILE = path.join(DATA_DIR, 'users.json');
let users = {};
try { users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch (e) {}
function saveUsers() { const t = USERS_FILE + '.tmp'; fs.writeFileSync(t, JSON.stringify(users, null, 1)); fs.renameSync(t, USERS_FILE); }
function rememberUser(id, d) {
  if (!/^[a-f0-9]{64}$/.test(id) || !d || !d.phone) return;
  const old = users[id] || {};
  users[id] = { name: d.name || old.name || '', phone: d.phone, email: d.email || old.email || '', created: old.created || Date.now(), updated: Date.now() };
  saveUsers();
}
Object.keys(db).forEach(id => { if (!users[id]) rememberUser(id, db[id]); }); // משחזר משתמשים מהזמנות קיימות
function persist() { const t = FILE + '.tmp'; fs.writeFileSync(t, JSON.stringify(db)); fs.renameSync(t, FILE); }
const ADMIN_TOKEN = ADMIN_PASSWORD ? crypto.createHmac('sha256', ADMIN_PASSWORD).update('fw-admin').digest('hex') : null;
const eq = (a, b) => { a = Buffer.from(String(a)); b = Buffer.from(String(b)); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const isAdmin = req => !!ADMIN_TOKEN && eq(req.headers['x-admin'] || '', ADMIN_TOKEN);
const CUSTOMER_LOCKED = ['paid', 'delivered', 'refunded']; // רק מנהל קובע סטטוסים כאלה
const tries = {};
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.webmanifest': 'application/manifest+json', '.png': 'image/png', '.ico': 'image/x-icon' };
function send(res, code, obj) { res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }); res.end(JSON.stringify(obj)); }
function body(req) { return new Promise((ok, no) => { let b = ''; req.on('data', c => { b += c; if (b.length > 300000) { req.destroy(); no(new Error('big')); } }); req.on('end', () => { try { ok(JSON.parse(b || '{}')); } catch (e) { no(e); } }); }); }
function customerOk(old, neu) {
  const ow = (old && old.weeks) || {}, nw = (neu && neu.weeks) || {};
  for (const k of Object.keys(ow)) if (CUSTOMER_LOCKED.includes(ow[k].status) && !nw[k]) return false;
  for (const k of Object.keys(nw)) {
    const s = nw[k] && nw[k].status;
    if (CUSTOMER_LOCKED.includes(s) && !(ow[k] && ow[k].status === s)) return false;
  }
  return true;
}
http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  try {
    if (u.pathname === '/api/admin/login' && req.method === 'POST') {
      const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress, now = Date.now();
      tries[ip] = (tries[ip] || []).filter(t => now - t < 60000); if (tries[ip].length >= 8) return send(res, 429, { error: 'many' });
      tries[ip].push(now);
      const b = await body(req);
      if (ADMIN_TOKEN && eq(b.password || '', ADMIN_PASSWORD)) return send(res, 200, { token: ADMIN_TOKEN });
      return send(res, 401, { error: 'bad' });
    }
    if (u.pathname === '/api/orders' && req.method === 'GET') {
      if (!isAdmin(req)) return send(res, 401, { error: 'auth' });
      return send(res, 200, Object.keys(db).map(id => ({ id, data: db[id] })));
    }
    if (u.pathname === '/api/users' && req.method === 'GET') {
      if (!isAdmin(req)) return send(res, 401, { error: 'auth' });
      const list = Object.values(users).sort((a, b) => b.created - a.created);
      if (u.searchParams.get('format') === 'csv') {
        const q = v => '"' + String(v).replace(/"/g, '""') + '"';
        res.writeHead(200, { 'content-type': 'text/csv; charset=utf-8', 'content-disposition': 'attachment; filename=users.csv' });
        return res.end('\ufeff' + 'שם,טלפון,מייל,נרשם\n' + list.map(x => [x.name, x.phone, x.email, new Date(x.created).toISOString()].map(q).join(',')).join('\n'));
      }
      return send(res, 200, list);
    }
    const m = u.pathname.match(/^\/api\/doc\/([a-z0-9]{2,64})$/);
    if (m) {
      const id = m[1], admin = isAdmin(req);
      if (!admin && !(/^[a-f0-9]{64}$/.test(id) && eq(req.headers['x-id'] || '', id))) return send(res, 401, { error: 'auth' });
      if (req.method === 'GET') return db[id] ? send(res, 200, { data: db[id] }) : send(res, 404, { error: 'none' });
      if (req.method === 'PUT') {
        const b = await body(req);
        if (!admin && !customerOk(db[id], b)) return send(res, 403, { error: 'locked' });
        db[id] = b; persist(); rememberUser(id, b); return send(res, 200, { ok: true });
      }
    }
    if (u.pathname.startsWith('/api/')) return send(res, 404, { error: 'none' });
    let p = path.normalize(decodeURIComponent(u.pathname)).replace(/^(\.\.[\/\\])+/, '');
    if (p === '/' || p === '\\') p = '/index.html';
    const f = path.join(__dirname, 'public', p);
    if (!f.startsWith(path.join(__dirname, 'public'))) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => {
      if (e) { res.writeHead(404); return res.end('Not found'); }
      res.writeHead(200, { 'content-type': MIME[path.extname(f)] || 'application/octet-stream', 'x-content-type-options': 'nosniff' }); res.end(d);
    });
  } catch (e) { send(res, 400, { error: 'bad' }); }
}).listen(PORT, () => console.log('flowers on :' + PORT + (ADMIN_PASSWORD ? '' : ' (ADMIN_PASSWORD לא הוגדר!)')));
