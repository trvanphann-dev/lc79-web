'use strict';
const express = require('express');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ==================== CONFIG ====================
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const WEB_USER = process.env.WEB_USER || 'admin';
const WEB_PASSWORD = process.env.WEB_PASSWORD || '';
const COOKIE_SECURE = process.env.COOKIE_SECURE === '1';
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
const INDEX_FILE = path.join(__dirname, 'index.html');

if (!WEB_PASSWORD || WEB_PASSWORD.length < 12) {
  console.error('THIEU WEB_PASSWORD (>=12 ky tu). Set env var truoc khi chay.');
  process.exit(1);
}

const ORIGIN = 'https://lc79b.bet';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)';
const API_LOGIN = 'https://apifo88daigia.tele68.com/api';
const API_LOBBY = 'https://wlb.tele68.com/v1/lobby/auth/login';
const API_REDEEM = 'https://gameapi.tele68.com/v1/giftcode/redemption';
const DEFAULT_CHANNEL = 'toolrdlc79test';
const DEFAULT_REGEX = '[A-Z]{8,10}';

// ==================== STATE ====================
const S = {
  accounts: [],
  channel: DEFAULT_CHANNEL,
  regex: DEFAULT_REGEX,
  pollSec: 5,
  paused: false,
  lastCode: '',
  startTime: Date.now(),
  logs: [],
};

function log(msg) {
  const line = '[' + new Date().toTimeString().slice(0, 8) + '] ' + String(msg);
  S.logs.unshift(line);
  if (S.logs.length > 200) S.logs.length = 200;
  console.log(line);
}

function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const d = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      if (Array.isArray(d.accounts)) S.accounts = d.accounts.map(a => ({
        username: a.username, password: a.password,
        loggedIn: false, at: '', jwt: '', lastError: ''
      }));
      if (d.channel) S.channel = d.channel;
      if (d.regex) S.regex = d.regex;
      if (typeof d.pollSec === 'number') S.pollSec = Math.max(1, d.pollSec);
      log('Nap data: ' + S.accounts.length + ' acc, kenh ' + S.channel);
    }
  } catch (e) { log('loadData loi: ' + e.message); }
}
function saveData() {
  try {
    const dir = path.dirname(DATA_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(DATA_FILE, JSON.stringify({
      accounts: S.accounts.map(a => ({ username: a.username, password: a.password })),
      channel: S.channel, regex: S.regex, pollSec: S.pollSec
    }, null, 2), 'utf8');
  } catch (e) { log('saveData loi: ' + e.message); }
}

// ==================== HELPERS ====================
const md5 = s => crypto.createHash('md5').update(s, 'utf8').digest('hex');
const hashPass = p => /^[0-9a-fA-F]{32}$/.test(p) ? p.toLowerCase() : md5(p);
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function http(url, { method = 'GET', headers = {}, body } = {}) {
  const opts = { method, headers: { ...headers } };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = body;
  }
  const r = await fetch(url, opts);
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch (_) {}
  return { status: r.status, text, json };
}

function cleanMsg(m0) {
  let m = String(m0 || '');
  const mm = /"message":"([^"]*)"/.exec(m);
  if (mm) m = mm[1];
  m = m.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
  if (/h[^ ]?t h[^ ]?n|qu[^ ]? ?t[^ ]?ng.*h[^ ]?p l[^ ]?/.test(m)) return 'Ma qua tang khong hop le hoac da het han';
  if (/x[^ ]?c th[^ ]?c b[^ ]?o m[^ ]?t/.test(m)) return 'Can xac thuc bao mat truoc khi su dung code';
  return m;
}

// ==================== LOGIN / REDEEM ====================
async function loginOne(acc) {
  try {
    const url = API_LOGIN + '?c=3&un=' + encodeURIComponent(acc.username) + '&pw=' + acc.password + '&cp=R&cl=R&pf=web&at=';
    const r = await http(url);
    if (r.status >= 400 || !r.json || r.json.success !== true) {
      acc.loggedIn = false; acc.at = ''; acc.jwt = '';
      acc.lastError = 'login fail: ' + cleanMsg(r.text);
      return false;
    }
    const at = r.json.accessToken;
    let nick = '';
    try {
      let b64 = r.json.sessionKey;
      const pad = (4 - (b64.length % 4)) % 4;
      if (pad) b64 += '='.repeat(pad);
      nick = JSON.parse(Buffer.from(b64, 'base64').toString('utf8')).nickname;
    } catch (_) {}
    const lob = await http(API_LOBBY + '?cp=R&cl=R&pf=web&at=' + at, {
      method: 'POST',
      headers: { Origin: ORIGIN, Referer: ORIGIN + '/' },
      body: JSON.stringify({ username: acc.username, nickName: nick, accessToken: at }),
    });
    if (lob.status >= 400 || !lob.json || !lob.json.token) {
      acc.loggedIn = false; acc.at = ''; acc.jwt = '';
      acc.lastError = 'lobby: ' + cleanMsg(lob.text);
      return false;
    }
    acc.loggedIn = true;
    acc.at = at;
    acc.jwt = lob.json.token;
    acc.lastError = '';
    return true;
  } catch (e) {
    acc.loggedIn = false;
    acc.lastError = 'HTTP: ' + (e.message || '');
    return false;
  }
}

async function redeemOne(acc, code) {
  if (!acc.loggedIn) return { user: acc.username, ok: false, msg: 'chua login' };
  try {
    const r = await http(API_REDEEM + '?cp=R&cl=R&pf=web&at=' + acc.at, {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + acc.jwt, Origin: ORIGIN, Referer: ORIGIN + '/' },
      body: JSON.stringify({ code }),
    });
    if (r.status >= 400) return { user: acc.username, ok: false, msg: cleanMsg(r.text) };
    return { user: acc.username, ok: true, msg: cleanMsg(r.text) };
  } catch (e) {
    return { user: acc.username, ok: false, msg: 'HTTP: ' + (e.message || '') };
  }
}

async function loginAll() {
  if (!S.accounts.length) return { ok: 0, fail: 0, details: [] };
  log('Dang login ' + S.accounts.length + ' acc ...');
  const results = await Promise.all(S.accounts.map(loginOne));
  const ok = results.filter(Boolean).length;
  const fail = results.length - ok;
  for (const a of S.accounts)
    log('  [' + (a.loggedIn ? 'OK' : 'FAIL') + '] ' + a.username + (a.lastError ? ' - ' + a.lastError : ''));
  log('Login xong: OK=' + ok + ' FAIL=' + fail);
  return { ok, fail, details: S.accounts.map(a => ({ user: a.username, ok: a.loggedIn, error: a.lastError })) };
}

async function redeemAll(code) {
  const list = S.accounts.filter(a => a.loggedIn);
  if (!list.length) return { code, ok: 0, fail: 0, details: [] };
  log('Dang doi ma ' + code + ' cho ' + list.length + ' acc ...');
  const results = await Promise.all(list.map(a => redeemOne(a, code)));
  const ok = results.filter(r => r.ok).length;
  const fail = results.length - ok;
  for (const r of results) log('  [' + (r.ok ? 'OK' : 'FAIL') + '] ' + r.user + ' - ' + r.msg);
  log('Doi ma xong: OK=' + ok + ' FAIL=' + fail);
  return { code, ok, fail, details: results };
}

// ==================== TELEGRAM PULL ====================
async function getCodes(channel, rxStr) {
  let html = '';
  try {
    const r = await fetch('https://t.me/s/' + channel, { headers: { 'User-Agent': UA, 'Cache-Control': 'no-cache' } });
    html = await r.text();
  } catch (_) {}
  const rx = new RegExp(rxStr);
  const out = [];
  const segs = String(html).split('<div class="tgme_widget_message_wrap');
  for (const s of segs) {
    const tm = (s.match(/<time datetime="([^"]+)"/) || [])[1] || '';
    for (const x of s.matchAll(/<code>([A-Z0-9]+)<\/code>/g))
      if (rx.test(x[1])) out.push({ time: tm, code: x[1] });
  }
  if (!out.length) {
    for (const s of segs) {
      const tm = (s.match(/<time datetime="([^"]+)"/) || [])[1] || '';
      const t = (s.match(/<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)<\/div>/s) || [])[1] || '';
      const txt = t.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
      for (const x of String(txt).matchAll(new RegExp('\\b' + rxStr + '\\b', 'g')))
        out.push({ time: tm, code: x[0] });
    }
  }
  out.sort((a, b) => (a.time < b.time ? 1 : a.time > b.time ? -1 : 0));
  return out;
}

// ==================== WATCHER ====================
let watcherRunning = false;
async function watcherLoop() {
  watcherRunning = true;
  log('Watcher khoi dong. Kenh: ' + S.channel);
  if (S.accounts.length) await loginAll();
  while (true) {
    try {
      if (!S.paused) {
        const codes = await getCodes(S.channel, S.regex);
        if (codes.length && codes[0].code !== S.lastCode) {
          S.lastCode = codes[0].code;
          log('CODE MOI: ' + S.lastCode + (codes[0].time ? ' (' + codes[0].time + ')' : ''));
          await redeemAll(S.lastCode);
        }
      }
    } catch (e) { log('Watcher loi: ' + (e.message || e)); }
    await sleep(Math.max(1, S.pollSec) * 1000);
  }
}

// ==================== EXPRESS ====================
const app = express();
const sessions = new Map();
const COOKIE_NAME = 'lc79sid';
const SESSION_TTL = 12 * 60 * 60 * 1000;

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"],
  styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", 'data:'],
  connectSrc: ["'self'"], upgradeInsecureRequests: null
} } }));
app.use(express.json({ limit: '256kb' }));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30 });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 200 });

const safeEqual = (a, b) => {
  const aa = Buffer.from(String(a)), bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
};
const cookieOpts = maxAge => ({ httpOnly: true, secure: COOKIE_SECURE, sameSite: 'strict', path: '/', maxAge });

function getSession(req) {
  const raw = req.headers.cookie || '';
  const m = raw.split(';').map(v => v.trim()).find(v => v.startsWith(COOKIE_NAME + '='));
  if (!m) return null;
  const sid = decodeURIComponent(m.slice(COOKIE_NAME.length + 1));
  const it = sessions.get(sid);
  if (!it || it.expires < Date.now()) { sessions.delete(sid); return null; }
  it.expires = Date.now() + SESSION_TTL;
  return it;
}
const requireAuth = (req, res, next) => getSession(req) ? next() : res.status(401).json({ ok: false, error: 'Vui long dang nhap.' });

function publicState() {
  return {
    running: watcherRunning,
    paused: S.paused,
    channel: S.channel,
    regex: S.regex,
    lastCode: S.lastCode,
    uptimeMinutes: Math.round((Date.now() - S.startTime) / 6000) / 10,
    totalAccounts: S.accounts.length,
    loggedIn: S.accounts.filter(a => a.loggedIn).length,
    accounts: S.accounts.map(a => ({ username: a.username, loggedIn: a.loggedIn, lastError: a.lastError || '' })),
    pollSec: S.pollSec,
    logs: S.logs.slice(0, 80),
    dataFile: DATA_FILE,
  };
}

// ---- AUTH ----
app.post('/api/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  if (!safeEqual(username || '', WEB_USER) || !safeEqual(password || '', WEB_PASSWORD))
    return res.status(401).json({ ok: false, error: 'Sai ten dang nhap hoac mat khau.' });
  const sid = crypto.randomBytes(32).toString('hex');
  sessions.set(sid, { expires: Date.now() + SESSION_TTL });
  res.cookie(COOKIE_NAME, sid, cookieOpts(SESSION_TTL));
  res.json({ ok: true });
});
app.post('/api/logout', requireAuth, (req, res) => {
  const raw = req.headers.cookie || '';
  const m = raw.split(';').map(v => v.trim()).find(v => v.startsWith(COOKIE_NAME + '='));
  if (m) sessions.delete(decodeURIComponent(m.slice(COOKIE_NAME.length + 1)));
  res.clearCookie(COOKIE_NAME, cookieOpts(0));
  res.json({ ok: true });
});

// ---- STATE ----
app.get('/api/state', requireAuth, apiLimiter, (req, res) => res.json({ ok: true, state: publicState() }));

// ---- ACCOUNTS ----
app.post('/api/accounts/add', requireAuth, apiLimiter, (req, res) => {
  const b = req.body || {};
  const list = Array.isArray(b.accounts) ? b.accounts : [{ username: b.username, password: b.password }];
  const added = [], errors = [];
  for (const it of list) {
    const u = String(it.username || '').trim();
    const p = String(it.password || '').trim();
    if (!/^[A-Za-z0-9_.-]{2,64}$/.test(u)) { errors.push(u + ': username khong hop le'); continue; }
    if (!p || p.length > 200 || /[\r\n]/.test(p)) { errors.push(u + ': password khong hop le'); continue; }
    if (S.accounts.some(a => a.username === u)) { errors.push(u + ': da ton tai'); continue; }
    S.accounts.push({ username: u, password: hashPass(p), loggedIn: false, at: '', jwt: '', lastError: '' });
    added.push(u);
  }
  if (added.length) {
    saveData();
    log('Them ' + added.length + ' acc: ' + added.join(', '));
    Promise.all(S.accounts.filter(a => added.includes(a.username)).map(loginOne))
      .then(() => saveData()).catch(() => {});
  }
  res.json({ ok: true, added, errors, state: publicState() });
});

app.post('/api/accounts/del', requireAuth, apiLimiter, (req, res) => {
  const u = String((req.body || {}).username || '').trim();
  const before = S.accounts.length;
  S.accounts = S.accounts.filter(a => a.username !== u);
  if (S.accounts.length === before) return res.status(404).json({ ok: false, error: 'Khong tim thay acc.' });
  saveData();
  log('Xoa acc: ' + u);
  res.json({ ok: true, state: publicState() });
});

app.post('/api/accounts/relogin', requireAuth, apiLimiter, async (req, res) => {
  const result = await loginAll();
  saveData();
  res.json({ ok: true, result, state: publicState() });
});

// ---- REDEEM ----
app.post('/api/redeem', requireAuth, apiLimiter, async (req, res) => {
  const code = String((req.body || {}).code || '').trim();
  if (!/^[A-Za-z0-9_-]{3,40}$/.test(code)) return res.status(400).json({ ok: false, error: 'Code khong hop le.' });
  const result = await redeemAll(code.toUpperCase());
  res.json({ ok: true, result, state: publicState() });
});

// ---- CONTROL ----
app.post('/api/control', requireAuth, apiLimiter, (req, res) => {
  const action = String((req.body || {}).action || '');
  if (action === 'pause') { S.paused = true; log('TAM DUNG watcher'); }
  else if (action === 'resume') { S.paused = false; log('CHAY TIEP watcher'); }
  else return res.status(400).json({ ok: false, error: 'Action khong hop le.' });
  res.json({ ok: true, state: publicState() });
});

// ---- CONFIG ----
app.post('/api/config', requireAuth, apiLimiter, (req, res) => {
  const b = req.body || {};
  if (b.channel !== undefined) {
    const ch = String(b.channel).replace(/^@/, '').trim();
    if (!/^[A-Za-z0-9_]{3,32}$/.test(ch)) return res.status(400).json({ ok: false, error: 'Ten kenh khong hop le.' });
    S.channel = ch;
  }
  if (b.regex !== undefined) {
    const rx = String(b.regex).trim();
    if (rx) { try { new RegExp(rx); } catch (e) { return res.status(400).json({ ok: false, error: 'Regex khong hop le.' }); } }
    S.regex = rx || DEFAULT_REGEX;
  }
  if (b.pollSec !== undefined) {
    const ps = parseInt(b.pollSec, 10);
    if (!Number.isFinite(ps) || ps < 1 || ps > 300) return res.status(400).json({ ok: false, error: 'pollSec 1-300.' });
    S.pollSec = ps;
  }
  saveData();
  log('Config: channel=' + S.channel + ' pollSec=' + S.pollSec);
  res.json({ ok: true, state: publicState() });
});

// ---- EXPORT / IMPORT ----
app.get('/api/export', requireAuth, apiLimiter, (req, res) => {
  res.setHeader('Content-Disposition', 'attachment; filename="lc79-accounts.json"');
  res.json({
    exportedAt: new Date().toISOString(),
    accounts: S.accounts.map(a => ({ username: a.username, password: a.password })),
    channel: S.channel, regex: S.regex, pollSec: S.pollSec
  });
});

app.post('/api/import', requireAuth, apiLimiter, (req, res) => {
  const b = req.body || {};
  if (!Array.isArray(b.accounts)) return res.status(400).json({ ok: false, error: 'Du lieu import khong hop le.' });
  let added = 0, skipped = 0;
  for (const it of b.accounts) {
    const u = String(it.username || '').trim();
    const p = String(it.password || '').trim();
    if (!/^[A-Za-z0-9_.-]{2,64}$/.test(u) || !p) { skipped++; continue; }
    if (S.accounts.some(a => a.username === u)) { skipped++; continue; }
    S.accounts.push({ username: u, password: hashPass(p), loggedIn: false, at: '', jwt: '', lastError: '' });
    added++;
  }
  if (b.channel) S.channel = String(b.channel).replace(/^@/, '').trim();
  if (b.regex) S.regex = String(b.regex).trim();
  if (typeof b.pollSec === 'number') S.pollSec = Math.max(1, b.pollSec);
  saveData();
  log('Import: +' + added + ' acc, skip ' + skipped);
  Promise.all(S.accounts.filter(a => !a.loggedIn).map(loginOne)).then(() => saveData()).catch(() => {});
  res.json({ ok: true, added, skipped, state: publicState() });
});

// ==================== SERVE index.html ====================
app.get('/', (req, res) => res.sendFile(INDEX_FILE));
app.get('*', (req, res) => res.sendFile(INDEX_FILE));

// ==================== BOOT ====================
loadData();
const server = app.listen(PORT, HOST, () => {
  console.log('LC79 Web nghe tai http://' + HOST + ':' + PORT);
  console.log('Frontend: ' + INDEX_FILE);
  watcherLoop().catch(e => log('Watcher chet: ' + (e.message || e)));
});
function shutdown() { server.close(() => process.exit(0)); setTimeout(() => process.exit(1), 5000).unref(); }
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);