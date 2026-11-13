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
const COOKIE_SECURE = process.env.COOKIE_SECURE === '1';
const ADMIN_PASS = process.env.WEB_PASSWORD || 'admin123456789'; 
const INDEX_FILE = path.join(__dirname, 'index.html');

if (!ADMIN_PASS || ADMIN_PASS.length < 12) {
  console.error('THIEU WEB_PASSWORD (>=12 ky tu).');
  process.exit(1);
}

const ORIGIN = 'https://lc79b.bet';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)';
const API_LOGIN = 'https://apifo88daigia.tele68.com/api';
const API_LOBBY = 'https://wlb.tele68.com/v1/lobby/auth/login';
const API_REDEEM = 'https://gameapi.tele68.com/v1/giftcode/redemption';

const DEFAULT_CHANNEL = 'codelaucuagame'; 
const DEFAULT_REGEX = '[A-Z0-9]{6,12}'; 
const FAST_POLL_MS = 1000; 
const FETCH_TIMEOUT_MS = 4000; // Tăng lên 4s để đỡ báo lỗi mạng

// ==================== DATABASE RAM ====================
const users = {}; // users[key] = { account: {u, p, loggedIn, at, jwt, lastError}, logs: [] }
const globalLogs = [];

function addLog(userKey, msg) {
  const time = new Date().toTimeString().slice(0, 8);
  const line = `[${time}] ${msg}`;
  if (userKey && users[userKey]) {
    users[userKey].logs.unshift(line);
    if (users[userKey].logs.length > 50) users[userKey].logs.length = 50;
  }
  globalLogs.unshift(`[${userKey || 'SYS'}] ${line}`);
  if (globalLogs.length > 100) globalLogs.length = 100;
  console.log(`[${userKey || 'SYS'}] ${line}`);
}

function generateKey() {
  return 'LC79-' + crypto.randomBytes(3).toString('hex').toUpperCase();
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function fetchWithTimeout(url, options = {}, timeout = FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(id);
    return response;
  } catch (error) {
    clearTimeout(id);
    throw error;
  }
}

async function http(url, { method = 'GET', headers = {}, body } = {}) {
  const opts = { method, headers: { ...headers } };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = body;
  }
  const r = await fetchWithTimeout(url, opts);
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
  if (/h[^ ]?t h[^ ]?n|qu[^ ]? ?t[^ ]?ng.*h[^ ]?p l[^ ]?/.test(m)) return 'Mã không hợp lệ/đã dùng';
  return m;
}

const hashPass = p => /^[0-9a-fA-F]{32}$/.test(p) ? p.toLowerCase() : crypto.createHash('md5').update(p, 'utf8').digest('hex');

// ==================== LOGIN / REDEEM ====================
async function loginAcc(userKey) {
  const acc = users[userKey].account;
  if (!acc) return false;
  try {
    const url = API_LOGIN + '?c=3&un=' + encodeURIComponent(acc.u) + '&pw=' + acc.p + '&cp=R&cl=R&pf=web&at=';
    const r = await http(url);
    if (r.status >= 400 || !r.json || r.json.success !== true) {
      acc.loggedIn = false; acc.lastError = 'Sai tài khoản/mật khẩu'; return false;
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
      method: 'POST', headers: { Origin: ORIGIN, Referer: ORIGIN + '/' },
      body: JSON.stringify({ username: acc.u, nickName: nick, accessToken: at }),
    });
    if (lob.status >= 400 || !lob.json || !lob.json.token) {
      acc.loggedIn = false; acc.lastError = 'Lỗi Lobby'; return false;
    }
    acc.loggedIn = true; acc.at = at; acc.jwt = lob.json.token; acc.lastError = '';
    addLog(userKey, 'Đăng nhập thành công: ' + acc.u);
    return true;
  } catch (e) {
    acc.loggedIn = false; acc.lastError = 'Lỗi mạng'; return false;
  }
}

async function redeemForUser(userKey, code) {
  const acc = users[userKey].account;
  if (!acc || !acc.loggedIn) return;
  
  const startT = Date.now();
  addLog(userKey, `BẮT ĐẦU ĐỔI MÃ: ${code}`);
  
  try {
    let r = await http(API_REDEEM + '?cp=R&cl=R&pf=web&at=' + acc.at, {
      method: 'POST', headers: { Authorization: 'Bearer ' + acc.jwt, Origin: ORIGIN, Referer: ORIGIN + '/' },
      body: JSON.stringify({ code }),
    });
    
    if (r.status === 401 || (r.json && r.json.errorCode === 401)) {
        const success = await loginAcc(userKey);
        if(success) {
            r = await http(API_REDEEM + '?cp=R&cl=R&pf=web&at=' + acc.at, {
              method: 'POST', headers: { Authorization: 'Bearer ' + acc.jwt, Origin: ORIGIN, Referer: ORIGIN + '/' },
              body: JSON.stringify({ code }),
            });
        }
    }

    const timeTaken = Date.now() - startT;
    if (r.status >= 400) addLog(userKey, `[FAIL] ${code} (${timeTaken}ms) - ${cleanMsg(r.text)}`);
    else addLog(userKey, `[OK] ${code} (${timeTaken}ms) - Nhận thành công!`);
  } catch (e) {
    const timeTaken = Date.now() - startT;
    let errMsg = e.message;
    if (errMsg.includes('aborted') || errMsg.includes('fetch failed')) {
        errMsg = 'Bị Server Game chặn hoặc rớt mạng (' + timeTaken + 'ms)';
    }
    addLog(userKey, `[LỖI] ${code} - ${errMsg}`);
  }
}

// ==================== BỘ QUÉT CODE ====================
async function getCodes(channel, rxStr) {
  const rx = new RegExp(rxStr);
  const out = [];
  try {
    const r = await fetchWithTimeout('https://t.me/s/' + channel, { headers: { 'User-Agent': UA } });
    const html = await r.text();
    const segs = html.split('<div class="tgme_widget_message_wrap');
    for (const s of segs) {
      const tmStr = (s.match(/<time datetime="([^"]+)"/) || [])[1] || '';
      const tmMs = tmStr ? new Date(tmStr).getTime() : Date.now();
      for (const x of s.matchAll(/<code>([A-Z0-9]+)<\/code>/g))
        if (rx.test(x[1])) out.push({ time: tmMs, code: x[1] });
    }
  } catch (_) {}
  out.sort((a, b) => (b.time - a.time));
  return out;
}

let lastGlobalCode = '';
async function watcherLoop() {
  addLog('SYS', 'Hệ thống theo dõi kênh: ' + DEFAULT_CHANNEL);
  while (true) {
    try {
      const codes = await getCodes(DEFAULT_CHANNEL, DEFAULT_REGEX);
      if (codes.length) {
        const newest = codes[0];
        if (newest.code !== lastGlobalCode) {
          lastGlobalCode = newest.code;
          addLog('SYS', '🔥 PHÁT HIỆN CODE MỚI: ' + lastGlobalCode);
          // Chạy ngầm không cần quan tâm người dùng có mở web hay ko
          for (const key in users) {
             if (users[key].account && users[key].account.loggedIn) {
                redeemForUser(key, lastGlobalCode);
             }
          }
        }
      }
    } catch (e) {}
    await sleep(FAST_POLL_MS);
  }
}

// ==================== EXPRESS ====================
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"],
  styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", 'data:', 'https://lc79.games'],
  connectSrc: ["'self'"], upgradeInsecureRequests: null
} } }));
app.use(express.json({ limit: '10kb' }));

function requireKey(req, res, next) {
  const key = req.headers['x-api-key'];
  if (key === 'ADMIN') return next();
  if (!key || !users[key]) return res.status(401).json({ ok: false, error: 'Key không hợp lệ hoặc đã bị xóa.' });
  req.userKey = key;
  next();
}

app.get('/api/user/state', requireKey, (req, res) => {
  const u = users[req.userKey];
  res.json({
    ok: true,
    state: {
      active: !!(u.account && u.account.loggedIn), // Tự động bật nếu có acc
      account: u.account ? { username: u.account.u, loggedIn: u.account.loggedIn, error: u.account.lastError } : null,
      logs: u.logs,
      lastCode: lastGlobalCode
    }
  });
});

app.post('/api/user/account', requireKey, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ ok: false, error: 'Thiếu thông tin.' });
  
  const u = users[req.userKey];
  if (u.account) return res.status(400).json({ ok: false, error: 'Bạn đã thêm 1 acc rồi. Vui lòng xóa acc cũ.' });

  u.account = { u: username, p: hashPass(password), loggedIn: false, at: '', jwt: '', lastError: '' };
  await loginAcc(req.userKey);
  res.json({ ok: true });
});

app.delete('/api/user/account', requireKey, (req, res) => {
  users[req.userKey].account = null;
  addLog(req.userKey, 'Đã xóa acc.');
  res.json({ ok: true });
});

app.post('/api/admin/login', (req, res) => {
  if (req.body.password === ADMIN_PASS) return res.json({ ok: true });
  res.status(401).json({ ok: false, error: 'Sai mật khẩu Admin.' });
});

app.get('/api/admin/keys', (req, res) => {
  if (req.headers['x-api-key'] !== 'ADMIN') return res.status(401).json({ ok: false });
  const list = Object.keys(users).map(k => ({
    key: k, hasAcc: !!users[k].account, username: users[k].account ? users[k].account.u : '', active: !!(users[k].account && users[k].account.loggedIn)
  }));
  res.json({ ok: true, keys: list });
});

app.post('/api/admin/keys', (req, res) => {
  if (req.headers['x-api-key'] !== 'ADMIN') return res.status(401).json({ ok: false });
  const newKey = generateKey();
  users[newKey] = { account: null, logs: [] };
  addLog('SYS', 'Admin tạo Key mới: ' + newKey);
  res.json({ ok: true, key: newKey });
});

app.delete('/api/admin/keys/:key', (req, res) => {
  if (req.headers['x-api-key'] !== 'ADMIN') return res.status(401).json({ ok: false });
  const k = req.params.key;
  if (users[k]) {
    delete users[k];
    addLog('SYS', 'Admin xóa Key: ' + k);
    res.json({ ok: true });
  } else res.status(404).json({ ok: false });
});

app.get('/', (req, res) => res.sendFile(INDEX_FILE));

// ==================== BOOT ====================
const server = app.listen(PORT, HOST, () => {
  console.log('Server Multi-User nghe tai http://' + HOST + ':' + PORT);
  watcherLoop().catch(e => console.log('Watcher chet: ' + e.message));
});
