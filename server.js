'use strict';

const express      = require('express');
const session      = require('express-session');
const bcrypt       = require('bcryptjs');
const path         = require('path');
const fs           = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;

/* ── CORS ── */
const ALLOWED_ORIGINS = [
  'https://bcm-app-production.up.railway.app',
  'http://localhost:3000',
  /\.github\.io$/,
  /\.claude\.ai$/
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allowed = ALLOWED_ORIGINS.some(o =>
    typeof o === 'string' ? o === origin : o.test(origin)
  );
  if (allowed) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

/* ── JSON flat-file database ── */
const DB_FILE = path.join(__dirname, 'db.json');

function readDb() {
  if (!fs.existsSync(DB_FILE)) {
    const blank = { users: {}, messages: {} };
    fs.writeFileSync(DB_FILE, JSON.stringify(blank, null, 2));
    return blank;
  }
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch(e) { return { users: {}, messages: {} }; }
}

function writeDb(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

/* ── Helpers ── */
function genCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let s = '';
  for (let i = 0; i < 8; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s.slice(0, 4) + '-' + s.slice(4);
}

/* ── Middleware ── */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'securecode-dev-secret-change-in-prod',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 7 * 24 * 60 * 60 * 1000   // 7 days
  }
}));

/* Serve the frontend */
app.use(express.static(path.join(__dirname, 'public')));

/* ── API: Session check ── */
app.get('/api/session', (req, res) => {
  if (req.session && req.session.userId) {
    return res.json({ loggedIn: true, id: req.session.userId });
  }
  res.json({ loggedIn: false });
});

/* ── API: Signup ── */
app.post('/api/signup', async (req, res) => {
  try {
    const { id, pin } = req.body;
    if (!id || !pin) return res.json({ error: 'ID and PIN are required.' });
    if (pin.length !== 6 || !/^\d{6}$/.test(pin))
      return res.json({ error: 'PIN must be exactly 6 digits.' });

    const key = id.trim().toUpperCase();
    if (key.length < 3) return res.json({ error: 'ID too short.' });

    const db = readDb();
    if (db.users[key]) return res.json({ error: 'ID already taken — try a different one.' });

    const hash = await bcrypt.hash(pin, 10);
    db.users[key] = { hash, createdAt: Date.now() };
    writeDb(db);

    req.session.userId = key;
    res.json({ ok: true, id: key });
  } catch (e) {
    console.error('signup error:', e);
    res.json({ error: 'Server error. Please try again.' });
  }
});

/* ── API: Login ── */
app.post('/api/login', async (req, res) => {
  try {
    const { id, pin } = req.body;
    if (!id || !pin) return res.json({ error: 'ID and PIN are required.' });

    const key = id.trim().toUpperCase();
    const db  = readDb();
    const user = db.users[key];

    if (!user) return res.json({ error: 'ID not found.' });

    const ok = await bcrypt.compare(pin, user.hash);
    if (!ok) return res.json({ error: 'Wrong PIN.' });

    req.session.userId = key;
    res.json({ ok: true, id: key });
  } catch (e) {
    console.error('login error:', e);
    res.json({ error: 'Server error. Please try again.' });
  }
});

/* ── API: Logout ── */
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

/* ── API: Create message ── */
app.post('/api/create-message', (req, res) => {
  try {
    if (!req.session || !req.session.userId)
      return res.json({ error: 'Not logged in.' });

    const { text } = req.body;
    if (!text || !text.trim()) return res.json({ error: 'Message cannot be empty.' });
    if (text.trim().length > 2000) return res.json({ error: 'Message too long (max 2000 chars).' });

    const db = readDb();
    let code;
    do { code = genCode(); } while (db.messages[code]);

    db.messages[code] = {
      text: text.trim(),
      createdBy: req.session.userId,
      createdAt: Date.now(),
      expiresAt: Date.now() + 30 * 60 * 1000   // 30 min TTL
    };
    writeDb(db);
    res.json({ code });
  } catch (e) {
    console.error('create-message error:', e);
    res.json({ error: 'Server error. Please try again.' });
  }
});

/* ── API: Redeem ── */
app.post('/api/redeem', (req, res) => {
  try {
    const code = (req.body.code || '').replace(/\s/g, '').toUpperCase();
    if (!code) return res.json({ error: 'Enter a code.' });

    const db = readDb();
    const msg = db.messages[code];
    if (!msg) return res.json({ error: 'Code not found or already used.' });

    // Check TTL
    if (Date.now() > msg.expiresAt)  {
      delete db.messages[code];
      writeDb(db);
      return res.json({ error: 'Code expired.' });
    }

    const text = msg.text;
    // One-time read — destroy immediately
    delete db.messages[code];
    writeDb(db);
    res.json({ text });
  } catch (e) {
    console.error('redeem error:', e);
    res.json({ error: 'Server error. Please try again.' });
  }
});

/* Catch-all: serve index.html for SPA */
app.get('/{*path}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/* ── Start ── */
app.listen(PORT, () => {
  console.log(`\n  ✅  SECURECODE server running → http://localhost:${PORT}\n`);
});
