'use strict';

const express      = require('express');
const session      = require('express-session');
const bcrypt       = require('bcrypt');
const Database     = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');
const helmet       = require('helmet');
const cors         = require('cors');
const path         = require('path');
const fs           = require('fs');

/* ─── Setup ─────────────────────────────────────────── */
const app  = express();
const PORT = process.env.PORT || 3000;

// Ensure data dir exists
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

/* ─── SQLite DB ──────────────────────────────────────── */
const db = new Database(path.join(DATA_DIR, 'securecode.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    pin_hash    TEXT NOT NULL,
    created_at  INTEGER DEFAULT (strftime('%s','now'))
  );

  CREATE TABLE IF NOT EXISTS messages (
    code        TEXT PRIMARY KEY,
    text        TEXT NOT NULL,
    created_at  INTEGER DEFAULT (strftime('%s','now')),
    expires_at  INTEGER NOT NULL,
    redeemed    INTEGER DEFAULT 0,
    redeemed_at INTEGER
  );
`);

/* Prepared statements */
const stmts = {
  getUser:    db.prepare('SELECT * FROM users WHERE id = ?'),
  createUser: db.prepare('INSERT INTO users (id, pin_hash) VALUES (?, ?)'),
  saveMsg:    db.prepare('INSERT INTO messages (code, text, expires_at) VALUES (?, ?, ?)'),
  getMsg:     db.prepare('SELECT * FROM messages WHERE code = ? AND redeemed = 0 AND expires_at > strftime(\'%s\',\'now\')'),
  redeemMsg:  db.prepare('UPDATE messages SET redeemed = 1, redeemed_at = strftime(\'%s\',\'now\') WHERE code = ?'),
  cleanOld:   db.prepare('DELETE FROM messages WHERE expires_at < strftime(\'%s\',\'now\') - 86400'),
};

/* Cleanup old messages every hour */
setInterval(() => { try { stmts.cleanOld.run(); } catch(_){} }, 3_600_000);

/* ─── Middleware ─────────────────────────────────────── */
app.use(helmet({
  contentSecurityPolicy: false // allow inline scripts in single-file frontend
}));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '50kb' }));
app.use(express.static(path.join(__dirname, 'public')));

/* Session — stored server-side, cookie remembers login for 30 days */
const SqliteStore = require('connect-sqlite3')(session);
app.use(session({
  store: new SqliteStore({
    db: 'sessions.db',
    dir: DATA_DIR
  }),
  secret: process.env.SESSION_SECRET || 'securecode-secret-change-in-prod-' + Math.random(),
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production'
  },
  name: 'sc_session'
}));

/* ─── Helpers ────────────────────────────────────────── */
function generateCode() {
  // 8-char alphanumeric code, uppercase, no ambiguous chars
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 8; i++) {
    if (i === 4) code += '-'; // format as XXXX-XXXX
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  return code;
}

const SALT_ROUNDS = 10;

/* ─── Auth Middleware ────────────────────────────────── */
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
}

/* ─── API Routes ─────────────────────────────────────── */

/* Check session — used by frontend on load to restore login */
app.get('/api/session', (req, res) => {
  if (req.session.userId) {
    res.json({ loggedIn: true, id: req.session.userId });
  } else {
    res.json({ loggedIn: false });
  }
});

/* Sign up */
app.post('/api/signup', async (req, res) => {
  try {
    const { id, pin } = req.body;
    if (!id || typeof id !== 'string' || id.length < 2 || id.length > 40) {
      return res.json({ error: 'Invalid ID' });
    }
    if (!pin || !/^\d{6}$/.test(pin)) {
      return res.json({ error: 'PIN must be exactly 6 digits' });
    }

    const existing = stmts.getUser.get(id);
    if (existing) return res.json({ error: 'ID already taken' });

    const pinHash = await bcrypt.hash(pin, SALT_ROUNDS);
    stmts.createUser.run(id, pinHash);

    // Auto-login after signup
    req.session.userId = id;
    req.session.save(() => res.json({ ok: true, id }));
  } catch (e) {
    console.error(e);
    res.json({ error: 'Server error' });
  }
});

/* Login */
app.post('/api/login', async (req, res) => {
  try {
    const { id, pin } = req.body;
    if (!id || !pin) return res.json({ error: 'Missing credentials' });

    const user = stmts.getUser.get(id);
    if (!user) return res.json({ error: 'Invalid ID or PIN' });

    const match = await bcrypt.compare(pin, user.pin_hash);
    if (!match) return res.json({ error: 'Invalid ID or PIN' });

    req.session.userId = id;
    req.session.save(() => res.json({ ok: true, id }));
  } catch (e) {
    console.error(e);
    res.json({ error: 'Server error' });
  }
});

/* Logout */
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

/* Create encrypted message → returns code */
app.post('/api/create-message', requireAuth, (req, res) => {
  try {
    const { text } = req.body;
    if (!text || typeof text !== 'string' || text.trim().length === 0) {
      return res.json({ error: 'Message cannot be empty' });
    }
    if (text.length > 5000) {
      return res.json({ error: 'Message too long (max 5000 chars)' });
    }

    let code;
    let attempts = 0;
    do {
      code = generateCode();
      attempts++;
      if (attempts > 20) return res.json({ error: 'Could not generate unique code, try again' });
    } while (stmts.getMsg.get(code));

    // Expires in 24 hours
    const expiresAt = Math.floor(Date.now() / 1000) + 86400;
    stmts.saveMsg.run(code, text.trim(), expiresAt);

    res.json({ ok: true, code });
  } catch (e) {
    console.error(e);
    res.json({ error: 'Server error' });
  }
});

/* Redeem code — works WITHOUT login so recipients can use it on their phone */
app.post('/api/redeem', (req, res) => {
  try {
    const raw  = (req.body.code || '').toString().trim().toUpperCase();
    // Accept with or without dash
    const code = raw.length === 9 ? raw : raw.replace(/[^A-Z0-9]/g, '').replace(/^(.{4})(.{4})$/, '$1-$2');

    if (!code || code.length < 4) {
      return res.json({ error: 'Invalid code format' });
    }

    const msg = stmts.getMsg.get(code);
    if (!msg) {
      return res.json({ error: 'Code not found, already redeemed, or expired' });
    }

    stmts.redeemMsg.run(code);
    res.json({ ok: true, text: msg.text });
  } catch (e) {
    console.error(e);
    res.json({ error: 'Server error' });
  }
});

/* Health check */
app.get('/api/health', (req, res) => res.json({ status: 'ok', ts: Date.now() }));

/* Catch-all → serve frontend */
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/* ─── Start ──────────────────────────────────────────── */
app.listen(PORT, () => {
  console.log(`
  ╔═══════════════════════════════════╗
  ║   SECURECODE  v2.0  ONLINE        ║
  ║   http://localhost:${PORT}           ║
  ╚═══════════════════════════════════╝
  `);
});
