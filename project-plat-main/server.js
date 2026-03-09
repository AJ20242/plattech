const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const SQLiteStoreFactory = require('connect-sqlite3');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
let nodemailer = null;
try {
  nodemailer = require('nodemailer');
} catch (err) {
  nodemailer = null;
}

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const SESSION_SECRET =
  process.env.SESSION_SECRET || 'replace-this-in-production-with-long-random-secret';
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'admin@vss.local').toLowerCase();
const ADMIN_INVITE_CODE = process.env.ADMIN_INVITE_CODE || 'ADMIN123';
const ADMIN_INVITE_CODE_NORMALIZED = ADMIN_INVITE_CODE.trim().toUpperCase();
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
const OPENAI_MODEL = process.env.OPENAI_MODEL || 'gpt-4.1-mini';
const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = Number(process.env.SMTP_PORT || 465);
const SMTP_USER = process.env.SMTP_USER || process.env.GMAIL_ADDRESS || '';
const SMTP_PASS = process.env.SMTP_PASS || process.env.GMAIL_APP_PASSWORD || '';
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER || '';
const AUTH_MFA_ENABLED = String(process.env.AUTH_MFA_ENABLED || 'true').toLowerCase() !== 'false';
const AUTH_MFA_EMAIL_ACTIVE = AUTH_MFA_ENABLED && Boolean(SMTP_USER && SMTP_PASS && SMTP_FROM);
const AUTH_LOCKOUT_MAX_ATTEMPTS = Math.max(Number(process.env.AUTH_LOCKOUT_MAX_ATTEMPTS || 5), 3);
const AUTH_LOCKOUT_MINUTES = Math.max(Number(process.env.AUTH_LOCKOUT_MINUTES || 15), 5);

const db = new sqlite3.Database(path.join(__dirname, 'app.db'));

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      full_name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      role TEXT NOT NULL DEFAULT 'student',
      email_verified INTEGER NOT NULL DEFAULT 0,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);
  db.all("PRAGMA table_info(users)", [], (err, rows) => {
    if (!err && Array.isArray(rows) && !rows.find((r) => r.name === 'role')) {
      db.run("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'student'");
    }
    if (!err && Array.isArray(rows) && !rows.find((r) => r.name === 'email_verified')) {
      db.run("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0");
    }
  });
  db.run(`
    CREATE TABLE IF NOT EXISTS audit_chain (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_type TEXT NOT NULL,
      user_email TEXT,
      payload_json TEXT NOT NULL,
      prev_hash TEXT NOT NULL,
      entry_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS attendance_records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_email TEXT NOT NULL,
      attendance_date TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('present','late','absent')),
      created_at TEXT NOT NULL,
      UNIQUE(user_email, attendance_date)
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS user_settings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_email TEXT NOT NULL UNIQUE,
      notifications_enabled INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS support_tickets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      public_id TEXT NOT NULL UNIQUE,
      user_email TEXT NOT NULL,
      subject TEXT NOT NULL,
      description TEXT NOT NULL,
      priority TEXT NOT NULL CHECK(priority IN ('low','medium','high')),
      status TEXT NOT NULL CHECK(status IN ('open','in_progress','resolved')) DEFAULT 'open',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS material_activities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      created_by_email TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_email TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TEXT NOT NULL,
      used INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS email_verification_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_email TEXT NOT NULL,
      code_hash TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS login_attempts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_email TEXT NOT NULL UNIQUE,
      failed_attempts INTEGER NOT NULL DEFAULT 0,
      locked_until TEXT,
      updated_at TEXT NOT NULL
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS login_mfa_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_email TEXT NOT NULL,
      code_hash TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    )
  `);
});

const SQLiteStore = SQLiteStoreFactory(session);

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'"],
        "style-src": ["'self'", "https://fonts.googleapis.com", "'unsafe-inline'"],
        "font-src": ["'self'", "https://fonts.gstatic.com"],
        "img-src": ["'self'", "data:"],
        "connect-src": ["'self'"]
      }
    },
    referrerPolicy: { policy: 'no-referrer' }
  })
);
app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));

app.use(
  session({
    name: 'vss.sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: new SQLiteStore({
      db: 'sessions.db',
      dir: __dirname
    }),
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: NODE_ENV === 'production',
      maxAge: 1000 * 60 * 60 * 24
    }
  })
);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 25,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many attempts. Please try again later.' }
});

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function sanitizeText(value, maxLen = 255) {
  return String(value || '')
    .replace(/[\u0000-\u001F\u007F]/g, ' ')
    .trim()
    .slice(0, maxLen);
}

function isValidName(name) {
  return /^[A-Za-z][A-Za-z\s.'-]{1,79}$/.test(name);
}

function isStrongPassword(password) {
  return (
    typeof password === 'string' &&
    password.length >= 8 &&
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /[0-9]/.test(password) &&
    /[^A-Za-z0-9]/.test(password)
  );
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function getLoginAttempt(email) {
  return new Promise((resolve, reject) => {
    db.get(
      'SELECT user_email, failed_attempts, locked_until, updated_at FROM login_attempts WHERE user_email = ?',
      [email],
      (err, row) => {
        if (err) return reject(err);
        resolve(row || null);
      }
    );
  });
}

function clearLoginAttempt(email) {
  return new Promise((resolve, reject) => {
    db.run('DELETE FROM login_attempts WHERE user_email = ?', [email], (err) => {
      if (err) return reject(err);
      resolve();
    });
  });
}

function recordFailedLogin(email) {
  return new Promise((resolve, reject) => {
    const now = new Date();
    getLoginAttempt(email)
      .then((row) => {
        const failed = row ? Number(row.failed_attempts || 0) + 1 : 1;
        const lockedUntil =
          failed >= AUTH_LOCKOUT_MAX_ATTEMPTS
            ? new Date(now.getTime() + AUTH_LOCKOUT_MINUTES * 60 * 1000).toISOString()
            : null;
        db.run(
          `
          INSERT INTO login_attempts (user_email, failed_attempts, locked_until, updated_at)
          VALUES (?, ?, ?, ?)
          ON CONFLICT(user_email) DO UPDATE SET
            failed_attempts = excluded.failed_attempts,
            locked_until = excluded.locked_until,
            updated_at = excluded.updated_at
          `,
          [email, failed, lockedUntil, now.toISOString()],
          (err) => {
            if (err) return reject(err);
            resolve({ failed, lockedUntil });
          }
        );
      })
      .catch(reject);
  });
}

function getLockoutSeconds(row) {
  if (!row || !row.locked_until) return 0;
  const lockMs = Date.parse(row.locked_until);
  if (!Number.isFinite(lockMs)) return 0;
  return Math.max(Math.ceil((lockMs - Date.now()) / 1000), 0);
}

function createLoginMfaCode(userEmail) {
  return new Promise((resolve, reject) => {
    const rawCode = String(Math.floor(100000 + Math.random() * 900000));
    const codeHash = sha256Hex(rawCode);
    const createdAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 1000 * 60 * 10).toISOString();
    db.run('UPDATE login_mfa_codes SET used = 1 WHERE user_email = ? AND used = 0', [userEmail], () => {
      db.run(
        `
        INSERT INTO login_mfa_codes (user_email, code_hash, expires_at, used, created_at)
        VALUES (?, ?, ?, 0, ?)
        `,
        [userEmail, codeHash, expiresAt, createdAt],
        function onInsert(err) {
          if (err) return reject(err);
          resolve({ id: this.lastID, code: rawCode, expiresAt });
        }
      );
    });
  });
}

function findValidLoginMfaCode(userEmail, rawCode) {
  return new Promise((resolve, reject) => {
    const codeHash = sha256Hex(String(rawCode || '').trim());
    const now = new Date().toISOString();
    db.get(
      `
      SELECT id, user_email, expires_at, used
      FROM login_mfa_codes
      WHERE user_email = ? AND code_hash = ? AND used = 0 AND expires_at > ?
      LIMIT 1
      `,
      [userEmail, codeHash, now],
      (err, row) => {
        if (err) return reject(err);
        resolve(row || null);
      }
    );
  });
}

function markLoginMfaCodeUsed(id) {
  return new Promise((resolve, reject) => {
    db.run('UPDATE login_mfa_codes SET used = 1 WHERE id = ?', [id], (err) => {
      if (err) return reject(err);
      resolve();
    });
  });
}

async function sendLoginMfaEmail({ toEmail, code }) {
  if (!nodemailer || !SMTP_USER || !SMTP_PASS || !SMTP_FROM) return false;
  const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
  await transporter.sendMail({
    from: SMTP_FROM,
    to: toEmail,
    subject: 'Virtual Support Login Verification Code',
    text: `Your login verification code is: ${code}. It expires in 10 minutes.`,
    html: `<p>Your login verification code is: <strong>${code}</strong></p><p>It expires in 10 minutes.</p>`
  });
  return true;
}

async function sendSigninAlertEmail({ toEmail }) {
  if (!nodemailer || !SMTP_USER || !SMTP_PASS || !SMTP_FROM) return false;
  const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
  const when = new Date().toLocaleString();
  await transporter.sendMail({
    from: SMTP_FROM,
    to: toEmail,
    subject: 'Virtual Support Sign-in Alert',
    text: `Your account signed in at ${when}. If this was not you, reset your password immediately.`,
    html: `<p>Your account signed in at <strong>${when}</strong>.</p><p>If this was not you, reset your password immediately.</p>`
  });
  return true;
}

function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) return reject(err);
      resolve();
    });
  });
}

async function finalizeSignedInSession(req, user) {
  await regenerateSession(req);
  req.session.userId = user.id;
  req.session.email = user.email;
  req.session.role = user.role || 'student';
}

function generateNlpReply(input, history = []) {
  const text = String(input || '').trim();
  const lower = text.toLowerCase();
  const ticketMatch = text.match(/\b(?:ticket|case|ref)\s*#?\s*([a-z0-9-]{4,})\b/i);
  const lastUser = [...history].reverse().find((m) => m.role === 'user');

  if (!text) {
    return 'Please type your question so I can help.';
  }
  if (/\b(hi|hello|hey|good morning|good afternoon)\b/.test(lower)) {
    return 'Hello. I am your AI support assistant. How can I help you today?';
  }
  if (/\b(password|reset|forgot)\b/.test(lower)) {
    return 'For password concerns, please contact your administrator for account assistance.';
  }
  if (/\b(hour|open|schedule|time)\b/.test(lower)) {
    return 'Support is available Monday to Friday, 8:00 AM to 6:00 PM (local time).';
  }
  if (/\b(price|pricing|plan|subscription)\b/.test(lower)) {
    return 'Pricing depends on your selected support package. I can connect you to sales for exact plan details.';
  }
  if (ticketMatch) {
    return `I found your reference ${ticketMatch[1]}. For status updates, please share your registered email or contact live support.`;
  }
  if (/\b(thank|thanks)\b/.test(lower)) {
    return 'You are welcome. If you need anything else, I am here.';
  }
  if (/^\s*(who are you|what can you do)\s*\??$/i.test(text)) {
    return 'I am your virtual assistant. I can handle general questions and also help with support workflows like tickets, attendance, and account concerns.';
  }
  if (/^(explain|define|summarize|compare|how|why|what|when|where)\b/i.test(lower)) {
    return 'Good question. I can give a concise explanation. If you want, I can also provide step-by-step details or a simpler version.';
  }
  if (lastUser && lastUser.content && lower.includes('more')) {
    return `Continuing from your last topic: "${lastUser.content}". Tell me if you want a short answer, detailed answer, or examples.`;
  }
  return 'I can help with open questions too. Share your topic clearly, and I will answer directly with practical steps when needed.';
}

function trimChatHistory(history, max = 12) {
  if (!Array.isArray(history)) return [];
  return history.slice(-max).map((item) => ({
    role: item.role === 'assistant' ? 'assistant' : 'user',
    content: String(item.content || '').slice(0, 1000)
  }));
}

function getSessionChatHistory(req) {
  return trimChatHistory(Array.isArray(req.session.chatHistory) ? req.session.chatHistory : []);
}

function getWelcomeMessage() {
  return {
    role: 'assistant',
    content:
      'Hello. I can handle open-ended conversations. Ask anything, and I will keep context across messages.'
  };
}

async function askOpenAI({ message, history, userEmail, role }) {
  if (!OPENAI_API_KEY) return null;

  const system =
    'You are a helpful assistant for a virtual support system. Provide accurate, concise, practical answers. If uncertain, say what is uncertain and suggest next steps.';
  const conversation = trimChatHistory(history).map((item) => ({
    role: item.role,
    content: item.content
  }));
  const contextLine = userEmail
    ? `Signed-in context: ${userEmail} (${role || 'student'}).`
    : 'Signed-in context: guest user.';

  const payload = {
    model: OPENAI_MODEL,
    input: [
      { role: 'system', content: `${system} ${contextLine}` },
      ...conversation,
      { role: 'user', content: message }
    ],
    temperature: 0.6
  };

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);

  try {
    const response = await fetch('https://api.openai.com/v1/responses', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${OPENAI_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload),
      signal: controller.signal
    });

    if (!response.ok) return null;
    const data = await response.json();
    const text = String(data.output_text || '').trim();
    return text || null;
  } catch (err) {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

function getUserByEmail(email) {
  return new Promise((resolve, reject) => {
    db.get(
      'SELECT id, full_name, email, role, email_verified, password_hash FROM users WHERE email = ?',
      [email],
      (err, row) => {
        if (err) return reject(err);
        resolve(row || null);
      }
    );
  });
}

function getUserById(id) {
  return new Promise((resolve, reject) => {
    db.get('SELECT id, full_name, email, role, email_verified FROM users WHERE id = ?', [id], (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
    });
  });
}

function createUser(fullName, email, role, passwordHash) {
  return new Promise((resolve, reject) => {
    db.run(
      'INSERT INTO users (full_name, email, role, email_verified, password_hash, created_at) VALUES (?, ?, ?, 1, ?, ?)',
      [fullName, email, role, passwordHash, new Date().toISOString()],
      function onInsert(err) {
        if (err) return reject(err);
        resolve(this.lastID);
      }
    );
  });
}

function updateUserPasswordByEmail(email, passwordHash) {
  return new Promise((resolve, reject) => {
    db.run(
      'UPDATE users SET password_hash = ? WHERE email = ?',
      [passwordHash, email],
      function onUpdate(err) {
        if (err) return reject(err);
        resolve(this.changes > 0);
      }
    );
  });
}

function setUserEmailVerified(email) {
  return new Promise((resolve, reject) => {
    db.run('UPDATE users SET email_verified = 1 WHERE email = ?', [email], function onUpdate(err) {
      if (err) return reject(err);
      resolve(this.changes > 0);
    });
  });
}

function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function getLastAuditHash() {
  return new Promise((resolve, reject) => {
    db.get('SELECT entry_hash FROM audit_chain ORDER BY id DESC LIMIT 1', [], (err, row) => {
      if (err) return reject(err);
      resolve(row ? row.entry_hash : 'GENESIS');
    });
  });
}

function createPasswordResetCode(userEmail) {
  return new Promise((resolve, reject) => {
    const rawCode = String(Math.floor(100000 + Math.random() * 900000));
    const codeHash = sha256Hex(rawCode);
    const createdAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 1000 * 60 * 10).toISOString();
    db.run('UPDATE password_reset_tokens SET used = 1 WHERE user_email = ? AND used = 0', [userEmail], () => {
      db.run(
        `
        INSERT INTO password_reset_tokens (user_email, token_hash, expires_at, used, created_at)
        VALUES (?, ?, ?, 0, ?)
        `,
        [userEmail, codeHash, expiresAt, createdAt],
        function onInsert(err) {
          if (err) return reject(err);
          resolve({ id: this.lastID, code: rawCode, expiresAt });
        }
      );
    });
  });
}

function findValidPasswordResetCode(userEmail, rawCode) {
  return new Promise((resolve, reject) => {
    const codeHash = sha256Hex(String(rawCode || '').trim());
    const now = new Date().toISOString();
    db.get(
      `
      SELECT id, user_email, expires_at, used
      FROM password_reset_tokens
      WHERE user_email = ? AND token_hash = ? AND used = 0 AND expires_at > ?
      LIMIT 1
      `,
      [userEmail, codeHash, now],
      (err, row) => {
        if (err) return reject(err);
        resolve(row || null);
      }
    );
  });
}

function markPasswordResetTokenUsed(id) {
  return new Promise((resolve, reject) => {
    db.run('UPDATE password_reset_tokens SET used = 1 WHERE id = ?', [id], (err) => {
      if (err) return reject(err);
      resolve();
    });
  });
}

async function sendPasswordResetEmail({ toEmail, code }) {
  if (!nodemailer || !SMTP_USER || !SMTP_PASS || !SMTP_FROM) return false;
  const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
  await transporter.sendMail({
    from: SMTP_FROM,
    to: toEmail,
    subject: 'Virtual Support Password Reset Code',
    text: `Your password reset code is: ${code}. It expires in 10 minutes.`,
    html: `<p>Your password reset code is: <strong>${code}</strong></p><p>It expires in 10 minutes.</p>`
  });
  return true;
}

async function sendVerificationCodeEmail({ toEmail, code }) {
  if (!nodemailer || !SMTP_USER || !SMTP_PASS || !SMTP_FROM) return false;
  const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
  await transporter.sendMail({
    from: SMTP_FROM,
    to: toEmail,
    subject: 'Virtual Support Email Verification Code',
    text: `Your verification code is: ${code}. It expires in 10 minutes.`,
    html: `<p>Your verification code is: <strong>${code}</strong></p><p>It expires in 10 minutes.</p>`
  });
  return true;
}

function createEmailVerificationCode(userEmail) {
  return new Promise((resolve, reject) => {
    const rawCode = String(Math.floor(100000 + Math.random() * 900000));
    const codeHash = sha256Hex(rawCode);
    const createdAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 1000 * 60 * 10).toISOString();
    db.run('UPDATE email_verification_codes SET used = 1 WHERE user_email = ? AND used = 0', [userEmail], () => {
      db.run(
        `
        INSERT INTO email_verification_codes (user_email, code_hash, expires_at, used, created_at)
        VALUES (?, ?, ?, 0, ?)
        `,
        [userEmail, codeHash, expiresAt, createdAt],
        function onInsert(err) {
          if (err) return reject(err);
          resolve({ id: this.lastID, code: rawCode, expiresAt });
        }
      );
    });
  });
}

function findValidEmailVerificationCode(userEmail, rawCode) {
  return new Promise((resolve, reject) => {
    const codeHash = sha256Hex(String(rawCode || '').trim());
    const now = new Date().toISOString();
    db.get(
      `
      SELECT id, user_email, expires_at, used
      FROM email_verification_codes
      WHERE user_email = ? AND code_hash = ? AND used = 0 AND expires_at > ?
      LIMIT 1
      `,
      [userEmail, codeHash, now],
      (err, row) => {
        if (err) return reject(err);
        resolve(row || null);
      }
    );
  });
}

function markEmailVerificationCodeUsed(id) {
  return new Promise((resolve, reject) => {
    db.run('UPDATE email_verification_codes SET used = 1 WHERE id = ?', [id], (err) => {
      if (err) return reject(err);
      resolve();
    });
  });
}

async function appendAuditEvent(eventType, userEmail, payload) {
  const prevHash = await getLastAuditHash();
  const createdAt = new Date().toISOString();
  const payloadJson = JSON.stringify(payload || {});
  const hashToStore = sha256Hex(
    `${prevHash}|${eventType}|${userEmail || ''}|${payloadJson}|${createdAt}`
  );

  const entryHash = await new Promise((resolve, reject) => {
    db.run(
      'INSERT INTO audit_chain (event_type, user_email, payload_json, prev_hash, entry_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      [eventType, userEmail || null, payloadJson, prevHash, hashToStore, createdAt],
      (err) => {
        if (err) return reject(err);
        resolve(hashToStore);
      }
    );
  });

  return entryHash;
}

function getAuditRowsByEmail(email) {
  return new Promise((resolve, reject) => {
    db.all(
      'SELECT id, event_type, user_email, payload_json, prev_hash, entry_hash, created_at FROM audit_chain WHERE user_email = ? ORDER BY id ASC',
      [email],
      (err, rows) => {
        if (err) return reject(err);
        resolve(rows || []);
      }
    );
  });
}

function getAllAuditRows() {
  return new Promise((resolve, reject) => {
    db.all(
      'SELECT id, event_type, user_email, payload_json, prev_hash, entry_hash, created_at FROM audit_chain ORDER BY id ASC',
      [],
      (err, rows) => {
        if (err) return reject(err);
        resolve(rows || []);
      }
    );
  });
}

function verifyAuditRows(rows) {
  let prev = 'GENESIS';
  for (const row of rows) {
    const expected = sha256Hex(
      `${prev}|${row.event_type}|${row.user_email || ''}|${row.payload_json}|${row.created_at}`
    );
    if (row.prev_hash !== prev || row.entry_hash !== expected) {
      return false;
    }
    prev = row.entry_hash;
  }
  return true;
}

function isAdminSession(req) {
  if (!req.session) return false;
  if (req.session.role === 'administrator') return true;
  return Boolean(req.session.email && req.session.email.toLowerCase() === ADMIN_EMAIL);
}

function isProfessorSession(req) {
  if (!req.session || !req.session.userId) return false;
  return req.session.role === 'professor';
}

function canUseAttendance(req) {
  if (!req.session || !req.session.userId) return false;
  if (isAdminSession(req)) return true;
  return req.session.role === 'professor';
}

function makeTicketId() {
  return `TKT-${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
}

function categorizeTicketPriority(subject, description) {
  const text = `${subject || ''} ${description || ''}`.toLowerCase();
  const highHints = [
    'urgent',
    'emergency',
    'cannot login',
    'can not login',
    'system down',
    'payment failed',
    'security',
    'breach',
    'critical'
  ];
  const mediumHints = ['error', 'failed', 'issue', 'problem', 'delay', 'not working', 'unable'];
  if (highHints.some((k) => text.includes(k))) return 'high';
  if (mediumHints.some((k) => text.includes(k))) return 'medium';
  return 'low';
}

function createTicket({ userEmail, subject, description, priority }) {
  return new Promise((resolve, reject) => {
    const publicId = makeTicketId();
    const now = new Date().toISOString();
    db.run(
      `
      INSERT INTO support_tickets (public_id, user_email, subject, description, priority, status, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, 'open', ?, ?)
      `,
      [publicId, userEmail, subject, description, priority, now, now],
      function onInsert(err) {
        if (err) return reject(err);
        resolve({ id: this.lastID, publicId, createdAt: now });
      }
    );
  });
}

function listTicketsByEmail(userEmail) {
  return new Promise((resolve, reject) => {
    db.all(
      `
      SELECT public_id, subject, description, priority, status, created_at, updated_at
      FROM support_tickets
      WHERE user_email = ?
      ORDER BY id DESC
      `,
      [userEmail],
      (err, rows) => {
        if (err) return reject(err);
        resolve(rows || []);
      }
    );
  });
}

function getTicketByPublicId(publicId) {
  return new Promise((resolve, reject) => {
    db.get(
      `
      SELECT id, public_id, user_email, subject, description, priority, status, created_at, updated_at
      FROM support_tickets
      WHERE public_id = ?
      `,
      [publicId],
      (err, row) => {
        if (err) return reject(err);
        resolve(row || null);
      }
    );
  });
}

function updateTicketStatus(publicId, status) {
  return new Promise((resolve, reject) => {
    const now = new Date().toISOString();
    db.run(
      'UPDATE support_tickets SET status = ?, updated_at = ? WHERE public_id = ?',
      [status, now, publicId],
      function onUpdate(err) {
        if (err) return reject(err);
        resolve(this.changes > 0);
      }
    );
  });
}

function listAllUsers() {
  return new Promise((resolve, reject) => {
    db.all(
      `
      SELECT id, full_name, email, role, created_at
      FROM users
      ORDER BY id DESC
      `,
      [],
      (err, rows) => {
        if (err) return reject(err);
        resolve(rows || []);
      }
    );
  });
}

function updateUserRoleById(userId, role) {
  return new Promise((resolve, reject) => {
    db.run('UPDATE users SET role = ? WHERE id = ?', [role, userId], function onUpdate(err) {
      if (err) return reject(err);
      resolve(this.changes > 0);
    });
  });
}

function listAllTickets() {
  return new Promise((resolve, reject) => {
    db.all(
      `
      SELECT public_id, user_email, subject, description, priority, status, created_at, updated_at
      FROM support_tickets
      ORDER BY id DESC
      `,
      [],
      (err, rows) => {
        if (err) return reject(err);
        resolve(rows || []);
      }
    );
  });
}

function listMaterialActivities() {
  return new Promise((resolve, reject) => {
    db.all(
      `SELECT id, title, description, created_by_email, created_at FROM material_activities ORDER BY id DESC`,
      [],
      (err, rows) => {
        if (err) return reject(err);
        resolve(rows || []);
      }
    );
  });
}

function createMaterialActivity({ title, description, createdByEmail }) {
  return new Promise((resolve, reject) => {
    const now = new Date().toISOString();
    db.run(
      `INSERT INTO material_activities (title, description, created_by_email, created_at) VALUES (?, ?, ?, ?)`,
      [String(title).trim(), String(description).trim(), createdByEmail, now],
      function (err) {
        if (err) return reject(err);
        resolve({ id: this.lastID, createdAt: now });
      }
    );
  });
}

function deleteMaterialActivity(id, createdByEmail) {
  return new Promise((resolve, reject) => {
    db.run(
      'DELETE FROM material_activities WHERE id = ? AND created_by_email = ?',
      [id, createdByEmail],
      function (err) {
        if (err) return reject(err);
        resolve(this.changes > 0);
      }
    );
  });
}

function getAttendanceSummary(attendanceDate) {
  return new Promise((resolve, reject) => {
    db.get('SELECT COUNT(*) AS total FROM users', [], (err, totalRow) => {
      if (err) return reject(err);
      db.all(
        'SELECT status, COUNT(*) AS count FROM attendance_records WHERE attendance_date = ? GROUP BY status',
        [attendanceDate],
        (err2, rows) => {
          if (err2) return reject(err2);

          const counts = { present: 0, late: 0, absent: 0 };
          for (const row of rows || []) {
            if (counts[row.status] !== undefined) {
              counts[row.status] = row.count;
            }
          }

          const totalStudents = totalRow ? totalRow.total : 0;
          const computedAbsent = Math.max(totalStudents - counts.present - counts.late, 0);
          const absent = counts.absent > 0 ? counts.absent : computedAbsent;

          resolve({
            date: attendanceDate,
            totalStudents,
            present: counts.present,
            late: counts.late,
            absent
          });
        }
      );
    });
  });
}

function markAttendance({ userEmail, attendanceDate, status }) {
  return new Promise((resolve, reject) => {
    const now = new Date().toISOString();
    db.run(
      `
      INSERT INTO attendance_records (user_email, attendance_date, status, created_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(user_email, attendance_date) DO UPDATE SET
        status = excluded.status,
        created_at = excluded.created_at
      `,
      [userEmail, attendanceDate, status, now],
      (err) => {
        if (err) return reject(err);
        resolve();
      }
    );
  });
}

function listAttendanceByDate(attendanceDate) {
  return new Promise((resolve, reject) => {
    db.all(
      `
      SELECT
        ar.user_email,
        ar.status,
        ar.created_at,
        u.full_name
      FROM attendance_records ar
      LEFT JOIN users u ON u.email = ar.user_email
      WHERE ar.attendance_date = ?
      ORDER BY ar.user_email ASC
      `,
      [attendanceDate],
      (err, rows) => {
        if (err) return reject(err);
        resolve(rows || []);
      }
    );
  });
}

function getNotificationSetting(userEmail) {
  return new Promise((resolve, reject) => {
    db.get(
      'SELECT notifications_enabled FROM user_settings WHERE user_email = ?',
      [userEmail],
      (err, row) => {
        if (err) return reject(err);
        resolve(Boolean(row && row.notifications_enabled === 1));
      }
    );
  });
}

function setNotificationSetting(userEmail, enabled) {
  return new Promise((resolve, reject) => {
    const flag = enabled ? 1 : 0;
    db.run(
      `
      INSERT INTO user_settings (user_email, notifications_enabled, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(user_email) DO UPDATE SET
        notifications_enabled = excluded.notifications_enabled,
        updated_at = excluded.updated_at
      `,
      [userEmail, flag, new Date().toISOString()],
      (err) => {
        if (err) return reject(err);
        resolve();
      }
    );
  });
}

function buildNotifications({ userEmail, attendanceSummary, chainValid, tickets, role = '', activities = [] }) {
  const items = [];
  const now = new Date().toISOString();
  const baseId = Date.now();
  let seq = 0;
  const makeId = (prefix) => `${prefix}-${baseId}-${++seq}`;
  const actionableTickets = (tickets || []).filter((t) => !['resolved', 'closed'].includes(String(t.status || '').toLowerCase()));
  const highPriorityOpen = actionableTickets.filter((t) => String(t.priority || '').toLowerCase() === 'high');
  const mediumPriorityOpen = actionableTickets.filter((t) => String(t.priority || '').toLowerCase() === 'medium');
  const lowPriorityOpen = actionableTickets.filter((t) => String(t.priority || '').toLowerCase() === 'low');
  const staleThresholdMs = 1000 * 60 * 60 * 48;
  const staleOpen = actionableTickets.filter((t) => {
    const createdAt = Date.parse(t.created_at || t.createdAt || '');
    return Number.isFinite(createdAt) && Date.now() - createdAt >= staleThresholdMs;
  });

  items.push({
    id: makeId('welcome'),
    level: 'info',
    title: 'Welcome back',
    message: `Signed in as ${userEmail}.`,
    createdAt: now,
    actionPath: null,
    actionLabel: null
  });

  if (highPriorityOpen.length > 0) {
    const top = highPriorityOpen[0];
    items.push({
      id: makeId('priority-high'),
      level: 'warning',
      title: 'High Priority First',
      message: `${highPriorityOpen.length} high-priority ticket(s) need action. Start with ${top.public_id || top.ticketId || 'your oldest open ticket'}.`,
      createdAt: now,
      actionPath: 'tickets.html',
      actionLabel: 'Open Tickets'
    });
  } else if (mediumPriorityOpen.length > 0) {
    items.push({
      id: makeId('priority-medium'),
      level: 'info',
      title: 'Next Priority Queue',
      message: `${mediumPriorityOpen.length} medium-priority ticket(s) are pending.`,
      createdAt: now,
      actionPath: 'tickets.html',
      actionLabel: 'Review Tickets'
    });
  } else if (lowPriorityOpen.length > 0) {
    items.push({
      id: makeId('priority-low'),
      level: 'info',
      title: 'Low Priority Follow-up',
      message: `${lowPriorityOpen.length} low-priority ticket(s) are still open.`,
      createdAt: now,
      actionPath: 'tickets.html',
      actionLabel: 'Check Tickets'
    });
  } else {
    items.push({
      id: makeId('priority-clear'),
      level: 'success',
      title: 'Priority Queue Clear',
      message: 'No open tickets in your queue.',
      createdAt: now,
      actionPath: 'tickets.html',
      actionLabel: 'View Tickets'
    });
  }

  if (staleOpen.length > 0) {
    items.push({
      id: makeId('stale-open'),
      level: 'warning',
      title: 'Overdue Follow-up',
      message: `${staleOpen.length} open ticket(s) are older than 48 hours.`,
      createdAt: now,
      actionPath: 'tickets.html',
      actionLabel: 'Prioritize Now'
    });
  }

  if (!chainValid) {
    items.push({
      id: makeId('audit'),
      level: 'warning',
      title: 'Audit Integrity Alert',
      message: 'Blockchain audit chain check failed. Please review admin verification.',
      createdAt: now,
      actionPath: 'admin.html',
      actionLabel: 'Open Admin Verify'
    });
  }

  if (attendanceSummary.absent > 0) {
    items.push({
      id: makeId('attendance'),
      level: 'warning',
      title: 'Attendance Update',
      message: `${attendanceSummary.absent} students are marked absent today.`,
      createdAt: now,
      actionPath: 'attendance.html',
      actionLabel: 'Open Attendance'
    });
  } else {
    items.push({
      id: makeId('attendance-good'),
      level: 'success',
      title: 'Attendance Update',
      message: 'No absences recorded for today.',
      createdAt: now,
      actionPath: 'attendance.html',
      actionLabel: 'Open Attendance'
    });
  }

  const roleLower = String(role || '').toLowerCase();
  if (roleLower === 'student' && activities && activities.length > 0) {
    const count = activities.length;
    const latest = activities[0];
    const latestTitle = (latest && (latest.title || latest.name)) ? String(latest.title || latest.name).trim() : 'New activity';
    const msg = count === 1
      ? `New activity from your professor: ${latestTitle}`
      : `You have ${count} activities from your professor. Latest: ${latestTitle}`;
    items.push({
      id: makeId('activities'),
      level: 'info',
      title: 'New Activities',
      message: msg,
      createdAt: now,
      actionPath: 'material.html',
      actionLabel: 'View Activities'
    });
  }

  return items;
}

app.post('/api/auth/signup', authLimiter, async (req, res) => {
  try {
    const fullName = sanitizeText(req.body.fullName, 80);
    const role = String(req.body.role || 'student').trim().toLowerCase();
    const adminCode = sanitizeText(req.body.adminCode, 64);
    const normalizedAdminCode = adminCode.toUpperCase();
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');
    const allowedRoles = ['student', 'professor', 'administrator'];

    if (!isValidName(fullName)) {
      return res.status(400).json({ message: 'Full name must be 2-80 letters and valid symbols only.' });
    }
    if (!allowedRoles.includes(role)) {
      return res.status(400).json({ message: 'Invalid role value.' });
    }
    if (role === 'administrator' && normalizedAdminCode !== ADMIN_INVITE_CODE_NORMALIZED) {
      return res.status(403).json({
        message: 'Invalid admin access code. For local demo, default is ADMIN123 unless changed in .env.'
      });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ message: 'Enter a valid email address.' });
    }
    if (!isStrongPassword(password)) {
      return res.status(400).json({
        message: 'Password must be 8+ chars with upper/lowercase, number, and symbol.'
      });
    }

    const existing = await getUserByEmail(email);
    if (existing) {
      return res.status(409).json({ message: 'This email is already registered.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const userId = await createUser(fullName, email, role, passwordHash);
    await appendAuditEvent('signup', email, {
      fullName,
      userId,
      role
    });

    return res.status(201).json({
      message: 'Account created successfully.'
    });
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.post('/api/auth/signin', authLimiter, async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');

    if (!isValidEmail(email) || password.length < 8) {
      return res.status(400).json({ message: 'Invalid email or password format.' });
    }

    const [attempt, user] = await Promise.all([getLoginAttempt(email), getUserByEmail(email)]);
    const lockoutSeconds = getLockoutSeconds(attempt);
    if (lockoutSeconds > 0) {
      return res.status(429).json({
        message: `Account temporarily locked. Try again in ${lockoutSeconds} seconds.`,
        lockoutSeconds
      });
    }
    if (!user) {
      await recordFailedLogin(email);
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      const result = await recordFailedLogin(email);
      const retryAfter = result.lockedUntil
        ? Math.max(Math.ceil((Date.parse(result.lockedUntil) - Date.now()) / 1000), 0)
        : 0;
      await appendAuditEvent('signin_failed', email, { failedAttempts: result.failed });
      if (retryAfter > 0) {
        await appendAuditEvent('signin_locked', email, { retryAfterSeconds: retryAfter });
        return res.status(429).json({
          message: `Account temporarily locked. Try again in ${retryAfter} seconds.`,
          lockoutSeconds: retryAfter
        });
      }
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    await clearLoginAttempt(email);
    if (AUTH_MFA_EMAIL_ACTIVE) {
      const mfa = await createLoginMfaCode(email);
      let emailSent = false;
      try {
        emailSent = await sendLoginMfaEmail({ toEmail: email, code: mfa.code });
      } catch (err) {
        emailSent = false;
      }
      req.session.pendingAuth = {
        userId: user.id,
        email: user.email,
        role: user.role || 'student',
        createdAt: new Date().toISOString()
      };
      await appendAuditEvent('signin_mfa_challenge', user.email, { emailSent });
      return res.json({
        message: 'Enter the 6-digit verification code to complete sign in.',
        mfaRequired: true,
        emailSent,
        verificationCode: emailSent ? undefined : mfa.code
      });
    }

    await finalizeSignedInSession(req, user);
    let signinAlertSent = false;
    try {
      signinAlertSent = await sendSigninAlertEmail({ toEmail: user.email });
    } catch (err) {
      signinAlertSent = false;
    }
    await appendAuditEvent('signin', user.email, { userId: user.id, role: user.role || 'student' });
    await appendAuditEvent('signin_alert', user.email, { emailSent: signinAlertSent });

    return res.json({ message: 'Sign in successful.' });
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.post('/api/auth/signin/verify-mfa', authLimiter, async (req, res) => {
  try {
    const pending = req.session.pendingAuth;
    if (!pending || !pending.email || !pending.userId) {
      return res.status(400).json({ message: 'No pending sign-in. Please sign in again.' });
    }
    const code = sanitizeText(req.body.code, 16);
    if (!/^\d{6}$/.test(code)) {
      return res.status(400).json({ message: 'Verification code must be 6 digits.' });
    }
    const valid = await findValidLoginMfaCode(pending.email, code);
    if (!valid) {
      return res.status(401).json({ message: 'Invalid or expired verification code.' });
    }
    await markLoginMfaCodeUsed(valid.id);
    const user = await getUserById(pending.userId);
    if (!user || user.email !== pending.email) {
      return res.status(401).json({ message: 'User session invalid. Please sign in again.' });
    }
    await finalizeSignedInSession(req, user);
    delete req.session.pendingAuth;
    let signinAlertSent = false;
    try {
      signinAlertSent = await sendSigninAlertEmail({ toEmail: user.email });
    } catch (err) {
      signinAlertSent = false;
    }
    await appendAuditEvent('signin', user.email, { userId: user.id, role: user.role || 'student', mfa: true });
    await appendAuditEvent('signin_alert', user.email, { emailSent: signinAlertSent });
    return res.json({ message: 'Sign in successful.' });
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.post('/api/auth/verify-email', authLimiter, async (req, res) => {
  return res.status(404).json({ message: 'Email verification is disabled.' });
});

app.post('/api/auth/resend-verification', authLimiter, async (req, res) => {
  return res.status(404).json({ message: 'Email verification is disabled.' });
});

app.post('/api/auth/forgot-password', authLimiter, async (req, res) => {
  return res.status(404).json({ message: 'Forgot password is disabled.' });
});

app.post('/api/auth/reset-password', authLimiter, async (req, res) => {
  return res.status(404).json({ message: 'Forgot password is disabled.' });
});

app.get('/api/auth/me', async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    const user = await getUserById(req.session.userId);
    if (!user) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    return res.json({
      id: user.id,
      fullName: user.full_name,
      email: user.email,
      role: user.role || 'student',
      emailVerified: Number(user.email_verified) === 1
    });
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  const email = req.session.email || null;
  if (email) {
    appendAuditEvent('logout', email, {}).catch(() => {});
  }
  req.session.destroy(() => {
    res.clearCookie('vss.sid');
    res.json({ message: 'Logged out.' });
  });
});

app.get('/api/audit/my', async (req, res) => {
  try {
    if (!req.session.email) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    const allRows = await getAllAuditRows();
    const chainValid = verifyAuditRows(allRows);
    const rows = allRows.filter((row) => row.user_email === req.session.email);
    return res.json({
      chainValid,
      records: rows.map((row) => ({
        id: row.id,
        eventType: row.event_type,
        createdAt: row.created_at,
        entryHash: row.entry_hash
      }))
    });
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.get('/api/audit/admin/full', async (req, res) => {
  try {
    if (!isAdminSession(req)) {
      return res.status(403).json({ message: 'Admin access required.' });
    }
    const rows = await getAllAuditRows();
    const chainValid = verifyAuditRows(rows);
    return res.json({
      chainValid,
      totalRecords: rows.length,
      records: rows.map((row) => ({
        id: row.id,
        eventType: row.event_type,
        userEmail: row.user_email,
        createdAt: row.created_at,
        prevHash: row.prev_hash,
        entryHash: row.entry_hash
      }))
    });
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.get('/api/admin/users', async (req, res) => {
  try {
    if (!isAdminSession(req)) {
      return res.status(403).json({ message: 'Admin access required.' });
    }
    const rows = await listAllUsers();
    return res.json({
      users: rows.map((row) => ({
        id: row.id,
        fullName: row.full_name,
        email: row.email,
        role: row.role || 'student',
        createdAt: row.created_at
      }))
    });
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.patch('/api/admin/users/:userId/role', async (req, res) => {
  try {
    if (!isAdminSession(req)) {
      return res.status(403).json({ message: 'Admin access required.' });
    }
    const userId = Number(req.params.userId);
    const role = String(req.body.role || '').trim().toLowerCase();
    const allowedRoles = ['student', 'professor', 'administrator'];
    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(400).json({ message: 'Invalid user id.' });
    }
    if (!allowedRoles.includes(role)) {
      return res.status(400).json({ message: 'Invalid role value.' });
    }
    const changed = await updateUserRoleById(userId, role);
    if (!changed) {
      return res.status(404).json({ message: 'User not found.' });
    }
    await appendAuditEvent('admin_user_role_updated', req.session.email || null, {
      userId,
      role
    });
    return res.json({ message: 'User role updated.' });
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.get('/api/admin/tickets', async (req, res) => {
  try {
    if (!isAdminSession(req)) {
      return res.status(403).json({ message: 'Admin access required.' });
    }
    const rows = await listAllTickets();
    return res.json({
      tickets: rows.map((row) => ({
        ticketId: row.public_id,
        userEmail: row.user_email,
        subject: row.subject,
        description: row.description,
        priority: row.priority,
        status: row.status,
        createdAt: row.created_at,
        updatedAt: row.updated_at
      }))
    });
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.patch('/api/admin/tickets/:ticketId/status', async (req, res) => {
  try {
    if (!isAdminSession(req)) {
      return res.status(403).json({ message: 'Admin access required.' });
    }
    const ticketId = String(req.params.ticketId || '').trim();
    const nextStatus = String(req.body.status || '').trim().toLowerCase();
    const allowed = ['open', 'in_progress', 'resolved'];
    if (!allowed.includes(nextStatus)) {
      return res.status(400).json({ message: 'Invalid status value.' });
    }
    const changed = await updateTicketStatus(ticketId, nextStatus);
    if (!changed) {
      return res.status(404).json({ message: 'Ticket not found.' });
    }
    await appendAuditEvent('admin_ticket_status_updated', req.session.email || null, {
      ticketId,
      status: nextStatus
    });
    return res.json({ message: 'Ticket status updated.' });
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.delete('/api/admin/tickets/:ticketId', async (req, res) => {
  try {
    if (!isAdminSession(req)) {
      return res.status(403).json({ message: 'Admin access required.' });
    }
    const ticketId = String(req.params.ticketId || '').trim();
    
    // Check if ticket exists
    const ticket = await new Promise((resolve, reject) => {
      db.get(
        'SELECT id, subject, user_email FROM tickets WHERE public_id = ?',
        [ticketId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });
    
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found.' });
    }
    
    // Delete the ticket
    await new Promise((resolve, reject) => {
      db.run('DELETE FROM tickets WHERE public_id = ?', [ticketId], (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
    
    await appendAuditEvent('admin_ticket_deleted', req.session.email || null, {
      ticketId,
      subject: ticket.subject,
      userEmail: ticket.user_email
    });
    
    return res.json({ message: 'Ticket removed.' });
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.get('/api/attendance/summary', async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    if (!canUseAttendance(req)) {
      return res.status(403).json({ message: 'Attendance is restricted to professors and administrators.' });
    }
    const date = String(req.query.date || new Date().toISOString().slice(0, 10));
    const summary = await getAttendanceSummary(date);
    return res.json(summary);
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});


app.post('/api/attendance/mark', async (req, res) => {
  try {
    if (!req.session.userId || !req.session.email) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    if (!canUseAttendance(req)) {
      return res.status(403).json({ message: 'Only professors and administrators can mark attendance.' });
    }
    const status = String(req.body.status || '').trim().toLowerCase();
    const date = String(req.body.date || new Date().toISOString().slice(0, 10)).trim();
    const allowedStatus = ['present', 'late', 'absent'];

    if (!allowedStatus.includes(status)) {
      return res.status(400).json({ message: 'Invalid attendance status.' });
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ message: 'Invalid date format. Use YYYY-MM-DD.' });
    }

    await markAttendance({
      userEmail: req.session.email,
      attendanceDate: date,
      status
    });
    await appendAuditEvent('attendance_marked', req.session.email, {
      date,
      status
    });
    return res.json({
      message: 'Attendance saved.',
      date,
      status
    });
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.get('/api/attendance/today', async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    if (!canUseAttendance(req)) {
      return res.status(403).json({ message: 'Attendance is restricted to professors and administrators.' });
    }
    const date = String(req.query.date || new Date().toISOString().slice(0, 10)).trim();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ message: 'Invalid date format. Use YYYY-MM-DD.' });
    }
    const [summary, rows] = await Promise.all([getAttendanceSummary(date), listAttendanceByDate(date)]);
    return res.json({
      date,
      summary,
      records: rows.map((row) => ({
        fullName: row.full_name || '-',
        userEmail: row.user_email,
        status: row.status,
        createdAt: row.created_at
      }))
    });
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.get('/api/material', async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    const role = (req.session.role || 'student').toLowerCase();
    if (role !== 'professor' && role !== 'student') {
      return res.status(403).json({ message: 'Material and activities are for professors and students only.' });
    }
    const rows = await listMaterialActivities();
    return res.json({
      activities: rows.map((row) => ({
        id: row.id,
        title: row.title,
        description: row.description,
        createdByEmail: row.created_by_email,
        createdAt: row.created_at
      }))
    });
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.post('/api/material', async (req, res) => {
  try {
    if (!req.session.userId || !req.session.email) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    if (!isProfessorSession(req)) {
      return res.status(403).json({ message: 'Material and activities are for professors only.' });
    }
    const title = String(req.body.title || '').trim();
    const description = String(req.body.description || '').trim();
    if (!title) {
      return res.status(400).json({ message: 'Title is required.' });
    }
    const result = await createMaterialActivity({
      title,
      description,
      createdByEmail: req.session.email
    });
    await appendAuditEvent('material_activity_created', req.session.email, {
      id: result.id,
      title
    });
    return res.status(201).json({
      message: 'Activity created.',
      id: result.id,
      createdAt: result.createdAt
    });
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.delete('/api/material/:id', async (req, res) => {
  try {
    if (!req.session.userId || !req.session.email) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    if (!isProfessorSession(req)) {
      return res.status(403).json({ message: 'Material and activities are for professors only.' });
    }
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ message: 'Invalid activity id.' });
    }
    const deleted = await deleteMaterialActivity(id, req.session.email);
    if (!deleted) {
      return res.status(404).json({ message: 'Activity not found or you can only delete your own.' });
    }
    await appendAuditEvent('material_activity_deleted', req.session.email, { id });
    return res.json({ message: 'Activity deleted.' });
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.get('/api/notifications', async (req, res) => {
  try {
    if (!req.session.userId || !req.session.email) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    const enabled = await getNotificationSetting(req.session.email);
    if (!enabled) {
      return res.json({
        enabled: false,
        totalReminders: 0,
        unreadReminders: 0,
        unreadCount: 0,
        notifications: []
      });
    }
    const today = new Date().toISOString().slice(0, 10);
    const userRole = req.session.role || 'student';
    const [attendanceSummary, allRows, userTickets, activitiesRows] = await Promise.all([
      getAttendanceSummary(today),
      getAllAuditRows(),
      listTicketsByEmail(req.session.email),
      userRole === 'student' ? listMaterialActivities() : Promise.resolve([])
    ]);
    const chainValid = verifyAuditRows(allRows);
    const activitiesForNotif = (activitiesRows || []).map((r) => ({ title: r.title, createdAt: r.created_at }));
    const notifications = buildNotifications({
      userEmail: req.session.email,
      attendanceSummary,
      chainValid,
      tickets: userTickets,
      role: userRole,
      activities: activitiesForNotif
    });
    const unreadReminders = notifications.filter((item) => item.level !== 'success').length;
    return res.json({
      enabled: true,
      totalReminders: notifications.length,
      unreadReminders,
      unreadCount: unreadReminders,
      notifications
    });
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.post('/api/tickets', async (req, res) => {
  try {
    if (!req.session.userId || !req.session.email) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    const subject = sanitizeText(req.body.subject, 160);
    const description = sanitizeText(req.body.description, 2000);
    const requestedPriority = String(req.body.priority || '').trim().toLowerCase();
    const inferredPriority = categorizeTicketPriority(subject, description);
    const priority = ['low', 'medium', 'high'].includes(requestedPriority)
      ? requestedPriority
      : inferredPriority;
    const allowedPriority = ['low', 'medium', 'high'];

    if (subject.length < 4) {
      return res.status(400).json({ message: 'Subject must be at least 4 characters.' });
    }
    if (description.length < 10) {
      return res.status(400).json({ message: 'Description must be at least 10 characters.' });
    }
    if (!allowedPriority.includes(priority)) return res.status(400).json({ message: 'Invalid priority value.' });

    const ticket = await createTicket({
      userEmail: req.session.email,
      subject,
      description,
      priority
    });
    await appendAuditEvent('ticket_created', req.session.email, {
      ticketId: ticket.publicId,
      priority
    });

    return res.status(201).json({
      message: 'Ticket created successfully.',
      ticketId: ticket.publicId,
      priority,
      categorizedBy: ['low', 'medium', 'high'].includes(requestedPriority) ? 'manual' : 'system'
    });
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.get('/api/tickets/my', async (req, res) => {
  try {
    if (!req.session.userId || !req.session.email) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    const rows = await listTicketsByEmail(req.session.email);
    return res.json({
      tickets: rows.map((row) => ({
        ticketId: row.public_id,
        subject: row.subject,
        description: row.description,
        priority: row.priority,
        status: row.status,
        createdAt: row.created_at,
        updatedAt: row.updated_at
      }))
    });
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.patch('/api/tickets/:ticketId/status', async (req, res) => {
  try {
    if (!req.session.userId || !req.session.email) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    const ticketId = String(req.params.ticketId || '').trim();
    const nextStatus = String(req.body.status || '').trim().toLowerCase();
    const allowed = ['open', 'in_progress', 'resolved'];
    if (!allowed.includes(nextStatus)) {
      return res.status(400).json({ message: 'Invalid status value.' });
    }

    const ticket = await getTicketByPublicId(ticketId);
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found.' });
    }
    const isOwner = ticket.user_email === req.session.email;
    if (!isOwner && !isAdminSession(req)) {
      return res.status(403).json({ message: 'Forbidden.' });
    }

    const changed = await updateTicketStatus(ticketId, nextStatus);
    if (!changed) {
      return res.status(404).json({ message: 'Ticket not found.' });
    }
    await appendAuditEvent('ticket_status_updated', req.session.email, {
      ticketId,
      status: nextStatus
    });
    return res.json({ message: 'Ticket status updated.' });
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.get('/api/blockchain/ticker', async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    const limit = Math.min(Number(req.query.limit || 12), 50);
    const rows = await new Promise((resolve, reject) => {
      db.all(
        `
        SELECT id, event_type, user_email, created_at, entry_hash
        FROM audit_chain
        ORDER BY id DESC
        LIMIT ?
        `,
        [limit],
        (err, items) => {
          if (err) return reject(err);
          resolve(items || []);
        }
      );
    });
    return res.json({
      events: rows.map((row) => ({
        id: row.id,
        eventType: row.event_type,
        userEmail: row.user_email,
        createdAt: row.created_at,
        hash: row.entry_hash
      }))
    });
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.get('/api/settings/notifications', async (req, res) => {
  try {
    if (!req.session.userId || !req.session.email) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    const enabled = await getNotificationSetting(req.session.email);
    return res.json({ enabled });
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.post('/api/settings/notifications', async (req, res) => {
  try {
    if (!req.session.userId || !req.session.email) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    const enabled = Boolean(req.body && req.body.enabled);
    await setNotificationSetting(req.session.email, enabled);
    return res.json({ enabled });
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.post('/api/chat', authLimiter, async (req, res) => {
  try {
    const message = String(req.body.message || '').trim();
    if (!message) {
      return res.status(400).json({ message: 'Message is required.' });
    }

    const sessionHistory = getSessionChatHistory(req);
    const replyFromLlm = await askOpenAI({
      message,
      history: sessionHistory,
      userEmail: req.session.email || null,
      role: req.session.role || null
    });
    const reply = replyFromLlm || generateNlpReply(message, sessionHistory);

    req.session.chatHistory = trimChatHistory([
      ...sessionHistory,
      { role: 'user', content: message },
      { role: 'assistant', content: reply }
    ]);

    return res.json({ reply, history: req.session.chatHistory });
  } catch (err) {
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

app.get('/api/chat/history', (req, res) => {
  const history = getSessionChatHistory(req);
  if (history.length === 0) {
    return res.json({ history: [getWelcomeMessage()] });
  }
  return res.json({ history });
});

app.delete('/api/chat/history', (req, res) => {
  req.session.chatHistory = [];
  return res.json({ message: 'Chat history cleared.' });
});

app.use(express.static(__dirname));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
