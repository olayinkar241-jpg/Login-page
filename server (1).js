/**
 * server.js — CSC426 Login App backend
 * Node.js + Express
 *
 * Install:  npm install
 * Run:      node server.js
 * Deploy:   Render / Railway / Heroku (set PORT env var)
 */

const express    = require('express');
const rateLimit  = require('express-rate-limit');
const helmet     = require('helmet');
const path       = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

/* ── Security headers ── */
app.use(helmet({ contentSecurityPolicy: false }));

/* ── Body parser ── */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* ── Serve static files ── */
app.use(express.static(path.join(__dirname, 'public')));
// Also serve index.html at root if not in public/
app.get('/', (req, res) => {
  const p = path.join(__dirname, 'public', 'index.html');
  res.sendFile(p);
});

/* ── Rate limiter: max 10 login attempts per 15 min per IP ── */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, message: 'Too many login attempts. Try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

/* ─────────────────────────────────────────────────────────────
   Simulated user store
   In production: replace with a real DB (PostgreSQL, MongoDB)
   and store bcrypt password hashes, never plaintext.
───────────────────────────────────────────────────────────── */
const USERS = {
  admin:   'Admin@123',
  student: 'Student#1',
  csc426:  'Portal@2024',
};

/* ── POST /api/login ── */
app.post('/api/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;

  // Server-side validation
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username and password are required.' });
  }
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ success: false, message: 'Invalid input types.' });
  }

  const u = username.trim().toLowerCase();

  if (u.length < 3 || u.length > 20) {
    return res.status(400).json({ success: false, message: 'Username must be 3–20 characters.' });
  }
  if (password.length < 8) {
    return res.status(400).json({ success: false, message: 'Password must be at least 8 characters.' });
  }

  // Credential check (use bcrypt.compare in production)
  if (USERS[u] && USERS[u] === password) {
    return res.json({
      success: true,
      message: `Welcome back, ${username.trim()}!`,
      user: { username: username.trim() },
    });
  }

  // Generic error — don't reveal which field was wrong
  return res.status(401).json({ success: false, message: 'Invalid username or password.' });
});

/* ── Health check ── */
app.get('/api/health', (req, res) => res.json({ status: 'ok', ts: new Date().toISOString() }));

/* ── Start server ── */
app.listen(PORT, () => {
  console.log(`CSC426 Login Server running → http://localhost:${PORT}`);
});

module.exports = app;
