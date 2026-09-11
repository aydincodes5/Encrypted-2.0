'use strict';
/**
 * server.js — EncryptedChat v2 backend
 *
 * Features: login, change-password, file upload, web push, Socket.IO chat,
 *           WebRTC signaling with pending-offer relay for offline callee.
 */

const express  = require('express');
const http     = require('http');
const { Server } = require('socket.io');
const path     = require('path');
const crypto   = require('crypto');
const multer   = require('multer');
const webpush  = require('web-push');
const fs       = require('fs');
const db       = require('./db');

// Vercel Functions execute from /var/task. Checking the working directory as
// well as VERCEL makes this reliable even when system env vars are not exposed.
const IS_VERCEL = process.env.VERCEL === '1' || process.cwd().startsWith('/var/task');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*', methods: ['GET', 'POST'] } });

// ── Ensure uploads directory exists ──────────────────────────────────────────
// Keep uploads on the same persistent volume as the database in production.
const UPLOADS_DIR = process.env.UPLOADS_DIR || path.join(__dirname, 'public', 'uploads');
// Vercel's deployment filesystem is read-only. Uploads need object storage
// there, so do not try to create a local directory during a Function start.
if (!IS_VERCEL) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// Keep the persistent disk small. Uploaded files follow the same seven-day
// retention policy as messages. This runs on every Render restart.
function purgeExpiredUploads() {
  if (!fs.existsSync(UPLOADS_DIR)) return;
  const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
  for (const entry of fs.readdirSync(UPLOADS_DIR, { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const file = path.join(UPLOADS_DIR, entry.name);
    if (fs.statSync(file).mtimeMs < cutoff) fs.unlinkSync(file);
  }
}

// GitHub's browser uploader can flatten folders. Support both the normal
// ./public layout and a flat layout where the webpage files sit beside server.js.
const bundledPublicDir = path.join(__dirname, 'public');
const CLIENT_DIR = fs.existsSync(path.join(bundledPublicDir, 'index.html')) ? bundledPublicDir : __dirname;
const CLIENT_FILES = new Set(['index.html', 'chat.html', 'style.css', 'app.js', 'chat.js', 'sw.js']);

app.use(express.json());
app.use('/uploads', express.static(UPLOADS_DIR));
app.get(['/', '/index.html'], (req, res) => res.sendFile(path.join(CLIENT_DIR, 'index.html')));
app.get('/:clientFile', (req, res, next) => {
  if (!CLIENT_FILES.has(req.params.clientFile)) return next();
  res.sendFile(path.join(CLIENT_DIR, req.params.clientFile));
});

// ── VAPID (Web Push) ──────────────────────────────────────────────────────────
let vapidKeys;

// ── Multer file upload ────────────────────────────────────────────────────────
const storage = IS_VERCEL
  // The route returns a clear 501 response on Vercel before Multer runs.
  // memoryStorage prevents Multer from trying to create a read-only folder
  // while the serverless function is loading.
  ? multer.memoryStorage()
  : multer.diskStorage({
      destination: UPLOADS_DIR,
      filename: (req, file, cb) => {
        const ext  = path.extname(file.originalname).toLowerCase().replace(/[^a-z0-9.]/g, '');
        const name = Date.now() + '-' + crypto.randomBytes(8).toString('hex') + ext;
        cb(null, name);
      }
    });
const upload = multer({
  storage,
  limits: { fileSize: 15 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    const blocked = /\.(?:exe|msi|bat|cmd|com|scr|ps1|sh|jar)$/i.test(file.originalname);
    cb(blocked ? new Error('This file type is not allowed.') : null, !blocked);
  }
}); // 15 MB max

// ── Rate limiter (brute-force protection) ─────────────────────────────────────
const loginAttempts = new Map();
function checkRateLimit(ip) {
  const now = Date.now();
  const r   = loginAttempts.get(ip) || { n: 0, ts: now };
  if (now - r.ts > 60_000) { r.n = 0; r.ts = now; }
  r.n++;
  loginAttempts.set(ip, r);
  return r.n > 8;
}

// ── Session store: token → username ──────────────────────────────────────────
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const sessionSecret = process.env.SESSION_SECRET || [process.env.MUHAMMED_PASSWORD, process.env.AYAAN_PASSWORD].join(':');
const invalidatedBefore = new Map();

function signSession(payload) {
  return crypto.createHmac('sha256', sessionSecret).update(payload).digest('base64url');
}

function makeSessionToken(username) {
  const payload = Buffer.from(JSON.stringify({ username, issuedAt: Date.now(), expiresAt: Date.now() + SESSION_TTL_MS })).toString('base64url');
  return `${payload}.${signSession(payload)}`;
}

function getSessionUsername(token) {
  if (typeof token !== 'string') return null;
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return null;
  const expected = signSession(payload);
  const given = Buffer.from(signature);
  const expectedBuf = Buffer.from(expected);
  if (given.length !== expectedBuf.length || !crypto.timingSafeEqual(given, expectedBuf)) return null;
  try {
    const session = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!ALL_USERS.includes(session.username) || session.expiresAt <= Date.now()) return null;
    if (session.issuedAt <= (invalidatedBefore.get(session.username) || 0)) return null;
    return session.username;
  } catch { return null; }
}

function validateHeaders(req) {
  const token    = req.headers['x-token'];
  const username = req.headers['x-username'];
  if (!token || !username || getSessionUsername(token) !== username) return null;
  return username;
}

// ── Known user list (only 2 users, static) ───────────────────────────────────
const ALL_USERS = ['Muhammed_Aydin', 'Ayaan_Mohammed_Iqbal'];

// ── Online sockets: username → socket.id ─────────────────────────────────────
const onlineUsers = {};

// ── Pending call offer (held so offline callee can answer after push) ─────────
// Format: { from: string, offer: RTCSessionDescriptionInit, ts: number } | null
let pendingOffer = null;

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

/** Kick a user's current socket (used after password change) */
function kickUser(username) {
  const sockId = onlineUsers[username];
  if (sockId) {
    const sock = io.sockets.sockets.get(sockId);
    if (sock) sock.disconnect();
  }
}

/** Friendly first-name of the OTHER user */
async function friendFirstName(myUsername) {
  const other = ALL_USERS.find(u => u !== myUsername);
  if (!other) return 'Friend';
  const user = await db.getUser(other);
  return user ? user.display_name.split(' ')[0] : 'Friend';
}

/** Send a Web Push notification to the friend (only if they're offline) */
async function pushToFriend(fromUsername, title, body, isCall = false) {
  const friendUsername = ALL_USERS.find(u => u !== fromUsername);
  if (!friendUsername || onlineUsers[friendUsername]) return; // online → no push needed

  const subJson = await db.getPushSubscription(friendUsername);
  if (!subJson) return;

  try {
    await webpush.sendNotification(
      JSON.parse(subJson),
      JSON.stringify({ title, body, url: '/chat.html', isCall })
    );
  } catch (err) {
    if (err.statusCode === 410 || err.statusCode === 404) {
      await db.deletePushSubscription(friendUsername); // subscription expired
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP ROUTES
// ─────────────────────────────────────────────────────────────────────────────

/** POST /login */
app.post('/login', async (req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  if (checkRateLimit(ip)) return res.status(429).json({ error: 'Too many attempts. Wait 1 minute.' });

  const { username, password } = req.body || {};
  const user = await db.getUser(username);

  if (!user || !db.verifyPassword(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  if (!user.password_hash.startsWith('scrypt$')) await db.updatePassword(username, db.hashPwd(password));

  const token = makeSessionToken(username);

  res.json({ success: true, token, username, displayName: user.display_name, initial: user.initial });
});

/** POST /change-password — works both logged-in and from login page */
app.post('/change-password', async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  if (checkRateLimit(ip)) return res.status(429).json({ error: 'Too many attempts. Wait 1 minute.' });

  const { username, oldPassword, newPassword } = req.body || {};

  if (!username || !oldPassword || !newPassword) {
    return res.status(400).json({ error: 'All fields are required.' });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  }
  if (newPassword === oldPassword) {
    return res.status(400).json({ error: 'New password must be different from the current one.' });
  }

  const user = await db.getUser(username);
  if (!user || !db.verifyPassword(oldPassword, user.password_hash)) {
    return res.status(401).json({ error: 'Wrong username or current password.' });
  }

  // Update in database (persists across restarts)
  await db.updatePassword(username, db.hashPwd(newPassword));

  // Invalidate all tokens for this user and disconnect their socket
  await db.deleteSessionsForUser(username);
  invalidatedBefore.set(username, Date.now());
  kickUser(username);

  res.json({ success: true });
});

/** GET /push-config — returns VAPID public key for push subscription */
app.get('/push-config', (req, res) => {
  res.json({ publicKey: vapidKeys.publicKey });
});

/** POST /subscribe — save push subscription */
app.post('/subscribe', async (req, res) => {
  const username = validateHeaders(req);
  if (!username) return res.status(401).json({ error: 'Unauthorized.' });

  const { subscription } = req.body || {};
  if (!subscription) return res.status(400).json({ error: 'No subscription provided.' });

  await db.savePushSubscription(username, JSON.stringify(subscription));
  res.json({ success: true });
});

// HTTP message API. This is used by Vercel deployments, where persistent
// Socket.IO connections are not available. The browser polls this endpoint
// for new messages, while local development may still use Socket.IO for calls.
app.get('/messages', async (req, res) => {
  if (!validateHeaders(req)) return res.status(401).json({ error: 'Unauthorized.' });
  res.json(await db.getRecentMessages());
});

app.post('/messages', async (req, res) => {
  const username = validateHeaders(req);
  if (!username) return res.status(401).json({ error: 'Unauthorized.' });
  const { content, msg_type, filename } = req.body || {};
  if (typeof content !== 'string' || content.length > 60_000) {
    return res.status(400).json({ error: 'Invalid message.' });
  }
  const message = {
    id: crypto.randomBytes(8).toString('hex'), from: username, content,
    msg_type: ['image', 'file', 'gif'].includes(msg_type) ? msg_type : 'text',
    filename: typeof filename === 'string' ? filename : '', timestamp: new Date().toISOString()
  };
  await db.saveMessage(message);
  res.status(201).json(message);
  pushToFriend(username, 'New Message', `${await friendFirstName(username)} sent you a message`).catch(() => {});
});

/** POST /upload — file upload (15 MB max) */
app.post('/upload',
  (req, res, next) => {
    if (!validateHeaders(req)) return res.status(401).json({ error: 'Unauthorized.' });
    if (IS_VERCEL) return res.status(501).json({ error: 'File uploads need object storage on Vercel.' });
    next();
  },
  upload.single('file'),
  (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file received.' });
    res.json({
      url:      '/uploads/' + req.file.filename,
      name:     req.file.originalname,
      size:     req.file.size,
      mimetype: req.file.mimetype
    });
  }
);

app.use((err, req, res, next) => {
  if (err) return res.status(400).json({ error: err.message || 'Upload failed.' });
  next();
});

// ─────────────────────────────────────────────────────────────────────────────
// SOCKET.IO
// ─────────────────────────────────────────────────────────────────────────────

io.on('connection', (socket) => {
  let me = null; // authenticated username for this socket

  // ── Auth ──
  socket.on('auth', async ({ username, token }) => {
    if (!await db.getUser(username) || getSessionUsername(token) !== username) {
      socket.emit('auth-fail');
      return socket.disconnect();
    }

    // Disconnect prior session for this user
    if (onlineUsers[username]) {
      const old = io.sockets.sockets.get(onlineUsers[username]);
      if (old) old.disconnect();
    }

    me = username;
    onlineUsers[username] = socket.id;

    // Deliver pending call offer if fresh (< 60 seconds old) and from the other user
    if (pendingOffer && pendingOffer.from !== me && (Date.now() - pendingOffer.ts) < 60_000) {
      socket.emit('call-offer', { from: pendingOffer.from, offer: pendingOffer.offer });
    }

    // Send history + presence
    socket.emit('history', await db.getRecentMessages());
    io.emit('presence', Object.keys(onlineUsers));
  });

  // ── Text message ──
  socket.on('msg', async ({ content }) => {
    if (!me || typeof content !== 'string' || content.length > 60_000) return;

    const msg = {
      id:        crypto.randomBytes(8).toString('hex'),
      from:      me,
      content,
      msg_type:  'text',
      filename:  '',
      timestamp: new Date().toISOString()
    };
    await db.saveMessage(msg);
    io.emit('msg', msg);
    pushToFriend(me, 'New Message', `${await friendFirstName(me)} sent you a message`).catch(() => {});
  });

  // ── File / image message ──
  socket.on('file-msg', async ({ content, filename, msg_type }) => {
    if (!me || typeof content !== 'string') return;

    const msg = {
      id:        crypto.randomBytes(8).toString('hex'),
      from:      me,
      content,
      msg_type:  msg_type === 'image' ? 'image' : 'file',
      filename:  filename || '',
      timestamp: new Date().toISOString()
    };
    await db.saveMessage(msg);
    io.emit('msg', msg);

    const label = msg_type === 'image' ? 'sent you an image 🖼' : 'sent you a file 📎';
    pushToFriend(me, 'New Message', `${await friendFirstName(me)} ${label}`).catch(() => {});
  });

  // ── Typing indicator ──
  socket.on('typing', ({ typing }) => {
    if (me) socket.broadcast.emit('typing', { from: me, typing: !!typing });
  });

  // ── WebRTC: Call offer ──
  socket.on('call-offer', ({ offer }) => {
    if (!me) return;
    pendingOffer = { from: me, offer, ts: Date.now() };
    socket.broadcast.emit('call-offer', { from: me, offer });
    pushToFriend(me, '📞 Incoming Call', `${friendFirstName(me)} is calling! Open the app to answer.`, true);
  });

  // ── WebRTC: Call answer ──
  socket.on('call-answer', ({ answer }) => {
    if (!me) return;
    pendingOffer = null; // offer consumed — call is active
    socket.broadcast.emit('call-answer', { from: me, answer });
  });

  // ── WebRTC: ICE candidate ──
  socket.on('ice-candidate', ({ candidate }) => {
    if (me) socket.broadcast.emit('ice-candidate', { from: me, candidate });
  });

  // ── WebRTC: End call ──
  socket.on('call-end', () => {
    if (!me) return;
    pendingOffer = null;
    socket.broadcast.emit('call-end');
  });

  // ── Disconnect ──
  socket.on('disconnect', () => {
    if (me && onlineUsers[me] === socket.id) {
      delete onlineUsers[me];
      io.emit('presence', Object.keys(onlineUsers));
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// START
// ─────────────────────────────────────────────────────────────────────────────
let initialiseAppPromise;
function initialiseApp() {
  if (initialiseAppPromise) return initialiseAppPromise;
  initialiseAppPromise = (async () => {
    db.initialise();
    purgeExpiredUploads();
    vapidKeys = db.getOrCreateVapidKeys();
    webpush.setVapidDetails('mailto:admin@encryptedchat.app', vapidKeys.publicKey, vapidKeys.privateKey);
  })();
  return initialiseAppPromise;
}

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  initialiseApp().then(() => server.listen(PORT, () => {
    console.log(`EncryptedChat 2.0 running at http://localhost:${PORT}`);
  })).catch(err => {
    console.error('Could not initialise the database:', err.message);
    process.exit(1);
  });
}

module.exports = { app, initialiseApp };
