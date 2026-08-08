'use strict';
/**
 * db.js — SQLite database module for EncryptedChat v2
 *
 * Handles: users, messages (7-day retention), push subscriptions, VAPID keys
 */

const Database = require('better-sqlite3');
const crypto   = require('crypto');
const webpush  = require('web-push');
const path     = require('path');
const fs       = require('fs');

// ── Ensure data directory exists ──────────────────────────────────────────────
// DATA_DIR can point to a managed/persistent volume in production (for example
// /var/data on Render). Local development continues to use ./data.
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'chat.db'));
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');

// ── Schema ────────────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    display_name  TEXT NOT NULL,
    initial       TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS messages (
    id        TEXT PRIMARY KEY,
    from_user TEXT NOT NULL,
    content   TEXT NOT NULL,
    msg_type  TEXT NOT NULL DEFAULT 'text',
    filename  TEXT NOT NULL DEFAULT '',
    timestamp TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS push_subscriptions (
    username     TEXT PRIMARY KEY,
    subscription TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    expires_at TEXT NOT NULL
  );
`);

// ── Password hashing (exported so server.js uses the same function) ───────────
function legacyHashPwd(raw) {
  return crypto.createHash('sha256').update('EC-SALT-2024-' + raw).digest('hex');
}

function hashPwd(raw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(raw, salt, 64).toString('hex');
  return `scrypt$${salt}$${hash}`;
}

function verifyPassword(raw, storedHash) {
  if (typeof raw !== 'string' || typeof storedHash !== 'string') return false;
  if (!storedHash.startsWith('scrypt$')) {
    const actual = Buffer.from(legacyHashPwd(raw), 'hex');
    const expected = Buffer.from(storedHash, 'hex');
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  }
  const [, salt, expectedHex] = storedHash.split('$');
  if (!salt || !expectedHex) return false;
  const actual = crypto.scryptSync(raw, salt, 64);
  const expected = Buffer.from(expectedHex, 'hex');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

// ── Seed default users on first run ───────────────────────────────────────────
const DEFAULT_USERS = [
  { username: 'Muhammed_Aydin',       password: process.env.MUHAMMED_PASSWORD, displayName: 'Muhammed Aydin',       initial: 'M' },
  { username: 'Ayaan_Mohammed_Iqbal', password: process.env.AYAAN_PASSWORD,    displayName: 'Ayaan Mohammed Iqbal', initial: 'A' }
];

const _insertUser = db.prepare(
  'INSERT OR IGNORE INTO users (username, password_hash, display_name, initial) VALUES (?, ?, ?, ?)'
);
const existingUserCount = db.prepare('SELECT COUNT(*) AS count FROM users').get().count;
if (existingUserCount === 0) {
  if (!DEFAULT_USERS.every(u => typeof u.password === 'string' && u.password.length >= 8)) {
    throw new Error('Set MUHAMMED_PASSWORD and AYAAN_PASSWORD before starting a new database.');
  }
  db.transaction(() => {
    for (const u of DEFAULT_USERS) {
      _insertUser.run(u.username, hashPwd(u.password), u.displayName, u.initial);
    }
  })();
}

// ── Auto-delete messages older than 7 days ────────────────────────────────────
const SEVEN_DAYS_AGO = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
db.prepare('DELETE FROM messages WHERE timestamp < ?').run(SEVEN_DAYS_AGO);
db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(new Date().toISOString());

// ── VAPID key management ──────────────────────────────────────────────────────
function getOrCreateVapidKeys() {
  const pub  = db.prepare('SELECT value FROM settings WHERE key = ?').get('vapid_public');
  const priv = db.prepare('SELECT value FROM settings WHERE key = ?').get('vapid_private');
  if (pub && priv) return { publicKey: pub.value, privateKey: priv.value };

  const keys   = webpush.generateVAPIDKeys();
  const upsert = db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
  db.transaction(() => {
    upsert.run('vapid_public',  keys.publicKey);
    upsert.run('vapid_private', keys.privateKey);
  })();
  return keys;
}

// ── User operations ───────────────────────────────────────────────────────────
function getUser(username) {
  return db.prepare('SELECT * FROM users WHERE username = ?').get(username) || null;
}

function updatePassword(username, newHash) {
  db.prepare('UPDATE users SET password_hash = ? WHERE username = ?').run(newHash, username);
}

function createSession(token, username, expiresAt) {
  db.prepare('INSERT INTO sessions (token, username, expires_at) VALUES (?, ?, ?)').run(token, username, expiresAt);
}

function getSessionUsername(token) {
  const row = db.prepare('SELECT username FROM sessions WHERE token = ? AND expires_at > ?').get(token, new Date().toISOString());
  return row ? row.username : null;
}

function deleteSessionsForUser(username) {
  db.prepare('DELETE FROM sessions WHERE username = ?').run(username);
}

// ── Message operations ────────────────────────────────────────────────────────
const _insertMsg = db.prepare(
  'INSERT INTO messages (id, from_user, content, msg_type, filename, timestamp) VALUES (?, ?, ?, ?, ?, ?)'
);

function saveMessage({ id, from, content, msg_type, filename, timestamp }) {
  _insertMsg.run(id, from, content, msg_type || 'text', filename || '', timestamp);
}

function getRecentMessages() {
  return db.prepare('SELECT * FROM messages ORDER BY timestamp ASC').all().map(r => ({
    id:        r.id,
    from:      r.from_user,
    content:   r.content,
    msg_type:  r.msg_type,
    filename:  r.filename,
    timestamp: r.timestamp
  }));
}

// ── Push subscription operations ──────────────────────────────────────────────
function savePushSubscription(username, subscriptionJson) {
  db.prepare('INSERT OR REPLACE INTO push_subscriptions (username, subscription) VALUES (?, ?)')
    .run(username, subscriptionJson);
}

function getPushSubscription(username) {
  const row = db.prepare('SELECT subscription FROM push_subscriptions WHERE username = ?').get(username);
  return row ? row.subscription : null;
}

function deletePushSubscription(username) {
  db.prepare('DELETE FROM push_subscriptions WHERE username = ?').run(username);
}

module.exports = {
  hashPwd,
  verifyPassword,
  getOrCreateVapidKeys,
  getUser,
  updatePassword,
  createSession,
  getSessionUsername,
  deleteSessionsForUser,
  saveMessage,
  getRecentMessages,
  savePushSubscription,
  getPushSubscription,
  deletePushSubscription
};
