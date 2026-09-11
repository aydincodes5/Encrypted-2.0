'use strict';

// Render-only persistence. The database file belongs on Render's persistent
// disk (set DATA_DIR=/var/data in Render). No Supabase account is required.
const { DatabaseSync } = require('node:sqlite');
const crypto = require('crypto');
const webpush = require('web-push');
const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DATABASE_PATH = path.join(DATA_DIR, 'encryptedchat.sqlite');
const RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
let db;

function initialise() {
  if (db) return;
  fs.mkdirSync(DATA_DIR, { recursive: true });
  db = new DatabaseSync(DATABASE_PATH);
  db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
      display_name TEXT NOT NULL, initial TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY, from_user TEXT NOT NULL, content TEXT NOT NULL,
      msg_type TEXT NOT NULL DEFAULT 'text', filename TEXT NOT NULL DEFAULT '',
      timestamp TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS push_subscriptions (username TEXT PRIMARY KEY, subscription TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS messages_timestamp_idx ON messages (timestamp);
  `);
  const defaults = [
    ['Muhammed_Aydin', process.env.MUHAMMED_PASSWORD, 'Muhammed Aydin', 'M'],
    ['Ayaan_Mohammed_Iqbal', process.env.AYAAN_PASSWORD, 'Ayaan Mohammed Iqbal', 'A']
  ];
  if (!defaults.every(([, password]) => typeof password === 'string' && password.length >= 8)) {
    throw new Error('Set MUHAMMED_PASSWORD and AYAAN_PASSWORD in Render before the first start.');
  }
  const insert = db.prepare('INSERT OR IGNORE INTO users (username, password_hash, display_name, initial) VALUES (?, ?, ?, ?)');
  for (const [username, password, displayName, initial] of defaults) insert.run(username, hashPwd(password), displayName, initial);
  purgeExpiredMessages();
}

function hashPwd(raw) { const salt = crypto.randomBytes(16).toString('hex'); return `scrypt$${salt}$${crypto.scryptSync(raw, salt, 64).toString('hex')}`; }
function verifyPassword(raw, storedHash) {
  if (typeof raw !== 'string' || typeof storedHash !== 'string' || !storedHash.startsWith('scrypt$')) return false;
  const [, salt, expectedHex] = storedHash.split('$');
  const actual = crypto.scryptSync(raw, salt, 64), expected = Buffer.from(expectedHex, 'hex');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}
function purgeExpiredMessages() { if (db) db.prepare('DELETE FROM messages WHERE timestamp < ?').run(new Date(Date.now() - RETENTION_MS).toISOString()); }
function getOrCreateVapidKeys() {
  initialise();
  const values = Object.fromEntries(db.prepare("SELECT key, value FROM settings WHERE key IN ('vapid_public', 'vapid_private')").all().map(row => [row.key, row.value]));
  if (values.vapid_public && values.vapid_private) return { publicKey: values.vapid_public, privateKey: values.vapid_private };
  const keys = webpush.generateVAPIDKeys(), save = db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
  save.run('vapid_public', keys.publicKey); save.run('vapid_private', keys.privateKey); return keys;
}
function getUser(username) { initialise(); return db.prepare('SELECT * FROM users WHERE username = ?').get(username) || null; }
function updatePassword(username, newHash) { initialise(); db.prepare('UPDATE users SET password_hash = ? WHERE username = ?').run(newHash, username); }
function deleteSessionsForUser() {}
function saveMessage({ id, from, content, msg_type, filename, timestamp }) { initialise(); purgeExpiredMessages(); db.prepare('INSERT INTO messages (id, from_user, content, msg_type, filename, timestamp) VALUES (?, ?, ?, ?, ?, ?)').run(id, from, content, msg_type || 'text', filename || '', timestamp); }
function getRecentMessages() { initialise(); purgeExpiredMessages(); return db.prepare('SELECT id, from_user AS "from", content, msg_type, filename, timestamp FROM messages ORDER BY timestamp ASC').all(); }
function savePushSubscription(username, subscription) { initialise(); db.prepare('INSERT OR REPLACE INTO push_subscriptions (username, subscription) VALUES (?, ?)').run(username, subscription); }
function getPushSubscription(username) { initialise(); return db.prepare('SELECT subscription FROM push_subscriptions WHERE username = ?').get(username)?.subscription || null; }
function deletePushSubscription(username) { initialise(); db.prepare('DELETE FROM push_subscriptions WHERE username = ?').run(username); }

module.exports = { initialise, hashPwd, verifyPassword, getOrCreateVapidKeys, getUser, updatePassword, deleteSessionsForUser, saveMessage, getRecentMessages, savePushSubscription, getPushSubscription, deletePushSubscription, DATA_DIR };
