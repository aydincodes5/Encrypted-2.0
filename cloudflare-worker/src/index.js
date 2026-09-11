const USERS = [
  ['Muhammed_Aydin', 'Muhammed Aydin', 'M'],
  ['Ayaan_Mohammed_Iqbal', 'Ayaan Mohammed Iqbal', 'A']
];
const MAX_FILE_BYTES = 10 * 1024 * 1024;
const CHUNK_BYTES = 900 * 1024;
const WEEK = 7 * 24 * 60 * 60 * 1000;

const text = new TextEncoder();
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const bytes = b64value => Uint8Array.from(atob(b64value), c => c.charCodeAt(0));
const id = () => crypto.randomUUID().replaceAll('-', '');
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json', ...headers } });
function cors(request, env) {
  const origin = request.headers.get('Origin');
  const allowed = env.APP_ORIGIN || '*';
  return { 'access-control-allow-origin': allowed === '*' ? '*' : origin === allowed ? origin : allowed, 'access-control-allow-headers': 'content-type,x-token,x-username', 'access-control-allow-methods': 'GET,POST,OPTIONS', 'access-control-max-age': '86400' };
}
async function hashPassword(password, secret, salt = crypto.getRandomValues(new Uint8Array(16))) {
  // The server-only secret acts as a pepper. This deliberately uses a fast
  // WebCrypto operation so it stays inside Workers Free's short CPU budget.
  const output = await crypto.subtle.digest('SHA-256', text.encode(`${b64(salt)}:${password}:${secret}`));
  return `${b64(salt)}.${b64(output)}`;
}
async function passwordMatches(password, stored, secret) {
  const [salt] = stored.split('.');
  return stored === await hashPassword(password, secret, bytes(salt));
}
async function sign(payload, secret) {
  const key = await crypto.subtle.importKey('raw', text.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64(await crypto.subtle.sign('HMAC', key, text.encode(payload))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}
async function makeToken(username, secret) { const payload = btoa(JSON.stringify({ username, expiresAt: Date.now() + WEEK })).replaceAll('=', ''); return `${payload}.${await sign(payload, secret)}`; }
async function authenticate(request, env) {
  const username = request.headers.get('x-username'), token = request.headers.get('x-token');
  if (!username || !token || !USERS.some(([name]) => name === username)) return null;
  const [payload, signature] = token.split('.');
  if (!payload || !signature || signature !== await sign(payload, env.SESSION_SECRET)) return null;
  try { const session = JSON.parse(atob(payload)); return session.username === username && session.expiresAt > Date.now() ? username : null; } catch { return null; }
}
async function setup(env) {
  await env.DB.batch([
    env.DB.prepare('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, display_name TEXT NOT NULL, initial TEXT NOT NULL)'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, from_user TEXT NOT NULL, content TEXT NOT NULL, msg_type TEXT NOT NULL, filename TEXT NOT NULL, timestamp TEXT NOT NULL)'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS files (id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL, size INTEGER NOT NULL, created_at TEXT NOT NULL)'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS file_chunks (file_id TEXT NOT NULL, chunk_index INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY (file_id, chunk_index))')
  ]);
  for (const [username, displayName, initial] of USERS) {
    const password = username.startsWith('Muhammed') ? env.MUHAMMED_PASSWORD : env.AYAAN_PASSWORD;
    if (!password || password.length < 8) throw new Error('Worker password secrets are missing.');
    await env.DB.prepare('INSERT OR IGNORE INTO users (username,password_hash,display_name,initial) VALUES (?,?,?,?)').bind(username, await hashPassword(password, env.SESSION_SECRET), displayName, initial).run();
  }
  const cutoff = new Date(Date.now() - WEEK).toISOString();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM messages WHERE timestamp < ?').bind(cutoff),
    env.DB.prepare('DELETE FROM file_chunks WHERE file_id IN (SELECT id FROM files WHERE created_at < ?)').bind(cutoff),
    env.DB.prepare('DELETE FROM files WHERE created_at < ?').bind(cutoff)
  ]);
}

export default {
  async fetch(request, env) {
    const headers = cors(request, env);
    if (request.method === 'OPTIONS') return new Response(null, { headers });
    try {
      await setup(env);
      const url = new URL(request.url), path = url.pathname;
      if (path === '/login' && request.method === 'POST') {
        const { username, password } = await request.json();
        const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
        if (!user || !await passwordMatches(password || '', user.password_hash, env.SESSION_SECRET)) return json({ error: 'Invalid username or password.' }, 401, headers);
        return json({ username: user.username, displayName: user.display_name, initial: user.initial, token: await makeToken(user.username, env.SESSION_SECRET) }, 200, headers);
      }
      if (path === '/change-password' && request.method === 'POST') {
        const { username, oldPassword, newPassword } = await request.json();
        const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
        if (!user || !await passwordMatches(oldPassword || '', user.password_hash, env.SESSION_SECRET)) return json({ error: 'Current password is incorrect.' }, 401, headers);
        if (typeof newPassword !== 'string' || newPassword.length < 8) return json({ error: 'New password must be at least 8 characters.' }, 400, headers);
        await env.DB.prepare('UPDATE users SET password_hash = ? WHERE username = ?').bind(await hashPassword(newPassword, env.SESSION_SECRET), username).run();
        return json({ success: true }, 200, headers);
      }
      if (path === '/messages') {
        const username = await authenticate(request, env); if (!username) return json({ error: 'Unauthorized.' }, 401, headers);
        if (request.method === 'GET') { const result = await env.DB.prepare('SELECT id, from_user AS "from", content, msg_type, filename, timestamp FROM messages ORDER BY timestamp ASC').all(); return json(result.results, 200, headers); }
        if (request.method === 'POST') { const { content, msg_type, filename } = await request.json(); if (typeof content !== 'string' || content.length > 60000) return json({ error: 'Invalid message.' }, 400, headers); const message = { id: id(), from: username, content, msg_type: ['image','file','gif'].includes(msg_type) ? msg_type : 'text', filename: typeof filename === 'string' ? filename : '', timestamp: new Date().toISOString() }; await env.DB.prepare('INSERT INTO messages VALUES (?,?,?,?,?,?)').bind(message.id, message.from, message.content, message.msg_type, message.filename, message.timestamp).run(); return json(message, 201, headers); }
      }
      if (path === '/upload' && request.method === 'POST') {
        if (!await authenticate(request, env)) return json({ error: 'Unauthorized.' }, 401, headers);
        const file = (await request.formData()).get('file'); if (!(file instanceof File) || file.size > MAX_FILE_BYTES) return json({ error: 'Choose one file up to 10 MB.' }, 400, headers);
        const fileId = id(), now = new Date().toISOString(), data = new Uint8Array(await file.arrayBuffer());
        await env.DB.prepare('INSERT INTO files VALUES (?,?,?,?,?)').bind(fileId, file.name.slice(0, 180), file.type || 'application/octet-stream', file.size, now).run();
        const inserts = []; for (let offset = 0, index = 0; offset < data.length; offset += CHUNK_BYTES, index++) { const chunk = data.slice(offset, offset + CHUNK_BYTES); inserts.push(env.DB.prepare('INSERT INTO file_chunks VALUES (?,?,?)').bind(fileId, index, chunk.buffer)); }
        await env.DB.batch(inserts); return json({ url: `${url.origin}/files/${fileId}`, name: file.name, size: file.size }, 201, headers);
      }
      const fileMatch = path.match(/^\/files\/([a-f0-9]{32})$/);
      if (fileMatch && request.method === 'GET') { const file = await env.DB.prepare('SELECT * FROM files WHERE id = ?').bind(fileMatch[1]).first(); if (!file) return new Response('Not found', { status: 404, headers }); const chunks = await env.DB.prepare('SELECT data FROM file_chunks WHERE file_id = ? ORDER BY chunk_index').bind(file.id).all(); return new Response(new Blob(chunks.results.map(row => row.data), { type: file.type }), { headers: { ...headers, 'content-type': file.type, 'content-length': String(file.size), 'content-disposition': `inline; filename="${file.name.replaceAll('"', '')}"` } }); }
      return json({ error: 'Not found.' }, 404, headers);
    } catch (error) { return json({ error: 'Temporary storage error. Please try again.' }, 500, cors(request, env)); }
  }
};
