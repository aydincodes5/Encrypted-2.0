/* ─── chat.js — EncryptedChat v2 — Main Chat + WebRTC Logic ──────────────── */
'use strict';

// ══════════════════════════════════════════════════════════════════════════════
// SESSION CHECK
// ══════════════════════════════════════════════════════════════════════════════
function getSavedSession() {
  return localStorage.getItem('ec_session') || sessionStorage.getItem('ec_session');
}

function clearSavedSession() {
  localStorage.removeItem('ec_session');
  sessionStorage.removeItem('ec_session');
}

let session = null;
try { session = JSON.parse(getSavedSession() || 'null'); }
catch { clearSavedSession(); }
if (!session) { window.location.replace('index.html'); }

const { username, displayName, initial, token } = session;

// Friend lookup
const USER_MAP = {
  'Muhammed_Aydin':       { displayName: 'Muhammed Aydin',       initial: 'M' },
  'Ayaan_Mohammed_Iqbal': { displayName: 'Ayaan Mohammed Iqbal', initial: 'A' }
};
const friendKey         = Object.keys(USER_MAP).find(k => k !== username);
const friendDisplayName = USER_MAP[friendKey].displayName;
const friendInitial     = USER_MAP[friendKey].initial;
const friendFirstName   = friendDisplayName.split(' ')[0];

// ══════════════════════════════════════════════════════════════════════════════
// AES-256-GCM END-TO-END ENCRYPTION
// Server only ever sees encrypted blobs — never plaintext.
// Both clients derive the same key from the same secret via PBKDF2.
// ══════════════════════════════════════════════════════════════════════════════
const ENC_SECRET = 'EC-AES256-MUHAMMED-AYAAN-2024-V2-XKQP91';
let AES_KEY = null;
const MESSAGE_CACHE_KEY = `ec_messages_v1_${username}`;
const renderedMessageIds = new Set();

function readCachedMessages() {
  try {
    const oldest = Date.now() - 7 * 24 * 60 * 60 * 1000;
    const messages = JSON.parse(localStorage.getItem(MESSAGE_CACHE_KEY) || '[]')
      .filter(msg => msg && msg.id && new Date(msg.timestamp).getTime() >= oldest)
      .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    localStorage.setItem(MESSAGE_CACHE_KEY, JSON.stringify(messages));
    return messages;
  } catch {
    return [];
  }
}

function cacheMessage(msg) {
  try {
    const messages = readCachedMessages();
    const index = messages.findIndex(item => item.id === msg.id);
    if (index >= 0) messages[index] = msg;
    else messages.push(msg);
    localStorage.setItem(MESSAGE_CACHE_KEY, JSON.stringify(messages.slice(-1000)));
  } catch { /* Storage may be disabled or full. Live chat still works. */ }
}

async function initEncryption() {
  const enc = new TextEncoder();
  const raw = await crypto.subtle.importKey('raw', enc.encode(ENC_SECRET), { name: 'PBKDF2' }, false, ['deriveKey']);
  AES_KEY = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode('EC-SALT-V2'), iterations: 100_000, hash: 'SHA-256' },
    raw,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encrypt(plaintext) {
  const enc = new TextEncoder();
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const enc_buf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, AES_KEY, enc.encode(plaintext));
  const buf = new Uint8Array(12 + enc_buf.byteLength);
  buf.set(iv);
  buf.set(new Uint8Array(enc_buf), 12);
  return btoa(String.fromCharCode(...buf));
}

async function decrypt(b64) {
  try {
    const buf  = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const dec  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, AES_KEY, buf.slice(12));
    return new TextDecoder().decode(dec);
  } catch {
    return '🔒 [Encrypted]';
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// UI ELEMENT REFERENCES
// ══════════════════════════════════════════════════════════════════════════════
const chatLayout      = document.getElementById('chatLayout');
const loadingScreen   = document.getElementById('loadingScreen');
const messagesArea    = document.getElementById('messagesArea');
const msgInput        = document.getElementById('msgInput');
const sendBtn         = document.getElementById('sendBtn');
const typingRow       = document.getElementById('typingRow');
const typingLabel     = document.getElementById('typingLabel');
const statusDot       = document.getElementById('statusDot');
const statusLabel     = document.getElementById('statusLabel');

// Populate friend's info
document.getElementById('hdrAvatar').textContent     = friendInitial;
document.getElementById('hdrName').textContent       = friendDisplayName;
document.getElementById('callerAvatar').textContent  = friendInitial;
document.getElementById('callerName').textContent    = `${friendFirstName} is calling…`;
document.getElementById('ringingAvatar').textContent = friendInitial;
document.getElementById('ringingName').textContent   = `Calling ${friendFirstName}…`;
document.getElementById('activeAvatar').textContent  = friendInitial;
document.getElementById('activeCallName').textContent = `In call with ${friendFirstName}`;
document.getElementById('pwdModalUser').textContent  = displayName;

// ══════════════════════════════════════════════════════════════════════════════
// SOCKET.IO
// ══════════════════════════════════════════════════════════════════════════════
const socket = io({ transports: ['websocket', 'polling'], autoConnect: false });

socket.on('connect',   () => socket.emit('auth', { username, token }));
socket.on('auth-fail', () => { clearSavedSession(); window.location.replace('index.html'); });

// ── History ──
socket.on('history', async (messages) => {
  for (const msg of messages) await renderMessage(msg, false);
  if (messages.length > 0) removeEmptyState();
  scrollToBottom(false);

  revealChat();
});

// ── New message ──
socket.on('msg', async (msg) => {
  await renderMessage(msg, true);
  removeEmptyState();
  scrollToBottom(true);
  if (msg.from !== username) pingSound();
});

socket.on('connect_error', () => {
  if (renderedMessageIds.size) revealChat();
});

function revealChat() {
  if (chatLayout.style.display !== 'none') return;
  loadingScreen.classList.add('hidden');
  setTimeout(() => {
    loadingScreen.style.display = 'none';
    chatLayout.style.display = '';
  }, 400);
}

// ── Typing ──
let typingHideTimer = null;
socket.on('typing', ({ from, typing }) => {
  if (from === username) return;
  clearTimeout(typingHideTimer);
  if (typing) {
    typingLabel.textContent = `${friendFirstName} is typing…`;
    typingRow.style.display = 'flex';
    typingHideTimer = setTimeout(() => { typingRow.style.display = 'none'; }, 4000);
  } else {
    typingRow.style.display = 'none';
  }
});

// ── Presence ──
socket.on('presence', (online) => {
  const isOnline = online.includes(friendKey);
  statusDot.className     = 'status-dot' + (isOnline ? ' online' : '');
  statusLabel.textContent = isOnline ? 'Online' : 'Offline';
});

// ══════════════════════════════════════════════════════════════════════════════
// MESSAGE RENDERING
// ══════════════════════════════════════════════════════════════════════════════
let lastDateStr = '';

async function renderMessage(msg, animate) {
  if (!msg || !msg.id || renderedMessageIds.has(msg.id)) return;
  renderedMessageIds.add(msg.id);
  cacheMessage(msg);
  const isMine = (msg.from === username);
  const d      = new Date(msg.timestamp);

  // Date separator
  const dateKey = d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
  if (dateKey !== lastDateStr) {
    lastDateStr = dateKey;
    const sep = document.createElement('div');
    sep.className   = 'date-sep';
    sep.textContent = dateKey;
    if (!animate) sep.style.animation = 'none';
    messagesArea.appendChild(sep);
  }

  const wrap   = document.createElement('div');
  wrap.className = `msg-wrap ${isMine ? 'mine' : 'theirs'}`;
  if (!animate) wrap.style.animation = 'none';

  // Decrypt content
  const plaintext = await decrypt(msg.content);

  // Determine message type
  let bubble;
  const msgType = msg.msg_type || 'text';

  if (msgType === 'image' || msgType === 'gif') {
    bubble = buildImageBubble(plaintext, isMine);
  } else if (msgType === 'file') {
    bubble = buildFileBubble(plaintext, isMine);
  } else {
    // Try parsing as JSON (fallback for older file messages)
    let parsed = null;
    try { parsed = JSON.parse(plaintext); } catch { /* not JSON */ }

    if (parsed && parsed.type === 'image' && parsed.url) {
      bubble = buildImageBubble(JSON.stringify(parsed), isMine);
    } else if (parsed && parsed.type === 'gif' && parsed.url) {
      bubble = buildImageBubble(JSON.stringify(parsed), isMine);
    } else if (parsed && parsed.type === 'file' && parsed.url) {
      bubble = buildFileBubble(JSON.stringify(parsed), isMine);
    } else {
      bubble = document.createElement('div');
      bubble.className   = 'msg-bubble';
      bubble.textContent = plaintext;
    }
  }

  const time = document.createElement('div');
  time.className   = 'msg-time';
  time.textContent = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  wrap.appendChild(bubble);
  wrap.appendChild(time);
  messagesArea.appendChild(wrap);
}

/** Build image bubble from JSON string or URL */
function buildImageBubble(content, isMine) {
  let url = content, name = '';
  try {
    const p = JSON.parse(content);
    url  = p.url  || content;
    name = p.name || '';
  } catch { url = content; }

  const img = document.createElement('img');
  img.className = 'msg-image';
  img.src       = url;
  img.alt       = name || 'Image';
  img.loading   = 'lazy';
  img.onerror   = () => { img.alt = '⚠ Image unavailable'; img.style.opacity = '0.4'; };
  img.addEventListener('click', () => window.open(url, '_blank'));

  const wrap2 = document.createElement('div');
  // Images sit directly in the msg-wrap (no extra padding bubble)
  if (name) {
    const cap = document.createElement('span');
    cap.className   = 'msg-img-name';
    cap.textContent = name;
    wrap2.appendChild(img);
    wrap2.appendChild(cap);
  } else {
    wrap2.appendChild(img);
  }
  return wrap2;
}

/** Build file download bubble from JSON string */
function buildFileBubble(content, isMine) {
  let url = '', name = 'file', size = 0;
  try {
    const p = JSON.parse(content);
    url  = p.url  || '';
    name = p.name || 'file';
    size = p.size || 0;
  } catch { url = content; }

  const div = document.createElement('div');
  div.className = 'file-bubble';

  const ext = name.split('.').pop().toLowerCase();
  const icon = getFileIcon(ext);

  div.innerHTML = `
    <div class="file-bubble-icon">${icon}</div>
    <div class="file-bubble-info">
      <span class="file-bubble-name">${escHtml(name)}</span>
      <span class="file-bubble-size">${size ? fmtSize(size) : ''}</span>
    </div>
  `;

  if (url) {
    const btn = document.createElement('a');
    btn.href      = url;
    btn.download  = name;
    btn.className = 'file-dl-btn';
    btn.setAttribute('aria-label', 'Download');
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>`;
    div.appendChild(btn);
  }

  return div;
}

function getFileIcon(ext) {
  const map = { pdf: '📄', doc: '📝', docx: '📝', txt: '📃', zip: '🗜', rar: '🗜', '7z': '🗜', mp3: '🎵', mp4: '🎬', mov: '🎬', webm: '🎬', png: '🖼', jpg: '🖼', jpeg: '🖼', gif: '🖼', svg: '🖼' };
  return map[ext] || '📎';
}

function fmtSize(b) {
  if (!b) return '';
  if (b < 1024) return b + ' B';
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' KB';
  return (b / (1024 * 1024)).toFixed(1) + ' MB';
}

function escHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function removeEmptyState() {
  const es = document.getElementById('emptyState');
  if (es) es.remove();
}

function scrollToBottom(smooth) {
  messagesArea.scrollTo({ top: messagesArea.scrollHeight, behavior: smooth ? 'smooth' : 'instant' });
}

// ══════════════════════════════════════════════════════════════════════════════
// NOTIFICATION SOUND (Web Audio — no file needed)
// ══════════════════════════════════════════════════════════════════════════════
let audioCtx = null;
function pingSound() {
  try {
    if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = audioCtx.createOscillator();
    const g   = audioCtx.createGain();
    osc.connect(g); g.connect(audioCtx.destination);
    osc.type = 'sine';
    osc.frequency.setValueAtTime(880, audioCtx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(660, audioCtx.currentTime + 0.12);
    g.gain.setValueAtTime(0.16, audioCtx.currentTime);
    g.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + 0.22);
    osc.start(); osc.stop(audioCtx.currentTime + 0.22);
  } catch { /* browser may block audio */ }
}

let ringtoneTimer = null;
function startRingtone() {
  stopRingtone();
  const ring = () => {
    try {
      if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      const now = audioCtx.currentTime;
      [523, 659].forEach((frequency, i) => {
        const osc = audioCtx.createOscillator(), gain = audioCtx.createGain();
        osc.type = 'sine'; osc.frequency.value = frequency; gain.gain.setValueAtTime(0.0001, now + i * .24);
        gain.gain.exponentialRampToValueAtTime(.13, now + i * .24 + .025); gain.gain.exponentialRampToValueAtTime(.0001, now + i * .24 + .20);
        osc.connect(gain); gain.connect(audioCtx.destination); osc.start(now + i * .24); osc.stop(now + i * .24 + .22);
      });
    } catch { /* Audio needs a prior browser interaction on some devices. */ }
  };
  ring(); ringtoneTimer = setInterval(ring, 1700);
}
function stopRingtone() { if (ringtoneTimer) clearInterval(ringtoneTimer); ringtoneTimer = null; }

// ══════════════════════════════════════════════════════════════════════════════
// SEND MESSAGE
// ══════════════════════════════════════════════════════════════════════════════
let typingTimeout = null;
let isTyping = false;

async function postMessage(content, msgType = 'text', filename = '') {
  const res = await chatFetch('/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-token': token, 'x-username': username },
    body: JSON.stringify({ content, msg_type: msgType, filename })
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

async function refreshMessages() {
  try {
    const res = await chatFetch('/messages', { headers: { 'x-token': token, 'x-username': username } });
    if (res.status === 401) { clearSavedSession(); window.location.replace('index.html'); return; }
    if (!res.ok) return;
    const messages = await res.json();
    for (const msg of messages) await renderMessage(msg, false);
    if (messages.length) { removeEmptyState(); scrollToBottom(false); }
    revealChat();
  } catch { /* A later poll will retry after a temporary network failure. */ }
}

async function sendMessage() {
  const text    = msgInput.value.trim();
  const hasFile = !!pendingFile;
  const hasText = !!text;

  if (!hasFile && !hasText) return;
  if (!AES_KEY) return;

  // Clear input immediately for UX
  msgInput.value = '';
  msgInput.style.height = 'auto';

  // Stop typing
  clearTimeout(typingTimeout);
  if (isTyping) { isTyping = false; socket.emit('typing', { typing: false }); }

  // Send file first (if any)
  if (hasFile) await uploadAndSendFile();

  // Send text
  if (hasText) {
    try {
      const msg = await postMessage(await encrypt(text));
      await renderMessage(msg, true);
      removeEmptyState();
      scrollToBottom(true);
    } catch (e) { console.error('Encrypt error:', e); }
  }
}

sendBtn.addEventListener('click', sendMessage);

const emojiPicker = document.getElementById('emojiPicker');
document.getElementById('emojiBtn').addEventListener('click', () => { emojiPicker.style.display = emojiPicker.style.display === 'none' ? 'flex' : 'none'; });
emojiPicker.querySelectorAll('button').forEach(button => button.addEventListener('click', () => { msgInput.value += button.textContent; msgInput.focus(); emojiPicker.style.display = 'none'; msgInput.dispatchEvent(new Event('input')); }));
const gifModal = document.getElementById('gifModal');
document.getElementById('gifBtn').addEventListener('click', () => { gifModal.style.display = 'flex'; document.getElementById('gifUrl').focus(); });
document.getElementById('closeGifModal').addEventListener('click', () => gifModal.style.display = 'none');
document.getElementById('sendGifBtn').addEventListener('click', async () => {
  const input = document.getElementById('gifUrl'), error = document.getElementById('gifError');
  const url = input.value.trim();
  if (!/^https:\/\/.+\.(gif)(\?.*)?$/i.test(url)) { error.textContent = 'Please paste a direct https GIF link ending in .gif.'; error.style.display = 'block'; return; }
  try { const msg = await postMessage(await encrypt(JSON.stringify({ url, name: 'GIF', type: 'gif' })), 'gif'); await renderMessage(msg, true); removeEmptyState(); scrollToBottom(true); input.value = ''; error.style.display = 'none'; gifModal.style.display = 'none'; }
  catch { error.textContent = 'Could not send the GIF. Please try again.'; error.style.display = 'block'; }
});

msgInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
});

msgInput.addEventListener('input', () => {
  // Auto-grow
  msgInput.style.height = 'auto';
  msgInput.style.height = Math.min(msgInput.scrollHeight, 130) + 'px';
  // Typing indicator
  if (!isTyping) { isTyping = true; socket.emit('typing', { typing: true }); }
  clearTimeout(typingTimeout);
  typingTimeout = setTimeout(() => { isTyping = false; socket.emit('typing', { typing: false }); }, 2500);
});

// ══════════════════════════════════════════════════════════════════════════════
// FILE UPLOAD
// ══════════════════════════════════════════════════════════════════════════════
const fileInput       = document.getElementById('fileInput');
const filePreviewStrip = document.getElementById('filePreviewStrip');
const filePreviewImg  = document.getElementById('filePreviewImg');
const filePreviewName = document.getElementById('filePreviewName');
const filePreviewSize = document.getElementById('filePreviewSize');
const filePreviewIcon = document.getElementById('filePreviewIcon');
const removeFileBtn   = document.getElementById('removeFileBtn');

let pendingFile = null;

fileInput.addEventListener('change', () => {
  const file = fileInput.files[0];
  if (!file) return;
  pendingFile = file;

  // Show strip
  filePreviewName.textContent = file.name;
  filePreviewSize.textContent = fmtSize(file.size);

  if (file.type.startsWith('image/')) {
    filePreviewIcon.style.display = 'none';
    const reader = new FileReader();
    reader.onload = (e) => { filePreviewImg.src = e.target.result; filePreviewImg.style.display = ''; };
    reader.readAsDataURL(file);
  } else {
    filePreviewImg.style.display = 'none';
    filePreviewIcon.style.display = '';
  }

  filePreviewStrip.style.display = 'flex';
  fileInput.value = ''; // allow re-selecting same file
});

removeFileBtn.addEventListener('click', () => {
  pendingFile = null;
  filePreviewStrip.style.display = 'none';
  filePreviewImg.style.display   = 'none';
  filePreviewImg.src = '';
});

/** Upload the pending file to server, then emit a file-msg event */
async function uploadAndSendFile() {
  if (!pendingFile) return;
  let file = pendingFile;
  pendingFile = null;
  filePreviewStrip.style.display = 'none';
  filePreviewImg.src = '';
  filePreviewImg.style.display = 'none';

  if (file.type.startsWith('image/') && file.type !== 'image/gif') file = await compressImage(file);
  const formData = new FormData();
  formData.append('file', file);

  let uploadData;
  try {
    const res = await chatFetch('/upload', {
      method: 'POST',
      headers: { 'x-token': token, 'x-username': username },
      body: formData
    });
    if (!res.ok) throw new Error(await res.text());
    uploadData = await res.json();
  } catch (err) {
    console.error('Upload failed:', err);
    showCallToast('Upload failed. Try a smaller file.');
    return;
  }

  const isImage = file.type.startsWith('image/');
  const payload = JSON.stringify({ url: uploadData.url, name: uploadData.name, size: uploadData.size, type: isImage ? 'image' : 'file' });

  try {
    const encrypted = await encrypt(payload);
    const msg = await postMessage(encrypted, isImage ? 'image' : 'file', file.name);
    await renderMessage(msg, true);
    removeEmptyState();
    scrollToBottom(true);
  } catch (e) { console.error('Encrypt file error:', e); }
}

// Fast client-side compression removes camera metadata and makes large photos
// much quicker to upload. GIFs stay untouched so their animation is preserved.
async function compressImage(file) {
  if (file.size < 350 * 1024) return file;
  try {
    const bitmap = await createImageBitmap(file), max = 1920;
    const scale = Math.min(1, max / Math.max(bitmap.width, bitmap.height));
    const canvas = document.createElement('canvas'); canvas.width = Math.round(bitmap.width * scale); canvas.height = Math.round(bitmap.height * scale);
    canvas.getContext('2d', { alpha: false }).drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/webp', .80));
    return blob && blob.size < file.size ? new File([blob], file.name.replace(/\.[^.]+$/, '') + '.webp', { type: 'image/webp' }) : file;
  } catch { return file; }
}

// Drag-and-drop support on the messages area
messagesArea.addEventListener('dragover', (e) => { e.preventDefault(); messagesArea.style.outline = '2px dashed var(--p1)'; });
messagesArea.addEventListener('dragleave', () => { messagesArea.style.outline = ''; });
messagesArea.addEventListener('drop', (e) => {
  e.preventDefault();
  messagesArea.style.outline = '';
  const file = e.dataTransfer.files[0];
  if (!file) return;
  pendingFile = file;
  filePreviewName.textContent = file.name;
  filePreviewSize.textContent = fmtSize(file.size);
  if (file.type.startsWith('image/')) {
    filePreviewIcon.style.display = 'none';
    const reader = new FileReader();
    reader.onload = (ev) => { filePreviewImg.src = ev.target.result; filePreviewImg.style.display = ''; };
    reader.readAsDataURL(file);
  } else { filePreviewImg.style.display = 'none'; filePreviewIcon.style.display = ''; }
  filePreviewStrip.style.display = 'flex';
});

// ══════════════════════════════════════════════════════════════════════════════
// PUSH NOTIFICATIONS (Web Push)
// ══════════════════════════════════════════════════════════════════════════════
async function initPush() {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) return;

  try {
    const reg = await navigator.serviceWorker.register('/sw.js');
    await navigator.serviceWorker.ready;

    if (Notification.permission === 'granted') {
      await subscribeToPush(reg);
    } else if (Notification.permission === 'default') {
      // Show banner if not permanently dismissed
      if (!localStorage.getItem('notif-dismissed')) {
        const banner = document.getElementById('notifBanner');
        banner.style.display = 'flex';

        document.getElementById('notifAllow').onclick = async () => {
          banner.style.display = 'none';
          const perm = await Notification.requestPermission();
          if (perm === 'granted') await subscribeToPush(reg);
        };
        document.getElementById('notifDismiss').onclick = () => {
          banner.style.display = 'none';
          localStorage.setItem('notif-dismissed', '1');
        };
      }
    }
  } catch (err) { console.warn('Push init failed:', err); }
}

async function subscribeToPush(reg) {
  try {
    const cfg = await chatFetch('/push-config').then(r => r.json());
    let sub = await reg.pushManager.getSubscription();
    if (!sub) {
      sub = await reg.pushManager.subscribe({
        userVisibleOnly:      true,
        applicationServerKey: urlBase64ToUint8Array(cfg.publicKey)
      });
    }
    await chatFetch('/subscribe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-token': token, 'x-username': username },
      body: JSON.stringify({ subscription: sub })
    });
  } catch (e) { console.warn('Push subscription failed:', e); }
}

function urlBase64ToUint8Array(b64) {
  const pad  = '='.repeat((4 - b64.length % 4) % 4);
  const str  = atob((b64 + pad).replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from([...str].map(c => c.charCodeAt(0)));
}

// ══════════════════════════════════════════════════════════════════════════════
// CHANGE PASSWORD MODAL
// ══════════════════════════════════════════════════════════════════════════════
const settingsModal = document.getElementById('settingsModal');
const settingsRemember = document.getElementById('settingsRemember');
function isRemembered() { return !!localStorage.getItem('ec_session'); }
function applyWallpaper(name) { document.body.dataset.wallpaper = name; localStorage.setItem('ec_wallpaper', name); document.querySelectorAll('.wallpaper-choice').forEach(b => b.classList.toggle('active', b.dataset.wallpaper === name)); }
applyWallpaper(localStorage.getItem('ec_wallpaper') || 'aurora');
settingsRemember.checked = isRemembered();
document.getElementById('settingsBtn').addEventListener('click', () => { settingsRemember.checked = isRemembered(); settingsModal.style.display = 'flex'; });
document.getElementById('closeSettingsModal').addEventListener('click', () => settingsModal.style.display = 'none');
settingsModal.addEventListener('click', e => { if (e.target === settingsModal) settingsModal.style.display = 'none'; });
document.querySelectorAll('.wallpaper-choice').forEach(btn => btn.addEventListener('click', () => applyWallpaper(btn.dataset.wallpaper)));
settingsRemember.addEventListener('change', () => {
  const raw = getSavedSession(); if (!raw) return;
  if (settingsRemember.checked) { localStorage.setItem('ec_session', raw); sessionStorage.removeItem('ec_session'); }
  else { sessionStorage.setItem('ec_session', raw); localStorage.removeItem('ec_session'); }
});
document.getElementById('openPasswordSettings').addEventListener('click', () => { settingsModal.style.display = 'none'; document.getElementById('changePwdModal').style.display = 'flex'; document.getElementById('changeUsername').focus(); });
document.getElementById('settingsLogout').addEventListener('click', () => { clearSavedSession(); window.location.replace('index.html'); });

document.getElementById('closePwdModal').addEventListener('click', closePwdModal);
document.getElementById('changePwdModal').addEventListener('click', (e) => {
  if (e.target === e.currentTarget) closePwdModal();
});

function closePwdModal() {
  document.getElementById('changePwdModal').style.display = 'none';
  document.getElementById('changePwdForm').reset();
  document.getElementById('pwdError').style.display   = 'none';
  document.getElementById('pwdSuccess').style.display = 'none';
  document.getElementById('pwdStrengthFill').style.width      = '0%';
  document.getElementById('pwdStrengthLabel').textContent     = '';
  document.getElementById('changePwdBtnLabel').textContent    = 'Update Password';
  document.getElementById('changePwdBtn').disabled            = false;
  document.getElementById('pwdSpinner').style.display         = 'none';
}

// Password strength indicator
document.getElementById('newPassword').addEventListener('input', function () {
  const v = this.value;
  let strength = 0;
  if (v.length >= 8)                         strength++;
  if (v.length >= 12)                        strength++;
  if (/[0-9]/.test(v) && /[a-zA-Z]/.test(v)) strength++;
  if (/[^a-zA-Z0-9]/.test(v))               strength++;

  const fill   = document.getElementById('pwdStrengthFill');
  const label  = document.getElementById('pwdStrengthLabel');
  const colors = ['', '#f87171', '#fbbf24', '#4ade80', '#22c55e'];
  const labels = ['', 'Weak', 'Fair', 'Good', 'Strong'];
  fill.style.width      = (strength * 25) + '%';
  fill.style.background = colors[strength] || 'transparent';
  label.textContent     = labels[strength] || '';
  label.style.color     = colors[strength] || 'transparent';
});

document.getElementById('changePwdForm').addEventListener('submit', async (e) => {
  e.preventDefault();

  const confirmUsername = document.getElementById('changeUsername').value.trim();
  const oldPwd  = document.getElementById('oldPassword').value;
  const newPwd  = document.getElementById('newPassword').value;
  const confPwd = document.getElementById('confirmPassword').value;
  const errEl   = document.getElementById('pwdError');
  const okEl    = document.getElementById('pwdSuccess');
  const btn     = document.getElementById('changePwdBtn');
  const spinner = document.getElementById('pwdSpinner');
  const label   = document.getElementById('changePwdBtnLabel');

  errEl.style.display = 'none';
  okEl.style.display  = 'none';

  if (!confirmUsername || !oldPwd || !newPwd || !confPwd) {
    errEl.textContent  = '⚠ All fields are required.';
    errEl.style.display = 'flex';
    return;
  }
  if (newPwd !== confPwd) {
    errEl.textContent  = '⚠ New passwords do not match.';
    errEl.style.display = 'flex';
    return;
  }
  if (confirmUsername !== username) {
    errEl.textContent  = 'Please enter your account username to confirm this change.';
    errEl.style.display = 'flex';
    return;
  }
  if (newPwd.length < 8) {
    errEl.textContent  = '⚠ New password must be at least 8 characters.';
    errEl.style.display = 'flex';
    return;
  }

  btn.disabled = true; label.textContent = 'Updating…'; spinner.style.display = '';

  try {
    const res  = await chatFetch('/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, oldPassword: oldPwd, newPassword: newPwd })
    });
    const data = await res.json();

    if (!res.ok) {
      errEl.textContent  = '⚠ ' + (data.error || 'Error.');
      errEl.style.display = 'flex';
      btn.disabled = false; label.textContent = 'Update Password'; spinner.style.display = 'none';
      return;
    }

    okEl.textContent  = '✅ Password updated! Logging you out in 3 seconds…';
    okEl.style.display = 'flex';

    setTimeout(() => {
       clearSavedSession();
      socket.disconnect();
      window.location.replace('index.html');
    }, 3000);

  } catch {
    errEl.textContent  = '⚠ Connection error. Try again.';
    errEl.style.display = 'flex';
    btn.disabled = false; label.textContent = 'Update Password'; spinner.style.display = 'none';
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// LOGOUT
// ══════════════════════════════════════════════════════════════════════════════
document.getElementById('logoutBtn').addEventListener('click', () => {
  socket.disconnect();
  clearSavedSession();
  window.location.replace('index.html');
});

// ══════════════════════════════════════════════════════════════════════════════
// WEBRTC VOICE CALLS — State Machine
//
// States: 'idle' | 'ringing' | 'incoming' | 'active'
//
// Transitions:
//  idle     → ringing  : I clicked call button
//  idle     → incoming : Received call-offer
//  ringing  → active   : Received call-answer (friend answered)
//  ringing  → idle     : Cancel / timeout / friend declined (call-end)
//  incoming → active   : I accepted
//  incoming → idle     : I declined / caller cancelled (call-end)
//  active   → idle     : Either party ends (call-end or endCallBtn)
// ══════════════════════════════════════════════════════════════════════════════
let callState    = 'idle';
let pc           = null;   // RTCPeerConnection
let localStream  = null;   // Microphone stream
let callTimer    = null;   // setInterval handle
let callSecs     = 0;
let ringingTimer = null;   // Auto-cancel timeout
let muted        = false;
let queuedIceCandidates = [];

const CALL_TIMEOUT_MS = 60_000; // 60 seconds before "No Answer"

const ICE = {
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302'  },
    { urls: 'stun:stun1.l.google.com:19302' },
    { urls: 'stun:stun2.l.google.com:19302' }
  ]
};

function buildPC() {
  const conn = new RTCPeerConnection(ICE);
  conn.onicecandidate = (e) => { if (e.candidate) socket.emit('ice-candidate', { candidate: e.candidate }); };
  conn.ontrack = (e) => { document.getElementById('remoteAudio').srcObject = e.streams[0]; };
  conn.onconnectionstatechange = () => {
    if (['disconnected', 'failed', 'closed'].includes(conn.connectionState) && callState === 'active') {
      endActiveCall(false);
      showCallToast('Call ended');
    }
  };
  if (localStream) localStream.getTracks().forEach(t => conn.addTrack(t, localStream));
  return conn;
}

async function getMic() {
  try {
    localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
    return true;
  } catch {
    alert('🎤 Microphone access denied.\nPlease allow mic access in your browser settings.');
    return false;
  }
}

// ── Initiate call ────────────────────────────────────────────────────────────
document.getElementById('callBtn').addEventListener('click', async () => {
  if (callState !== 'idle') return;
  callState = 'ringing';
  document.getElementById('ringingStatus').textContent = 'Ringing…';
  document.getElementById('ringingCall').style.display = 'flex';
  if (!await getMic()) {
    document.getElementById('ringingCall').style.display = 'none';
    callState = 'idle';
    return;
  }

  try {
    pc = buildPC();
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    socket.emit('call-offer', { offer });
  } catch {
    dismissRinging('Could not start the call');
    return;
  }

  // Auto-timeout
  ringingTimer = setTimeout(() => {
    if (callState !== 'ringing') return;
    socket.emit('call-end');
    dismissRinging('No Answer');
  }, CALL_TIMEOUT_MS);
});

// ── Cancel ringing ───────────────────────────────────────────────────────────
document.getElementById('cancelCallBtn').addEventListener('click', () => {
  if (callState !== 'ringing') return;
  clearTimeout(ringingTimer);
  socket.emit('call-end');
  document.getElementById('ringingCall').style.display = 'none';
  cleanupMedia();
  callState = 'idle';
});

// ── Incoming call ────────────────────────────────────────────────────────────
socket.on('call-offer', async ({ offer }) => {
  if (callState !== 'idle') { socket.emit('call-end'); return; } // busy

  callState = 'incoming';
  queuedIceCandidates = [];
  document.getElementById('incomingCall').style.display = 'flex';
  startRingtone();

  // ── Accept ──
  document.getElementById('acceptCall').onclick = async () => {
    if (callState !== 'incoming') return;
    document.getElementById('incomingCall').style.display = 'none';
    stopRingtone();
    if (!await getMic()) { callState = 'idle'; return; }

    pc = buildPC();
    await pc.setRemoteDescription(new RTCSessionDescription(offer));
    for (const candidate of queuedIceCandidates.splice(0)) {
      await pc.addIceCandidate(new RTCIceCandidate(candidate));
    }
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    socket.emit('call-answer', { answer });

    callState = 'active';
    startTimer();
    document.getElementById('activeCall').style.display = 'flex';
  };

  // ── Decline ──
  document.getElementById('rejectCall').onclick = () => {
    if (callState !== 'incoming') return;
    document.getElementById('incomingCall').style.display = 'none';
    stopRingtone();
    socket.emit('call-end');
    cleanupMedia();
    callState = 'idle';
  };
});

// ── Call answered (I was ringing, friend picked up) ──────────────────────────
socket.on('call-answer', async ({ answer }) => {
  if (!pc || callState !== 'ringing') return;
  clearTimeout(ringingTimer);
  await pc.setRemoteDescription(new RTCSessionDescription(answer));
  document.getElementById('ringingCall').style.display = 'none';
  callState = 'active';
  startTimer();
  document.getElementById('activeCall').style.display = 'flex';
});

// ── ICE candidates ───────────────────────────────────────────────────────────
socket.on('ice-candidate', async ({ candidate }) => {
  if (pc && candidate) {
    try { await pc.addIceCandidate(new RTCIceCandidate(candidate)); } catch { /* ignore */ }
  } else if (candidate && callState === 'incoming') {
    queuedIceCandidates.push(candidate);
  }
});

// ── Remote ended call ─────────────────────────────────────────────────────────
socket.on('call-end', () => {
  stopRingtone();
  clearTimeout(ringingTimer);
  if      (callState === 'ringing')  { dismissRinging('Call Declined'); }
  else if (callState === 'incoming') { document.getElementById('incomingCall').style.display = 'none'; cleanupMedia(); callState = 'idle'; }
  else if (callState === 'active')   { endActiveCall(false); showCallToast('Call ended'); }
});

// ── End active call ───────────────────────────────────────────────────────────
document.getElementById('endCallBtn').addEventListener('click', () => {
  if (callState !== 'active') return;
  socket.emit('call-end');
  endActiveCall(true);
});

// ── Mute ─────────────────────────────────────────────────────────────────────
document.getElementById('muteBtn').addEventListener('click', () => {
  if (!localStream) return;
  muted = !muted;
  localStream.getAudioTracks().forEach(t => { t.enabled = !muted; });
  document.getElementById('muteBtn').classList.toggle('muted', muted);
  document.getElementById('micOnIcon').style.display  = muted ? 'none' : '';
  document.getElementById('micOffIcon').style.display = muted ? '' : 'none';
});

function dismissRinging(reason) {
  document.getElementById('ringingCall').style.display = 'none';
  cleanupMedia();
  callState = 'idle';
  showCallToast(reason);
}

function endActiveCall(emitted) {
  clearInterval(callTimer);
  document.getElementById('activeCall').style.display = 'none';
  document.getElementById('remoteAudio').srcObject = null;
  document.getElementById('muteBtn').classList.remove('muted');
  document.getElementById('micOnIcon').style.display  = '';
  document.getElementById('micOffIcon').style.display = 'none';
  muted = false;
  cleanupMedia();
  callState = 'idle';
}

function cleanupMedia() {
  if (pc)          { pc.close(); pc = null; }
  if (localStream) { localStream.getTracks().forEach(t => t.stop()); localStream = null; }
  queuedIceCandidates = [];
}

function startTimer() {
  callSecs = 0;
  document.getElementById('callTimer').textContent = '00:00';
  callTimer = setInterval(() => {
    callSecs++;
    const m = String(Math.floor(callSecs / 60)).padStart(2, '0');
    const s = String(callSecs % 60).padStart(2, '0');
    document.getElementById('callTimer').textContent = `${m}:${s}`;
  }, 1000);
}

// ── Call result toast ─────────────────────────────────────────────────────────
function showCallToast(msg) {
  let toast = document.querySelector('.call-toast');
  if (!toast) { toast = document.createElement('div'); toast.className = 'call-toast'; document.body.appendChild(toast); }
  toast.textContent = msg;
  requestAnimationFrame(() => { requestAnimationFrame(() => { toast.classList.add('visible'); }); });
  setTimeout(() => {
    toast.classList.remove('visible');
    setTimeout(() => { if (toast.parentNode) toast.remove(); }, 400);
  }, 3000);
}

// ══════════════════════════════════════════════════════════════════════════════
// BOOT — initialise everything
// ══════════════════════════════════════════════════════════════════════════════
(async () => {
  await initEncryption();
  const cachedMessages = readCachedMessages();
  for (const msg of cachedMessages) await renderMessage(msg, false);
  if (cachedMessages.length) {
    removeEmptyState();
    scrollToBottom(false);
    revealChat();
  }
  await refreshMessages();
  // Text messages use the HTTP API so they also work on Vercel Functions.
  // Keep Socket.IO for local real-time calls; Vercel does not provide durable
  // WebSocket connections for this server.
  const cloudChatApi = await getChatApiBase();
  // Render's lightweight Socket.IO connection is only for live presence,
  // typing, and voice-call signalling. Messages still use Cloudflare D1.
  if (!location.hostname.endsWith('.vercel.app')) socket.connect();
  setInterval(refreshMessages, 3_000);
  if (!cloudChatApi) await initPush();
  // Socket connection is already initiated above; 'connect' event sends auth,
  // server responds with 'history', which reveals the chat UI.
})();
