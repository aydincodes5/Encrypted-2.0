/* ─── sw.js — Service Worker for Web Push Notifications ──────────────────── */
'use strict';

// Take control immediately so push works right away
self.addEventListener('install',  () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(clients.claim()));

// ── Push notification received ─────────────────────────────────────────────
self.addEventListener('push', (event) => {
  if (!event.data) return;

  let data;
  try { data = event.data.json(); }
  catch { return; }

  const isCall = !!data.isCall;

  const options = {
    body:               data.body || '',
    vibrate:            isCall ? [400, 150, 400, 150, 400] : [200, 100, 200],
    tag:                isCall ? 'ec-incoming-call' : 'ec-message',
    renotify:           true,
    requireInteraction: isCall,  // Call notifications stay until dismissed
    data: { url: data.url || '/chat.html' }
  };

  if (isCall) {
    options.actions = [
      { action: 'open',    title: '📞 Open App'  },
      { action: 'dismiss', title: '✖ Dismiss'   }
    ];
  }

  event.waitUntil(
    self.registration.showNotification(data.title || 'EncryptedChat', options)
  );
});

// ── Notification clicked ───────────────────────────────────────────────────
self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  // Dismissed action — do nothing
  if (event.action === 'dismiss') return;

  const targetUrl = (event.notification.data || {}).url || '/chat.html';

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      // If the chat page is already open, focus it
      for (const c of list) {
        if (c.url.endsWith(targetUrl) && 'focus' in c) return c.focus();
      }
      // Otherwise open a new window
      return clients.openWindow(targetUrl);
    })
  );
});
