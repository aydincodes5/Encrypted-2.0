/* The chat data API lives on Cloudflare's free Workers platform in production.
   Local development falls back to this Render server when CHAT_API_URL is blank. */
let chatApiBasePromise;
async function getChatApiBase() {
  if (!chatApiBasePromise) {
    chatApiBasePromise = fetch('/chat-config').then(async res => {
      if (!res.ok) return '';
      const { chatApiUrl } = await res.json();
      return (chatApiUrl || '').replace(/\/$/, '');
    }).catch(() => '');
  }
  return chatApiBasePromise;
}
async function chatFetch(path, options) {
  const base = await getChatApiBase();
  return fetch(base + path, options);
}
