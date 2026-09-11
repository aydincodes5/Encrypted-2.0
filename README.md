# 🔐 EncryptedChat — Render-only setup

> A private, encrypted chat + voice call app. Just for you and Ayaan.

---

## What this version needs

It does **not** use Supabase. It saves its small encrypted database and uploads on a Render Persistent Disk. Messages and their uploads are automatically removed after 7 days.

> Important: a Render free web service has temporary storage. For messages to survive a restart or deploy, attach a Render Persistent Disk. A disk is a Render feature, not a separate account.

## Step 1 — Install Node.js (only once, ever)

1. Go to: **https://nodejs.org**
2. Download the **LTS** version (the green button)
3. Install it (just keep clicking Next)

---

## Step 2 — Run the app on your laptop (for testing)

1. Open this folder in **File Explorer**
2. Click the address bar at the top, type `cmd`, press Enter
   *(a black window will open)*
3. Type this and press Enter:
   ```
   npm install
   ```
   *(wait for it to finish — it downloads the app's tools)*

4. Then type this and press Enter:
   ```
   node server.js
   ```
5. Open **Chrome** and go to: **http://localhost:3000**
6. You'll see the login page! 🎉

> ⚠️ The server must be running (the black window must stay open) for the app to work.

---

## Step 3 — Put it on Render

1. Create a **Web Service** in Render and connect this repository.
2. Use build command `npm install` and start command `npm start`.
3. Add a **Persistent Disk** mounted at `/var/data`.
4. In Render's Environment page, add `MUHAMMED_PASSWORD`, `AYAAN_PASSWORD`, and `SESSION_SECRET` (a long random value). Also add `DATA_DIR=/var/data` and `UPLOADS_DIR=/var/data/uploads`.
5. Deploy. The chat works at the Render URL.

The app uses the disk for the encrypted SQLite database and uploaded files. It automatically deletes chat data older than seven days. See `DEPLOYMENT.md` for the exact Render settings.

---

## Your Login Details

Set `MUHAMMED_PASSWORD` and `AYAAN_PASSWORD` as environment variables before starting a new database. Never put either password in GitHub.

---

## How to Use It

| Feature | How |
|---|---|
| 💬 Send a message | Type in the box → press Enter |
| 🖼️ Send an image/file | Tap the paperclip; photos are compressed automatically before upload |
| 😀 Emoji / GIF | Use the smiley button, or paste a direct GIF link with the GIF button |
| 📞 Voice call | Click the phone button in the top right |
| 🔇 Mute yourself | Click the mic button during a call |
| ⚙️ Settings | Change wallpaper, password, and keep-signed-in preference |
| ⏻ Logout | Click the logout button (top right) |

---

## Security Facts 🔐

- All messages are **AES-256 encrypted** before leaving your device
- The server only stores **scrambled data** — nobody can read your messages
- Wrong password locks you out after 8 attempts
- Sessions expire after 7 days

---

## Problems?

| Problem | Fix |
|---|---|
| "Cannot reach server" | Make sure `node server.js` is running |
| Can't hear in calls | Allow microphone access in your browser |
| App is slow at first | Normal on free hosting — wait 30 seconds |
| Lost all messages | Normal — messages reset when server restarts |
