# 🔐 EncryptedChat — Setup Guide

> A private, encrypted chat + voice call app. Just for you and Ayaan.

---

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

## Step 3 — Make it work from Ayaan's laptop too (free hosting)

For Ayaan to use it from his house, you need to put it on the internet for free.

### 3a — Upload to GitHub
1. Go to **https://github.com** → create a free account
2. Click **New Repository** → name it `encrypted-chat` → click **Create**
3. Upload all files from this folder to GitHub
   *(drag and drop them onto the GitHub page)*

### 3b — Deploy on Render (free hosting)
1. Go to **https://render.com** → create a free account
2. Click **New** → **Web Service**
3. Connect your GitHub account → choose `encrypted-chat`
4. Render will auto-detect Node.js. Just click **Create Web Service**
5. Wait ~2 minutes → you get a free link like:
   ```
   https://encrypted-chat-xxxx.onrender.com
   ```
6. **Share that link with Ayaan** — that's it! You're both connected! 🚀

> 💡 **Free tier note**: Render's free server sleeps after 15 minutes of no use.
> When you first open it, it takes ~30 seconds to wake up. That's normal!

---

## Your Login Details

Set `MUHAMMED_PASSWORD` and `AYAAN_PASSWORD` as environment variables before starting a new database. Never put either password in GitHub.

---

## How to Use It

| Feature | How |
|---|---|
| 💬 Send a message | Type in the box → press Enter |
| 📞 Voice call | Click the phone button in the top right |
| 🔇 Mute yourself | Click the mic button during a call |
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
