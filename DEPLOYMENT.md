# Deploy EncryptedChat on Render

This is a **Render-only** version. It does not need Supabase, Vercel, or any external database.

## Create the service

1. Push this project to a GitHub repository.
2. In Render, click **New** → **Web Service**, then connect that repository.
3. Choose these commands:
   - Build command: `npm install`
   - Start command: `npm start`
4. Use Node 22.13 or newer. The project tells Render this automatically through `package.json`.

## Add durable storage

1. In the service's **Disks** section, add a Persistent Disk.
2. Set its mount path to `/var/data`.
3. In **Environment**, add these values:
   - `DATA_DIR` = `/var/data`
   - `UPLOADS_DIR` = `/var/data/uploads`
   - `MUHAMMED_PASSWORD` = your private password (at least 8 characters)
   - `AYAAN_PASSWORD` = the other private password (at least 8 characters)
   - `SESSION_SECRET` = a long, random private value
4. Save and deploy.

The app creates its database at `/var/data/encryptedchat.sqlite` and puts uploaded files in `/var/data/uploads`. Messages and uploaded files older than seven days are automatically removed.

Without the Persistent Disk, Render's temporary filesystem can be erased whenever the service restarts or deploys. The chat will still open, but message saving cannot be relied upon.
