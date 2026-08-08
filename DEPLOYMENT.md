# Deploying safely on Render

Do not use a free Render Web Service if you need message history or uploaded files to survive. Its filesystem is temporary and can be wiped when the service sleeps, restarts, or redeploys.

Use a paid Web Service with a persistent disk instead:

1. Connect the GitHub repository and use `npm install` as the build command and `npm start` as the start command.
2. Add a persistent disk mounted at `/var/data`.
3. Add these environment variables in Render:
   - `MUHAMMED_PASSWORD` — a strong password for Muhammed's account.
   - `AYAAN_PASSWORD` — a strong password for Ayaan's account.
   - `DATA_DIR=/var/data`
   - `UPLOADS_DIR=/var/data/uploads`

The first deployment creates the account database in `/var/data`. From then on, messages and uploads persist across redeploys and restarts; the application removes messages older than seven days.
