# StudyTracker Sync API

FastAPI + PostgreSQL backend for GitHub Pages StudyTracker.

## Railway setup

1. Create a separate GitHub repository `StudyTracker-API` and upload `main.py`, `requirements.txt`, `railway.json`, `.gitignore`.
2. In the existing StudyTracker Railway project, add a service **GitHub Repo**, select `StudyTracker-API`.
3. In API service Variables set:
   - `DATABASE_URL=${{Postgres.DATABASE_URL}}` (replace `Postgres` with actual PostgreSQL service name; enter as **reference variable**)
   - `OWNER_EMAIL=your-own-email@example.com`
   - `JWT_SECRET=` a securely generated random value of 32+ characters (prefer 64)
   - `FRONTEND_ORIGIN=https://kritzelb0b.github.io`
4. Generate a public domain **for the API service only** at Settings > Networking. Keep PostgreSQL private.
5. Browse `https://<api-domain>/health` => `{"status":"ok"}`.

## API

- POST `/auth/register` (only allowed `OWNER_EMAIL`, once) JSON `{"email":"...","password":"at least 12 characters"}` => bearer token.
- POST `/auth/login` same body => bearer token.
- GET `/sync` header `Authorization: Bearer <token>` => `{revision,data,updated_at}`.
- PUT `/sync` header `Authorization: Bearer <token>`, JSON `{revision:0,data:{modules:[],topics:[],entries:[]}}` => `{revision:1}`; mismatching revision returns 409.

**IMPORTANT:** The existing HTML frontend is not yet connected to this API. Don't put `DATABASE_URL` or `JWT_SECRET` in GitHub Pages / browser files. Export an existing StudyTracker JSON backup before migration. Never blindly overwrite cloud data or implement automatic retries of a 409.

## Note

This is an initial owner-only sync backend. For production, extend with rate limiting, reset/recovery, monitoring, device/session handling, comprehensive schema validation and backups. Secrets must be held only in Railway variables.
