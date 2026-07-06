# Medical Advisors Hub

A password-protected portal that serves the BillionToOne **Medical Advisors Hub**
content (a static snapshot of the Notion page) to authorized medical advisors only.

- **Backend:** FastAPI (Python)
- **Auth:** individual email + password accounts (bcrypt-hashed, stored in an env var — no database)
- **Hosting:** Render web service (auto-deploys on push to `main`)

---

## How accounts work

There is **no database**. Advisor accounts live in the `ADVISOR_ACCOUNTS`
environment variable as JSON mapping each email to a bcrypt password hash:

```json
{"jane@example.com": "$2b$12$....", "john@example.com": "$2b$12$...."}
```

Passwords are never stored in plain text. This survives Render redeploys because
it's configuration, not disk state.

### Add or update an advisor

```bash
python make_hash.py advisor@example.com
```

It prints a JSON entry. Merge that key into the `ADVISOR_ACCOUNTS` value
(locally in `.env`, and in the Render dashboard for production), then redeploy.

### Remove an advisor
Delete their key from `ADVISOR_ACCOUNTS` and redeploy.

### Reset a password
Re-run `make_hash.py` for that email, replace their hash, redeploy.

---

## Run locally

```bash
cd advisor-portal
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# 1) put a real SECRET_KEY in .env:
python -c "import secrets; print(secrets.token_hex(32))"
# 2) create at least one account and paste it into ADVISOR_ACCOUNTS in .env:
python make_hash.py you@example.com
# 3) keep COOKIE_HTTPS_ONLY=false for localhost

uvicorn app:app --reload
```

Open http://127.0.0.1:8000 → you'll be sent to the login page.

---

## Update the hub content

The content advisors see lives in [`templates/_content.html`](templates/_content.html).
Edit that file, commit, and push — Render redeploys automatically.

---

## Deploy to Render

1. Push this repo to GitHub.
2. Render → **New** → **Web Service** → connect the repo.
3. Settings:
   - **Runtime:** Python (auto-detected; `runtime.txt` pins the version)
   - **Build command:** `pip install -r requirements.txt`
   - **Start command:** `uvicorn app:app --host 0.0.0.0 --port $PORT`
4. **Environment variables** (Render dashboard → Environment):
   - `SECRET_KEY` — a long random string
   - `ADVISOR_ACCOUNTS` — the JSON of email→hash (one line)
   - `COOKIE_HTTPS_ONLY` — `true` (or leave unset)
5. Create the service. It builds and deploys; subsequent pushes to `main`
   redeploy automatically.

Health check: `GET /healthz` returns `{"ok": true, "accounts_loaded": N}`.
