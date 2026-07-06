# Medical Advisors Hub

A passwordless, access-controlled portal that serves the BillionToOne
**Medical Advisors Hub** content (a static snapshot of the Notion page) to
authorized, active medical advisors only.

- **Backend:** FastAPI (Python)
- **Auth:** passwordless email login codes. Access is controlled by the Airtable
  "Advisors Roster" table — advisors with **Status = Active** can log in.
- **Email:** one-time codes sent via the SendGrid HTTPS API (Render blocks SMTP)
- **Hosting:** Render web service (auto-deploys on push to `main`)

---

## How login works

1. Advisor enters their email.
2. If that email belongs to an **Active** advisor in Airtable, the app emails a
   **6-digit code** (expires in 10 min, attempt-capped, rate-limited).
3. Advisor enters the code and is signed in for 12 hours.

No passwords are stored anywhere. **To grant or revoke access, add/remove the
advisor (or change their Status) in Airtable** — nothing to deploy.

The login response is identical whether or not the email is on the list, so the
portal never reveals who is (or isn't) an advisor.

Confidential assets (headshots, PDFs) live in `protected_files/` and are served
only through the authenticated `/files/<name>` route — never publicly.

---

## Run locally

```bash
cd advisor-portal
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Put a real SECRET_KEY in .env:
python -c "import secrets; print(secrets.token_hex(32))"
```

For quick local testing **without** Airtable or email, set in `.env`:

```
COOKIE_HTTPS_ONLY=false
DEV_ALLOWED_EMAILS=you@billiontoone.com
```

With no `SMTP_USER`/`SMTP_PASSWORD` set, the login code is **printed to the
server log** instead of emailed. Then:

```bash
uvicorn app:app --reload
```

Open http://127.0.0.1:8000, enter the dev email, and read the code from the
terminal.

---

## Update the hub content

The content advisors see lives in [`templates/_content.html`](templates/_content.html).
Edit that file, commit, and push — Render redeploys automatically.

---

## Environment variables (set in the Render dashboard)

| Variable | Purpose |
|----------|---------|
| `SECRET_KEY` | Session signing key (long random string) |
| `COOKIE_HTTPS_ONLY` | `true` in production |
| `AIRTABLE_TOKEN` | Reads the advisor roster (allowlist) |
| `SENDGRID_API_KEY` | SendGrid API key for sending login codes |
| `MAIL_FROM` | A SendGrid-verified sender address |

Optional overrides (sensible defaults in `app.py`): `AIRTABLE_BASE_ID`,
`AIRTABLE_TABLE`, `AIRTABLE_EMAIL_FIELD`, `AIRTABLE_STATUS_FIELD`,
`ALLOWED_STATUS`, `MAIL_FROM_NAME`, `CODE_TTL_SECONDS`, `MAX_ATTEMPTS`,
`RESEND_COOLDOWN`, `ROSTER_CACHE_TTL`, `SESSION_MAX_AGE`.

---

## Deploy to Render

1. Push this repo to GitHub.
2. Render → **New** → **Web Service** → connect the repo.
3. Settings:
   - **Build command:** `pip install -r requirements.txt`
   - **Start command:** `uvicorn app:app --host 0.0.0.0 --port $PORT`
4. Add the environment variables above.
5. Create the service. Pushes to `main` redeploy automatically.

Health check: `GET /healthz` returns
`{"ok": true, "airtable_configured": true, "smtp_configured": true}`.
