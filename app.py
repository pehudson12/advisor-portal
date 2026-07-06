"""
BillionToOne Medical Advisors Hub — passwordless portal.

Login flow (no passwords stored anywhere):
  1. Advisor enters their email.
  2. If that email belongs to an ACTIVE advisor in Airtable, we email a
     6-digit code (expires in 10 min, attempt-capped, rate-limited).
  3. Advisor enters the code and is signed in.

Access is controlled entirely by the Airtable "Advisors Roster" table:
add/remove an advisor (or flip their Status) there to grant/revoke access.
No database — pending codes live in memory (they are short-lived).
"""

import os
import secrets
import time
from urllib.parse import quote as urlquote

import bcrypt
import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

load_dotenv()  # load .env for local development; no-op in production

# --- Configuration (all via environment variables) ---------------------------

SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
COOKIE_HTTPS_ONLY = os.environ.get("COOKIE_HTTPS_ONLY", "true").lower() == "true"
SESSION_MAX_AGE = int(os.environ.get("SESSION_MAX_AGE", 60 * 60 * 12))  # 12h

# Airtable allowlist
AIRTABLE_TOKEN = os.environ.get("AIRTABLE_TOKEN", "")
AIRTABLE_BASE_ID = os.environ.get("AIRTABLE_BASE_ID", "appHoBhZB7dghdDBT")
AIRTABLE_TABLE = os.environ.get("AIRTABLE_TABLE", "Advisors Roster \U0001FA7A")
AIRTABLE_EMAIL_FIELD = os.environ.get("AIRTABLE_EMAIL_FIELD", "Email")
AIRTABLE_STATUS_FIELD = os.environ.get("AIRTABLE_STATUS_FIELD", "Status")
ALLOWED_STATUS = os.environ.get("ALLOWED_STATUS", "Active").strip().lower()
ROSTER_CACHE_TTL = int(os.environ.get("ROSTER_CACHE_TTL", 300))  # 5 min

# Email (SendGrid HTTPS API — Render blocks outbound SMTP ports)
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY", "")
MAIL_FROM = os.environ.get("MAIL_FROM", "no-reply@billiontoone.com")
MAIL_FROM_NAME = os.environ.get("MAIL_FROM_NAME", "BillionToOne Medical Advisors")

# Login-code policy
CODE_TTL = int(os.environ.get("CODE_TTL_SECONDS", 600))  # 10 min
MAX_ATTEMPTS = int(os.environ.get("MAX_ATTEMPTS", 5))
RESEND_COOLDOWN = int(os.environ.get("RESEND_COOLDOWN", 60))  # seconds

# Dev/testing helpers (leave unset in production):
#   DEV_ALLOWED_EMAILS — comma-separated emails treated as allowed without Airtable
#   If SendGrid is not configured, codes are printed to the server log instead.
DEV_ALLOWED_EMAILS = {
    e.strip().lower()
    for e in os.environ.get("DEV_ALLOWED_EMAILS", "").split(",")
    if e.strip()
}
EMAIL_CONFIGURED = bool(SENDGRID_API_KEY and MAIL_FROM)

# Temporary diagnostics: when DEBUG_KEY is set, GET /debug/diag?key=...&email=...
# reports allowlist + email status. Leave DEBUG_KEY unset in normal operation.
DEBUG_KEY = os.environ.get("DEBUG_KEY", "")

# --- App ---------------------------------------------------------------------

app = FastAPI(title="Medical Advisors Hub")
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    https_only=COOKIE_HTTPS_ONLY,
    same_site="lax",
    max_age=SESSION_MAX_AGE,
)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Confidential assets are served ONLY through the authenticated /files route.
PROTECTED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "protected_files")

# In-memory stores (single instance; short-lived data).
_roster_cache = {"emails": set(), "fetched_at": 0.0}
_codes = {}  # email -> {"hash": bytes, "expires": float, "attempts": int, "sent_at": float}


# --- Allowlist (Airtable) ----------------------------------------------------


def _as_str(val):
    """Airtable Status can be a string or a single-element list."""
    if isinstance(val, list):
        return val[0] if val else ""
    return val or ""


async def _fetch_roster_emails():
    """Fetch lowercased emails of ACTIVE advisors from Airtable."""
    if not AIRTABLE_TOKEN:
        return set()
    base_url = "https://api.airtable.com/v0/{}/{}".format(
        AIRTABLE_BASE_ID, urlquote(AIRTABLE_TABLE, safe="")
    )
    headers = {"Authorization": "Bearer " + AIRTABLE_TOKEN}
    emails, offset = set(), None
    async with httpx.AsyncClient(timeout=30.0) as client:
        while True:
            params = {
                "pageSize": 100,
                "fields[]": [AIRTABLE_EMAIL_FIELD, AIRTABLE_STATUS_FIELD],
            }
            if offset:
                params["offset"] = offset
            resp = await client.get(base_url, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json()
            for rec in data.get("records", []):
                f = rec.get("fields", {})
                email = (f.get(AIRTABLE_EMAIL_FIELD) or "").strip().lower()
                status = _as_str(f.get(AIRTABLE_STATUS_FIELD)).strip().lower()
                if email and status == ALLOWED_STATUS:
                    emails.add(email)
            offset = data.get("offset")
            if not offset:
                break
    return emails


async def is_allowed(email: str) -> bool:
    email = email.strip().lower()
    if email in DEV_ALLOWED_EMAILS:
        return True
    now = time.time()
    if now - _roster_cache["fetched_at"] > ROSTER_CACHE_TTL:
        try:
            _roster_cache["emails"] = await _fetch_roster_emails()
            _roster_cache["fetched_at"] = now
        except Exception as exc:  # keep serving the stale cache on transient errors
            print("[roster] refresh failed:", repr(exc))
    return email in _roster_cache["emails"]


# --- Login codes -------------------------------------------------------------


def _prune_codes():
    now = time.time()
    for email in [e for e, c in _codes.items() if c["expires"] < now]:
        _codes.pop(email, None)


def _issue_code(email: str) -> str:
    code = "{:06d}".format(secrets.randbelow(1_000_000))
    _codes[email] = {
        "hash": bcrypt.hashpw(code.encode(), bcrypt.gensalt()),
        "expires": time.time() + CODE_TTL,
        "attempts": 0,
        "sent_at": time.time(),
    }
    return code


def _check_code(email: str, code: str) -> bool:
    rec = _codes.get(email)
    if not rec:
        return False
    if time.time() > rec["expires"] or rec["attempts"] >= MAX_ATTEMPTS:
        _codes.pop(email, None)
        return False
    rec["attempts"] += 1
    if bcrypt.checkpw(code.strip().encode(), rec["hash"]):
        _codes.pop(email, None)
        return True
    return False


async def _send_code_email(to_email: str, code: str):
    subject = "Your BillionToOne Medical Advisors Hub login code"
    body = (
        "Hello,\n\n"
        "Your one-time login code for the BillionToOne Medical Advisors Hub is:\n\n"
        "    {code}\n\n"
        "This code expires in {mins} minutes. If you did not request it, you can "
        "ignore this email.\n\n"
        "— BillionToOne Medical Affairs"
    ).format(code=code, mins=CODE_TTL // 60)

    if not EMAIL_CONFIGURED:
        # Dev mode: no SendGrid key configured, so log the code instead.
        print("[DEV] login code for {}: {}".format(to_email, code), flush=True)
        return

    payload = {
        "personalizations": [{"to": [{"email": to_email}]}],
        "from": {"email": MAIL_FROM, "name": MAIL_FROM_NAME},
        "subject": subject,
        "content": [{"type": "text/plain", "value": body}],
    }
    headers = {
        "Authorization": "Bearer " + SENDGRID_API_KEY,
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.post(
            "https://api.sendgrid.com/v3/mail/send", headers=headers, json=payload
        )
        resp.raise_for_status()


# --- Session helpers ---------------------------------------------------------


def current_user(request: Request):
    return request.session.get("user")


# --- Routes ------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    if current_user(request):
        return RedirectResponse("/hub", status_code=302)
    return RedirectResponse("/login", status_code=302)


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    if current_user(request):
        return RedirectResponse("/hub", status_code=302)
    return templates.TemplateResponse(
        "login.html", {"request": request, "error": None}
    )


@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request, email: str = Form(...)):
    email = email.strip().lower()
    _prune_codes()
    if await is_allowed(email):
        # Respect the resend cooldown even on first request bursts.
        prev = _codes.get(email)
        if not prev or (time.time() - prev["sent_at"]) >= RESEND_COOLDOWN:
            code = _issue_code(email)
            try:
                await _send_code_email(email, code)
            except Exception as exc:
                print("[email] send failed:", repr(exc), flush=True)
    # Always behave identically so we never reveal who is/isn't an advisor.
    request.session["pending_email"] = email
    return RedirectResponse("/verify", status_code=302)


@app.get("/verify", response_class=HTMLResponse)
async def verify_form(request: Request):
    email = request.session.get("pending_email")
    if not email:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(
        "verify.html", {"request": request, "email": email, "error": None}
    )


@app.post("/verify", response_class=HTMLResponse)
async def verify_submit(request: Request, code: str = Form(...)):
    email = request.session.get("pending_email")
    if not email:
        return RedirectResponse("/login", status_code=302)
    if _check_code(email, code):
        request.session.pop("pending_email", None)
        request.session["user"] = email
        return RedirectResponse("/hub", status_code=302)
    return templates.TemplateResponse(
        "verify.html",
        {"request": request, "email": email,
         "error": "That code is invalid or expired. Please try again or resend."},
        status_code=401,
    )


@app.post("/resend")
async def resend(request: Request):
    email = request.session.get("pending_email")
    if not email:
        return RedirectResponse("/login", status_code=302)
    _prune_codes()
    if await is_allowed(email):
        prev = _codes.get(email)
        if not prev or (time.time() - prev["sent_at"]) >= RESEND_COOLDOWN:
            code = _issue_code(email)
            try:
                await _send_code_email(email, code)
            except Exception as exc:
                print("[email] send failed:", repr(exc), flush=True)
    return RedirectResponse("/verify", status_code=302)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


@app.get("/hub", response_class=HTMLResponse)
async def hub(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("hub.html", {"request": request, "user": user})


@app.get("/files/{filename}")
async def protected_file(request: Request, filename: str):
    """Serve a confidential asset only to signed-in advisors."""
    if not current_user(request):
        return RedirectResponse("/login", status_code=302)
    if "/" in filename or "\\" in filename or filename.startswith("."):
        return Response(status_code=404)
    path = os.path.join(PROTECTED_DIR, filename)
    if not os.path.isfile(path):
        return Response(status_code=404)
    return FileResponse(path)


@app.get("/debug/diag")
async def diag(request: Request, key: str = "", email: str = ""):
    """Secret-guarded diagnostics. Disabled unless DEBUG_KEY is set and matches."""
    if not DEBUG_KEY or key != DEBUG_KEY:
        return Response(status_code=404)

    # 1) Airtable allowlist check
    try:
        emails = await _fetch_roster_emails()
        roster = {
            "ok": True,
            "active_count": len(emails),
            "email_in_roster": email.strip().lower() in emails if email else None,
        }
    except Exception as exc:
        roster = {"ok": False, "error": repr(exc)}

    # 2) SendGrid credential check (auth only; sends nothing)
    if not EMAIL_CONFIGURED:
        email_check = {"configured": False}
    else:
        try:
            headers = {"Authorization": "Bearer " + SENDGRID_API_KEY}
            async with httpx.AsyncClient(timeout=20.0) as client:
                r = await client.get(
                    "https://api.sendgrid.com/v3/scopes", headers=headers
                )
            email_check = {
                "configured": True,
                "auth": "ok" if r.status_code == 200 else "FAILED",
                "status_code": r.status_code,
            }
        except Exception as exc:
            email_check = {"configured": True, "auth": "FAILED", "error": repr(exc)}

    return {
        "roster": roster,
        "email": email_check,
        "mail_from": MAIL_FROM,
        "mail_from_name": MAIL_FROM_NAME,
        "airtable_table": AIRTABLE_TABLE,
        "email_field": AIRTABLE_EMAIL_FIELD,
        "status_field": AIRTABLE_STATUS_FIELD,
        "allowed_status": ALLOWED_STATUS,
    }


@app.get("/healthz")
async def healthz():
    return {
        "ok": True,
        "airtable_configured": bool(AIRTABLE_TOKEN),
        "email_configured": EMAIL_CONFIGURED,
    }
