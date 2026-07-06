"""
BillionToOne Medical Advisors Hub — protected portal.

FastAPI app with individual email/password accounts for external medical
advisors. Accounts live in the ADVISOR_ACCOUNTS environment variable as JSON
(email -> bcrypt hash) so nothing sensitive is written to disk and the app
survives Render redeploys without a database.
"""

import json
import os
import secrets

import bcrypt
from dotenv import load_dotenv
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

load_dotenv()  # load .env for local development; no-op in production

# --- Configuration (all via environment variables) ---------------------------

SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
# In production HTTPS is always on (Render), so lock cookies to https.
COOKIE_HTTPS_ONLY = os.environ.get("COOKIE_HTTPS_ONLY", "true").lower() == "true"
SESSION_MAX_AGE = int(os.environ.get("SESSION_MAX_AGE", 60 * 60 * 12))  # 12h


def load_accounts():
    """Parse ADVISOR_ACCOUNTS env var into {email(lowercased): bcrypt_hash}."""
    raw = os.environ.get("ADVISOR_ACCOUNTS", "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        raise RuntimeError(
            "ADVISOR_ACCOUNTS is not valid JSON. Expected "
            '{"email@example.com": "$2b$...", ...}'
        )
    return {email.strip().lower(): h for email, h in data.items()}


ACCOUNTS = load_accounts()

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


def current_user(request: Request):
    """Return the logged-in advisor's email, or None."""
    return request.session.get("user")


def verify_password(email: str, password: str) -> bool:
    stored = ACCOUNTS.get(email.strip().lower())
    if not stored:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), stored.encode("utf-8"))
    except ValueError:
        return False


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
async def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
):
    if verify_password(email, password):
        request.session["user"] = email.strip().lower()
        return RedirectResponse("/hub", status_code=302)
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": "Incorrect email or password."},
        status_code=401,
    )


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


@app.get("/hub", response_class=HTMLResponse)
async def hub(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(
        "hub.html", {"request": request, "user": user}
    )


@app.get("/healthz")
async def healthz():
    return {"ok": True, "accounts_loaded": len(ACCOUNTS)}
