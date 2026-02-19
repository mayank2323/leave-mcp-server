"""
Combined Leave Management MCP + OAuth 2.1 Authorization Server.

Single process, single port — suitable for a single Ngrok tunnel.
All OAuth endpoints live at the root, MCP tools at /mcp.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time
import os
import secrets
import urllib.parse
import uuid
from dataclasses import dataclass
from datetime import datetime
from html import escape as html_escape
from typing import Annotated

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Form, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastmcp import FastMCP

# ═══════════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════════
BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000")
SESSION_SECRET = os.environ.get("SESSION_SECRET", "dev-secret-change-me")
ACCESS_TOKEN_TTL = int(os.environ.get("ACCESS_TOKEN_TTL", "3600"))
AUTH_CODE_TTL = int(os.environ.get("AUTH_CODE_TTL", "600"))
SCOPES_SUPPORTED = {"mcp.read", "mcp.write"}

# ═══════════════════════════════════════════════════════════════════════════════
# RSA Key Management
# ═══════════════════════════════════════════════════════════════════════════════
_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_public_key = _private_key.public_key()
_kid = "key-1"


def get_public_jwks() -> dict:
    pub = _public_key.public_numbers()
    n_bytes = pub.n.to_bytes((pub.n.bit_length() + 7) // 8, byteorder="big")
    e_bytes = pub.e.to_bytes((pub.e.bit_length() + 7) // 8, byteorder="big")
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": _kid,
                "n": base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode(),
                "e": base64.urlsafe_b64encode(e_bytes).rstrip(b"=").decode(),
            }
        ]
    }


# ═══════════════════════════════════════════════════════════════════════════════
# In-Memory Storage
# ═══════════════════════════════════════════════════════════════════════════════
USERS = {"alice": "password123", "bob": "hunter2"}


@dataclass
class RegisteredClient:
    client_id: str
    client_secret: str | None
    redirect_uris: list[str]
    token_endpoint_auth_method: str = "none"
    client_name: str | None = None


@dataclass
class AuthorizationCode:
    code: str
    client_id: str
    user_id: str
    scope: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    resource: str
    expires_at: float


CLIENTS: dict[str, RegisteredClient] = {}
AUTH_CODES: dict[str, AuthorizationCode] = {}
CONSENTS: dict[str, set[str]] = {}

# ═══════════════════════════════════════════════════════════════════════════════
# Mock Leave Data
# ═══════════════════════════════════════════════════════════════════════════════
EMPLOYEES = {
    "EMP001": {"name": "Alice Johnson", "department": "Engineering", "balance": {"sick": 8, "vacation": 15, "personal": 3}},
    "EMP002": {"name": "Bob Smith", "department": "Product", "balance": {"sick": 5, "vacation": 10, "personal": 2}},
    "EMP003": {"name": "Carol Davis", "department": "Design", "balance": {"sick": 10, "vacation": 20, "personal": 4}},
    "EMP004": {"name": "Dan Wilson", "department": "Sales", "balance": {"sick": 3, "vacation": 7, "personal": 1}},
}

LEAVE_REQUESTS: list[dict] = [
    {"request_id": "LR-0001", "employee_id": "EMP001", "leave_type": "vacation", "start_date": "2026-03-10", "end_date": "2026-03-14", "reason": "Family trip", "status": "approved", "submitted_at": "2026-02-01T10:00:00Z"},
    {"request_id": "LR-0002", "employee_id": "EMP002", "leave_type": "sick", "start_date": "2026-02-05", "end_date": "2026-02-06", "reason": "Flu", "status": "approved", "submitted_at": "2026-02-05T08:30:00Z"},
]


# ═══════════════════════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════════════════════
import hmac as _hmac

RE_PKCE = re.compile(r"[A-Za-z0-9\-._~]{43,128}")


def _sign(data: str) -> str:
    return _hmac.new(SESSION_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()


def make_session_token(username: str) -> str:
    sid = uuid.uuid4().hex[:16]
    payload = json.dumps({"u": username, "sid": sid, "t": int(time.time())})
    return base64.urlsafe_b64encode(f"{payload}|{_sign(payload)}".encode()).decode()


def parse_session_token(token: str) -> dict | None:
    try:
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        payload_str, sig = decoded.rsplit("|", 1)
        if not _hmac.compare_digest(sig, _sign(payload_str)):
            return None
        return json.loads(payload_str)
    except Exception:
        return None


def make_csrf(sid: str) -> str:
    data = f"{sid}:{int(time.time())}"
    return base64.urlsafe_b64encode(f"{data}|{_sign(data)}".encode()).decode()


def check_csrf(token: str, sid: str, max_age: int = 600) -> bool:
    try:
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        data, sig = decoded.rsplit("|", 1)
        if not _hmac.compare_digest(sig, _sign(data)):
            return False
        token_sid, ts = data.split(":", 1)
        return token_sid == sid and (int(time.time()) - int(ts)) <= max_age
    except Exception:
        return False


def _consent_key(uid: str, cid: str, res: str) -> str:
    return f"{uid}:{cid}:{res}"


def oauth_err_redirect(uri: str, error: str, desc: str | None = None, state: str | None = None) -> RedirectResponse:
    p: dict[str, str] = {"error": error}
    if desc:
        p["error_description"] = desc
    if state:
        p["state"] = state
    sep = "&" if "?" in uri else "?"
    return RedirectResponse(url=uri + sep + urllib.parse.urlencode(p), status_code=302)


def oauth_err_json(error: str, desc: str | None = None, status: int = 400, www_auth: str | None = None) -> JSONResponse:
    body: dict[str, str] = {"error": error}
    if desc:
        body["error_description"] = desc
    resp = JSONResponse(body, status_code=status)
    if www_auth:
        resp.headers["WWW-Authenticate"] = www_auth
    return resp


# ═══════════════════════════════════════════════════════════════════════════════
# FastAPI — OAuth 2.1 Authorization Server
# ═══════════════════════════════════════════════════════════════════════════════
mcp_starlette_app = None  # set after mcp is defined

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(application):
    async with mcp_starlette_app.lifespan(application):
        yield

app = FastAPI(title="Leave MCP — Combined Server", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


@app.get("/.well-known/oauth-authorization-server")
def metadata():
    return {
        "issuer": BASE_URL,
        "authorization_endpoint": f"{BASE_URL}/authorize",
        "token_endpoint": f"{BASE_URL}/token",
        "jwks_uri": f"{BASE_URL}/oauth/jwks",
        "registration_endpoint": f"{BASE_URL}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "scopes_supported": list(SCOPES_SUPPORTED),
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
    }


@app.post("/register")
async def register(req: Request):
    body = await req.json()
    redirect_uris = body.get("redirect_uris", [])
    auth_method = body.get("token_endpoint_auth_method", "none")
    client_name = body.get("client_name")
    cid = uuid.uuid4().hex
    csecret = secrets.token_urlsafe(32) if auth_method != "none" else None
    client = RegisteredClient(
        client_id=cid, client_secret=csecret, redirect_uris=redirect_uris,
        token_endpoint_auth_method=auth_method, client_name=client_name,
    )
    CLIENTS[cid] = client
    resp: dict = {"client_id": cid, "redirect_uris": redirect_uris, "token_endpoint_auth_method": auth_method}
    if csecret:
        resp["client_secret"] = csecret
    if client_name:
        resp["client_name"] = client_name
    return JSONResponse(resp, status_code=201)


@app.get("/oauth/jwks")
def jwks():
    return get_public_jwks()


LOGIN_HTML = """<!DOCTYPE html>
<html><head><title>Login</title>
<style>
body{{font-family:-apple-system,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f5f5f5}}
.c{{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.1);width:340px}}
h2{{margin-top:0;color:#333}}label{{display:block;margin-top:1rem;font-weight:600;color:#555}}
input{{width:100%;padding:.6rem;margin-top:.3rem;border:1px solid #ddd;border-radius:6px;box-sizing:border-box;font-size:1rem}}
button{{width:100%;padding:.7rem;margin-top:1.5rem;background:#0070d2;color:#fff;border:none;border-radius:6px;font-size:1rem;cursor:pointer}}
button:hover{{background:#005bb5}}p{{color:#888;font-size:.85rem;margin-top:1rem}}
</style></head><body>
<div class="c"><h2>Sign In</h2>
<form method="POST" action="/login"><input type="hidden" name="redirect_to" value="{redirect_to}">
<label>Username</label><input name="username" required autofocus>
<label>Password</label><input name="password" type="password" required>
<button type="submit">Log in</button></form>
<p>Demo: alice / password123</p></div></body></html>"""

CONSENT_HTML = """<!DOCTYPE html>
<html><head><title>Authorize</title>
<style>
body{{font-family:-apple-system,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f5f5f5}}
.c{{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.1);width:380px}}
h2{{margin-top:0;color:#333}}.s{{background:#f0f4ff;padding:.8rem;border-radius:6px;margin:1rem 0;font-family:monospace}}
.b{{display:flex;gap:.5rem;margin-top:1.5rem}}button{{flex:1;padding:.7rem;border:none;border-radius:6px;font-size:1rem;cursor:pointer}}
.a{{background:#0070d2;color:#fff}}.a:hover{{background:#005bb5}}.d{{background:#eee;color:#333}}.d:hover{{background:#ddd}}
</style></head><body>
<div class="c"><h2>Authorize Access</h2>
<p>Logged in as <strong>{username}</strong></p>
<p>Application <strong>{client_id}</strong> requests:</p>
<div class="s">{scopes}</div>
<form method="POST" action="/authorize">
<input type="hidden" name="client_id" value="{client_id}">
<input type="hidden" name="redirect_uri" value="{redirect_uri}">
<input type="hidden" name="scope" value="{scopes}">
<input type="hidden" name="state" value="{state}">
<input type="hidden" name="code_challenge" value="{code_challenge}">
<input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
<input type="hidden" name="resource" value="{resource}">
<input type="hidden" name="csrf_token" value="{csrf_token}">
<div class="b"><button type="submit" name="action" value="deny" class="d">Deny</button>
<button type="submit" name="action" value="approve" class="a">Approve</button></div>
</form></div></body></html>"""


@app.get("/login")
def login_page(redirect_to: str | None = None):
    return HTMLResponse(LOGIN_HTML.format(redirect_to=html_escape(redirect_to or "", quote=True)))


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...), redirect_to: str | None = Form(None)):
    if USERS.get(username) != password:
        raise HTTPException(401, "invalid credentials")
    resp = RedirectResponse(url=redirect_to or "/", status_code=302)
    resp.set_cookie("session", make_session_token(username), httponly=True, secure=True, samesite="lax")
    return resp


@app.get("/authorize")
async def authorize_get(
    request: Request,
    response_type: str,
    client_id: Annotated[str, Query(min_length=1)],
    redirect_uri: Annotated[str, Query(min_length=1)],
    code_challenge: Annotated[str, Query(min_length=1)],
    code_challenge_method: str,
    resource: Annotated[str, Query(min_length=1)],
    scope: str | None = None,
    state: str | None = None,
):
    client = CLIENTS.get(client_id)
    if not client:
        raise HTTPException(400, "unknown client_id")
    if redirect_uri not in client.redirect_uris:
        raise HTTPException(400, "invalid redirect_uri")
    if response_type != "code":
        return oauth_err_redirect(redirect_uri, "unsupported_response_type", state=state)
    if code_challenge_method != "S256":
        return oauth_err_redirect(redirect_uri, "invalid_request", state=state)

    known = [BASE_URL, BASE_URL + "/mcp"]
    if not any(resource.rstrip("/") == k.rstrip("/") for k in known):
        return oauth_err_redirect(redirect_uri, "invalid_target", state=state)

    sd = parse_session_token(request.cookies.get("session", ""))
    if not sd:
        return RedirectResponse(f"/login?redirect_to={urllib.parse.quote(str(request.url))}", 302)

    username, sid = sd["u"], sd["sid"]
    scope = scope or ""
    scopes = scope.split()
    if not set(scopes).issubset(SCOPES_SUPPORTED):
        return oauth_err_redirect(redirect_uri, "invalid_scope", state=state)

    ck = _consent_key(username, client_id, resource)
    if set(scopes).issubset(CONSENTS.get(ck, set())):
        code_val = secrets.token_urlsafe(48)
        AUTH_CODES[code_val] = AuthorizationCode(
            code=code_val, client_id=client_id, user_id=username, scope=scope,
            redirect_uri=redirect_uri, code_challenge=code_challenge,
            code_challenge_method=code_challenge_method, resource=resource,
            expires_at=time.time() + AUTH_CODE_TTL,
        )
        url = f"{redirect_uri}?code={urllib.parse.quote(code_val)}"
        if state:
            url += f"&state={urllib.parse.quote(state)}"
        return RedirectResponse(url, 302)

    return HTMLResponse(CONSENT_HTML.format(
        username=username, client_id=client_id, scopes=scope,
        redirect_uri=redirect_uri, state=state or "",
        code_challenge=code_challenge, code_challenge_method=code_challenge_method,
        resource=resource, csrf_token=make_csrf(sid),
    ))


@app.post("/authorize")
async def authorize_post(
    request: Request,
    action: str = Form(...), client_id: str = Form(...), redirect_uri: str = Form(...),
    scope: str = Form(""), state: str | None = Form(None),
    code_challenge: str = Form(...), code_challenge_method: str = Form(...),
    resource: str = Form(...), csrf_token: str = Form(...),
):
    sd = parse_session_token(request.cookies.get("session", ""))
    if not sd:
        return oauth_err_redirect(redirect_uri, "access_denied", state=state)
    username, sid = sd["u"], sd["sid"]

    if not check_csrf(csrf_token, sid):
        raise HTTPException(400, "invalid csrf")
    client = CLIENTS.get(client_id)
    if not client or redirect_uri not in client.redirect_uris:
        raise HTTPException(400, "invalid_request")
    if action != "approve":
        return oauth_err_redirect(redirect_uri, "access_denied", state=state)
    if code_challenge_method != "S256":
        return oauth_err_redirect(redirect_uri, "invalid_request", state=state)

    granted = [s for s in scope.split() if s]
    if granted:
        ck = _consent_key(username, client_id, resource)
        CONSENTS.setdefault(ck, set()).update(granted)

    code_val = secrets.token_urlsafe(48)
    AUTH_CODES[code_val] = AuthorizationCode(
        code=code_val, client_id=client_id, user_id=username, scope=scope,
        redirect_uri=redirect_uri, code_challenge=code_challenge,
        code_challenge_method=code_challenge_method, resource=resource,
        expires_at=time.time() + AUTH_CODE_TTL,
    )
    url = f"{redirect_uri}?code={urllib.parse.quote(code_val)}"
    if state:
        url += f"&state={urllib.parse.quote(state)}"
    return RedirectResponse(url, 302)


@app.post("/token")
async def token_endpoint(
    request: Request,
    grant_type: str = Form(...), code: str = Form(...),
    redirect_uri: str | None = Form(None), client_id: str | None = Form(None),
    client_secret: str | None = Form(None), code_verifier: str = Form(...),
    resource: str = Form(...),
):
    if grant_type != "authorization_code":
        return oauth_err_json("unsupported_grant_type")

    auth_h = request.headers.get("Authorization", "")
    basic_id = basic_sec = None
    if auth_h.startswith("Basic "):
        try:
            d = base64.b64decode(auth_h[6:]).decode()
            basic_id, basic_sec = d.split(":", 1)
        except Exception:
            return oauth_err_json("invalid_client", status=401, www_auth='Basic realm="token"')

    rid = basic_id or client_id or ""
    client = CLIENTS.get(rid)
    if not client:
        return oauth_err_json("invalid_client", status=401, www_auth='Basic realm="token"')

    m = client.token_endpoint_auth_method or "none"
    if m == "client_secret_basic" and (not basic_sec or client.client_secret != basic_sec):
        return oauth_err_json("invalid_client", status=401, www_auth='Basic realm="token"')
    elif m == "client_secret_post" and (not client_secret or client.client_secret != client_secret):
        return oauth_err_json("invalid_client", status=401)
    elif m == "none" and (basic_id or basic_sec or client_secret):
        return oauth_err_json("invalid_client", status=401)

    ac = AUTH_CODES.pop(code, None)
    if not ac or time.time() > ac.expires_at:
        return oauth_err_json("invalid_grant")
    if ac.client_id != client.client_id or redirect_uri != ac.redirect_uri or resource != ac.resource:
        return oauth_err_json("invalid_grant")

    if not RE_PKCE.fullmatch(code_verifier):
        return oauth_err_json("invalid_request", desc="invalid code_verifier")
    s256 = hashlib.sha256(code_verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(s256).rstrip(b"=").decode("ascii")
    if ac.code_challenge_method != "S256" or challenge != ac.code_challenge:
        return oauth_err_json("invalid_grant")

    now = int(time.time())
    access_token = jwt.encode(
        {"iss": BASE_URL, "sub": ac.user_id, "aud": ac.resource,
         "client_id": ac.client_id, "scope": ac.scope,
         "iat": now, "exp": now + ACCESS_TOKEN_TTL},
        _private_key, algorithm="RS256", headers={"kid": _kid},
    )
    resp = JSONResponse(
        {"access_token": access_token, "token_type": "Bearer", "expires_in": ACCESS_TOKEN_TTL, "scope": ac.scope},
    )
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/")
def root():
    return {"status": "ok", "service": "leave-mcp-combined", "base_url": BASE_URL}


# ═══════════════════════════════════════════════════════════════════════════════
# FastMCP — Leave Management Tools (mounted at /mcp)
# ═══════════════════════════════════════════════════════════════════════════════

mcp = FastMCP(name="Leave Management MCP Server")


@mcp.tool(title="Get Leave")
async def get_leave(employee_id: str) -> str:
    """Get leave balance and request history for an employee.

    Args:
        employee_id: The employee ID (e.g. EMP001, EMP002, EMP003, EMP004)
    """
    emp = EMPLOYEES.get(employee_id.upper())
    if not emp:
        return json.dumps({"error": f"Employee '{employee_id}' not found. Valid IDs: EMP001-EMP004"})
    reqs = [r for r in LEAVE_REQUESTS if r["employee_id"] == employee_id.upper()]
    return json.dumps({"employee_id": employee_id.upper(), "name": emp["name"],
                        "department": emp["department"], "balance": emp["balance"],
                        "requests": reqs}, indent=2)


@mcp.tool(title="Submit Leave")
async def submit_leave(
    employee_id: str, leave_type: str, start_date: str, end_date: str, reason: str,
) -> str:
    """Submit a new leave request for an employee.

    Args:
        employee_id: The employee ID (e.g. EMP001)
        leave_type: Type of leave — sick, vacation, or personal
        start_date: Start date in YYYY-MM-DD format
        end_date: End date in YYYY-MM-DD format
        reason: Reason for the leave request
    """
    eid = employee_id.upper()
    emp = EMPLOYEES.get(eid)
    if not emp:
        return json.dumps({"error": f"Employee {eid} not found"})
    valid = ("sick", "vacation", "personal")
    if leave_type.lower() not in valid:
        return json.dumps({"error": f"Invalid type. Must be: {', '.join(valid)}"})
    if emp["balance"].get(leave_type.lower(), 0) <= 0:
        return json.dumps({"error": f"No {leave_type} balance remaining"})

    rid = f"LR-{uuid.uuid4().hex[:6].upper()}"
    rec = {"request_id": rid, "employee_id": eid, "leave_type": leave_type.lower(),
           "start_date": start_date, "end_date": end_date, "reason": reason,
           "status": "pending", "submitted_at": datetime.utcnow().isoformat() + "Z"}
    LEAVE_REQUESTS.append(rec)
    return json.dumps({"message": "Leave request submitted successfully", "request": rec}, indent=2)


mcp_starlette_app = mcp.http_app(path="/", transport="streamable-http", json_response=True)  # noqa: F811
app.mount("/mcp", mcp_starlette_app)


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
