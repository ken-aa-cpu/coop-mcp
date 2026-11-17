"""Self-hosted OAuth 2.1 + PKCE Authorization Server for CoopMCP Gateway."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import hmac
import html
import json
import logging
import secrets
import time
from typing import Any, Iterable
from urllib.parse import parse_qs, urlencode, urlparse

import jwt
from starlette.types import Receive, Scope, Send

logger = logging.getLogger(__name__)

DEFAULT_ALLOWED_REDIRECT_HOSTS = frozenset({
    "oauth-redirect.googleusercontent.com",
    "oauth-redirect-sandbox.googleusercontent.com",
    "gemini.google.com",
    "vertexaisearch.cloud.google.com",
})

ACCESS_TOKEN_TTL = 3600  # 1 hour
REFRESH_TOKEN_TTL = 30 * 24 * 3600  # 30 days
AUTH_CODE_TTL = 120  # 2 minutes
CSRF_TTL = 600  # 10 minutes
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 900  # 15 minutes


def hash_password(password: str, iterations: int = 260_000) -> str:
    """Generate a salted PBKDF2-HMAC-SHA256 password hash string."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return (
        f"pbkdf2_sha256${iterations}$"
        f"{base64.b64encode(salt).decode('ascii')}$"
        f"{base64.b64encode(digest).decode('ascii')}"
    )


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify plaintext password against stored PBKDF2-HMAC-SHA256 hash."""
    try:
        algo, iters_str, salt_b64, hash_b64 = stored_hash.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iters_str)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def is_allowed_redirect_uri(uri: str, extra_hosts: Iterable[str] = ()) -> bool:
    """Allow only HTTPS OAuth callback URLs on trusted redirect hosts."""
    try:
        parsed = urlparse(uri.strip())
        allowed = DEFAULT_ALLOWED_REDIRECT_HOSTS | {h.strip().lower() for h in extra_hosts if h.strip()}
        return parsed.scheme == "https" and (parsed.hostname or "").lower() in allowed
    except Exception:
        return False


@dataclass
class _AuthCodeRecord:
    code: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    scope: str
    expires_at: float


class OAuth21Provider:
    """Implements OAuth 2.1 + PKCE + Discovery + Login UI + Rate Limiting."""

    def __init__(
        self,
        public_url: str,
        client_id: str,
        client_secret: str,
        password_hash: str,
        jwt_secret: str,
        *,
        extra_redirect_hosts: Iterable[str] = (),
        read_roots_summary: str = "configured workspace",
        write_root_summary: str = "configured output folder",
    ) -> None:
        self.public_url = public_url.rstrip("/")
        self.static_client_id = client_id
        self.static_client_secret = client_secret
        self.password_hash = password_hash
        self.jwt_secret = jwt_secret
        self.extra_redirect_hosts = tuple(extra_redirect_hosts)
        self.read_roots_summary = read_roots_summary
        self.write_root_summary = write_root_summary

        self._dynamic_clients: dict[str, dict[str, Any]] = {}
        self._auth_codes: dict[str, _AuthCodeRecord] = {}
        self._failed_attempts: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}

    def protected_resource_metadata(self) -> dict[str, Any]:
        return {
            "resource": f"{self.public_url}/mcp",
            "authorization_servers": [self.public_url],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["coop:tools"],
        }

    def auth_server_metadata(self) -> dict[str, Any]:
        return {
            "issuer": self.public_url,
            "authorization_endpoint": f"{self.public_url}/oauth/authorize",
            "token_endpoint": f"{self.public_url}/oauth/token",
            "registration_endpoint": f"{self.public_url}/oauth/register",
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["coop:tools"],
        }

    def verify_bearer_token(self, token: str) -> dict[str, Any] | None:
        try:
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=["HS256"],
                audience=f"{self.public_url}/mcp",
                issuer=self.public_url,
            )
            if payload.get("typ") != "access":
                return None
            return payload
        except Exception:
            return None

    def _is_known_client(self, client_id: str) -> bool:
        if self.static_client_id and hmac.compare_digest(client_id, self.static_client_id):
            return True
        return client_id in self._dynamic_clients

    def _verify_client_credentials(self, client_id: str, client_secret: str) -> bool:
        if self.static_client_id and hmac.compare_digest(client_id, self.static_client_id):
            return bool(self.static_client_secret) and hmac.compare_digest(client_secret, self.static_client_secret)
        dyn = self._dynamic_clients.get(client_id)
        if not dyn:
            return False
        dyn_secret = dyn.get("client_secret")
        if dyn_secret:
            return hmac.compare_digest(client_secret, dyn_secret)
        return True  # Public PKCE DCR client

    def _client_ip(self, scope: Scope) -> str:
        for name, val in scope.get("headers", []):
            if name.decode("latin-1").lower() == "x-forwarded-for":
                return val.decode("latin-1").split(",")[0].strip()
        client = scope.get("client")
        return client[0] if client else "unknown"

    def _check_rate_limit(self, ip: str) -> tuple[bool, int]:
        now = time.time()
        locked = self._locked_until.get(ip, 0)
        if locked > now:
            return False, int(locked - now)
        attempts = [t for t in self._failed_attempts.get(ip, []) if (now - t) < 600]
        self._failed_attempts[ip] = attempts
        return True, 0

    def _record_failure(self, ip: str) -> None:
        now = time.time()
        attempts = [t for t in self._failed_attempts.get(ip, []) if (now - t) < 600]
        attempts.append(now)
        self._failed_attempts[ip] = attempts
        if len(attempts) >= MAX_LOGIN_ATTEMPTS:
            self._locked_until[ip] = now + LOCKOUT_SECONDS
            logger.warning("OAuth login rate-limited for IP %s", ip)

    def _clear_failures(self, ip: str) -> None:
        self._failed_attempts.pop(ip, None)
        self._locked_until.pop(ip, None)

    def _issue_csrf(self) -> str:
        now = int(time.time())
        return jwt.encode(
            {"typ": "csrf", "iat": now, "exp": now + CSRF_TTL, "n": secrets.token_hex(8)},
            self.jwt_secret,
            algorithm="HS256",
        )

    def _verify_csrf(self, token: str) -> bool:
        try:
            data = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
            return data.get("typ") == "csrf"
        except Exception:
            return False

    def _issue_tokens(self, client_id: str, scope: str) -> dict[str, Any]:
        now = int(time.time())
        access = jwt.encode(
            {
                "typ": "access",
                "sub": "coop-owner",
                "cid": client_id,
                "scope": scope,
                "iss": self.public_url,
                "aud": f"{self.public_url}/mcp",
                "iat": now,
                "exp": now + ACCESS_TOKEN_TTL,
                "jti": secrets.token_hex(12),
            },
            self.jwt_secret,
            algorithm="HS256",
        )
        refresh = jwt.encode(
            {
                "typ": "refresh",
                "sub": "coop-owner",
                "cid": client_id,
                "scope": scope,
                "iss": self.public_url,
                "aud": f"{self.public_url}/mcp",
                "iat": now,
                "exp": now + REFRESH_TOKEN_TTL,
                "jti": secrets.token_hex(12),
            },
            self.jwt_secret,
            algorithm="HS256",
        )
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL,
            "refresh_token": refresh,
            "scope": scope,
        }

    async def handle_http(self, scope: Scope, receive: Receive, send: Send) -> bool:
        """Handle OAuth discovery, DCR, /oauth/authorize, and /oauth/token. Returns True if handled."""
        path: str = scope.get("path", "")
        method: str = scope.get("method", "GET").upper()

        if path.startswith("/.well-known/oauth-protected-resource"):
            await _send_json(send, 200, self.protected_resource_metadata())
            return True

        if path in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
            await _send_json(send, 200, self.auth_server_metadata())
            return True

        if path == "/oauth/register" and method == "POST":
            await self._handle_register(receive, send)
            return True

        if path == "/oauth/authorize":
            if method == "GET":
                await self._handle_authorize_get(scope, send)
                return True
            if method == "POST":
                await self._handle_authorize_post(scope, receive, send)
                return True

        if path == "/oauth/token" and method == "POST":
            await self._handle_token(scope, receive, send)
            return True

        return False

    async def _handle_register(self, receive: Receive, send: Send) -> None:
        raw = await _read_body(receive)
        try:
            body = json.loads(raw.decode("utf-8"))
        except Exception:
            await _send_json(send, 400, {"error": "invalid_client_metadata"})
            return

        redirect_uris = body.get("redirect_uris") or []
        if (
            not isinstance(redirect_uris, list)
            or not redirect_uris
            or not all(is_allowed_redirect_uri(u, self.extra_redirect_hosts) for u in redirect_uris)
        ):
            await _send_json(
                send,
                400,
                {
                    "error": "invalid_redirect_uri",
                    "error_description": "Redirect URI must use HTTPS on an allowed OAuth callback host.",
                },
            )
            return

        cid = f"coop_dcr_{secrets.token_urlsafe(12)}"
        auth_method = body.get("token_endpoint_auth_method", "client_secret_post")
        csecret = f"coop_sec_{secrets.token_urlsafe(24)}" if auth_method != "none" else None

        record: dict[str, Any] = {
            "client_id": cid,
            "redirect_uris": redirect_uris,
            "token_endpoint_auth_method": auth_method,
            "client_name": str(body.get("client_name") or "Remote MCP Client"),
        }
        if csecret:
            record["client_secret"] = csecret
        self._dynamic_clients[cid] = record
        await _send_json(send, 201, record)

    async def _handle_authorize_get(self, scope: Scope, send: Send, error_msg: str = "") -> None:
        qs = parse_qs(scope.get("query_string", b"").decode("utf-8", errors="ignore"))
        client_id = _first(qs, "client_id")
        redirect_uri = _first(qs, "redirect_uri")
        response_type = _first(qs, "response_type") or "code"
        state = _first(qs, "state")
        code_challenge = _first(qs, "code_challenge")
        code_challenge_method = (_first(qs, "code_challenge_method") or "S256").upper()
        scope_str = _first(qs, "scope") or "coop:tools"

        if response_type != "code":
            await _send_html(send, 400, _render_error_page("Unsupported response_type (only 'code' is supported)."))
            return
        if not self._is_known_client(client_id):
            await _send_html(send, 400, _render_error_page("Unknown or invalid client_id."))
            return
        if not is_allowed_redirect_uri(redirect_uri, self.extra_redirect_hosts):
            await _send_html(send, 400, _render_error_page("Redirect URI host is not in the allowlist."))
            return
        if code_challenge and code_challenge_method != "S256":
            await _send_html(send, 400, _render_error_page("Only PKCE S256 is supported."))
            return

        csrf = self._issue_csrf()
        page = _render_login_page(
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope_str=scope_str,
            csrf=csrf,
            read_roots_summary=self.read_roots_summary,
            write_root_summary=self.write_root_summary,
            error_msg=error_msg,
        )
        await _send_html(send, 200, page)

    async def _handle_authorize_post(self, scope: Scope, receive: Receive, send: Send) -> None:
        ip = self._client_ip(scope)
        allowed, wait_sec = self._check_rate_limit(ip)
        if not allowed:
            await _send_html(send, 429, _render_error_page(f"Too many attempts. Try again in {wait_sec}s."))
            return

        raw = await _read_body(receive)
        form = parse_qs(raw.decode("utf-8", errors="ignore"))

        csrf = _first(form, "csrf")
        if not self._verify_csrf(csrf):
            await _send_html(send, 400, _render_error_page("Authorization form expired. Please restart from your MCP client."))
            return

        client_id = _first(form, "client_id")
        redirect_uri = _first(form, "redirect_uri")
        state = _first(form, "state")
        code_challenge = _first(form, "code_challenge")
        code_challenge_method = (_first(form, "code_challenge_method") or "S256").upper()
        scope_str = _first(form, "scope") or "coop:tools"
        password = _first(form, "password")

        if not self._is_known_client(client_id) or not is_allowed_redirect_uri(redirect_uri, self.extra_redirect_hosts):
            await _send_html(send, 400, _render_error_page("Invalid client_id or redirect_uri."))
            return

        if not verify_password(password, self.password_hash):
            self._record_failure(ip)
            page = _render_login_page(
                client_id=client_id,
                redirect_uri=redirect_uri,
                state=state,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
                scope_str=scope_str,
                csrf=self._issue_csrf(),
                read_roots_summary=self.read_roots_summary,
                write_root_summary=self.write_root_summary,
                error_msg="Invalid password. Please try again.",
            )
            await _send_html(send, 401, page)
            return

        self._clear_failures(ip)
        code = f"coop_code_{secrets.token_urlsafe(24)}"
        self._auth_codes[code] = _AuthCodeRecord(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope=scope_str,
            expires_at=time.time() + AUTH_CODE_TTL,
        )

        params = {"code": code}
        if state:
            params["state"] = state
        sep = "&" if "?" in redirect_uri else "?"
        location = f"{redirect_uri}{sep}{urlencode(params)}"
        await send({
            "type": "http.response.start",
            "status": 302,
            "headers": [
                (b"location", location.encode("utf-8")),
                (b"cache-control", b"no-store"),
                (b"content-length", b"0"),
            ],
        })
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    async def _handle_token(self, scope: Scope, receive: Receive, send: Send) -> None:
        raw = await _read_body(receive)
        form = parse_qs(raw.decode("utf-8", errors="ignore"))

        client_id = _first(form, "client_id")
        client_secret = _first(form, "client_secret")

        for name, val in scope.get("headers", []):
            if name.decode("latin-1").lower() == "authorization":
                val_str = val.decode("latin-1")
                if val_str.startswith("Basic "):
                    try:
                        decoded = base64.b64decode(val_str[6:].strip()).decode("utf-8")
                        if ":" in decoded:
                            b_id, b_sec = decoded.split(":", 1)
                            client_id = client_id or b_id
                            client_secret = client_secret or b_sec
                    except Exception:
                        pass

        if not self._verify_client_credentials(client_id, client_secret):
            await _send_json(send, 401, {"error": "invalid_client"})
            return

        grant_type = _first(form, "grant_type")

        if grant_type == "authorization_code":
            code = _first(form, "code")
            redirect_uri = _first(form, "redirect_uri")
            code_verifier = _first(form, "code_verifier")

            rec = self._auth_codes.pop(code, None)
            if rec is None or rec.expires_at < time.time():
                await _send_json(send, 400, {"error": "invalid_grant", "error_description": "Invalid or expired code."})
                return
            if not hmac.compare_digest(rec.client_id, client_id) or rec.redirect_uri != redirect_uri:
                await _send_json(send, 400, {"error": "invalid_grant", "error_description": "Client or redirect_uri mismatch."})
                return
            if rec.code_challenge:
                digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
                computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
                if not hmac.compare_digest(computed, rec.code_challenge):
                    await _send_json(send, 400, {"error": "invalid_grant", "error_description": "PKCE verification failed."})
                    return

            tokens = self._issue_tokens(client_id, rec.scope)
            await _send_json(send, 200, tokens)
            return

        if grant_type == "refresh_token":
            rt = _first(form, "refresh_token")
            try:
                payload = jwt.decode(
                    rt,
                    self.jwt_secret,
                    algorithms=["HS256"],
                    audience=f"{self.public_url}/mcp",
                    issuer=self.public_url,
                )
                if payload.get("typ") != "refresh" or not hmac.compare_digest(str(payload.get("cid", "")), client_id):
                    raise ValueError("Refresh token mismatch")
                tokens = self._issue_tokens(client_id, str(payload.get("scope") or "coop:tools"))
                await _send_json(send, 200, tokens)
                return
            except Exception:
                await _send_json(send, 400, {"error": "invalid_grant", "error_description": "Invalid refresh token."})
                return

        await _send_json(send, 400, {"error": "unsupported_grant_type"})


def _first(qs: dict[str, list[str]], key: str) -> str:
    vals = qs.get(key)
    return vals[0] if vals else ""


async def _read_body(receive: Receive) -> bytes:
    chunks = []
    while True:
        msg = await receive()
        chunks.append(msg.get("body", b""))
        if not msg.get("more_body", False):
            break
    return b"".join(chunks)


async def _send_json(send: Send, status: int, data: dict[str, Any]) -> None:
    body = json.dumps(data, ensure_ascii=False).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json; charset=utf-8"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"cache-control", b"no-store"),
            (b"access-control-allow-origin", b"*"),
        ],
    })
    await send({"type": "http.response.body", "body": body, "more_body": False})


async def _send_html(send: Send, status: int, content: str) -> None:
    body = content.encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"text/html; charset=utf-8"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"cache-control", b"no-store"),
            (b"x-frame-options", b"DENY"),
        ],
    })
    await send({"type": "http.response.body", "body": body, "more_body": False})


def _render_error_page(message: str) -> str:
    safe_msg = html.escape(message)
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CoopMCP Authorization Error</title>
<style>body{{font-family:system-ui,sans-serif;background:#111827;color:#f3f4f6;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}.card{{background:#1f2937;padding:2rem;border-radius:14px;max-width:420px;border:1px solid #374151}}h2{{color:#f87171;margin-top:0}}</style>
</head><body><div class="card"><h2>Authorization Failed</h2><p>{safe_msg}</p></div></body></html>"""


def _render_login_page(
    *,
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    code_challenge_method: str,
    scope_str: str,
    csrf: str,
    read_roots_summary: str,
    write_root_summary: str,
    error_msg: str = "",
) -> str:
    err_html = f'<div class="err">{html.escape(error_msg)}</div>' if error_msg else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CoopMCP Authorization</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 16px; }}
  .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 16px; padding: 28px; width: 100%; max-width: 420px; box-shadow: 0 20px 50px rgba(0,0,0,.45); }}
  h1 {{ font-size: 1.25rem; margin: 0 0 8px; color: #fde047; }}
  p {{ font-size: 0.9rem; color: #cbd5e1; line-height: 1.5; margin: 0 0 18px; }}
  .err {{ background: rgba(239,68,68,.15); border: 1px solid #ef4444; color: #fca5a5; padding: 10px 12px; border-radius: 8px; margin-bottom: 14px; font-size: 0.9rem; }}
  label {{ display: block; font-size: 0.85rem; color: #94a3b8; margin-bottom: 6px; }}
  input[type=password] {{ width: 100%; box-sizing: border-box; padding: 11px 12px; border-radius: 10px; border: 1px solid #475569; background: #0f172a; color: #fff; font-size: 1rem; margin-bottom: 16px; }}
  button {{ width: 100%; padding: 12px; border: 0; border-radius: 10px; background: #eab308; color: #0f172a; font-weight: 700; font-size: 1rem; cursor: pointer; }}
  button:hover {{ background: #facc15; }}
  .meta {{ margin-top: 14px; font-size: 0.78rem; color: #64748b; word-break: break-all; }}
</style>
</head>
<body>
  <div class="card">
    <h1>🐤 CoopMCP Authorization</h1>
    <p>An AI client is requesting sandboxed access to <strong>{html.escape(read_roots_summary)}</strong> (outputs confined to <strong>{html.escape(write_root_summary)}</strong>). Enter your gateway password to approve:</p>
    {err_html}
    <form method="post" action="/oauth/authorize">
      <input type="hidden" name="client_id" value="{html.escape(client_id)}">
      <input type="hidden" name="redirect_uri" value="{html.escape(redirect_uri)}">
      <input type="hidden" name="state" value="{html.escape(state)}">
      <input type="hidden" name="code_challenge" value="{html.escape(code_challenge)}">
      <input type="hidden" name="code_challenge_method" value="{html.escape(code_challenge_method)}">
      <input type="hidden" name="scope" value="{html.escape(scope_str)}">
      <input type="hidden" name="csrf" value="{html.escape(csrf)}">
      <label for="password">Gateway Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
      <button type="submit">Approve &amp; Connect</button>
    </form>
    <div class="meta">Callback host: {html.escape(urlparse(redirect_uri).hostname or '')}</div>
  </div>
</body>
</html>"""
