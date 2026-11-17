"""End-to-end verification of OAuth 2.1 + PKCE and SecureCompatLayer in server.py."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import html
import json
from pathlib import Path
import re
import secrets
import shutil
import socket
import sys
import tempfile
import threading
from urllib.parse import parse_qs, urlparse

ROOT_DIR = str(Path(__file__).resolve().parent.parent)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.transport_security import TransportSecuritySettings
import httpx2 as httpx
import uvicorn

from files_tools import PathPolicy
from oauth_provider import OAuth21Provider, hash_password
import server as gw_server


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return verifier, challenge


async def run_tests() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="coop_oauth_"))
    orig_policy = gw_server.POLICY
    try:
        read_root = tmp / "workspace"
        write_root = read_root / "output"
        read_root.mkdir()
        write_root.mkdir()
        (read_root / "hello.txt").write_text("hi", encoding="utf-8")

        gw_server.POLICY = PathPolicy(
            read_roots=(read_root.resolve(),),
            write_root=write_root.resolve(),
            cloud_sync_dir=(write_root / "CloudSync").resolve(),
            gdrive_mirror_dir=None,
        )

        port = _free_port()
        public_url = f"http://127.0.0.1:{port}"
        secret_key = "local_health_secret"
        client_id = "coop-mcp-client"
        client_secret = "test_client_secret_123"
        jwt_secret = "test_jwt_secret_456_0123456789abcdef0123456789abcdef"
        password = "CorrectHorseBatteryStaple!"

        oauth = OAuth21Provider(
            public_url=public_url,
            client_id=client_id,
            client_secret=client_secret,
            password_hash=hash_password(password),
            jwt_secret=jwt_secret,
        )
        starlette_app = gw_server.mcp_server.streamable_http_app(
            streamable_http_path="/mcp",
            stateless_http=True,
            host="127.0.0.1",
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        )
        app = gw_server.SecureCompatLayer(
            starlette_app,
            public_url=public_url,
            secret_key=secret_key,
            oauth=oauth,
            require_oauth=True,
        )

        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        srv = uvicorn.Server(config)
        thread = threading.Thread(target=srv.run, daemon=True)
        thread.start()
        while not srv.started:
            await asyncio.sleep(0.05)

        try:
            async with httpx.AsyncClient(base_url=public_url, follow_redirects=False) as client:
                # 1. Unauthenticated /mcp -> 401 with WWW-Authenticate
                r = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
                assert r.status_code == 401, f"Expected 401, got {r.status_code}"
                assert "resource_metadata=" in r.headers.get("www-authenticate", "")

                # 2. Static ?key= must NOT bypass OAuth on /mcp
                r = await client.post(f"/mcp?key={secret_key}", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
                assert r.status_code == 401, f"Static key bypassed OAuth on /mcp! {r.status_code}"

                # 3. Direct localhost /health?key=... -> 200; proxied X-Forwarded-For /health?key=... -> 401
                r = await client.get(f"/health?key={secret_key}")
                assert r.status_code == 200 and r.json()["status"] == "ok"
                r = await client.get(f"/health?key={secret_key}", headers={"X-Forwarded-For": "203.0.113.5"})
                assert r.status_code == 401, f"Proxied /health leaked without OAuth! {r.status_code}"

                # 4. Well-known discovery
                prm = (await client.get("/.well-known/oauth-protected-resource")).json()
                assert prm["resource"] == f"{public_url}/mcp"
                assert prm["authorization_servers"] == [public_url]
                asm = (await client.get("/.well-known/oauth-authorization-server")).json()
                assert asm["authorization_endpoint"] == f"{public_url}/oauth/authorize"
                assert asm["token_endpoint"] == f"{public_url}/oauth/token"

                # 5. Authorize GET + wrong password rejected
                verifier, challenge = _pkce_pair()
                redirect_uri = "https://gemini.google.com/oauth/callback"
                auth_qs = {
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "state": "st_abc",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "scope": "coop:tools",
                }
                r = await client.get("/oauth/authorize", params=auth_qs)
                assert r.status_code == 200
                m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
                assert m, "CSRF hidden input missing"
                csrf = html.unescape(m.group(1))

                r_bad = await client.post(
                    "/oauth/authorize",
                    data={**auth_qs, "csrf": csrf, "password": "wrong_password"},
                )
                assert r_bad.status_code == 401, f"Wrong password should return 401, got {r_bad.status_code}"

                # 6. Correct password -> 302 redirect with code & state
                r_ok = await client.post(
                    "/oauth/authorize",
                    data={**auth_qs, "csrf": csrf, "password": password},
                )
                assert r_ok.status_code == 302, f"Expected 302, got {r_ok.status_code}: {r_ok.text}"
                loc = urlparse(r_ok.headers["location"])
                cb_params = parse_qs(loc.query)
                assert cb_params["state"] == ["st_abc"]
                code = cb_params["code"][0]

                # 7. Token exchange
                tok_resp = await client.post(
                    "/oauth/token",
                    data={
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": redirect_uri,
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "code_verifier": verifier,
                    },
                )
                assert tok_resp.status_code == 200, f"Token failed: {tok_resp.text}"
                tok_data = tok_resp.json()
                refresh_token = tok_data["refresh_token"]

                # 8. Refresh token grant
                ref_resp = await client.post(
                    "/oauth/token",
                    data={
                        "grant_type": "refresh_token",
                        "refresh_token": refresh_token,
                        "client_id": client_id,
                        "client_secret": client_secret,
                    },
                )
                assert ref_resp.status_code == 200, f"Refresh failed: {ref_resp.text}"
                access_token_2 = ref_resp.json()["access_token"]

            # 9. Full MCP ClientSession using Bearer access_token_2
            http_client = httpx.AsyncClient(headers={"Authorization": f"Bearer {access_token_2}"})
            async with http_client:
                async with streamable_http_client(f"{public_url}/mcp", http_client=http_client) as (rs, ws):
                    async with ClientSession(rs, ws) as session:
                        await session.initialize()
                        res = await session.call_tool("coop_list_dir", {"path": ""})
                        assert not res.is_error
                        payload = json.loads(res.content[0].text)
                        assert payload["count"] >= 2

            print("ALL_OAUTH_TESTS_PASSED")
        finally:
            srv.should_exit = True
    finally:
        gw_server.POLICY = orig_policy
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(run_tests())
