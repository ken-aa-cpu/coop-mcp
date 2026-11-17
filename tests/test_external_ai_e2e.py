"""Full end-to-end simulation of an external AI MCP client driving CoopMCP over HTTP + OAuth."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import html
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import sys
import tempfile
import threading
from urllib.parse import parse_qs, urlparse

import httpx2 as httpx
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from PIL import Image
import uvicorn

ROOT_DIR = str(Path(__file__).resolve().parent.parent)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from admin_privilege import AdminPrivilegeManager
from app_registry import AppPluginSpec
from files_tools import PathPolicy
import mcp_discovery
from oauth_provider import OAuth21Provider, hash_password
from plugin_router import PluginSessionManager
import server as gw_server
from ui_server import LocalUiController


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _make_png_bytes(color: tuple[int, int, int] = (255, 210, 60)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (64, 64), color).save(buf, format="PNG")
    return buf.getvalue()


async def run_tests() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="coop_e2e_"))
    orig_policy = gw_server.POLICY
    orig_admin = gw_server.ADMIN_MANAGER
    orig_plugins = gw_server.PLUGIN_MANAGER
    try:
        read_root = tmp / "workspace"
        write_root = read_root / "output"
        cloud_dir = write_root / "CloudSync"
        mirror_dir = tmp / "mirror"
        outside_dir = tmp / "outside"
        for d in (read_root, write_root, cloud_dir, mirror_dir, outside_dir):
            d.mkdir(parents=True, exist_ok=True)

        (read_root / "notes.md").write_text("# Notes\nCoopMCP E2E Alpha\nLine 3\n", encoding="utf-8")
        (read_root / ".env").write_text("TOP_SECRET=do_not_leak\n", encoding="utf-8")
        (read_root / "sample.png").write_bytes(_make_png_bytes())
        (outside_dir / "host_secret.txt").write_text("outside-content", encoding="utf-8")

        # Test ArtCraft smart folder detection without hardcoding install paths
        art_dir = tmp / "artcraft_bin"
        art_dir.mkdir()
        suffix = ".exe" if os.name == "nt" else ""
        (art_dir / f"solidcraft-cli{suffix}").write_bytes(b"stub")
        (art_dir / f"vectorcraft-cli{suffix}").write_bytes(b"stub")
        art_cands = {c["key"]: c for c in mcp_discovery.scan_folder_for_mcp(art_dir)}
        assert art_cands["solidcraft"]["root_mode"] == "allow_path"
        assert "--require-allow-path" in art_cands["solidcraft"]["extra_mcp_args"]
        assert art_cands["vectorcraft"]["root_mode"] == "automation"
        assert "--headless" in art_cands["vectorcraft"]["extra_mcp_args"]

        # Upstream HTTP MCP server to verify HTTP plugin transport
        http_plugin_port = _free_port()
        upstream_srv = MCPServer("upstream-http-plugin")

        @upstream_srv.tool()
        def http_ping(tag: str = "e2e") -> str:
            return f"http-pong:{tag}"

        upstream_asgi = upstream_srv.streamable_http_app(
            streamable_http_path="/mcp",
            stateless_http=True,
            host="127.0.0.1",
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        )
        up_srv = uvicorn.Server(uvicorn.Config(upstream_asgi, host="127.0.0.1", port=http_plugin_port, log_level="warning"))
        up_thread = threading.Thread(target=up_srv.run, daemon=True)
        up_thread.start()
        while not up_srv.started:
            await asyncio.sleep(0.05)

        policy = PathPolicy(
            read_roots=(read_root.resolve(),),
            write_root=write_root.resolve(),
            cloud_sync_dir=cloud_dir.resolve(),
            gdrive_mirror_dir=mirror_dir.resolve(),
        )
        pin = "93571"
        admin_jwt = "e2e_admin_jwt_secret_0123456789abcdef0123456789"
        admin_mgr = AdminPrivilegeManager(
            pin_hash=hash_password(pin),
            jwt_secret=admin_jwt,
            ttl_seconds=3600,
            epoch_file=tmp / ".admin_epoch",
        )
        mock_script = Path(__file__).resolve().parent / "mock_stdio_plugin.py"
        registry = {
            "mock": AppPluginSpec(
                key="mock",
                display_name="MockPlugin",
                category="Test",
                description="Stdio mock plugin",
                command=(sys.executable, str(mock_script)),
                formats=(".txt", ".png"),
                root_mode="gateway_only",
            ),
            "gated": AppPluginSpec(
                key="gated",
                display_name="GatedPlugin",
                category="Test",
                description="Admin-gated plugin",
                command=(sys.executable, str(mock_script)),
                root_mode="gateway_only",
                require_admin_unlock=True,
            ),
            "http-echo": AppPluginSpec(
                key="http-echo",
                display_name="HttpEcho",
                category="Test",
                description="HTTP upstream plugin",
                transport="http",
                url=f"http://127.0.0.1:{http_plugin_port}/mcp",
            ),
        }
        plugin_mgr = PluginSessionManager(policy, registry=registry, soft_step_warning=3, max_batch_steps=10)

        gw_server.POLICY = policy
        gw_server.ADMIN_MANAGER = admin_mgr
        gw_server.PLUGIN_MANAGER = plugin_mgr

        port = _free_port()
        public_url = f"http://127.0.0.1:{port}"
        local_key = "e2e_local_key"
        oauth_pw = "ExternalAiTestPass!"
        oauth = OAuth21Provider(
            public_url=public_url,
            client_id="coop-mcp-client",
            client_secret="e2e_client_secret",
            password_hash=hash_password(oauth_pw),
            jwt_secret="e2e_oauth_jwt_secret_0123456789abcdef0123456789",
            read_roots_summary=str(read_root),
            write_root_summary=str(write_root),
        )
        starlette_app = gw_server.mcp_server.streamable_http_app(
            streamable_http_path="/mcp",
            stateless_http=True,
            host="127.0.0.1",
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        )
        ui_ctrl = LocalUiController(secret_key=local_key, plugin_manager=plugin_mgr, admin_manager=admin_mgr)
        app = gw_server.SecureCompatLayer(
            starlette_app,
            public_url=public_url,
            secret_key=local_key,
            oauth=oauth,
            require_oauth=True,
            ui_controller=ui_ctrl,
        )

        srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
        thread = threading.Thread(target=srv.run, daemon=True)
        thread.start()
        while not srv.started:
            await asyncio.sleep(0.05)

        try:
            # Step A: External AI completes OAuth 2.1 + PKCE login
            verifier, challenge = _pkce_pair()
            redirect_uri = "https://gemini.google.com/oauth/callback"
            async with httpx.AsyncClient(base_url=public_url, follow_redirects=False) as auth_http:
                auth_qs = {
                    "response_type": "code",
                    "client_id": "coop-mcp-client",
                    "redirect_uri": redirect_uri,
                    "state": "e2e_state",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "scope": "coop:tools",
                }
                r_get = await auth_http.get("/oauth/authorize", params=auth_qs)
                assert r_get.status_code == 200
                m = re.search(r'name="csrf"\s+value="([^"]+)"', r_get.text)
                assert m
                csrf = html.unescape(m.group(1))
                r_post = await auth_http.post("/oauth/authorize", data={**auth_qs, "csrf": csrf, "password": oauth_pw})
                assert r_post.status_code == 302
                code = parse_qs(urlparse(r_post.headers["location"]).query)["code"][0]
                r_tok = await auth_http.post(
                    "/oauth/token",
                    data={
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": redirect_uri,
                        "client_id": "coop-mcp-client",
                        "client_secret": "e2e_client_secret",
                        "code_verifier": verifier,
                    },
                )
                assert r_tok.status_code == 200
                bearer = r_tok.json()["access_token"]

            # Step B: External AI drives all MCP tools via ClientSession
            ai_client = httpx.AsyncClient(headers={"Authorization": f"Bearer {bearer}"})
            async with ai_client:
                async with streamable_http_client(f"{public_url}/mcp", http_client=ai_client) as (rs, ws):
                    async with ClientSession(rs, ws) as session:
                        await session.initialize()

                        tools_resp = await session.list_tools()
                        tool_names = {t.name for t in tools_resp.tools}
                        for expected in (
                            "coop_get_skill",
                            "coop_unlock_system",
                            "coop_set_sandbox",
                            "coop_run_command",
                            "coop_list_dir",
                            "coop_search_files",
                            "coop_search_text",
                            "coop_read_text_file",
                            "coop_file_info",
                            "coop_preview_image",
                            "coop_write_output_file",
                            "coop_edit_output_file",
                            "coop_manage_output",
                            "coop_make_output_dir",
                            "coop_publish_to_cloud",
                            "plugin_list_apps",
                            "plugin_list_tools",
                            "plugin_call_tool",
                            "plugin_batch_call",
                            "plugin_close_app",
                        ):
                            assert expected in tool_names, f"Missing tool: {expected}"

                        # Skill resource & tool
                        res_skill = await session.read_resource("coop://skill")
                        assert "CoopMCP" in res_skill.contents[0].text
                        r_sk = await session.call_tool("coop_get_skill", {"section": "Sandbox"})
                        assert not r_sk.is_error and "coop_unlock_system" in r_sk.content[0].text

                        # Filesystem reads + .env block + outside block
                        r_ls = await session.call_tool("coop_list_dir", {"path": ""})
                        ls_names = {e["name"] for e in json.loads(r_ls.content[0].text)["entries"]}
                        assert "notes.md" in ls_names and ".env" not in ls_names

                        r_env = await session.call_tool("coop_read_text_file", {"path": ".env"})
                        assert r_env.is_error

                        r_out_blk = await session.call_tool("coop_read_text_file", {"path": str(outside_dir / "host_secret.txt")})
                        assert r_out_blk.is_error

                        r_sf = await session.call_tool("coop_search_files", {"pattern": "*.md"})
                        assert json.loads(r_sf.content[0].text)["count"] == 1

                        r_st = await session.call_tool("coop_search_text", {"query": "CoopMCP E2E Alpha"})
                        assert json.loads(r_st.content[0].text)["match_count"] == 1

                        r_fi = await session.call_tool("coop_file_info", {"path": "notes.md"})
                        assert json.loads(r_fi.content[0].text)["name"] == "notes.md"

                        r_img = await session.call_tool("coop_preview_image", {"path": "sample.png"})
                        assert not r_img.is_error
                        assert any(
                            getattr(c, "type", "") == "image"
                            and getattr(c, "mime_type", getattr(c, "mimeType", "")) == "image/png"
                            for c in r_img.content
                        )

                        # Filesystem writes + edit + dir + manage + cloud publish
                        r_w_blk = await session.call_tool("coop_write_output_file", {"path": str(outside_dir / "bad.txt"), "content": "x"})
                        assert r_w_blk.is_error

                        r_w = await session.call_tool("coop_write_output_file", {"path": "report.md", "content": "v1\nline2\n"})
                        assert not r_w.is_error
                        r_ed = await session.call_tool("coop_edit_output_file", {"path": "report.md", "target": "v1", "replacement": "v2"})
                        assert json.loads(r_ed.content[0].text)["replacements"] == 1
                        r_mk = await session.call_tool("coop_make_output_dir", {"path": "sub"})
                        assert not r_mk.is_error
                        r_cp = await session.call_tool("coop_manage_output", {"action": "copy", "path": str(write_root / "report.md"), "destination": "sub/report_copy.md"})
                        assert not r_cp.is_error
                        r_mv = await session.call_tool("coop_manage_output", {"action": "rename", "path": "sub/report_copy.md", "destination": "sub/report_final.md"})
                        assert not r_mv.is_error
                        r_pub = await session.call_tool("coop_publish_to_cloud", {"local_path": str(write_root / "sub/report_final.md")})
                        pub_data = json.loads(r_pub.content[0].text)
                        assert pub_data["file_unlocked"] is True and pub_data["mirror_unlocked"] is True
                        assert (mirror_dir / "report_final.md").exists()
                        r_del = await session.call_tool("coop_manage_output", {"action": "delete", "path": "sub/report_final.md"})
                        assert not r_del.is_error

                        # Sandbox elevation flow
                        r_cmd_blk = await session.call_tool("coop_run_command", {"command": "echo nope"})
                        assert r_cmd_blk.is_error

                        r_bad_pin = await session.call_tool("coop_unlock_system", {"pin": "00000"})
                        assert r_bad_pin.is_error

                        r_un = await session.call_tool("coop_unlock_system", {"pin": pin})
                        assert not r_un.is_error
                        adm_tok = json.loads(r_un.content[0].text)["admin_token"]

                        r_out_ok = await session.call_tool("coop_read_text_file", {"path": str(outside_dir / "host_secret.txt")})
                        assert "outside-content" in json.loads(r_out_ok.content[0].text)["content"]

                        if os.name == "nt":
                            r_cmd = await session.call_tool("coop_run_command", {"command": "Write-Output 'AI_E2E_CMD_OK'", "shell": "powershell"})
                        else:
                            r_cmd = await session.call_tool("coop_run_command", {"command": "echo AI_E2E_CMD_OK", "shell": "sh"})
                        assert "AI_E2E_CMD_OK" in json.loads(r_cmd.content[0].text)["stdout"]

                        r_lock = await session.call_tool("coop_set_sandbox", {"open": False})
                        assert json.loads(r_lock.content[0].text)["sandbox_open"] is False
                        r_cmd_blk2 = await session.call_tool("coop_run_command", {"command": "echo nope"})
                        assert r_cmd_blk2.is_error

                        # Gated plugin blocked when locked, allowed with unlock
                        r_gated_blk = await session.call_tool("plugin_call_tool", {"app": "gated", "tool_name": "echo_info", "arguments": {"message": "x"}})
                        assert r_gated_blk.is_error

                        r_reopen = await session.call_tool("coop_set_sandbox", {"open": True, "admin_token": adm_tok})
                        assert json.loads(r_reopen.content[0].text)["sandbox_open"] is True
                        r_gated_ok = await session.call_tool("plugin_call_tool", {"app": "gated", "tool_name": "echo_info", "arguments": {"message": "ok"}})
                        assert not r_gated_ok.is_error and "mock:ok" in r_gated_ok.content[0].text

                        # Revoke from tray invalidates token
                        admin_mgr.revoke_all()
                        r_rev_fail = await session.call_tool("coop_set_sandbox", {"open": True, "admin_token": adm_tok})
                        assert r_rev_fail.is_error

                        # Stdio & HTTP plugin router tools + soft step advisory + ImageContent forwarding
                        r_apps = await session.call_tool("plugin_list_apps", {})
                        app_keys = {a["key"] for a in json.loads(r_apps.content[0].text)["apps"]}
                        assert {"mock", "gated", "http-echo"}.issubset(app_keys)

                        r_ptools = await session.call_tool("plugin_list_tools", {"app": "mock"})
                        assert json.loads(r_ptools.content[0].text)["total_tools"] >= 2

                        r_pimg = await session.call_tool("plugin_call_tool", {"app": "mock", "tool_name": "render_preview"})
                        assert any(
                            getattr(c, "type", "") == "image"
                            and getattr(c, "mime_type", getattr(c, "mimeType", "")) == "image/png"
                            for c in r_pimg.content
                        )

                        r_batch = await session.call_tool(
                            "plugin_batch_call",
                            {
                                "app": "mock",
                                "calls": [{"tool_name": "echo_info", "arguments": {"message": f"b{i}"}} for i in range(5)],
                                "include_final_image": False,
                            },
                        )
                        batch_json = json.loads(r_batch.content[0].text)
                        assert batch_json["all_ok"] is True and batch_json["completed_steps"] == 5
                        assert "advisory" in batch_json

                        r_htools = await session.call_tool("plugin_list_tools", {"app": "http-echo"})
                        assert json.loads(r_htools.content[0].text)["total_tools"] >= 1
                        r_hcall = await session.call_tool("plugin_call_tool", {"app": "http-echo", "tool_name": "http_ping", "arguments": {"tag": "via_coop"}})
                        assert "http-pong:via_coop" in r_hcall.content[0].text

                        r_close = await session.call_tool("plugin_close_app", {"app": "mock"})
                        assert json.loads(r_close.content[0].text)["status"] == "closed"

            print("ALL_EXTERNAL_AI_E2E_TESTS_PASSED")
        finally:
            srv.should_exit = True
            up_srv.should_exit = True
            thread.join(timeout=3.0)
            up_thread.join(timeout=3.0)
    finally:
        gw_server.POLICY = orig_policy
        gw_server.ADMIN_MANAGER = orig_admin
        gw_server.PLUGIN_MANAGER = orig_plugins
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(run_tests())
