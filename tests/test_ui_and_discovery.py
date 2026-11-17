"""Tests for soft step advisories, plugin admin gating, local MCP discovery, and loopback-only Settings UI."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import shutil
import socket
import sys
import tempfile
import threading

import httpx2 as httpx
import uvicorn

ROOT_DIR = str(Path(__file__).resolve().parent.parent)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from admin_privilege import AdminPrivilegeManager
from app_registry import AppPluginSpec
from files_tools import PathPolicy
import mcp_discovery
from oauth_provider import hash_password
from plugin_router import PluginSessionManager
import server as gw_server
from ui_server import LocalUiController


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def run_tests() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="coop_ui_"))
    try:
        read_root = tmp / "workspace"
        write_root = read_root / "output"
        read_root.mkdir()
        write_root.mkdir()

        policy = PathPolicy(
            read_roots=(read_root.resolve(),),
            write_root=write_root.resolve(),
            cloud_sync_dir=(write_root / "CloudSync").resolve(),
            gdrive_mirror_dir=None,
        )

        # 1. Soft step threshold (does NOT abort above 3 steps; emits advisory) + require_admin_unlock
        mock_script = Path(__file__).resolve().parent / "mock_stdio_plugin.py"
        registry = {
            "mock": AppPluginSpec(
                key="mock",
                display_name="MockPlugin",
                category="Test",
                description="Mock stdio plugin",
                command=(sys.executable, str(mock_script)),
                root_mode="gateway_only",
            ),
            "gated": AppPluginSpec(
                key="gated",
                display_name="GatedPlugin",
                category="Test",
                description="Admin-gated mock plugin",
                command=(sys.executable, str(mock_script)),
                root_mode="gateway_only",
                require_admin_unlock=True,
            ),
        }
        mgr = PluginSessionManager(policy, registry=registry, soft_step_warning=3, max_batch_steps=6)
        try:
            steps = [{"tool_name": "echo_info", "arguments": {"message": f"s{i}"}} for i in range(5)]
            res = await mgr.batch_call("mock", steps, include_final_image=False)
            assert res["all_ok"] is True
            assert res["completed_steps"] == 5
            assert "advisory" in res and "5 steps" in res["advisory"]

            try:
                await mgr.batch_call("mock", steps + steps, include_final_image=False)
                raise AssertionError("Expected ValueError above max_batch_steps=6")
            except ValueError:
                pass

            try:
                await mgr.call_tool("gated", "echo_info", {"message": "blocked"}, unrestricted=False)
                raise AssertionError("Expected PermissionError for require_admin_unlock plugin")
            except PermissionError:
                pass

            ok_gated = await mgr.call_tool("gated", "echo_info", {"message": "allowed"}, unrestricted=True)
            assert ok_gated["isError"] is False and "mock:allowed" in ok_gated["output"]
        finally:
            await mgr.shutdown_all()

        # 2. Local MCP discovery (masked preview + unmasked opt-in resolution + folder scan)
        cfg_file = tmp / "claude_desktop_config.json"
        cfg_file.write_text(
            json.dumps({
                "mcpServers": {
                    "LocalStdio": {
                        "command": "uvx",
                        "args": ["mcp-server-sqlite"],
                        "env": {"API_SECRET": "super_secret_token"},
                    },
                    "LocalHttp": {
                        "url": "http://127.0.0.1:3999/mcp",
                        "headers": {"Authorization": "Bearer top_secret_hdr"},
                    },
                }
            }),
            encoding="utf-8",
        )
        scan_dir = tmp / "apps_scan"
        scan_dir.mkdir()
        (scan_dir / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"FolderTool": {"command": "python", "args": ["-V"]}}}),
            encoding="utf-8",
        )
        (scan_dir / "demo-cli.exe").write_bytes(b"MZ")

        disc = mcp_discovery.discover_local_mcps(extra_config_paths=[cfg_file], scan_folder=scan_dir, mask_secrets=True)
        http_cands = [c for c in disc["client_candidates"] if c["key"] == "localhttp"]
        assert len(http_cands) == 1
        assert http_cands[0]["headers"]["Authorization"] == "***"
        unmasked = mcp_discovery.resolve_unmasked_candidate("localhttp", "custom_config", str(cfg_file))
        assert unmasked is not None and unmasked.headers_dict()["Authorization"] == "Bearer top_secret_hdr"
        folder_keys = {c["key"] for c in disc["folder_candidates"]}
        assert "foldertool" in folder_keys and "demo" in folder_keys

        # 3. Loopback-only Settings UI security + trilingual assets + secret redaction
        port = _free_port()
        local_key = "test_local_ui_secret_xyz"
        admin_mgr = AdminPrivilegeManager(
            pin_hash=hash_password("1234"),
            jwt_secret="ui_test_jwt_secret_0123456789abcdef012345",
            epoch_file=tmp / ".admin_epoch",
        )
        ui_ctrl = LocalUiController(secret_key=local_key, plugin_manager=mgr, admin_manager=admin_mgr)
        app = gw_server.SecureCompatLayer(
            gw_server.mcp_server.streamable_http_app(streamable_http_path="/mcp", stateless_http=True, host="127.0.0.1"),
            public_url=f"http://127.0.0.1:{port}",
            secret_key=local_key,
            oauth=None,
            require_oauth=False,
            ui_controller=ui_ctrl,
        )

        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        srv = uvicorn.Server(config)
        thread = threading.Thread(target=srv.run, daemon=True)
        thread.start()
        while not srv.started:
            await asyncio.sleep(0.05)

        try:
            async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
                # Proxied /ui & /api/ui/state blocked (403)
                r = await client.get("/ui", headers={"X-Forwarded-For": "198.51.100.10"})
                assert r.status_code == 403
                r = await client.get("/api/ui/state", headers={"X-Forwarded-Host": "evil.example", "X-Coop-Local-Key": local_key})
                assert r.status_code == 403

                # Bad Origin blocked (403)
                r = await client.get("/api/ui/state", headers={"Origin": "https://evil.example", "X-Coop-Local-Key": local_key})
                assert r.status_code == 403

                # Missing / wrong local key rejected (401)
                r = await client.get("/api/ui/state")
                assert r.status_code == 401
                r = await client.get("/api/ui/state", headers={"X-Coop-Local-Key": "wrong"})
                assert r.status_code == 401

                # Direct loopback /ui serves trilingual dashboard
                r = await client.get("/ui")
                assert r.status_code == 200
                assert "zh-Hant" in r.text and "日本語" in r.text and "English" in r.text

                # Direct loopback /api/ui/state returns sanitized config without leaking secret hashes
                r = await client.get("/api/ui/state", headers={"X-Coop-Local-Key": local_key})
                assert r.status_code == 200
                body_txt = r.text
                assert local_key not in body_txt
                assert "pbkdf2_sha256" not in body_txt
                data = r.json()
                assert data["status"] == "ok"
                assert "plugins" in data

                # Discovery API works over loopback
                r = await client.post(
                    "/api/ui/discover",
                    headers={"X-Coop-Local-Key": local_key},
                    json={"scan_folder": str(scan_dir)},
                )
                assert r.status_code == 200
                assert len(r.json()["folder_candidates"]) >= 2

                # Setup-pending guard: require_oauth=True with oauth=None locks /mcp (503) while /ui stays open
                app.require_oauth = True
                app.oauth = None
                r = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
                assert r.status_code == 503
                r = await client.get("/ui")
                assert r.status_code == 200
        finally:
            srv.should_exit = True

        print("ALL_UI_AND_DISCOVERY_TESTS_PASSED")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(run_tests())
