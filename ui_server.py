"""Loopback-only management API and Web UI handler for CoopMCP."""

from __future__ import annotations

import hmac
import json
import logging
import os
from pathlib import Path
import time
from typing import Any
from urllib.parse import urlparse

from starlette.types import Receive, Scope, Send

from admin_privilege import AdminPrivilegeManager
from app_registry import AppPluginSpec, parse_plugin_entry, save_plugin_manifest
from config import APP_DIR, ENV_PATH, GatewayConfig
from mcp_discovery import discover_local_mcps, resolve_unmasked_candidate
from plugin_router import PluginSessionManager
from set_oauth_password import _upsert_env, update_admin_pin, update_env_password

logger = logging.getLogger(__name__)

UI_HTML_PATH = APP_DIR / "ui" / "index.html"


def _is_direct_loopback(scope: Scope) -> bool:
    client = scope.get("client")
    client_host = client[0] if client else ""
    if client_host not in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
        return False
    for name, _val in scope.get("headers", []):
        if name.decode("latin-1").lower() in (
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "forwarded",
            "x-real-ip",
        ):
            return False
    return True


def _header(scope: Scope, target: str) -> str:
    tgt = target.lower()
    for name, val in scope.get("headers", []):
        if name.decode("latin-1").lower() == tgt:
            return val.decode("latin-1").strip()
    return ""


def _is_loopback_origin(scope: Scope) -> bool:
    origin = _header(scope, "origin")
    if not origin:
        return True
    parsed = urlparse(origin)
    return parsed.scheme in ("http", "https") and (parsed.hostname or "").lower() in ("127.0.0.1", "localhost")


async def _read_json(receive: Receive) -> dict[str, Any]:
    chunks = []
    total = 0
    while True:
        msg = await receive()
        body = msg.get("body", b"")
        total += len(body)
        if total > 1_048_576:
            raise ValueError("Request body exceeds 1 MB limit.")
        chunks.append(body)
        if not msg.get("more_body", False):
            break
    raw = b"".join(chunks).decode("utf-8")
    if not raw.strip():
        return {}
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("Expected JSON object.")
    return parsed


async def _send_bytes(send: Send, status: int, body: bytes, content_type: str) -> None:
    headers = [
        (b"content-type", content_type.encode("ascii")),
        (b"content-length", str(len(body)).encode("ascii")),
        (b"cache-control", b"no-store"),
        (b"x-frame-options", b"DENY"),
        (b"content-security-policy", b"default-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"),
    ]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body, "more_body": False})


async def _send_json(send: Send, status: int, data: dict[str, Any]) -> None:
    await _send_bytes(send, status, json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")


class LocalUiController:
    """Handles loopback-only /ui and /api/ui/* endpoints without exposing secrets to public tunnels."""

    def __init__(
        self,
        *,
        secret_key: str,
        plugin_manager: PluginSessionManager,
        admin_manager: AdminPrivilegeManager,
    ) -> None:
        self.secret_key = secret_key
        self.plugin_manager = plugin_manager
        self.admin_manager = admin_manager
        self.restart_required = False

    def _authorized_api(self, scope: Scope) -> bool:
        if not self.secret_key:
            return True
        provided = _header(scope, "x-coop-local-key")
        return bool(provided) and hmac.compare_digest(provided, self.secret_key)

    def _state_payload(self) -> dict[str, Any]:
        cfg = GatewayConfig.from_env(reload_dotenv=ENV_PATH.exists())
        apps = self.plugin_manager.list_apps()["apps"]
        mcp_endpoint = (
            f"{cfg.public_url.rstrip('/')}/mcp"
            if cfg.require_oauth
            else f"{cfg.public_url.rstrip('/')}/mcp?key=(configured-secret)"
        )
        return {
            "status": "ok",
            "timestamp": int(time.time()),
            "restart_required": self.restart_required,
            "mcp_endpoint": mcp_endpoint,
            "admin": self.admin_manager.status(),
            "config": {
                "host": cfg.host,
                "port": cfg.port,
                "public_url": cfg.public_url,
                "tunnel_mode": cfg.tunnel_mode,
                "ssh_host": cfg.ssh_host,
                "ssh_user": cfg.ssh_user,
                "ssh_key": cfg.ssh_key,
                "ssh_remote_port": cfg.ssh_remote_port,
                "read_roots": [str(r) for r in cfg.read_roots],
                "write_root": str(cfg.write_root),
                "cloud_sync_dir": str(cfg.cloud_sync_dir),
                "gdrive_mirror_dir": str(cfg.gdrive_mirror_dir) if cfg.gdrive_mirror_dir else "",
                "idle_timeout": cfg.idle_timeout,
                "soft_step_warning": cfg.soft_step_warning,
                "max_batch_steps": cfg.max_batch_steps,
                "require_oauth": cfg.require_oauth,
                "oauth_client_id": cfg.oauth_client_id,
                "oauth_extra_redirect_hosts": list(cfg.oauth_extra_redirect_hosts),
                "oauth_password_configured": bool(cfg.oauth_password_hash or cfg.oauth_password_plain),
                "admin_pin_configured": bool(cfg.admin_pin_hash or cfg.admin_pin_plain),
                "env_exists": ENV_PATH.exists(),
                "apps_config_path": str(cfg.apps_config_path),
            },
            "plugins": [
                {
                    **app_info,
                    "details": (
                        self.plugin_manager.registry[app_info["key"]].to_manifest_dict(mask_secrets=True)
                        if app_info["key"] in self.plugin_manager.registry
                        else {}
                    ),
                }
                for app_info in apps
            ],
        }

    def _save_config(self, body: dict[str, Any]) -> dict[str, Any]:
        updates: dict[str, str] = {}
        restart_keys = {
            "PUBLIC_URL",
            "COOP_TUNNEL_MODE",
            "COOP_SSH_HOST",
            "COOP_SSH_USER",
            "COOP_SSH_KEY",
            "COOP_SSH_REMOTE_PORT",
            "COOP_REQUIRE_OAUTH",
            "COOP_OAUTH_CLIENT_ID",
            "COOP_OAUTH_ALLOWED_REDIRECT_HOSTS",
        }
        str_map = {
            "public_url": "PUBLIC_URL",
            "tunnel_mode": "COOP_TUNNEL_MODE",
            "ssh_host": "COOP_SSH_HOST",
            "ssh_user": "COOP_SSH_USER",
            "ssh_key": "COOP_SSH_KEY",
            "cloud_sync_dir": "COOP_CLOUD_SYNC_DIR",
            "gdrive_mirror_dir": "COOP_GDRIVE_MIRROR_DIR",
            "write_root": "COOP_WRITE_ROOT",
            "oauth_client_id": "COOP_OAUTH_CLIENT_ID",
        }
        for field_key, env_key in str_map.items():
            if field_key in body and isinstance(body[field_key], str):
                updates[env_key] = body[field_key].strip()

        if "read_roots" in body:
            raw_rr = body["read_roots"]
            if isinstance(raw_rr, list):
                updates["COOP_READ_ROOTS"] = ",".join(str(x).strip() for x in raw_rr if str(x).strip())
            elif isinstance(raw_rr, str):
                updates["COOP_READ_ROOTS"] = raw_rr.strip()

        if "oauth_extra_redirect_hosts" in body:
            raw_rh = body["oauth_extra_redirect_hosts"]
            if isinstance(raw_rh, list):
                updates["COOP_OAUTH_ALLOWED_REDIRECT_HOSTS"] = ",".join(str(x).strip() for x in raw_rh if str(x).strip())
            elif isinstance(raw_rh, str):
                updates["COOP_OAUTH_ALLOWED_REDIRECT_HOSTS"] = raw_rh.strip()

        for int_key, env_key, lo, hi in (
            ("ssh_remote_port", "COOP_SSH_REMOTE_PORT", 1, 65535),
            ("idle_timeout", "COOP_IDLE_TIMEOUT", 60, 86400),
            ("soft_step_warning", "COOP_SOFT_STEP_WARNING", 1, 500),
            ("max_batch_steps", "COOP_MAX_BATCH_STEPS", 10, 1000),
        ):
            if int_key in body and body[int_key] not in ("", None):
                val = max(lo, min(int(body[int_key]), hi))
                updates[env_key] = str(val)

        if "require_oauth" in body:
            updates["COOP_REQUIRE_OAUTH"] = "true" if bool(body["require_oauth"]) else "false"

        if updates:
            _upsert_env(updates)
            for k, v in updates.items():
                os.environ[k] = v
            if any(k in restart_keys for k in updates):
                self.restart_required = True

        new_pw = str(body.get("new_oauth_password") or "")
        if new_pw:
            update_env_password(new_pw, rotate_jwt=True)
            self.restart_required = True

        new_pin = str(body.get("new_admin_pin") or "")
        if new_pin:
            update_admin_pin(new_pin)
            self.restart_required = True

        # Live-apply step limits right away
        cfg = GatewayConfig.from_env(reload_dotenv=True)
        self.plugin_manager.soft_step_warning = cfg.soft_step_warning
        self.plugin_manager.max_batch_steps = cfg.max_batch_steps
        self.plugin_manager.idle_timeout_seconds = cfg.idle_timeout

        return {"status": "saved", "restart_required": self.restart_required, "state": self._state_payload()}

    def _persist_current_registry(self) -> None:
        cfg = GatewayConfig.from_env(reload_dotenv=False)
        specs = list(self.plugin_manager.registry.values())
        save_plugin_manifest(specs, cfg.apps_config_path)

    async def handle_http(self, scope: Scope, receive: Receive, send: Send) -> bool:
        path: str = scope.get("path", "")
        if path != "/ui" and not path.startswith("/ui/") and not path.startswith("/api/ui/"):
            return False

        if not _is_direct_loopback(scope):
            await _send_json(send, 403, {"error": "Forbidden: Settings UI is strictly restricted to direct loopback access."})
            return True

        if not _is_loopback_origin(scope):
            await _send_json(send, 403, {"error": "Forbidden: Non-loopback Origin rejected."})
            return True

        method: str = scope.get("method", "GET").upper()

        if path in ("/ui", "/ui/") and method == "GET":
            if not UI_HTML_PATH.exists():
                await _send_bytes(send, 404, b"UI file not found.", "text/plain; charset=utf-8")
                return True
            await _send_bytes(send, 200, UI_HTML_PATH.read_bytes(), "text/html; charset=utf-8")
            return True

        if not self._authorized_api(scope):
            await _send_json(send, 401, {"error": "Unauthorized: missing or invalid X-Coop-Local-Key."})
            return True

        try:
            if path == "/api/ui/state" and method == "GET":
                await _send_json(send, 200, self._state_payload())
                return True

            if path == "/api/ui/config" and method == "POST":
                body = await _read_json(receive)
                await _send_json(send, 200, self._save_config(body))
                return True

            if path == "/api/ui/discover" and method == "POST":
                body = await _read_json(receive)
                folder_str = str(body.get("scan_folder") or "").strip()
                scan_folder = Path(folder_str) if folder_str else None
                res = discover_local_mcps(scan_folder=scan_folder, mask_secrets=True)
                await _send_json(send, 200, res)
                return True

            if path == "/api/ui/plugins/import" and method == "POST":
                body = await _read_json(receive)
                items = body.get("items") or []
                if not isinstance(items, list):
                    raise ValueError("items must be a list")
                imported: list[str] = []
                for item in items:
                    if not isinstance(item, dict) or not item.get("key"):
                        continue
                    key = str(item["key"]).strip().lower()
                    source = str(item.get("source") or "")
                    origin_file = str(item.get("origin_file") or "")
                    unmasked = resolve_unmasked_candidate(key, source, origin_file)
                    spec = unmasked or parse_plugin_entry(item)
                    if "require_admin_unlock" in item:
                        spec = AppPluginSpec(
                            **{
                                **spec.__dict__,
                                "require_admin_unlock": bool(item["require_admin_unlock"]),
                                "enabled": bool(item.get("enabled", True)),
                            }
                        )
                    self.plugin_manager.registry[spec.key] = spec
                    imported.append(spec.key)
                self._persist_current_registry()
                await _send_json(send, 200, {"status": "imported", "keys": imported, "state": self._state_payload()})
                return True

            if path == "/api/ui/plugins/add" and method == "POST":
                body = await _read_json(receive)
                if not body.get("key"):
                    raise ValueError("Plugin 'key' is required.")
                spec = parse_plugin_entry({**body, "source": body.get("source") or "manual"})
                self.plugin_manager.registry[spec.key] = spec
                self._persist_current_registry()
                await _send_json(send, 200, {"status": "saved", "key": spec.key, "state": self._state_payload()})
                return True

            if path == "/api/ui/plugins/toggle" and method == "POST":
                body = await _read_json(receive)
                key = str(body.get("key") or "").strip().lower()
                if key not in self.plugin_manager.registry:
                    raise ValueError(f"Unknown plugin key: {key}")
                cur = self.plugin_manager.registry[key]
                new_enabled = bool(body["enabled"]) if "enabled" in body else cur.enabled
                new_admin = bool(body["require_admin_unlock"]) if "require_admin_unlock" in body else cur.require_admin_unlock
                new_source = "manual" if (cur.source == "builtin" and (not new_enabled or new_admin)) else cur.source
                self.plugin_manager.registry[key] = AppPluginSpec(
                    **{
                        **cur.__dict__,
                        "enabled": new_enabled,
                        "require_admin_unlock": new_admin,
                        "source": new_source,
                    }
                )
                if not new_enabled:
                    await self.plugin_manager.close_app(key)
                self._persist_current_registry()
                await _send_json(send, 200, {"status": "updated", "key": key, "state": self._state_payload()})
                return True

            if path == "/api/ui/plugins/delete" and method == "POST":
                body = await _read_json(receive)
                key = str(body.get("key") or "").strip().lower()
                if key == "blender":
                    raise ValueError("Built-in Blender bridge cannot be deleted; disable it instead.")
                if key in self.plugin_manager.registry:
                    await self.plugin_manager.close_app(key)
                    self.plugin_manager.registry.pop(key, None)
                    self._persist_current_registry()
                await _send_json(send, 200, {"status": "deleted", "key": key, "state": self._state_payload()})
                return True

            if path == "/api/ui/plugins/tools" and method == "POST":
                body = await _read_json(receive)
                key = str(body.get("key") or "").strip()
                res = await self.plugin_manager.list_tools(key)
                await _send_json(send, 200, res)
                return True

            if path == "/api/ui/plugins/stop" and method == "POST":
                body = await _read_json(receive)
                key = str(body.get("key") or "").strip()
                res = await self.plugin_manager.close_app(key)
                await _send_json(send, 200, {"result": res, "state": self._state_payload()})
                return True

            if path == "/api/ui/admin/revoke" and method == "POST":
                res = self.admin_manager.revoke_all()
                await _send_json(send, 200, {"result": res, "state": self._state_payload()})
                return True

            await _send_json(send, 404, {"error": f"Unknown UI API route: {path}"})
            return True
        except Exception as exc:
            logger.exception("Local UI API error on %s", path)
            await _send_json(send, 400, {"error": str(exc)})
            return True
