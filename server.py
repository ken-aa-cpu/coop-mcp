"""CoopMCP: Sandboxed HTTPS MCP Gateway & Lazy Stdio Plugin Router."""

from __future__ import annotations

import argparse
from collections import deque
from contextlib import asynccontextmanager
import hmac
import json
import logging
import os
import secrets
import time
from typing import Any
from urllib.parse import parse_qs

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ImageContent, TextContent, ToolAnnotations
from starlette.types import ASGIApp, Receive, Scope, Send
import uvicorn

from admin_privilege import AdminPrivilegeManager
from config import GatewayConfig, SKILL_PATH
from files_tools import (
    PathPolicy,
    edit_output_file,
    get_file_info,
    list_directory,
    make_output_dir,
    manage_output_path,
    preview_image_file,
    publish_to_cloud,
    read_text_file,
    search_files,
    search_text_in_files,
    write_output_file,
)
from oauth_provider import OAuth21Provider, hash_password
from plugin_router import PluginSessionManager
from ui_server import LocalUiController

logger = logging.getLogger(__name__)

CFG = GatewayConfig.from_env()
POLICY = PathPolicy.from_env(CFG)
PLUGIN_MANAGER = PluginSessionManager(
    POLICY,
    idle_timeout_seconds=CFG.idle_timeout,
    soft_step_warning=CFG.soft_step_warning,
    max_batch_steps=CFG.max_batch_steps,
)

_ADMIN_PIN_HASH = CFG.admin_pin_hash or (hash_password(CFG.admin_pin_plain) if CFG.admin_pin_plain else "")
_ADMIN_JWT_SECRET = CFG.oauth_jwt_secret or CFG.secret_key or secrets.token_urlsafe(36)
ADMIN_MANAGER = AdminPrivilegeManager(
    pin_hash=_ADMIN_PIN_HASH,
    jwt_secret=_ADMIN_JWT_SECRET,
    ttl_seconds=CFG.admin_token_ttl,
)

READ_ONLY_ANNOTATIONS = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False)
WRITE_ANNOTATIONS = ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False)

CORS_HEADERS: list[tuple[bytes, bytes]] = [
    (b"access-control-allow-origin", b"*"),
    (b"access-control-allow-methods", b"GET, POST, DELETE, HEAD, OPTIONS"),
    (b"access-control-allow-headers", b"content-type, mcp-session-id, mcp-protocol-version, accept, authorization, x-api-key"),
]


def _get_secret_key() -> str:
    key = os.getenv("MCP_SECRET_KEY", "").strip()
    if not key:
        key = f"coop_key_{secrets.token_urlsafe(24)}"
        os.environ["MCP_SECRET_KEY"] = key
        logger.warning("MCP_SECRET_KEY was empty; generated temporary key for this session.")
    return key


def _is_authorized(scope: Scope, secret_key: str) -> bool:
    if not secret_key:
        return True

    query_str = scope.get("query_string", b"").decode("utf-8", errors="ignore")
    params = parse_qs(query_str)
    for param_name in ("key", "token"):
        vals = params.get(param_name)
        if vals and hmac.compare_digest(vals[0], secret_key):
            return True

    for name, val in scope.get("headers", []):
        name_str = name.decode("latin-1").lower()
        val_str = val.decode("latin-1")
        if name_str == "x-api-key" and hmac.compare_digest(val_str.strip(), secret_key):
            return True
        if name_str == "authorization" and val_str.startswith("Bearer "):
            if hmac.compare_digest(val_str[7:].strip(), secret_key):
                return True

    return False


def _is_direct_loopback(scope: Scope) -> bool:
    """True only for unproxied localhost requests (never forwarded from a public tunnel/proxy)."""
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


def _extract_bearer(scope: Scope) -> str:
    for name, val in scope.get("headers", []):
        if name.decode("latin-1").lower() == "authorization":
            val_str = val.decode("latin-1").strip()
            if val_str.lower().startswith("bearer "):
                return val_str[7:].strip()
    return ""


def _get_oauth_provider(public_url: str, cfg: GatewayConfig | None = None) -> tuple[bool, OAuth21Provider | None]:
    cfg = cfg or GatewayConfig.from_env(reload_dotenv=False)
    if not cfg.require_oauth:
        return False, None

    password_hash = cfg.oauth_password_hash
    if not password_hash and cfg.oauth_password_plain:
        password_hash = hash_password(cfg.oauth_password_plain)

    if not (cfg.oauth_client_secret and cfg.oauth_jwt_secret and password_hash):
        logger.warning(
            "COOP_REQUIRE_OAUTH=true but OAuth credentials/password are not set yet. "
            "/mcp will remain locked (503) until configured via local Settings UI or set_oauth_password.py."
        )
        return True, None

    provider = OAuth21Provider(
        public_url=public_url,
        client_id=cfg.oauth_client_id,
        client_secret=cfg.oauth_client_secret,
        password_hash=password_hash,
        jwt_secret=cfg.oauth_jwt_secret,
        redirect_mode=cfg.oauth_redirect_mode,
        extra_redirect_hosts=cfg.oauth_extra_redirect_hosts,
        read_roots_summary=", ".join(str(r) for r in POLICY.read_roots),
        write_root_summary=str(POLICY.write_root),
    )
    return True, provider


class SecureCompatLayer:
    """ASGI wrapper handling remote MCP probes, CORS, OAuth 2.1 + PKCE, and loopback health auth."""

    def __init__(
        self,
        inner: ASGIApp,
        public_url: str,
        secret_key: str,
        oauth: OAuth21Provider | None = None,
        require_oauth: bool = False,
        ui_controller: LocalUiController | None = None,
    ) -> None:
        self.inner = inner
        self.public_url = public_url.rstrip("/")
        self.secret_key = secret_key
        self.oauth = oauth
        self.require_oauth = require_oauth
        self.ui_controller = ui_controller or LocalUiController(
            secret_key=secret_key,
            plugin_manager=PLUGIN_MANAGER,
            admin_manager=ADMIN_MANAGER,
        )
        self.well_known_body = json.dumps({
            "resource": f"{self.public_url}/mcp",
            "authorization_servers": [self.public_url] if oauth else [],
            "bearer_methods_supported": ["header"] if oauth else [],
        }).encode("utf-8")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.inner(scope, receive, send)
            return

        path: str = scope.get("path", "")
        method: str = scope.get("method", "GET").upper()

        if method == "OPTIONS":
            await self._send_bytes(send, 204, b"", CORS_HEADERS)
            return

        if await self.ui_controller.handle_http(scope, receive, send):
            return

        if self.oauth is not None and await self.oauth.handle_http(scope, receive, send):
            return

        if path.startswith("/.well-known/oauth-protected-resource"):
            headers = [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(self.well_known_body)).encode("ascii")),
            ] + CORS_HEADERS
            await self._send_bytes(send, 200, self.well_known_body, headers)
            return

        if self.require_oauth:
            local_control_ok = (
                path in ("/health", "/admin/revoke")
                and _is_direct_loopback(scope)
                and _is_authorized(scope, self.secret_key)
            )
            if self.oauth is None and not local_control_ok:
                err_body = (
                    b'{"jsonrpc":"2.0","error":{"code":-32000,'
                    b'"message":"Service setup incomplete: configure OAuth password in local Settings UI."}}'
                )
                headers = [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(err_body)).encode("ascii")),
                ] + CORS_HEADERS
                await self._send_bytes(send, 503, err_body, headers)
                return
            bearer = _extract_bearer(scope)
            oauth_ok = bool(self.oauth is not None and bearer and self.oauth.verify_bearer_token(bearer))
            if not (local_control_ok or oauth_ok):
                err_body = b'{"jsonrpc":"2.0","error":{"code":-32000,"message":"Unauthorized: OAuth Bearer token required."}}'
                www_auth = f'Bearer resource_metadata="{self.public_url}/.well-known/oauth-protected-resource"'.encode("ascii")
                headers = [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(err_body)).encode("ascii")),
                    (b"www-authenticate", www_auth),
                ] + CORS_HEADERS
                await self._send_bytes(send, 401, err_body, headers)
                return
        elif not _is_authorized(scope, self.secret_key):
            err_body = b'{"jsonrpc":"2.0","error":{"code":-32000,"message":"Unauthorized: Invalid or missing security key."}}'
            headers = [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(err_body)).encode("ascii")),
            ] + CORS_HEADERS
            await self._send_bytes(send, 401, err_body, headers)
            return

        if method in ("HEAD", "DELETE") and path in ("/mcp", "/"):
            await self._send_bytes(send, 200, b"", [(b"content-length", b"0")] + CORS_HEADERS)
            return

        if path == "/admin/revoke" and method == "POST":
            if not (_is_direct_loopback(scope) and _is_authorized(scope, self.secret_key)):
                err = b'{"error":"Forbidden: loopback admin key required"}'
                await self._send_bytes(send, 403, err, [(b"content-type", b"application/json")] + CORS_HEADERS)
                return
            payload = json.dumps(ADMIN_MANAGER.revoke_all(), ensure_ascii=False).encode("utf-8")
            headers = [
                (b"content-type", b"application/json; charset=utf-8"),
                (b"content-length", str(len(payload)).encode("ascii")),
            ] + CORS_HEADERS
            await self._send_bytes(send, 200, payload, headers)
            return

        if path == "/health":
            payload = json.dumps({
                "status": "ok",
                "service": "coop-mcp-gateway",
                "read_roots": [str(r) for r in POLICY.read_roots],
                "write_root": str(POLICY.write_root),
                "cloud_sync_dir": str(POLICY.cloud_sync_dir),
                "mirror_dir": str(POLICY.gdrive_mirror_dir) if POLICY.gdrive_mirror_dir else None,
                "apps": [a["name"] for a in PLUGIN_MANAGER.list_apps()["apps"] if a["running"]],
                "admin": ADMIN_MANAGER.status(),
            }, ensure_ascii=False).encode("utf-8")
            headers = [
                (b"content-type", b"application/json; charset=utf-8"),
                (b"content-length", str(len(payload)).encode("ascii")),
            ] + CORS_HEADERS
            await self._send_bytes(send, 200, payload, headers)
            return

        await self.inner(scope, receive, send)

    @staticmethod
    async def _send_bytes(
        send: Send, status: int, body: bytes, headers: list[tuple[bytes, bytes]]
    ) -> None:
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body, "more_body": False})


@asynccontextmanager
async def _lifespan(_server: MCPServer):
    PLUGIN_MANAGER.start_reaper()
    try:
        yield
    finally:
        await PLUGIN_MANAGER.shutdown_all()


mcp_server = MCPServer(
    name="coop-mcp",
    title="CoopMCP Sandboxed PC & Plugin Gateway",
    instructions=(
        "Local Windows sandboxed MCP gateway and lazy stdio plugin router.\n"
        "- Call coop_get_skill() (or read resource coop://skill) at the start of tasks to inspect sandbox and delivery rules.\n"
        f"- Default sandbox: readable {', '.join(str(r) for r in POLICY.read_roots)}; writable {POLICY.write_root}; CloudSync {POLICY.cloud_sync_dir}.\n"
        "- Full-PC / terminal access: Ask user for the admin PIN if needed, call coop_unlock_system(pin) to get a 1-hour admin_token, toggle via coop_set_sandbox(open=True/False, admin_token), and run shell commands via coop_run_command.\n"
        "- Use plugin_list_apps -> plugin_list_tools(app) -> plugin_call_tool or plugin_batch_call(app, calls) to operate local stdio MCP plugins and Blender.\n"
        "- Visual tools attach compressed PNG ImageContent previews; use coop_publish_to_cloud to stage deliverables in CloudSync."
    ),
    lifespan=_lifespan,
)

_EXPECTED_ERRORS = (
    PermissionError,
    FileNotFoundError,
    FileExistsError,
    ValueError,
    IsADirectoryError,
    NotADirectoryError,
    json.JSONDecodeError,
)


def _json_text(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


def _run_sync(fn, *args, **kwargs) -> str:
    try:
        return _json_text(fn(*args, **kwargs))
    except _EXPECTED_ERRORS as exc:
        raise ToolError(str(exc)) from exc


# ── Skill, Admin Elevation & Terminal Tools ───────────────────────────────────


@mcp_server.resource("coop://skill", mime_type="text/markdown")
def coop_skill_resource() -> str:
    """Host environment, sandbox rules, CloudSync, and plugin routing playbook."""
    if SKILL_PATH.exists():
        return SKILL_PATH.read_text(encoding="utf-8")
    return "COOP_SKILL.md not found."


@mcp_server.tool(annotations=READ_ONLY_ANNOTATIONS)
def coop_get_skill(section: str = "") -> str:
    """Read the CoopMCP host skill/playbook (sandbox rules, CloudSync, and plugin guidelines)."""
    if not SKILL_PATH.exists():
        raise ToolError("COOP_SKILL.md not found.")
    text = SKILL_PATH.read_text(encoding="utf-8")
    sec = (section or "").strip().lower()
    if sec:
        chunks = text.split("\n## ")
        matched = [chunks[0]] + [f"## {c}" for c in chunks[1:] if sec in c.lower()]
        if len(matched) > 1:
            return "\n\n".join(matched)
    return text


@mcp_server.tool(annotations=WRITE_ANNOTATIONS)
def coop_unlock_system(pin: str) -> str:
    """Verify the user-provided admin PIN to open full-PC access and issue a 1-hour non-renewable admin_token."""
    return _run_sync(ADMIN_MANAGER.unlock_with_pin, pin)


@mcp_server.tool(annotations=WRITE_ANNOTATIONS)
def coop_set_sandbox(open: bool, admin_token: str = "") -> str:
    """Lock back into safe sandbox (open=False) anytime, or re-open full-PC access (open=True) using an unexpired 1h admin_token."""
    return _run_sync(ADMIN_MANAGER.set_sandbox, open, admin_token)


@mcp_server.tool(annotations=WRITE_ANNOTATIONS)
async def coop_run_command(
    command: str,
    cwd: str = "",
    timeout_seconds: int = 30,
    shell: str = "powershell",
    admin_token: str = "",
) -> str:
    """Run a PowerShell or CMD command on Windows (requires unlocked sandbox or valid 1h admin_token)."""
    try:
        res = await ADMIN_MANAGER.run_command(
            command,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            shell=shell,
            admin_token=admin_token,
        )
        return _json_text(res)
    except _EXPECTED_ERRORS as exc:
        raise ToolError(str(exc)) from exc


# ── Sandboxed Filesystem & CloudSync Tools ────────────────────────────────────


@mcp_server.tool(annotations=READ_ONLY_ANNOTATIONS)
def coop_list_dir(path: str = "", recursive: bool = False, max_entries: int = 200) -> str:
    """List files and folders under configured read roots (or anywhere when sandbox is unlocked)."""
    return _run_sync(
        list_directory,
        POLICY,
        path=path,
        recursive=recursive,
        max_entries=max_entries,
        unrestricted=ADMIN_MANAGER.is_unrestricted(),
    )


@mcp_server.tool(annotations=READ_ONLY_ANNOTATIONS)
def coop_search_files(pattern: str, folder: str = "", max_results: int = 100) -> str:
    """Search files under configured read roots (or anywhere when unlocked) by glob or name substring."""
    return _run_sync(
        search_files,
        POLICY,
        pattern=pattern,
        folder=folder,
        max_results=max_results,
        unrestricted=ADMIN_MANAGER.is_unrestricted(),
    )


@mcp_server.tool(annotations=READ_ONLY_ANNOTATIONS)
def coop_search_text(
    query: str,
    folder: str = "",
    file_glob: str = "*",
    case_sensitive: bool = False,
    regex: bool = False,
    max_matches: int = 80,
) -> str:
    """Search inside text/code/markdown/json file contents under allowed read roots (or anywhere when unlocked)."""
    return _run_sync(
        search_text_in_files,
        POLICY,
        query=query,
        folder=folder,
        file_glob=file_glob,
        case_sensitive=case_sensitive,
        regex=regex,
        max_matches=max_matches,
        unrestricted=ADMIN_MANAGER.is_unrestricted(),
    )


@mcp_server.tool(annotations=READ_ONLY_ANNOTATIONS)
def coop_read_text_file(path: str, start_line: int = 1, max_lines: int = 200) -> str:
    """Read a text/markdown/json/csv/code file under allowed read roots (or anywhere when unlocked) with line numbers."""
    return _run_sync(
        read_text_file,
        POLICY,
        path=path,
        start_line=start_line,
        max_lines=max_lines,
        unrestricted=ADMIN_MANAGER.is_unrestricted(),
    )


@mcp_server.tool(annotations=READ_ONLY_ANNOTATIONS)
def coop_file_info(path: str) -> str:
    """Get metadata (size, modified time, writable flag) and compatible plugins for a file."""
    return _run_sync(get_file_info, POLICY, path=path, unrestricted=ADMIN_MANAGER.is_unrestricted())


@mcp_server.tool(annotations=READ_ONLY_ANNOTATIONS)
def coop_preview_image(path: str, max_side: int = 1024) -> list[TextContent | ImageContent]:
    """Preview an image (.png/.jpg/.webp/.bmp) under allowed read roots as compressed PNG ImageContent."""
    try:
        info = preview_image_file(POLICY, path=path, max_side=max_side, unrestricted=ADMIN_MANAGER.is_unrestricted())
        b64 = info.pop("data_base64")
        mime = info.pop("mime_type")
        return [
            TextContent(type="text", text=_json_text(info)),
            ImageContent(type="image", data=b64, mimeType=mime),
        ]
    except _EXPECTED_ERRORS as exc:
        raise ToolError(str(exc)) from exc


@mcp_server.tool(annotations=WRITE_ANNOTATIONS)
def coop_write_output_file(path: str, content: str, overwrite: bool = False) -> str:
    """Write a text/code/markdown/json file inside COOP_WRITE_ROOT (or anywhere when sandbox is unlocked)."""
    return _run_sync(
        write_output_file,
        POLICY,
        path=path,
        content=content,
        overwrite=overwrite,
        unrestricted=ADMIN_MANAGER.is_unrestricted(),
    )


@mcp_server.tool(annotations=WRITE_ANNOTATIONS)
def coop_edit_output_file(
    path: str,
    target: str,
    replacement: str,
    replace_all: bool = False,
) -> str:
    """Partially edit an existing text file inside COOP_WRITE_ROOT (or anywhere when sandbox is unlocked)."""
    return _run_sync(
        edit_output_file,
        POLICY,
        path=path,
        target=target,
        replacement=replacement,
        replace_all=replace_all,
        unrestricted=ADMIN_MANAGER.is_unrestricted(),
    )


@mcp_server.tool(annotations=WRITE_ANNOTATIONS)
def coop_manage_output(
    action: str,
    path: str,
    destination: str = "",
    overwrite: bool = False,
) -> str:
    """Organize files within COOP_WRITE_ROOT (or anywhere when unlocked): action='move'|'rename'|'copy'|'delete'."""
    return _run_sync(
        manage_output_path,
        POLICY,
        action=action,
        path=path,
        destination=destination,
        overwrite=overwrite,
        unrestricted=ADMIN_MANAGER.is_unrestricted(),
    )


@mcp_server.tool(annotations=WRITE_ANNOTATIONS)
def coop_make_output_dir(path: str) -> str:
    """Create a folder inside COOP_WRITE_ROOT (or anywhere when sandbox is unlocked)."""
    return _run_sync(make_output_dir, POLICY, path=path, unrestricted=ADMIN_MANAGER.is_unrestricted())


@mcp_server.tool(annotations=WRITE_ANNOTATIONS)
def coop_publish_to_cloud(
    local_path: str,
    subfolder: str = "",
    overwrite: bool = True,
    timeout_seconds: float = 15.0,
) -> str:
    """Publish a local file into CloudSync (and optional mirror directory) and verify file lock release."""
    return _run_sync(
        publish_to_cloud,
        POLICY,
        local_path=local_path,
        subfolder=subfolder,
        overwrite=overwrite,
        timeout_seconds=timeout_seconds,
        unrestricted=ADMIN_MANAGER.is_unrestricted(),
    )


# ── Lazy Stdio Plugin Router Tools ────────────────────────────────────────────


@mcp_server.tool(annotations=READ_ONLY_ANNOTATIONS)
def plugin_list_apps() -> str:
    """List configured stdio MCP plugins and Blender bridge, their supported formats, and active session status."""
    return _run_sync(PLUGIN_MANAGER.list_apps)


@mcp_server.tool(annotations=READ_ONLY_ANNOTATIONS)
async def plugin_list_tools(app: str, query: str = "") -> str:
    """Start (if needed) a local stdio MCP plugin and list its available tools and parameter schemas."""
    try:
        return _json_text(await PLUGIN_MANAGER.list_tools(app, query=query))
    except _EXPECTED_ERRORS as exc:
        raise ToolError(str(exc)) from exc


class _ConsumptionMonitor:
    """Sliding-window tracker emitting non-blocking English advisories during high-frequency tool loops."""

    def __init__(self, window_seconds: float = 180.0, warn_calls: int = 18) -> None:
        self.window_seconds = window_seconds
        self.warn_calls = warn_calls
        self._events: deque[tuple[float, int]] = deque()

    def record(self, image_count: int = 0) -> str | None:
        now = time.monotonic()
        self._events.append((now, image_count))
        cutoff = now - self.window_seconds
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()
        total_calls = len(self._events)
        total_imgs = sum(ev[1] for ev in self._events)
        if total_calls >= self.warn_calls or total_imgs >= 8:
            return (
                f"Advisory: {total_calls} plugin tool calls ({total_imgs} images) occurred in the last "
                f"{int(self.window_seconds)}s. Consider consolidating steps with plugin_batch_call "
                "or summarizing progress for the user."
            )
        return None


_CONSUMPTION = _ConsumptionMonitor()


def _format_plugin_contents(result: dict[str, Any]) -> list[TextContent | ImageContent]:
    images = result.pop("_images", [])
    freq_advisory = _CONSUMPTION.record(image_count=len(images))
    if freq_advisory and "advisory" not in result:
        result["advisory"] = freq_advisory
    contents: list[TextContent | ImageContent] = [
        TextContent(type="text", text=_json_text(result)),
    ]
    for img in images:
        contents.append(
            ImageContent(
                type="image",
                data=img["data_base64"],
                mimeType=img["mime_type"],
            )
        )
    return contents


@mcp_server.tool(annotations=WRITE_ANNOTATIONS)
async def plugin_call_tool(
    app: str,
    tool_name: str,
    arguments: dict[str, Any] | str | None = None,
    include_image: bool = True,
    max_image_side: int = 1024,
) -> list[TextContent | ImageContent]:
    """Execute a tool on a local stdio MCP plugin or Blender (returns text JSON plus compressed ImageContent previews)."""
    try:
        if arguments is None:
            parsed_args: dict[str, Any] = {}
        elif isinstance(arguments, str):
            parsed_args = json.loads(arguments) if arguments.strip() else {}
        else:
            parsed_args = dict(arguments)

        result = await PLUGIN_MANAGER.call_tool(
            app,
            tool_name,
            parsed_args,
            include_image=include_image,
            max_image_side=max_image_side,
            unrestricted=ADMIN_MANAGER.is_unrestricted(),
        )
        return _format_plugin_contents(result)
    except _EXPECTED_ERRORS as exc:
        raise ToolError(str(exc)) from exc


@mcp_server.tool(annotations=WRITE_ANNOTATIONS)
async def plugin_batch_call(
    app: str,
    calls: list[dict[str, Any]],
    stop_on_error: bool = True,
    include_final_image: bool = True,
    max_image_side: int = 1024,
) -> list[TextContent | ImageContent]:
    """Run multiple sequential tool steps on one warm plugin or Blender in a single round-trip (soft warning above COOP_SOFT_STEP_WARNING)."""
    try:
        result = await PLUGIN_MANAGER.batch_call(
            app,
            calls,
            stop_on_error=stop_on_error,
            include_final_image=include_final_image,
            max_image_side=max_image_side,
            unrestricted=ADMIN_MANAGER.is_unrestricted(),
        )
        return _format_plugin_contents(result)
    except _EXPECTED_ERRORS as exc:
        raise ToolError(str(exc)) from exc


@mcp_server.tool(annotations=WRITE_ANNOTATIONS)
async def plugin_close_app(app: str = "") -> str:
    """Close a warm plugin worker (leave app blank to close all running plugin workers)."""
    try:
        return _json_text(await PLUGIN_MANAGER.close_app(app))
    except _EXPECTED_ERRORS as exc:
        raise ToolError(str(exc)) from exc


# ── Entrypoint ────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(description="CoopMCP HTTP Gateway")
    parser.add_argument("--port", type=int, default=CFG.port)
    parser.add_argument("--host", default=CFG.host)
    parser.add_argument("--public-url", default=CFG.public_url)
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    secret_key = _get_secret_key()
    require_oauth, oauth_provider = _get_oauth_provider(args.public_url, CFG)
    starlette_app = mcp_server.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,
        host=args.host,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    app = SecureCompatLayer(
        starlette_app,
        public_url=args.public_url,
        secret_key=secret_key,
        oauth=oauth_provider,
        require_oauth=require_oauth,
    )

    clean_public = args.public_url.rstrip("/")
    mcp_public = f"{clean_public}/mcp" if require_oauth else f"{clean_public}/mcp?key={secret_key}"
    print("\n[CoopMCP HTTP Gateway]")
    print(f"  Read roots : {', '.join(str(r) for r in POLICY.read_roots)}")
    print(f"  Write root : {POLICY.write_root}")
    print(f"  CloudSync  : {POLICY.cloud_sync_dir}")
    if POLICY.gdrive_mirror_dir:
        print(f"  MirrorDir  : {POLICY.gdrive_mirror_dir}")
    print(f"  Auth Mode  : {'OAuth 2.1 + PKCE' if require_oauth else 'Static Key'}")
    if oauth_provider:
        print(f"  Client ID  : {oauth_provider.static_client_id}")
    print(f"  Local URL  : http://{args.host}:{args.port}/mcp")
    print(f"  Settings UI: http://{args.host}:{args.port}/ui")
    print(f"  Public URL : {mcp_public}\n")

    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level.lower())


if __name__ == "__main__":
    main()
