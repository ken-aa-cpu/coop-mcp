"""Lazy-loaded stdio / HTTP / SSE MCP plugin router & session manager."""

from __future__ import annotations

import asyncio
import base64
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
import json
import logging
import os
from pathlib import Path
import time
from typing import Any

import httpx2 as httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.types import CallToolResult, EmbeddedResource, ImageContent, TextContent

from app_registry import AppPluginSpec, load_plugin_registry, resolve_app_key
from blender_bridge import BLENDER_TOOLS, BlenderBridgeManager
from config import APP_DIR
from files_tools import PathPolicy, compress_image_to_png_base64
from media_timeline import summarize_filmcraft_sequence, summarize_soundcraft_session

logger = logging.getLogger(__name__)

# Parameter names that indicate writing/outputting to disk
WRITE_PATH_KEYS = {
    "out",
    "output",
    "output_path",
    "outputpath",
    "output_file",
    "out_file",
    "outfile",
    "output_dir",
    "save",
    "save_as",
    "saveas",
    "export",
    "export_path",
    "dest",
    "destination",
    "target",
}

# Parameter names that indicate reading/opening from disk
READ_PATH_KEYS = {
    "path",
    "paths",
    "file",
    "file_path",
    "filepath",
    "in",
    "input",
    "input_path",
    "source",
    "media",
    "project",
    "workbook",
    "document",
    "template",
    "image",
    "audio",
    "video",
    "mesh",
}

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".bmp"}


@dataclass
class _PendingCall:
    kind: str  # "list_tools" | "call_tool"
    tool_name: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    include_image: bool = True
    max_image_side: int = 1024
    future: asyncio.Future[Any] = field(default_factory=lambda: asyncio.get_running_loop().create_future())


class _PluginWorker:
    """Owns a single MCP ClientSession (stdio, HTTP, or SSE) inside one dedicated asyncio task."""

    def __init__(self, spec: AppPluginSpec, policy: PathPolicy, *, unrestricted: bool = False) -> None:
        self.spec = spec
        self.policy = policy
        self.unrestricted = unrestricted
        self.queue: asyncio.Queue[_PendingCall | None] = asyncio.Queue()
        self.ready = asyncio.Event()
        self.init_error: BaseException | None = None
        self.last_used = time.monotonic()
        self.started_at = time.time()
        self.tools_cache: list[dict[str, Any]] | None = None
        self._task: asyncio.Task[None] | None = None

    @property
    def is_running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def start(self) -> None:
        if self.is_running:
            return
        self.ready.clear()
        self.init_error = None
        self._task = asyncio.create_task(self._run(), name=f"coop-mcp-{self.spec.key}")
        await self.ready.wait()
        if self.init_error is not None:
            raise self.init_error

    async def stop(self) -> None:
        if not self.is_running:
            return
        await self.queue.put(None)
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                self._task.cancel()
                try:
                    await self._task
                except asyncio.CancelledError:
                    pass
        self.tools_cache = None

    async def list_tools(self) -> list[dict[str, Any]]:
        await self.start()
        self.last_used = time.monotonic()
        if self.tools_cache is not None:
            return self.tools_cache
        call = _PendingCall(kind="list_tools")
        await self.queue.put(call)
        tools = await call.future
        self.tools_cache = tools
        return tools

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        include_image: bool = True,
        max_image_side: int = 1024,
    ) -> dict[str, Any]:
        await self.start()
        self.last_used = time.monotonic()
        call = _PendingCall(
            kind="call_tool",
            tool_name=tool_name,
            arguments=arguments,
            include_image=include_image,
            max_image_side=max_image_side,
        )
        await self.queue.put(call)
        return await call.future

    @asynccontextmanager
    async def _open_transport(self):
        if self.spec.transport == "http":
            headers = self.spec.headers_dict()
            async with httpx.AsyncClient(headers=headers) as client:
                async with streamable_http_client(self.spec.url, http_client=client) as streams:
                    yield streams[0], streams[1]
            return

        if self.spec.transport == "sse":
            async with sse_client(self.spec.url, headers=self.spec.headers_dict() or None) as streams:
                yield streams[0], streams[1]
            return

        cmd = self.spec.build_command(
            list(self.policy.read_roots),
            self.policy.write_root,
            unrestricted=self.unrestricted,
        )
        work_cwd = self.spec.cwd or str(APP_DIR)
        env = None
        extra_env = self.spec.env_dict()
        if extra_env:
            env = {**os.environ, **extra_env}
        params = StdioServerParameters(
            command=cmd[0],
            args=cmd[1:],
            cwd=work_cwd,
            env=env,
        )
        logger.info("Starting %s MCP stdio: %s", self.spec.display_name, " ".join(cmd))
        async with stdio_client(params) as (read_stream, write_stream):
            yield read_stream, write_stream

    async def _run(self) -> None:
        try:
            async with self._open_transport() as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    self.ready.set()

                    while True:
                        item = await self.queue.get()
                        if item is None:
                            break
                        try:
                            if item.kind == "list_tools":
                                resp = await session.list_tools()
                                tools_data = [
                                    {
                                        "name": t.name,
                                        "description": t.description or "",
                                        "inputSchema": getattr(t, "input_schema", getattr(t, "inputSchema", {})),
                                    }
                                    for t in resp.tools
                                ]
                                if not item.future.done():
                                    item.future.set_result(tools_data)
                            elif item.kind == "call_tool":
                                result = await session.call_tool(item.tool_name, item.arguments)
                                normalized = _normalize_call_result(
                                    self.spec,
                                    self.policy,
                                    item.tool_name,
                                    item.arguments,
                                    result,
                                    include_image=item.include_image,
                                    max_image_side=item.max_image_side,
                                )
                                if not item.future.done():
                                    item.future.set_result(normalized)
                        except BaseException as exc:
                            if not item.future.done():
                                item.future.set_exception(exc)
        except BaseException as exc:
            logger.exception("Plugin MCP worker %s exited with error", self.spec.display_name)
            self.init_error = exc
            self.ready.set()
            while not self.queue.empty():
                pending = self.queue.get_nowait()
                if pending is not None and not pending.future.done():
                    pending.future.set_exception(exc)
        finally:
            logger.info("Stopped %s MCP worker", self.spec.display_name)


def _normalize_call_result(
    spec: AppPluginSpec,
    policy: PathPolicy,
    tool_name: str,
    arguments: dict[str, Any],
    result: CallToolResult,
    *,
    include_image: bool = True,
    max_image_side: int = 1024,
) -> dict[str, Any]:
    """Convert MCP CallToolResult into structured metadata + optional compressed PNG ImageContent list."""
    texts: list[str] = []
    saved_images: list[str] = []
    compressed_images: list[dict[str, Any]] = []
    other_items: list[str] = []

    for item in result.content:
        if isinstance(item, TextContent):
            texts.append(item.text)
        elif isinstance(item, ImageContent):
            raw_bytes = base64.b64decode(item.data)
            mime = getattr(item, "mime_type", getattr(item, "mimeType", "image/png"))
            saved_path = _save_preview_image(spec.key, tool_name, mime, raw_bytes, policy.write_root)
            saved_images.append(saved_path)

            if include_image:
                thumb = compress_image_to_png_base64(raw_bytes, max_side=max_image_side)
                compressed_images.append(thumb)
                texts.append(
                    f"[Visual preview attached ({thumb['width']}x{thumb['height']} PNG, "
                    f"{thumb['png_bytes']} bytes); full-res saved to: {saved_path}]"
                )
            else:
                texts.append(f"[Rendered image ({mime}) saved to: {saved_path}]")
        elif isinstance(item, EmbeddedResource):
            other_items.append(f"[EmbeddedResource: {getattr(item.resource, 'uri', 'unknown')}]")
        else:
            other_items.append(str(item))

    is_visual_tool = any(
        k in tool_name.lower() for k in ("render", "screenshot", "preview", "export_frame", "export")
    )
    if include_image and not compressed_images and is_visual_tool:
        _maybe_attach_image_from_text_or_args(texts, arguments, policy, max_image_side, compressed_images)

    raw_output = "\n".join(texts) if texts else ""
    structured = getattr(result, "structured_content", getattr(result, "structuredContent", None))
    is_err = bool(getattr(result, "is_error", getattr(result, "isError", False)))

    payload: dict[str, Any] = {
        "app": spec.display_name,
        "tool": tool_name,
        "isError": is_err,
        "output": raw_output,
    }
    if structured is not None:
        payload["structuredContent"] = structured
    if saved_images:
        payload["saved_images"] = saved_images
    if other_items:
        payload["other"] = other_items
    if not is_err:
        timeline_summary = _maybe_build_timeline_summary(spec.key, tool_name, raw_output, policy)
        if timeline_summary is not None:
            payload["timeline_summary"] = timeline_summary
    if compressed_images:
        payload["_images"] = compressed_images
    return payload


def _maybe_build_timeline_summary(
    app_key: str,
    tool_name: str,
    raw_output: str,
    policy: PathPolicy,
) -> dict[str, Any] | None:
    if not raw_output.strip():
        return None
    try:
        parsed = json.loads(raw_output)
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None
    if app_key == "soundcraft" and tool_name == "inspect_session":
        return summarize_soundcraft_session(parsed, policy=policy)
    if app_key == "filmcraft":
        if tool_name == "sequence_inspect":
            return summarize_filmcraft_sequence(parsed)
        if tool_name == "doc_inspect" and isinstance(parsed.get("sequence"), dict):
            return summarize_filmcraft_sequence(parsed["sequence"], project=parsed.get("project"))
    return None


def _maybe_attach_image_from_text_or_args(
    texts: list[str],
    arguments: dict[str, Any],
    policy: PathPolicy,
    max_image_side: int,
    out_images: list[dict[str, Any]],
) -> None:
    candidates: list[str] = []
    for k in ("path", "out", "output", "export_path"):
        v = arguments.get(k)
        if isinstance(v, str) and Path(v).suffix.lower() in IMAGE_EXTS:
            candidates.append(v)

    for txt in texts:
        try:
            parsed = json.loads(txt)
        except Exception:
            continue
        if isinstance(parsed, dict):
            if isinstance(parsed.get("dataBase64"), str):
                try:
                    raw = base64.b64decode(parsed["dataBase64"])
                    out_images.append(compress_image_to_png_base64(raw, max_side=max_image_side))
                    parsed["dataBase64"] = f"<omitted {len(raw)} bytes; attached as ImageContent>"
                    texts[:] = [json.dumps(parsed, ensure_ascii=False, indent=2)]
                    return
                except Exception:
                    pass
            p_val = parsed.get("path")
            if isinstance(p_val, str) and Path(p_val).suffix.lower() in IMAGE_EXTS:
                candidates.append(p_val)

    for cand in candidates:
        try:
            resolved = policy.resolve_read_path(cand)
            if resolved.exists() and resolved.is_file():
                thumb = compress_image_to_png_base64(resolved.read_bytes(), max_side=max_image_side)
                out_images.append(thumb)
                return
        except Exception:
            continue


def _save_preview_image(
    app_key: str,
    tool_name: str,
    mime: str,
    raw_bytes: bytes,
    write_root: Path,
) -> str:
    ext = "png"
    if "jpeg" in mime or "jpg" in mime:
        ext = "jpg"
    elif "webp" in mime:
        ext = "webp"

    preview_dir = write_root / "_previews"
    preview_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    safe_tool = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in tool_name)
    out_file = preview_dir / f"{app_key}_{safe_tool}_{ts}.{ext}"
    out_file.write_bytes(raw_bytes)
    return str(out_file)


class PluginSessionManager:
    """Manages lazy stdio/HTTP/SSE MCP plugin workers, path confinement, and idle cleanup."""

    def __init__(
        self,
        policy: PathPolicy,
        idle_timeout_seconds: int = 900,
        registry: dict[str, AppPluginSpec] | None = None,
        *,
        soft_step_warning: int = 25,
        max_batch_steps: int = 100,
    ) -> None:
        self.policy = policy
        self.idle_timeout_seconds = idle_timeout_seconds
        self.soft_step_warning = max(1, int(soft_step_warning))
        self.max_batch_steps = max(self.soft_step_warning, int(max_batch_steps))
        self.registry: dict[str, AppPluginSpec] = (
            dict(registry) if registry is not None else load_plugin_registry()
        )
        self._workers: dict[str, _PluginWorker] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._blender = BlenderBridgeManager()
        self._reaper_task: asyncio.Task[None] | None = None

    def reload_registry(self) -> dict[str, AppPluginSpec]:
        self.registry = load_plugin_registry()
        return self.registry

    def start_reaper(self) -> None:
        if self._reaper_task is None or self._reaper_task.done():
            self._reaper_task = asyncio.create_task(self._idle_reaper(), name="coop-idle-reaper")

    async def shutdown_all(self) -> None:
        if self._reaper_task is not None and not self._reaper_task.done():
            self._reaper_task.cancel()
            try:
                await self._reaper_task
            except asyncio.CancelledError:
                pass
        for worker in list(self._workers.values()):
            await worker.stop()
        await self._blender.stop_headless()

    async def _idle_reaper(self) -> None:
        while True:
            await asyncio.sleep(60)
            now = time.monotonic()
            for key, worker in list(self._workers.items()):
                if worker.is_running and (now - worker.last_used) > self.idle_timeout_seconds:
                    logger.info("Closing idle plugin worker: %s", key)
                    await worker.stop()
            if self._blender.has_headless_running and (now - self._blender.last_used) > self.idle_timeout_seconds:
                logger.info("Closing idle headless Blender worker")
                await self._blender.stop_headless()

    def _resolve_spec(self, app_name: str, *, require_enabled: bool = True) -> tuple[str, AppPluginSpec]:
        key = resolve_app_key(app_name, self.registry)
        if key is None:
            valid = ", ".join(spec.display_name for spec in self.registry.values())
            raise ValueError(f"Unknown plugin '{app_name}'. Available plugins: {valid}")
        spec = self.registry[key]
        if require_enabled and not spec.enabled:
            raise PermissionError(f"Plugin '{spec.display_name}' is currently disabled in Settings.")
        return key, spec

    def _check_plugin_access(self, spec: AppPluginSpec, *, unrestricted: bool) -> None:
        if not spec.enabled:
            raise PermissionError(f"Plugin '{spec.display_name}' is currently disabled in Settings.")
        if spec.require_admin_unlock and not unrestricted:
            raise PermissionError(
                f"Plugin '{spec.display_name}' requires Admin unlock (coop_unlock_system) before execution."
            )

    def _get_worker(self, app_name: str, *, require_enabled: bool = True) -> tuple[AppPluginSpec, _PluginWorker, asyncio.Lock]:
        key, spec = self._resolve_spec(app_name, require_enabled=require_enabled)
        if not spec.is_installed():
            target = spec.url if spec.transport in ("http", "sse") else spec.resolved_executable()
            raise FileNotFoundError(f"Target not found for {spec.display_name}: {target}")
        if key not in self._workers or self._workers[key].spec != spec:
            self._workers[key] = _PluginWorker(spec, self.policy)
            self._locks.setdefault(key, asyncio.Lock())
        return spec, self._workers[key], self._locks[key]

    async def _ensure_worker_mode(
        self, app_name: str, *, unrestricted: bool = False
    ) -> tuple[AppPluginSpec, _PluginWorker, asyncio.Lock]:
        spec, worker, lock = self._get_worker(app_name)
        self._check_plugin_access(spec, unrestricted=unrestricted)
        if worker.unrestricted != unrestricted:
            async with lock:
                if worker.is_running:
                    logger.info(
                        "Restarting %s worker to match sandbox mode (unrestricted=%s)",
                        spec.display_name,
                        unrestricted,
                    )
                    await worker.stop()
                worker.unrestricted = unrestricted
        return spec, worker, lock

    def list_apps(self) -> dict[str, Any]:
        apps_info = []
        for key, spec in self.registry.items():
            if key == "blender":
                running = self._blender.is_running()
            else:
                worker = self._workers.get(key)
                running = bool(worker and worker.is_running)
            apps_info.append({
                "key": key,
                "name": spec.display_name,
                "category": spec.category,
                "description": spec.description,
                "transport": spec.transport,
                "enabled": spec.enabled,
                "require_admin_unlock": spec.require_admin_unlock,
                "formats": list(spec.formats),
                "installed": spec.is_installed(),
                "running": running,
                "source": spec.source,
            })
        return {
            "read_roots": [str(r) for r in self.policy.read_roots],
            "write_output_root": str(self.policy.write_root),
            "cloud_sync_dir": str(self.policy.cloud_sync_dir),
            "apps": apps_info,
        }

    async def list_tools(self, app_name: str, query: str = "") -> dict[str, Any]:
        key, spec = self._resolve_spec(app_name)
        if key == "blender":
            q = (query or "").strip().lower()
            filtered = [
                t for t in BLENDER_TOOLS
                if not q or q in t["name"].lower() or q in t["description"].lower()
            ]
            return {
                "app": "Blender",
                "running": self._blender.is_running(),
                "auto_launch_headless": True,
                "read_roots": [str(r) for r in self.policy.read_roots],
                "write_output_root": str(self.policy.write_root),
                "total_tools": len(BLENDER_TOOLS),
                "returned_tools": len(filtered),
                "tools": filtered,
            }

        spec, worker, lock = self._get_worker(app_name)
        async with lock:
            tools = await worker.list_tools()

        q = (query or "").strip().lower()
        filtered = [
            t for t in tools
            if not q or q in t["name"].lower() or q in t["description"].lower()
        ]
        return {
            "app": spec.display_name,
            "transport": spec.transport,
            "require_admin_unlock": spec.require_admin_unlock,
            "read_roots": [str(r) for r in self.policy.read_roots],
            "write_output_root": str(self.policy.write_root),
            "total_tools": len(tools),
            "returned_tools": len(filtered),
            "tools": filtered,
        }

    async def call_tool(
        self,
        app_name: str,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        *,
        include_image: bool = True,
        max_image_side: int = 1024,
        unrestricted: bool = False,
    ) -> dict[str, Any]:
        key, spec = self._resolve_spec(app_name)
        self._check_plugin_access(spec, unrestricted=unrestricted)
        if key == "blender":
            args = dict(arguments or {})
            sanitized_args = self._enforce_path_arguments(spec, tool_name, args, unrestricted=unrestricted)
            return await self._blender.call_tool(
                tool_name,
                sanitized_args,
                self.policy,
                include_image=include_image,
                max_image_side=max_image_side,
                unrestricted=unrestricted,
            )

        spec, worker, lock = await self._ensure_worker_mode(app_name, unrestricted=unrestricted)
        args = dict(arguments or {})
        sanitized_args = self._enforce_path_arguments(spec, tool_name, args, unrestricted=unrestricted)
        async with lock:
            return await worker.call_tool(
                tool_name,
                sanitized_args,
                include_image=include_image,
                max_image_side=max_image_side,
            )

    async def batch_call(
        self,
        app_name: str,
        calls: list[dict[str, Any]],
        *,
        stop_on_error: bool = True,
        include_final_image: bool = True,
        max_image_side: int = 1024,
        unrestricted: bool = False,
    ) -> dict[str, Any]:
        """Execute sequential tool calls on one warm plugin or Blender, emitting soft consumption advisories."""
        if not calls:
            raise ValueError("calls must be a non-empty list of {tool_name, arguments} steps.")
        if len(calls) > self.max_batch_steps:
            raise ValueError(
                f"Maximum safety ceiling is {self.max_batch_steps} steps per plugin_batch_call "
                f"(received {len(calls)}). Split into smaller batches."
            )

        key, spec = self._resolve_spec(app_name)
        self._check_plugin_access(spec, unrestricted=unrestricted)

        step_results: list[dict[str, Any]] = []
        final_images: list[dict[str, Any]] = []
        last_idx = len(calls) - 1

        async def _run_steps(runner) -> None:
            nonlocal final_images
            for idx, step in enumerate(calls):
                if not isinstance(step, dict) or not str(step.get("tool_name", "")).strip():
                    raise ValueError(f"Step {idx + 1} must be an object with 'tool_name'.")
                t_name = str(step["tool_name"]).strip()
                raw_args = step.get("arguments")
                if raw_args is None:
                    step_args: dict[str, Any] = {}
                elif isinstance(raw_args, str):
                    step_args = json.loads(raw_args) if raw_args.strip() else {}
                else:
                    step_args = dict(raw_args)

                sanitized = self._enforce_path_arguments(spec, t_name, step_args, unrestricted=unrestricted)
                want_img = include_final_image and (idx == last_idx)
                try:
                    res = await runner(t_name, sanitized, want_img)
                    imgs = res.pop("_images", [])
                    if imgs:
                        final_images = imgs
                    is_err = bool(res.get("isError"))
                    step_results.append({
                        "step": idx + 1,
                        "tool_name": t_name,
                        "ok": not is_err,
                        "result": res,
                    })
                    if is_err and stop_on_error:
                        break
                except Exception as exc:
                    step_results.append({
                        "step": idx + 1,
                        "tool_name": t_name,
                        "ok": False,
                        "error": str(exc),
                    })
                    if stop_on_error:
                        break

        if key == "blender":
            await _run_steps(
                lambda t_name, s_args, want_img: self._blender.call_tool(
                    t_name,
                    s_args,
                    self.policy,
                    include_image=want_img,
                    max_image_side=max_image_side,
                    unrestricted=unrestricted,
                )
            )
        else:
            _spec, worker, lock = await self._ensure_worker_mode(app_name, unrestricted=unrestricted)
            async with lock:
                await _run_steps(
                    lambda t_name, s_args, want_img: worker.call_tool(
                        t_name,
                        s_args,
                        include_image=want_img,
                        max_image_side=max_image_side,
                    )
                )

        payload: dict[str, Any] = {
            "app": spec.display_name,
            "total_steps": len(calls),
            "completed_steps": len(step_results),
            "all_ok": len(step_results) == len(calls) and all(s.get("ok") for s in step_results),
            "steps": step_results,
            "_images": final_images,
        }
        if len(calls) > self.soft_step_warning:
            payload["advisory"] = (
                f"Notice: this batch executed {len(calls)} steps (above the recommended {self.soft_step_warning} steps). "
                "Please monitor token and compute consumption, consolidate redundant steps, and summarize progress for the user."
            )
        return payload

    async def close_app(self, app_name: str = "") -> dict[str, Any]:
        if not app_name.strip():
            closed = []
            for key, worker in self._workers.items():
                if worker.is_running:
                    await worker.stop()
                    closed.append(self.registry[key].display_name if key in self.registry else key)
            if await self._blender.stop_headless():
                closed.append("Blender (headless)")
            return {"closed": closed}

        key, spec = self._resolve_spec(app_name, require_enabled=False)
        if key == "blender":
            stopped = await self._blender.stop_headless()
            if stopped:
                return {"app": "Blender", "status": "headless_closed"}
            if self._blender.is_running():
                return {"app": "Blender", "status": "external_gui_app_left_running"}
            return {"app": "Blender", "status": "not_running"}

        worker = self._workers.get(key)
        if worker is None:
            return {"app": spec.display_name, "was_running": False, "status": "closed"}
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            was_running = worker.is_running
            await worker.stop()
        return {"app": spec.display_name, "was_running": was_running, "status": "closed"}

    def _enforce_path_arguments(
        self, spec: AppPluginSpec, tool_name: str, args: dict[str, Any], *, unrestricted: bool = False
    ) -> dict[str, Any]:
        """Validate/normalize file path arguments recursively (bypassing root confinement when unrestricted=True)."""
        tool_lower = tool_name.lower()
        explicit_write = any(w in tool_lower for w in ("save", "export", "bounce", "write", "screenshot"))
        render_ctx = "render" in tool_lower
        return self._sanitize_mapping(args, explicit_write, render_ctx, unrestricted=unrestricted)

    def _is_ambiguous_write_path(
        self,
        value: str,
        mapping: dict[str, Any],
        explicit_write: bool,
        render_ctx: bool,
        *,
        unrestricted: bool = False,
    ) -> bool:
        has_explicit_write_key = any(k.lower() in WRITE_PATH_KEYS for k in mapping)
        if has_explicit_write_key:
            return False
        if explicit_write:
            return True
        if render_ctx:
            try:
                existing = self.policy.resolve_read_path(value, unrestricted=unrestricted)
                if existing.exists():
                    return False
            except Exception:
                pass
            return True
        return False

    def _sanitize_mapping(
        self,
        mapping: dict[str, Any],
        parent_explicit_write: bool,
        parent_render_ctx: bool,
        *,
        unrestricted: bool = False,
    ) -> dict[str, Any]:
        cmd_hint = str(mapping.get("command", "") or mapping.get("id", "")).lower()
        explicit_write = parent_explicit_write or any(
            w in cmd_hint for w in ("save", "export", "bounce", "write", "screenshot")
        )
        render_ctx = parent_render_ctx or ("render" in cmd_hint)
        sanitized: dict[str, Any] = {}
        for k, v in mapping.items():
            k_lower = k.lower()
            if isinstance(v, dict):
                sanitized[k] = self._sanitize_mapping(v, explicit_write, render_ctx, unrestricted=unrestricted)
            elif isinstance(v, list):
                new_list = []
                for item in v:
                    if isinstance(item, dict):
                        new_list.append(self._sanitize_mapping(item, explicit_write, render_ctx, unrestricted=unrestricted))
                    elif isinstance(item, str) and item.strip():
                        if k_lower in WRITE_PATH_KEYS:
                            resolved = self.policy.resolve_write_path(item, unrestricted=unrestricted)
                            resolved.parent.mkdir(parents=True, exist_ok=True)
                            new_list.append(str(resolved))
                        elif k_lower in READ_PATH_KEYS:
                            new_list.append(str(self.policy.resolve_read_path(item, unrestricted=unrestricted)))
                        else:
                            new_list.append(item)
                    else:
                        new_list.append(item)
                sanitized[k] = new_list
            elif isinstance(v, str) and v.strip():
                if k_lower in WRITE_PATH_KEYS or (
                    k_lower in ("path", "filepath")
                    and self._is_ambiguous_write_path(
                        v, mapping, explicit_write, render_ctx, unrestricted=unrestricted
                    )
                ):
                    resolved = self.policy.resolve_write_path(v, unrestricted=unrestricted)
                    resolved.parent.mkdir(parents=True, exist_ok=True)
                    sanitized[k] = str(resolved)
                elif k_lower in READ_PATH_KEYS:
                    resolved = self.policy.resolve_read_path(v, unrestricted=unrestricted)
                    sanitized[k] = str(resolved)
                else:
                    sanitized[k] = v
            else:
                sanitized[k] = v
        return sanitized
