"""Hybrid TCP + Auto-Headless launcher bridge for CoopMCP Blender Addon."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
import socket
import subprocess
import time
from typing import Any

from config import APP_DIR, ENV_PATH, GatewayConfig, detect_blender_exe
from files_tools import PathPolicy, compress_image_to_png_base64

logger = logging.getLogger(__name__)

HEADLESS_RUNNER = APP_DIR / "blender_addon" / "headless_runner.py"
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

BLENDER_TOOLS: list[dict[str, Any]] = [
    {
        "name": "ping",
        "description": "Check Blender CoopMCP connection, mode (GUI vs auto-headless), and sandbox status.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_scene_info",
        "description": "Get active Blender scene summary: objects (up to 50), frame range, fps, render engine, collections.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "list_scene_items",
        "description": "Search objects, materials, and collections in the active Blender scene by substring.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Optional name substring filter"},
                "limit": {"type": "integer", "description": "Max items to return (default 30, max 100)"},
            },
            "required": [],
        },
    },
    {
        "name": "get_object_info",
        "description": "Inspect one Blender object's transform, world bounding box, materials, modifiers, and mesh counts.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string", "description": "Exact object name in bpy.data.objects"}},
            "required": ["name"],
        },
    },
    {
        "name": "get_viewport_screenshot",
        "description": "Capture the Blender 3D viewport (or auto-camera render in headless mode) inside COOP_WRITE_ROOT/_previews.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "max_size": {"type": "integer", "description": "Max image dimension in px (default 800)"},
                "filepath": {"type": "string", "description": "Optional output PNG path inside write root"},
            },
            "required": [],
        },
    },
    {
        "name": "render_scene",
        "description": "Render the active Blender camera to PNG inside COOP_WRITE_ROOT/_previews and return visual preview.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filepath": {"type": "string", "description": "Optional PNG path inside write root"},
                "width": {"type": "integer", "description": "Render width px (default 960)"},
                "height": {"type": "integer", "description": "Render height px (default 540)"},
                "samples": {"type": "integer", "description": "Cycles samples if using Cycles (default 16)"},
                "frame": {"type": "integer", "description": "Optional frame number to render"},
                "engine": {"type": "string", "description": "Optional render engine (e.g. CYCLES, BLENDER_EEVEE)"},
            },
            "required": [],
        },
    },
    {
        "name": "export_scene",
        "description": "Export the scene, selection, or named objects to GLB, FBX, OBJ, or STL inside write root.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filepath": {"type": "string", "description": "Output file path inside write root (e.g. model.glb)"},
                "format": {"type": "string", "enum": ["glb", "fbx", "obj", "stl"], "description": "Export format"},
                "object_names": {"type": "array", "items": {"type": "string"}, "description": "Optional specific object names"},
                "selection_only": {"type": "boolean", "description": "Export only selected objects"},
                "apply_modifiers": {"type": "boolean", "description": "Apply modifiers on export (default true)"},
            },
            "required": ["filepath"],
        },
    },
    {
        "name": "open_blend",
        "description": "Open a .blend file inside allowed read roots.",
        "inputSchema": {
            "type": "object",
            "properties": {"filepath": {"type": "string", "description": "Path to .blend file"}},
            "required": ["filepath"],
        },
    },
    {
        "name": "save_blend",
        "description": "Save the current Blender project as a .blend file inside write root.",
        "inputSchema": {
            "type": "object",
            "properties": {"filepath": {"type": "string", "description": "Output .blend path inside write root"}},
            "required": ["filepath"],
        },
    },
    {
        "name": "execute_code",
        "description": "Run AST-sandboxed Blender Python (bpy/bmesh/mathutils/math only; no os/subprocess/open/network).",
        "inputSchema": {
            "type": "object",
            "properties": {"code": {"type": "string", "description": "Sandboxed Python code using bpy/bmesh/mathutils"}},
            "required": ["code"],
        },
    },
]


def _blender_config() -> tuple[str, int, int, str, Path]:
    cfg = GatewayConfig.from_env(reload_dotenv=False)
    return (
        cfg.blender_host or "127.0.0.1",
        cfg.blender_port,
        cfg.blender_headless_port,
        cfg.blender_token,
        cfg.blender_exe or detect_blender_exe(),
    )


def _tcp_probe(host: str, port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.2)
    try:
        return s.connect_ex((host, port)) == 0
    except OSError:
        return False
    finally:
        s.close()


class BlenderBridgeManager:
    """Routes to open Blender GUI if available, or auto-launches headless background Blender on demand."""

    def __init__(self) -> None:
        self._proc: subprocess.Popen | None = None
        self._lock = asyncio.Lock()
        self.last_used = time.monotonic()

    @property
    def has_headless_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def is_running(self) -> bool:
        host, gui_port, headless_port, _, _ = _blender_config()
        if _tcp_probe(host, gui_port):
            return True
        if self.has_headless_running and _tcp_probe(host, headless_port):
            return True
        return False

    async def _ensure_endpoint(self, policy: PathPolicy) -> tuple[str, int, str, str]:
        """Return (host, port, token, mode) where mode is 'gui' or 'headless'."""
        host, gui_port, headless_port, token, blender_exe = _blender_config()
        if _tcp_probe(host, gui_port):
            return host, gui_port, token, "gui"

        if self.has_headless_running and _tcp_probe(host, headless_port):
            return host, headless_port, token, "headless"

        if not blender_exe.exists():
            raise FileNotFoundError(f"Blender executable not found: {blender_exe}")
        if not HEADLESS_RUNNER.exists():
            raise FileNotFoundError(f"Headless runner not found: {HEADLESS_RUNNER}")

        if self._proc is not None and self._proc.poll() is not None:
            self._proc = None

        env = os.environ.copy()
        env["COOP_ENV_PATH"] = str(ENV_PATH)
        env["COOP_BLENDER_HOST"] = host
        env["COOP_BLENDER_HEADLESS_PORT"] = str(headless_port)
        env["COOP_READ_ROOTS"] = ",".join(str(r) for r in policy.read_roots)
        env["COOP_WRITE_ROOT"] = str(policy.write_root)
        if token:
            env["COOP_BLENDER_TOKEN"] = token

        logger.info("Auto-starting headless Blender background session on %s:%s", host, headless_port)
        self._proc = subprocess.Popen(
            [
                str(blender_exe),
                "--background",
                "--python",
                str(HEADLESS_RUNNER),
            ],
            cwd=str(APP_DIR),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW,
        )

        for _ in range(60):
            if self._proc.poll() is not None:
                code = self._proc.returncode
                self._proc = None
                raise RuntimeError(f"Headless Blender exited early with code {code}.")
            if _tcp_probe(host, headless_port):
                return host, headless_port, token, "headless"
            await asyncio.sleep(0.25)

        await self.stop_headless()
        raise TimeoutError(f"Timed out waiting for headless Blender on {host}:{headless_port}.")

    async def stop_headless(self) -> bool:
        """Cleanly shut down managed headless Blender (never touches user-opened Blender GUI)."""
        async with self._lock:
            if not self.has_headless_running:
                self._proc = None
                return False

            host, _gui_port, headless_port, token, _ = _blender_config()
            if _tcp_probe(host, headless_port):
                try:
                    await self._send_raw(host, headless_port, token, "shutdown", {}, timeout=3.0)
                except Exception:
                    pass

            if self._proc is not None:
                try:
                    await asyncio.to_thread(self._proc.wait, 4.0)
                except Exception:
                    self._proc.terminate()
                    try:
                        await asyncio.to_thread(self._proc.wait, 3.0)
                    except Exception:
                        self._proc.kill()
            self._proc = None
            logger.info("Stopped headless Blender background session.")
            return True

    async def _send_raw(
        self,
        host: str,
        port: int,
        token: str,
        tool_name: str,
        arguments: dict[str, Any],
        timeout: float = 120.0,
        unrestricted: bool = False,
    ) -> dict[str, Any]:
        payload = (
            json.dumps(
                {
                    "type": tool_name,
                    "params": arguments,
                    "token": token,
                    "sandbox_unlocked": bool(unrestricted),
                },
                ensure_ascii=False,
            )
            + "\n"
        ).encode("utf-8")
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5.0)
        try:
            writer.write(payload)
            await writer.drain()
            raw_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if not raw_line:
                raise RuntimeError("Blender closed the socket connection without a response.")
            return json.loads(raw_line.decode("utf-8"))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        policy: PathPolicy,
        *,
        include_image: bool = True,
        max_image_side: int = 1024,
        unrestricted: bool = False,
    ) -> dict[str, Any]:
        valid_names = {t["name"] for t in BLENDER_TOOLS}
        if tool_name not in valid_names:
            raise ValueError(f"Unknown Blender tool '{tool_name}'. Available: {sorted(valid_names)}")

        async with self._lock:
            self.last_used = time.monotonic()
            host, port, token, mode = await self._ensure_endpoint(policy)
            resp = await self._send_raw(host, port, token, tool_name, arguments, unrestricted=unrestricted)

        if resp.get("status") != "success":
            return {
                "app": "Blender",
                "mode": mode,
                "tool": tool_name,
                "isError": True,
                "output": str(resp.get("message") or "Blender command failed."),
            }

        result = resp.get("result", {})
        out: dict[str, Any] = {
            "app": "Blender",
            "mode": mode,
            "tool": tool_name,
            "isError": False,
            "output": json.dumps(result, ensure_ascii=False, indent=2),
        }

        if include_image and tool_name in ("get_viewport_screenshot", "render_scene") and isinstance(result, dict):
            img_path_str = result.get("path")
            if isinstance(img_path_str, str):
                img_path = Path(img_path_str)
                if img_path.exists() and img_path.is_file():
                    thumb = compress_image_to_png_base64(img_path.read_bytes(), max_side=max_image_side)
                    out["saved_images"] = [str(img_path)]
                    out["_images"] = [thumb]

        return out
