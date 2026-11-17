# Hardened fork derived from blender-mcp (Siddharth Ahuja, github.com/ahujasid)
# Purpose-built for CoopMCP Gateway with:
#   - Loopback-only binding (127.0.0.1:9877) + optional shared-secret token auth
#   - Zero telemetry, zero auto-updater, zero external paid-API upsells
#   - Strict path sandboxing (reads in COOP_READ_ROOTS, writes/exports in COOP_WRITE_ROOT)
#   - AST + restricted-builtins Python sandbox on execute_code (toggleable in sidebar)

from __future__ import annotations

import ast
from contextlib import redirect_stdout
from datetime import datetime
import hmac
import io
import json
import math
import os
from pathlib import Path
import queue
import socket
import threading
import traceback
from typing import Any

import bmesh
import bpy
from bpy.app.handlers import persistent
from bpy.props import BoolProperty, IntProperty
import mathutils

bl_info = {
    "name": "CoopMCP Blender Bridge (Hardened)",
    "author": "CoopMCP Contributors (forked from Siddharth Ahuja's blender-mcp)",
    "version": (1, 0, 0),
    "blender": (4, 0, 0),
    "location": "View3D > Sidebar > CoopMCP",
    "description": "Hardened local MCP bridge for CoopMCP (sandboxed execute_code + path confinement)",
    "category": "Interface",
}

DEFAULT_REPO_DIR = Path(__file__).resolve().parent.parent
DEFAULT_GATEWAY_ENV = Path(os.getenv("COOP_ENV_PATH", str(DEFAULT_REPO_DIR / ".env")))
DEFAULT_PORT = 9877
_sandbox_unlocked_ctx = False

ALLOWED_IMPORTS = frozenset({
    "bpy",
    "bmesh",
    "mathutils",
    "math",
    "random",
    "json",
    "colorsys",
    "itertools",
    "functools",
})

BLOCKED_NAMES = frozenset({
    "__builtins__",
    "__import__",
    "__loader__",
    "__spec__",
    "eval",
    "exec",
    "compile",
    "open",
    "getattr",
    "setattr",
    "delattr",
    "globals",
    "locals",
    "vars",
    "dir",
    "breakpoint",
    "input",
    "exit",
    "quit",
    "type",
    "memoryview",
    "object",
})

BLOCKED_ATTRS = frozenset({
    "gi_frame",
    "gi_code",
    "gi_yieldfrom",
    "cr_frame",
    "cr_code",
    "cr_origin",
    "ag_frame",
    "ag_code",
    "f_globals",
    "f_locals",
    "f_builtins",
    "f_back",
    "driver_namespace",
})

BLOCKED_BPY_DOTTED_PREFIXES = (
    "bpy.ops.wm.open_mainfile",
    "bpy.ops.wm.save_mainfile",
    "bpy.ops.wm.save_as_mainfile",
    "bpy.ops.wm.quit_blender",
    "bpy.ops.wm.recover_last_session",
    "bpy.ops.preferences",
    "bpy.ops.script",
    "bpy.ops.export_scene",
    "bpy.ops.import_scene",
    "bpy.ops.wm.stl_export",
    "bpy.ops.wm.obj_export",
    "bpy.ops.wm.alembic_export",
    "bpy.ops.wm.usd_export",
)

_user_stopped_server = False


def _load_gateway_env() -> dict[str, str]:
    values: dict[str, str] = {}
    if DEFAULT_GATEWAY_ENV.exists():
        try:
            for raw_line in DEFAULT_GATEWAY_ENV.read_text(encoding="utf-8-sig").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                values[k.strip()] = v.strip()
        except Exception:
            pass
    for key in ("COOP_BLENDER_TOKEN", "COOP_BLENDER_PORT", "COOP_READ_ROOTS", "COOP_WRITE_ROOT"):
        if os.getenv(key):
            values[key] = os.environ[key].strip()
    return values


def _get_roots() -> tuple[tuple[Path, ...], Path]:
    env = _load_gateway_env()
    default_ws = DEFAULT_REPO_DIR / "workspace"
    raw_reads = env.get("COOP_READ_ROOTS", "").strip()
    if raw_reads:
        read_roots = tuple(Path(p.strip()).resolve() for p in raw_reads.split(",") if p.strip())
    else:
        read_roots = (default_ws.resolve(),)

    raw_write = env.get("COOP_WRITE_ROOT", "").strip()
    write_root = Path(raw_write).resolve() if raw_write else (read_roots[0] / "output").resolve()
    write_root.mkdir(parents=True, exist_ok=True)
    return read_roots, write_root


def _get_expected_token() -> str:
    env = _load_gateway_env()
    return env.get("COOP_BLENDER_TOKEN", "").strip()


def _is_under(target: Path, roots: tuple[Path, ...]) -> bool:
    for root in roots:
        try:
            target.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _resolve_read_path(raw_path: str) -> Path:
    read_roots, write_root = _get_roots()
    cleaned = (raw_path or "").strip()
    if not cleaned:
        raise ValueError("filepath is required")
    p = Path(cleaned)
    if not p.is_absolute():
        p = read_roots[0] / p
    resolved = p.resolve()
    if not _sandbox_unlocked_ctx and not _is_under(resolved, (*read_roots, write_root)):
        raise PermissionError(f"Read path '{resolved}' is outside allowed roots.")
    return resolved


def _resolve_write_path(raw_path: str) -> Path:
    _, write_root = _get_roots()
    cleaned = (raw_path or "").strip()
    if not cleaned:
        raise ValueError("filepath is required")
    p = Path(cleaned)
    if not p.is_absolute():
        p = write_root / p
    resolved = p.resolve()
    if not _sandbox_unlocked_ctx and not _is_under(resolved, (write_root,)):
        raise PermissionError(f"Write path '{resolved}' is outside output folder '{write_root}'.")
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def _dotted_name(node: ast.AST) -> str | None:
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _validate_safe_python_ast(code: str) -> None:
    """Reject imports, dunder escapes, file/OS builtins, and file-writing bpy.ops inside execute_code."""
    tree = ast.parse(code, mode="exec")
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_mod = alias.name.split(".", 1)[0]
                if root_mod not in ALLOWED_IMPORTS:
                    raise PermissionError(f"Import of '{alias.name}' is blocked in CoopMCP Blender sandbox.")
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            root_mod = mod.split(".", 1)[0]
            if root_mod not in ALLOWED_IMPORTS:
                raise PermissionError(f"Import from '{mod}' is blocked in CoopMCP Blender sandbox.")
            for alias in node.names:
                if alias.name == "*":
                    raise PermissionError("Wildcard imports ('*') are blocked in CoopMCP Blender sandbox.")
        elif isinstance(node, ast.Name):
            if node.id in BLOCKED_NAMES or node.id.startswith("__"):
                raise PermissionError(f"Identifier '{node.id}' is blocked in CoopMCP Blender sandbox.")
        elif isinstance(node, ast.Attribute):
            if node.attr.startswith("__") or node.attr in BLOCKED_ATTRS:
                raise PermissionError(f"Attribute '{node.attr}' is blocked in CoopMCP Blender sandbox.")
            dotted = _dotted_name(node)
            if dotted and any(dotted.startswith(prefix) for prefix in BLOCKED_BPY_DOTTED_PREFIXES):
                raise PermissionError(
                    f"'{dotted}' is blocked inside execute_code; use dedicated sandboxed tools (export_scene/open_blend/save_blend)."
                )


def _safe_import(name: str, globals=None, locals=None, fromlist=(), level: int = 0):
    if level != 0:
        raise PermissionError("Relative imports are blocked.")
    root_mod = name.split(".", 1)[0]
    if root_mod not in ALLOWED_IMPORTS:
        raise PermissionError(f"Module '{name}' is not in ALLOWED_IMPORTS.")
    return __import__(name, globals, locals, fromlist, level)


SAFE_BUILTINS: dict[str, Any] = {
    "__import__": _safe_import,
    "abs": abs,
    "all": all,
    "any": any,
    "bool": bool,
    "dict": dict,
    "enumerate": enumerate,
    "filter": filter,
    "float": float,
    "int": int,
    "isinstance": isinstance,
    "issubclass": issubclass,
    "len": len,
    "list": list,
    "map": map,
    "max": max,
    "min": min,
    "pow": pow,
    "print": print,
    "range": range,
    "repr": repr,
    "reversed": reversed,
    "round": round,
    "set": set,
    "slice": slice,
    "sorted": sorted,
    "str": str,
    "sum": sum,
    "tuple": tuple,
    "zip": zip,
    "Exception": Exception,
    "ValueError": ValueError,
    "TypeError": TypeError,
    "RuntimeError": RuntimeError,
    "KeyError": KeyError,
    "IndexError": IndexError,
    "True": True,
    "False": False,
    "None": None,
}


def _object_detail(obj: bpy.types.Object) -> str:
    if obj.type == "MESH" and obj.data:
        return f"Mesh ({len(obj.data.vertices)} verts, {len(obj.data.polygons)} faces)"
    return obj.type.capitalize()


class CoopBlenderMCPServer:
    """Hardened local TCP JSON server executing commands on Blender's main thread."""

    def __init__(self, host: str = "127.0.0.1", port: int = DEFAULT_PORT) -> None:
        self.host = host
        self.port = port
        self.running = False
        self.socket: socket.socket | None = None
        self.server_thread: threading.Thread | None = None
        self.command_queue: queue.Queue[tuple[dict[str, Any], socket.socket]] = queue.Queue()
        self._clients: set[socket.socket] = set()
        self._clients_lock = threading.Lock()
        self._timer_fn = self._process_queue

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(4)
        self.socket.settimeout(1.0)

        self.server_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.server_thread.start()

        if not bpy.app.timers.is_registered(self._timer_fn):
            bpy.app.timers.register(self._timer_fn, first_interval=0.05, persistent=True)
        print(f"[CoopBlenderMCP] Listening on {self.host}:{self.port}")

    def stop(self) -> None:
        self.running = False
        if bpy.app.timers.is_registered(self._timer_fn):
            bpy.app.timers.unregister(self._timer_fn)
        if self.socket is not None:
            try:
                self.socket.close()
            except OSError:
                pass
            self.socket = None
        with self._clients_lock:
            for c in list(self._clients):
                try:
                    c.close()
                except OSError:
                    pass
            self._clients.clear()
        print("[CoopBlenderMCP] Stopped")

    def _accept_loop(self) -> None:
        while self.running and self.socket is not None:
            try:
                client, _addr = self.socket.accept()
                threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_client(self, client: socket.socket) -> None:
        client.settimeout(1.0)
        with self._clients_lock:
            self._clients.add(client)
        buf = b""
        try:
            while self.running:
                try:
                    chunk = client.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        line = line.strip()
                        if not line:
                            continue
                        cmd = json.loads(line.decode("utf-8"))
                        self.command_queue.put((cmd, client))
                except socket.timeout:
                    continue
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    err = json.dumps({"status": "error", "message": f"Invalid JSON: {exc}"}) + "\n"
                    client.sendall(err.encode("utf-8"))
                    buf = b""
        except OSError:
            pass
        finally:
            with self._clients_lock:
                self._clients.discard(client)
            try:
                client.close()
            except OSError:
                pass

    def _process_queue(self):
        if not self.running:
            return None
        while True:
            try:
                cmd, client = self.command_queue.get_nowait()
            except queue.Empty:
                break
            try:
                resp = self._dispatch(cmd)
            except Exception as exc:
                traceback.print_exc()
                resp = {"status": "error", "message": str(exc)}
            try:
                payload = (json.dumps(resp, ensure_ascii=False) + "\n").encode("utf-8")
                client.sendall(payload)
            except OSError:
                pass
        return 0.05

    def _dispatch(self, command: dict[str, Any]) -> dict[str, Any]:
        expected_token = _get_expected_token()
        provided_token = str(command.get("token") or "")
        if expected_token and not hmac.compare_digest(provided_token, expected_token):
            return {"status": "error", "message": "Unauthorized: invalid or missing COOP_BLENDER_TOKEN."}

        cmd_type = command.get("type")
        params = command.get("params") or {}

        if cmd_type == "ping":
            scene = getattr(bpy.context, "scene", None)
            allow_exec = bool(getattr(scene, "coopmcp_allow_execute_code", True)) if scene else True
            return {
                "status": "success",
                "result": {
                    "pong": True,
                    "blender_version": bpy.app.version_string,
                    "execute_code_enabled": allow_exec,
                },
            }

        handlers = {
            "get_scene_info": self.get_scene_info,
            "list_scene_items": self.list_scene_items,
            "get_object_info": self.get_object_info,
            "get_viewport_screenshot": self.get_viewport_screenshot,
            "render_scene": self.render_scene,
            "export_scene": self.export_scene,
            "open_blend": self.open_blend,
            "save_blend": self.save_blend,
            "execute_code": self.execute_code,
            "shutdown": self.shutdown_headless,
        }
        fn = handlers.get(cmd_type)
        if fn is None:
            return {"status": "error", "message": f"Unknown command type: {cmd_type}"}

        global _sandbox_unlocked_ctx
        _sandbox_unlocked_ctx = bool(command.get("sandbox_unlocked", False))
        try:
            result = fn(**params)
        finally:
            _sandbox_unlocked_ctx = False
        return {"status": "success", "result": result}

    def get_scene_info(self) -> dict[str, Any]:
        scene = bpy.context.scene
        objects = []
        for idx, obj in enumerate(scene.objects):
            if idx >= 50:
                break
            objects.append({
                "name": obj.name,
                "type": obj.type,
                "location": [round(float(v), 3) for v in obj.location],
                "visible": obj.visible_get(),
            })
        return {
            "name": scene.name,
            "filepath": bpy.data.filepath or None,
            "frame_start": scene.frame_start,
            "frame_end": scene.frame_end,
            "frame_current": scene.frame_current,
            "fps": scene.render.fps,
            "render_engine": scene.render.engine,
            "object_count": len(scene.objects),
            "objects": objects,
            "materials_count": len(bpy.data.materials),
            "collections": [c.name for c in bpy.data.collections],
        }

    def list_scene_items(self, query: str = "", limit: int = 30) -> dict[str, Any]:
        needle = (query or "").strip().lower()
        limit = max(1, min(int(limit or 30), 100))
        items = []
        for obj in bpy.context.scene.objects:
            if not needle or needle in obj.name.lower():
                items.append({"kind": "object", "name": obj.name, "detail": _object_detail(obj)})
        for mat in bpy.data.materials:
            if not needle or needle in mat.name.lower():
                items.append({"kind": "material", "name": mat.name, "detail": "Material"})
        for coll in bpy.data.collections:
            if not needle or needle in coll.name.lower():
                items.append({"kind": "collection", "name": coll.name, "detail": f"{len(coll.all_objects)} objects"})
        return {"items": items[:limit], "total": len(items)}

    def get_object_info(self, name: str) -> dict[str, Any]:
        obj = bpy.data.objects.get(name)
        if obj is None:
            raise ValueError(f"Object not found: {name}")
        info: dict[str, Any] = {
            "name": obj.name,
            "type": obj.type,
            "location": [round(float(v), 4) for v in obj.location],
            "rotation_euler": [round(float(v), 4) for v in obj.rotation_euler],
            "scale": [round(float(v), 4) for v in obj.scale],
            "visible": obj.visible_get(),
            "materials": [s.material.name for s in obj.material_slots if s.material],
            "modifiers": [{"name": m.name, "type": m.type} for m in obj.modifiers],
        }
        if obj.type == "MESH" and obj.data:
            bbox = [list(obj.matrix_world @ mathutils.Vector(c)) for c in obj.bound_box]
            info["world_bounding_box"] = {
                "min": [round(min(p[i] for p in bbox), 4) for i in range(3)],
                "max": [round(max(p[i] for p in bbox), 4) for i in range(3)],
            }
            info["mesh"] = {
                "vertices": len(obj.data.vertices),
                "edges": len(obj.data.edges),
                "polygons": len(obj.data.polygons),
            }
        return info

    def get_viewport_screenshot(self, max_size: int = 800, filepath: str | None = None) -> dict[str, Any]:
        _, write_root = _get_roots()
        if filepath:
            dest = _resolve_write_path(filepath)
        else:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            dest = (write_root / "_previews" / f"blender_viewport_{ts}.png").resolve()
            dest.parent.mkdir(parents=True, exist_ok=True)

        screen = getattr(bpy.context, "screen", None)
        area = space = region = None
        if screen is not None:
            for a in screen.areas:
                if a.type == "VIEW_3D":
                    area = a
                    space = a.spaces.active
                    region = next((r for r in a.regions if r.type == "WINDOW"), None)
                    break

        if bpy.app.background or not area or space is None or region is None:
            scene = bpy.context.scene
            temp_cam_obj = None
            temp_cam_data = None
            orig_cam = scene.camera
            try:
                if scene.camera is None:
                    center = mathutils.Vector((0.0, 0.0, 0.0))
                    meshes = [o for o in scene.objects if o.type == "MESH"]
                    if meshes:
                        center = sum((o.location for o in meshes), mathutils.Vector()) / len(meshes)
                    temp_cam_data = bpy.data.cameras.new("_CoopTempPreviewCam")
                    temp_cam_obj = bpy.data.objects.new("_CoopTempPreviewCam", temp_cam_data)
                    scene.collection.objects.link(temp_cam_obj)
                    temp_cam_obj.location = center + mathutils.Vector((5.5, -5.5, 4.0))
                    direction = center - temp_cam_obj.location
                    temp_cam_obj.rotation_euler = direction.to_track_quat("-Z", "Y").to_euler()
                    scene.camera = temp_cam_obj
                return self.render_scene(
                    filepath=str(dest),
                    width=min(max_size, 960),
                    height=min(int(max_size * 0.5625), 540),
                )
            finally:
                if temp_cam_obj is not None:
                    scene.camera = orig_cam
                    bpy.data.objects.remove(temp_cam_obj, do_unlink=True)
                if temp_cam_data is not None:
                    bpy.data.cameras.remove(temp_cam_data)

        import gpu
        import numpy as np

        r3d = space.region_3d
        src_w, src_h = max(1, region.width), max(1, region.height)
        if max(src_w, src_h) > max_size:
            scale = max_size / max(src_w, src_h)
            width, height = max(1, int(src_w * scale)), max(1, int(src_h * scale))
        else:
            width, height = src_w, src_h

        offscreen = gpu.types.GPUOffScreen(width, height)
        try:
            offscreen.draw_view3d(
                bpy.context.scene,
                bpy.context.view_layer,
                space,
                region,
                r3d.view_matrix,
                r3d.window_matrix,
                do_color_management=True,
            )
            buf = offscreen.texture_color.read()
        finally:
            offscreen.free()

        buf.dimensions = width * height * 4
        pixels = np.asarray(buf, dtype=np.float32) / 255.0
        img = bpy.data.images.new("coop_mcp_viewport", width, height, alpha=True)
        try:
            img.pixels.foreach_set(pixels.ravel())
            img.filepath_raw = str(dest)
            img.file_format = "PNG"
            img.save()
        finally:
            bpy.data.images.remove(img)

        return {
            "success": True,
            "method": "offscreen_viewport",
            "path": str(dest),
            "width": width,
            "height": height,
        }

    def render_scene(
        self,
        filepath: str | None = None,
        width: int = 960,
        height: int = 540,
        samples: int = 16,
        frame: int | None = None,
        engine: str | None = None,
    ) -> dict[str, Any]:
        _, write_root = _get_roots()
        if filepath:
            dest = _resolve_write_path(filepath)
        else:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            dest = (write_root / "_previews" / f"blender_render_{ts}.png").resolve()
            dest.parent.mkdir(parents=True, exist_ok=True)

        scene = bpy.context.scene
        if scene.camera is None:
            raise RuntimeError("No active camera in the Blender scene; add or set scene.camera first.")

        orig = {
            "filepath": scene.render.filepath,
            "format": scene.render.image_settings.file_format,
            "res_x": scene.render.resolution_x,
            "res_y": scene.render.resolution_y,
            "res_pct": scene.render.resolution_percentage,
            "frame": scene.frame_current,
            "engine": scene.render.engine,
        }
        try:
            if engine:
                scene.render.engine = engine
            elif bpy.app.background and scene.render.engine != "CYCLES":
                scene.render.engine = "CYCLES"
                if hasattr(scene, "cycles"):
                    scene.cycles.device = "CPU"
            scene.render.filepath = str(dest)
            scene.render.image_settings.file_format = "PNG"
            scene.render.resolution_x = max(64, min(int(width), 2048))
            scene.render.resolution_y = max(64, min(int(height), 2048))
            scene.render.resolution_percentage = 100
            if frame is not None:
                scene.frame_set(int(frame))
            if scene.render.engine == "CYCLES" and hasattr(scene, "cycles"):
                scene.cycles.samples = max(1, min(int(samples), 256))
            bpy.ops.render.render(write_still=True)
        finally:
            scene.render.engine = orig["engine"]
            scene.render.filepath = orig["filepath"]
            scene.render.image_settings.file_format = orig["format"]
            scene.render.resolution_x = orig["res_x"]
            scene.render.resolution_y = orig["res_y"]
            scene.render.resolution_percentage = orig["res_pct"]
            scene.frame_set(orig["frame"])

        return {
            "success": True,
            "method": "camera_render",
            "path": str(dest),
            "width": int(width),
            "height": int(height),
            "bytes": dest.stat().st_size,
        }

    def export_scene(
        self,
        filepath: str,
        format: str = "glb",
        object_names: list[str] | None = None,
        selection_only: bool = False,
        apply_modifiers: bool = True,
    ) -> dict[str, Any]:
        dest = _resolve_write_path(filepath)
        fmt = (format or dest.suffix.lstrip(".") or "glb").lower()
        if fmt not in ("glb", "fbx", "obj", "stl"):
            raise ValueError(f"Unsupported format '{fmt}'. Allowed: glb, fbx, obj, stl")

        names = [n for n in (object_names or []) if n]
        use_selection = False
        exported: list[str] = []

        if names:
            missing = [n for n in names if bpy.data.objects.get(n) is None]
            if missing:
                raise ValueError("Objects not found in Blender: " + ", ".join(missing))
            bpy.ops.object.select_all(action="DESELECT")
            for n in names:
                obj = bpy.data.objects[n]
                for o in [obj, *obj.children_recursive]:
                    o.select_set(True)
                    if o.name not in exported:
                        exported.append(o.name)
            bpy.context.view_layer.objects.active = bpy.data.objects[names[0]]
            use_selection = True
        elif selection_only:
            if not bpy.context.selected_objects:
                raise ValueError("Nothing is selected in Blender.")
            exported = [o.name for o in bpy.context.selected_objects]
            use_selection = True
        else:
            exported = [o.name for o in bpy.context.scene.objects]

        if bpy.context.object and getattr(bpy.context.object, "mode", "OBJECT") != "OBJECT":
            try:
                bpy.ops.object.mode_set(mode="OBJECT")
            except Exception:
                pass

        if fmt == "glb":
            bpy.ops.export_scene.gltf(
                filepath=str(dest),
                export_format="GLB",
                use_selection=use_selection,
                use_active_scene=True,
                export_apply=apply_modifiers,
            )
        elif fmt == "fbx":
            bpy.ops.export_scene.fbx(
                filepath=str(dest),
                use_selection=use_selection,
                apply_unit_scale=True,
                bake_space_transform=apply_modifiers,
                use_mesh_modifiers=apply_modifiers,
                path_mode="COPY",
                embed_textures=True,
            )
        elif fmt == "obj":
            bpy.ops.wm.obj_export(
                filepath=str(dest),
                export_selected_objects=use_selection,
                apply_modifiers=apply_modifiers,
            )
        elif fmt == "stl":
            bpy.ops.wm.stl_export(
                filepath=str(dest),
                export_selected_objects=use_selection,
                apply_modifiers=apply_modifiers,
            )

        return {
            "path": str(dest),
            "format": fmt,
            "bytes": dest.stat().st_size,
            "selection_only": use_selection,
            "exported": exported,
        }

    def open_blend(self, filepath: str) -> dict[str, Any]:
        src = _resolve_read_path(filepath)
        if not src.exists():
            raise FileNotFoundError(f"Blend file not found: {src}")
        bpy.ops.wm.open_mainfile(filepath=str(src))
        return {"opened": str(src), "scene": bpy.context.scene.name}

    def save_blend(self, filepath: str) -> dict[str, Any]:
        dest = _resolve_write_path(filepath)
        if dest.suffix.lower() != ".blend":
            dest = dest.with_suffix(".blend")
        bpy.ops.wm.save_as_mainfile(filepath=str(dest))
        return {"saved": str(dest), "bytes": dest.stat().st_size}

    def execute_code(self, code: str) -> dict[str, Any]:
        scene = getattr(bpy.context, "scene", None)
        if not _sandbox_unlocked_ctx:
            if scene is not None and not getattr(scene, "coopmcp_allow_execute_code", True):
                raise PermissionError(
                    "execute_code is disabled in Blender Sidebar (CoopMCP -> Allow Sandboxed execute_code)."
                )
            _validate_safe_python_ast(code)

        namespace: dict[str, Any] = {
            "__builtins__": __builtins__ if _sandbox_unlocked_ctx else SAFE_BUILTINS,
            "bpy": bpy,
            "bmesh": bmesh,
            "mathutils": mathutils,
            "math": math,
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            exec(compile(code, "<coop_blender>", "exec"), namespace, namespace)
        return {"executed": True, "sandboxed": not _sandbox_unlocked_ctx, "result": buf.getvalue()}

    def shutdown_headless(self) -> dict[str, Any]:
        """Gracefully stop the background headless Blender server."""
        if not bpy.app.background:
            raise PermissionError("Refusing to shut down an interactive Blender GUI session.")
        self.running = False
        return {"status": "shutting_down", "background": True}


class COOPMCP_OT_StartServer(bpy.types.Operator):
    bl_idname = "coopmcp.start_server"
    bl_label = "Start CoopMCP"

    def execute(self, context):
        global _user_stopped_server
        _user_stopped_server = False
        scene = context.scene
        srv = getattr(bpy.types, "coopmcp_server", None)
        if srv is None:
            srv = CoopBlenderMCPServer(host="127.0.0.1", port=scene.coopmcp_port)
            bpy.types.coopmcp_server = srv
        if not srv.running:
            srv.port = scene.coopmcp_port
            srv.start()
        scene.coopmcp_server_running = srv.running
        return {"FINISHED"}


class COOPMCP_OT_StopServer(bpy.types.Operator):
    bl_idname = "coopmcp.stop_server"
    bl_label = "Stop CoopMCP"

    def execute(self, context):
        global _user_stopped_server
        _user_stopped_server = True
        srv = getattr(bpy.types, "coopmcp_server", None)
        if srv is not None:
            srv.stop()
        context.scene.coopmcp_server_running = False
        return {"FINISHED"}


class COOPMCP_PT_Panel(bpy.types.Panel):
    bl_label = "CoopMCP Bridge"
    bl_idname = "COOPMCP_PT_Panel"
    bl_space_type = "VIEW_3D"
    bl_region_type = "UI"
    bl_category = "CoopMCP"

    def draw(self, context):
        layout = self.layout
        scene = context.scene
        srv = getattr(bpy.types, "coopmcp_server", None)
        running = bool(srv is not None and srv.running)

        layout.label(text="Status: Running (127.0.0.1)" if running else "Status: Stopped", icon="CHECKMARK" if running else "X")
        layout.prop(scene, "coopmcp_port")
        layout.prop(scene, "coopmcp_auto_start")
        layout.prop(scene, "coopmcp_allow_execute_code")

        if running:
            layout.operator("coopmcp.stop_server", text="Stop Server", icon="PAUSE")
        else:
            layout.operator("coopmcp.start_server", text="Start Server", icon="PLAY")

        box = layout.box()
        box.label(text="Sandbox active:", icon="LOCKED")
        box.label(text="• Token auth + loopback only")
        box.label(text="• Blocks os/subprocess/open")
        box.label(text="• Output confined to COOP_WRITE_ROOT")


def _auto_start_callback():
    if bpy.app.background:
        return None
    scene = getattr(bpy.context, "scene", None)
    if scene is None:
        return 0.5
    if not scene.coopmcp_auto_start or _user_stopped_server:
        return None
    srv = getattr(bpy.types, "coopmcp_server", None)
    if srv is not None and srv.running:
        scene.coopmcp_server_running = True
        return None
    if srv is None:
        srv = CoopBlenderMCPServer(host="127.0.0.1", port=scene.coopmcp_port)
        bpy.types.coopmcp_server = srv
    try:
        srv.start()
        scene.coopmcp_server_running = True
    except OSError as exc:
        print(f"[CoopBlenderMCP] Auto-start failed: {exc}")
        scene.coopmcp_server_running = False
    return None


@persistent
def _on_load_post(_unused):
    if not bpy.app.timers.is_registered(_auto_start_callback):
        bpy.app.timers.register(_auto_start_callback, first_interval=0.5, persistent=True)


def register():
    bpy.types.Scene.coopmcp_port = IntProperty(name="Port", default=DEFAULT_PORT, min=1024, max=65535)
    bpy.types.Scene.coopmcp_server_running = BoolProperty(name="Running", default=False)
    bpy.types.Scene.coopmcp_auto_start = BoolProperty(name="Auto-start on Blender launch", default=True)
    bpy.types.Scene.coopmcp_allow_execute_code = BoolProperty(
        name="Allow sandboxed execute_code",
        description="Allows safe bpy/bmesh/mathutils subset; blocks os/subprocess/open",
        default=True,
    )
    for cls in (COOPMCP_OT_StartServer, COOPMCP_OT_StopServer, COOPMCP_PT_Panel):
        bpy.utils.register_class(cls)
    if _on_load_post not in bpy.app.handlers.load_post:
        bpy.app.handlers.load_post.append(_on_load_post)
    if not bpy.app.timers.is_registered(_auto_start_callback):
        bpy.app.timers.register(_auto_start_callback, first_interval=0.5, persistent=True)


def unregister():
    if _on_load_post in bpy.app.handlers.load_post:
        bpy.app.handlers.load_post.remove(_on_load_post)
    if bpy.app.timers.is_registered(_auto_start_callback):
        bpy.app.timers.unregister(_auto_start_callback)
    srv = getattr(bpy.types, "coopmcp_server", None)
    if srv is not None:
        srv.stop()
        del bpy.types.coopmcp_server
    for cls in (COOPMCP_PT_Panel, COOPMCP_OT_StopServer, COOPMCP_OT_StartServer):
        bpy.utils.unregister_class(cls)
    for prop in (
        "coopmcp_port",
        "coopmcp_server_running",
        "coopmcp_auto_start",
        "coopmcp_allow_execute_code",
    ):
        if hasattr(bpy.types.Scene, prop):
            delattr(bpy.types.Scene, prop)


if __name__ == "__main__":
    register()
