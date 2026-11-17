"""Configurable registry of local stdio MCP plugins and Blender bridge."""

from __future__ import annotations

from dataclasses import dataclass
import json
import logging
from pathlib import Path
import shutil
from typing import Any, Literal

from config import APP_DIR, GatewayConfig, detect_blender_exe

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AppPluginSpec:
    """Configuration for a lazily-launched local stdio MCP server plugin or bridge."""

    key: str
    display_name: str
    category: str
    description: str
    exe_path: str = ""
    command: tuple[str, ...] = ()
    formats: tuple[str, ...] = ()
    root_mode: Literal["automation", "short", "allow_path", "gateway_only"] = "gateway_only"
    extra_mcp_args: tuple[str, ...] = ()
    cwd: str = ""

    def resolved_executable(self) -> str:
        if self.command:
            return self.command[0]
        return self.exe_path

    def is_installed(self) -> bool:
        target = self.resolved_executable()
        if not target:
            return False
        p = Path(target)
        if p.is_absolute() or "\\" in target or "/" in target:
            return p.exists()
        return shutil.which(target) is not None

    def build_command(self, read_roots: list[Path], write_root: Path, *, unrestricted: bool = False) -> list[str]:
        """Build the CLI command line for launching this plugin's stdio MCP server."""
        if self.command:
            base = list(self.command)
        else:
            base = [self.exe_path, "mcp"]

        if unrestricted:
            args = [a for a in self.extra_mcp_args if a != "--require-allow-path"]
            return [*base, *args]

        cmd = [*base, *self.extra_mcp_args]
        if self.root_mode == "automation":
            for r in read_roots:
                cmd.extend(["--automation-read-root", str(r)])
            cmd.extend(["--automation-write-root", str(write_root)])
        elif self.root_mode == "short":
            for r in read_roots:
                cmd.extend(["--read-root", str(r)])
            cmd.extend(["--write-root", str(write_root)])
        elif self.root_mode == "allow_path":
            seen: set[Path] = set()
            for p in [*read_roots, write_root]:
                if p not in seen:
                    seen.add(p)
                    cmd.extend(["--allow-path", str(p)])
        return cmd


def _builtin_plugins(cfg: GatewayConfig) -> dict[str, AppPluginSpec]:
    return {
        "blender": AppPluginSpec(
            key="blender",
            display_name="Blender",
            category="3D Suite (Hardened Addon)",
            description="Blender via hardened CoopMCP bridge: AST-sandboxed bpy scripting, viewport/camera render, GLB/FBX/OBJ/STL export.",
            exe_path=str(cfg.blender_exe if cfg else detect_blender_exe()),
            formats=(".blend", ".glb", ".fbx", ".obj", ".stl", ".png"),
            root_mode="gateway_only",
        ),
    }


def _parse_plugin_entry(raw: dict[str, Any]) -> AppPluginSpec:
    key = str(raw["key"]).strip().lower()
    command = tuple(str(x) for x in (raw.get("command") or ()))
    exe_path = str(raw.get("exe_path") or "")
    root_mode = str(raw.get("root_mode") or "gateway_only")
    if root_mode not in ("automation", "short", "allow_path", "gateway_only"):
        root_mode = "gateway_only"
    return AppPluginSpec(
        key=key,
        display_name=str(raw.get("display_name") or key),
        category=str(raw.get("category") or "Plugin"),
        description=str(raw.get("description") or ""),
        exe_path=exe_path,
        command=command,
        formats=tuple(str(f).lower() for f in (raw.get("formats") or ())),
        root_mode=root_mode,  # type: ignore[arg-type]
        extra_mcp_args=tuple(str(a) for a in (raw.get("extra_mcp_args") or ())),
        cwd=str(raw.get("cwd") or ""),
    )


def load_plugin_registry(cfg: GatewayConfig | None = None) -> dict[str, AppPluginSpec]:
    """Load built-in plugins plus user-defined stdio MCP entries from apps.json (if present)."""
    cfg = cfg or GatewayConfig.from_env(reload_dotenv=False)
    plugins = _builtin_plugins(cfg)
    manifest = cfg.apps_config_path
    if not manifest.exists():
        return plugins

    try:
        data = json.loads(manifest.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        logger.warning("Failed to parse plugin manifest %s: %s", manifest, exc)
        return plugins

    entries = data.get("apps", []) if isinstance(data, dict) else data
    if not isinstance(entries, list):
        logger.warning("Invalid plugin manifest format in %s (expected list or {'apps': [...]})", manifest)
        return plugins

    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("key"):
            continue
        spec = _parse_plugin_entry(entry)
        plugins[spec.key] = spec
    return plugins


APP_ALIASES = {
    "blender3d": "blender",
    "blender5": "blender",
}


def resolve_app_key(name: str, registry: dict[str, AppPluginSpec] | None = None) -> str | None:
    """Normalize user-supplied plugin name (e.g. 'Blender', 'sqlite') to registry key."""
    apps = registry if registry is not None else load_plugin_registry()
    cleaned = name.strip().lower().removesuffix(".exe").removesuffix("-cli")
    cleaned = APP_ALIASES.get(cleaned, cleaned)
    if cleaned in apps:
        return cleaned
    for k, spec in apps.items():
        if spec.display_name.lower() == cleaned:
            return k
    return None


def suggest_apps_for_extension(ext: str, registry: dict[str, AppPluginSpec] | None = None) -> list[str]:
    """Return matching plugin display names for a given file extension."""
    apps = registry if registry is not None else load_plugin_registry()
    e = ext.lower()
    if not e.startswith("."):
        e = f".{e}"
    return [spec.display_name for spec in apps.values() if e in spec.formats]
