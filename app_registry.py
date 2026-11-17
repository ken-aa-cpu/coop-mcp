"""Configurable registry of local stdio, HTTP, and SSE MCP plugins plus Blender bridge."""

from __future__ import annotations

from dataclasses import dataclass
import json
import logging
from pathlib import Path
import shutil
from typing import Any, Literal

from config import GatewayConfig, detect_blender_exe

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AppPluginSpec:
    """Configuration for a lazily-launched local MCP plugin (stdio, HTTP, SSE, or bridge)."""

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
    transport: Literal["stdio", "http", "sse"] = "stdio"
    url: str = ""
    headers: tuple[tuple[str, str], ...] = ()
    env: tuple[tuple[str, str], ...] = ()
    enabled: bool = True
    require_admin_unlock: bool = False
    source: str = ""

    def headers_dict(self) -> dict[str, str]:
        return dict(self.headers)

    def env_dict(self) -> dict[str, str]:
        return dict(self.env)

    def resolved_executable(self) -> str:
        if self.command:
            return self.command[0]
        return self.exe_path

    def is_installed(self) -> bool:
        if self.transport in ("http", "sse"):
            return bool(self.url.strip())
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

    def to_manifest_dict(self, *, mask_secrets: bool = False) -> dict[str, Any]:
        """Serialize plugin spec for apps.json or sanitized UI responses."""
        data: dict[str, Any] = {
            "key": self.key,
            "display_name": self.display_name,
            "category": self.category,
            "description": self.description,
            "transport": self.transport,
            "enabled": self.enabled,
            "require_admin_unlock": self.require_admin_unlock,
            "formats": list(self.formats),
            "root_mode": self.root_mode,
        }
        if self.transport in ("http", "sse"):
            data["url"] = self.url
            if self.headers:
                data["headers"] = {
                    k: ("***" if mask_secrets else v) for k, v in self.headers
                }
        else:
            if self.command:
                data["command"] = list(self.command)
            if self.exe_path:
                data["exe_path"] = self.exe_path
            if self.extra_mcp_args:
                data["extra_mcp_args"] = list(self.extra_mcp_args)
            if self.cwd:
                data["cwd"] = self.cwd
            if self.env:
                data["env"] = {
                    k: ("***" if mask_secrets else v) for k, v in self.env
                }
        if self.source:
            data["source"] = self.source
        return data


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
            source="builtin",
        ),
    }


def _parse_kv_pairs(raw: Any) -> tuple[tuple[str, str], ...]:
    if not isinstance(raw, dict):
        return ()
    return tuple((str(k), str(v)) for k, v in raw.items() if str(k).strip())


def parse_plugin_entry(raw: dict[str, Any]) -> AppPluginSpec:
    key = str(raw["key"]).strip().lower()
    command = tuple(str(x) for x in (raw.get("command") or ()))
    exe_path = str(raw.get("exe_path") or "")
    root_mode = str(raw.get("root_mode") or "gateway_only")
    if root_mode not in ("automation", "short", "allow_path", "gateway_only"):
        root_mode = "gateway_only"
    transport = str(raw.get("transport") or "stdio").strip().lower()
    if transport not in ("stdio", "http", "sse"):
        transport = "stdio"
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
        transport=transport,  # type: ignore[arg-type]
        url=str(raw.get("url") or "").strip(),
        headers=_parse_kv_pairs(raw.get("headers")),
        env=_parse_kv_pairs(raw.get("env")),
        enabled=bool(raw.get("enabled", True)),
        require_admin_unlock=bool(raw.get("require_admin_unlock", False)),
        source=str(raw.get("source") or ""),
    )


def load_plugin_registry(cfg: GatewayConfig | None = None) -> dict[str, AppPluginSpec]:
    """Load built-in plugins plus user-defined MCP entries from apps.json (if present)."""
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
        spec = parse_plugin_entry(entry)
        plugins[spec.key] = spec
    return plugins


def save_plugin_manifest(specs: list[AppPluginSpec], manifest_path: Path) -> None:
    """Persist configured plugins (excluding unchanged builtin defaults unless customized) to apps.json."""
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "apps": [spec.to_manifest_dict(mask_secrets=False) for spec in specs if spec.source != "builtin"]
    }
    manifest_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


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
    """Return matching enabled plugin display names for a given file extension."""
    apps = registry if registry is not None else load_plugin_registry()
    e = ext.lower()
    if not e.startswith("."):
        e = f".{e}"
    return [spec.display_name for spec in apps.values() if spec.enabled and e in spec.formats]
