"""Opt-in local MCP discovery across desktop AI configs, custom folders, and starter templates."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
from typing import Any

from app_registry import AppPluginSpec
from config import APP_DIR

ARTCRAFT_PRESET_PATH = APP_DIR / "presets" / "artcraft.json"


def load_artcraft_profiles() -> dict[str, dict[str, Any]]:
    """Load ArtCraft CLI fingerprint profiles (without hardcoding any local install path)."""
    if not ARTCRAFT_PRESET_PATH.exists():
        return {}
    try:
        data = json.loads(ARTCRAFT_PRESET_PATH.read_text(encoding="utf-8-sig"))
        profiles: dict[str, dict[str, Any]] = {}
        for item in data.get("apps", []):
            if isinstance(item, dict) and item.get("key"):
                profiles[str(item["key"]).lower()] = item
        return profiles
    except Exception:
        return {}


def _slugify_key(name: str) -> str:
    cleaned = re.sub(r"[^a-z0-9_-]+", "-", name.strip().lower()).strip("-")
    return cleaned or "plugin"


def default_client_config_locations() -> list[tuple[str, Path]]:
    """Return well-known desktop AI MCP config file locations on the current OS."""
    home = Path.home()
    appdata = Path(os.getenv("APPDATA", str(home / "AppData" / "Roaming")))
    candidates: list[tuple[str, Path]] = [
        ("claude_desktop", appdata / "Claude" / "claude_desktop_config.json"),
        ("cursor", home / ".cursor" / "mcp.json"),
        ("windsurf", home / ".codeium" / "windsurf" / "mcp_config.json"),
        ("vscode", appdata / "Code" / "User" / "mcp.json"),
        ("gemini_cli", home / ".gemini" / "settings.json"),
        ("antigravity", home / ".gemini" / "antigravity" / "mcp_config.json"),
    ]
    return candidates


def parse_mcp_servers_file(
    path: Path,
    source_label: str,
    *,
    mask_secrets: bool = True,
) -> list[dict[str, Any]]:
    """Parse standard `mcpServers` / `servers` JSON config into opt-in candidate descriptors."""
    if not path.exists() or not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return []
    if not isinstance(data, dict):
        return []

    raw_servers = data.get("mcpServers") or data.get("servers") or {}
    if not isinstance(raw_servers, dict):
        return []

    results: list[dict[str, Any]] = []
    for raw_name, cfg in raw_servers.items():
        if not isinstance(cfg, dict):
            continue
        if cfg.get("disabled") is True:
            continue

        key = _slugify_key(str(raw_name))
        url = str(cfg.get("url") or cfg.get("serverUrl") or "").strip()
        cmd = str(cfg.get("command") or "").strip()
        args = [str(a) for a in (cfg.get("args") or [])]

        risky_hint = any(
            tok in (f"{raw_name} {cmd} {' '.join(args)} {url}").lower()
            for tok in ("shell", "bash", "powershell", "terminal", "filesystem", "cmd", "exec")
        )

        if url:
            raw_type = str(cfg.get("type") or cfg.get("transport") or "").lower()
            transport = "sse" if raw_type == "sse" or url.rstrip("/").endswith("/sse") else "http"
            headers = cfg.get("headers") if isinstance(cfg.get("headers"), dict) else {}
            spec_dict: dict[str, Any] = {
                "key": key,
                "display_name": str(raw_name),
                "category": f"Imported ({source_label})",
                "description": f"Imported {transport.upper()} MCP endpoint from {path.name}",
                "transport": transport,
                "url": url,
                "headers": {str(k): ("***" if mask_secrets else str(v)) for k, v in headers.items()},
                "enabled": True,
                "require_admin_unlock": risky_hint,
                "source": source_label,
                "origin_file": str(path),
                "has_secrets": bool(headers),
            }
            results.append(spec_dict)
        elif cmd:
            env = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
            spec_dict = {
                "key": key,
                "display_name": str(raw_name),
                "category": f"Imported ({source_label})",
                "description": f"Imported stdio MCP server from {path.name}",
                "transport": "stdio",
                "command": [cmd, *args],
                "env": {str(k): ("***" if mask_secrets else str(v)) for k, v in env.items()},
                "root_mode": "gateway_only",
                "enabled": True,
                "require_admin_unlock": risky_hint,
                "source": source_label,
                "origin_file": str(path),
                "has_secrets": bool(env),
            }
            results.append(spec_dict)

    return results


def scan_folder_for_mcp(folder: Path) -> list[dict[str, Any]]:
    """Scan a user-chosen folder (depth <= 2) for .mcp.json manifests or *-cli.exe apps."""
    root = folder.expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"Scan folder not found: {root}")

    candidates: list[dict[str, Any]] = []
    seen_keys: set[str] = set()

    for manifest_name in (".mcp.json", "mcp.json"):
        for mf in root.glob(manifest_name):
            for item in parse_mcp_servers_file(mf, "folder_manifest", mask_secrets=True):
                if item["key"] not in seen_keys:
                    seen_keys.add(item["key"])
                    candidates.append(item)
        for mf in root.glob(f"*/{manifest_name}"):
            for item in parse_mcp_servers_file(mf, "folder_manifest", mask_secrets=True):
                if item["key"] not in seen_keys:
                    seen_keys.add(item["key"])
                    candidates.append(item)

    artcraft_profiles = load_artcraft_profiles()
    cli_bins = list(root.glob("*-cli.exe")) + list(root.glob("*/*-cli.exe"))
    if os.name != "nt":
        cli_bins += list(root.glob("*-cli")) + list(root.glob("*/*-cli"))
    for exe in sorted(set(cli_bins)):
        stem = exe.stem.removesuffix("-cli")
        key = _slugify_key(stem)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        ac = artcraft_profiles.get(key)
        if ac:
            candidates.append({
                "key": key,
                "display_name": ac.get("display_name", stem),
                "category": f"ArtCraft ({ac.get('category', 'App')})",
                "description": ac.get("description", f"Detected ArtCraft CLI ({exe.name})."),
                "transport": "stdio",
                "exe_path": str(exe),
                "formats": list(ac.get("formats", ())),
                "root_mode": ac.get("root_mode", "gateway_only"),
                "extra_mcp_args": list(ac.get("extra_mcp_args", ())),
                "enabled": True,
                "require_admin_unlock": False,
                "source": "artcraft_folder",
                "origin_file": str(exe),
                "has_secrets": False,
            })
        else:
            candidates.append({
                "key": key,
                "display_name": stem,
                "category": "Local CLI App",
                "description": f"Detected CLI binary ({exe.name}); verify it supports `mcp` stdio subcommand before enabling.",
                "transport": "stdio",
                "exe_path": str(exe),
                "root_mode": "gateway_only",
                "enabled": True,
                "require_admin_unlock": False,
                "source": "folder_cli",
                "origin_file": str(exe),
                "has_secrets": False,
            })

    return candidates


def detect_artcraft_on_path() -> list[dict[str, Any]]:
    """Detect ArtCraft *-cli binaries installed on PATH."""
    found: list[dict[str, Any]] = []
    for key, ac in load_artcraft_profiles().items():
        exe_name = str(ac.get("exe_name") or f"{key}-cli")
        resolved = shutil.which(exe_name) or shutil.which(f"{exe_name}.exe")
        if not resolved:
            continue
        found.append({
            "key": key,
            "display_name": ac.get("display_name", key),
            "category": f"ArtCraft ({ac.get('category', 'App')})",
            "description": ac.get("description", ""),
            "transport": "stdio",
            "exe_path": resolved,
            "formats": list(ac.get("formats", ())),
            "root_mode": ac.get("root_mode", "gateway_only"),
            "extra_mcp_args": list(ac.get("extra_mcp_args", ())),
            "enabled": True,
            "require_admin_unlock": False,
            "source": "artcraft_path",
            "origin_file": resolved,
            "has_secrets": False,
        })
    return found


def starter_templates() -> list[dict[str, Any]]:
    """Return starter MCP templates with local runtime availability flags (uvx / npx)."""
    has_uvx = shutil.which("uvx") is not None
    has_npx = shutil.which("npx") is not None
    return [
        {
            "key": "sqlite",
            "display_name": "SQLite",
            "category": "Starter Template",
            "description": "Query and inspect a local SQLite database inside ./workspace.",
            "transport": "stdio",
            "command": ["uvx", "mcp-server-sqlite", "--db-path", "./workspace/sample.db"],
            "formats": [".db", ".sqlite"],
            "root_mode": "gateway_only",
            "enabled": True,
            "require_admin_unlock": False,
            "source": "template",
            "runtime_available": has_uvx,
            "runtime_hint": "uvx",
        },
        {
            "key": "fetch",
            "display_name": "Web Fetch",
            "category": "Starter Template",
            "description": "Fetch and convert web pages to markdown cleanly.",
            "transport": "stdio",
            "command": ["uvx", "mcp-server-fetch"],
            "formats": [],
            "root_mode": "gateway_only",
            "enabled": True,
            "require_admin_unlock": False,
            "source": "template",
            "runtime_available": has_uvx,
            "runtime_hint": "uvx",
        },
        {
            "key": "git",
            "display_name": "Git Inspector",
            "category": "Starter Template",
            "description": "Read git status, diffs, and logs for a repository inside your workspace.",
            "transport": "stdio",
            "command": ["uvx", "mcp-server-git", "--repository", "./workspace"],
            "formats": [],
            "root_mode": "gateway_only",
            "enabled": True,
            "require_admin_unlock": False,
            "source": "template",
            "runtime_available": has_uvx,
            "runtime_hint": "uvx",
        },
        {
            "key": "memory",
            "display_name": "Knowledge Graph Memory",
            "category": "Starter Template",
            "description": "Persistent local entity/relation memory MCP via npx.",
            "transport": "stdio",
            "command": ["npx", "-y", "@modelcontextprotocol/server-memory"],
            "formats": [],
            "root_mode": "gateway_only",
            "enabled": True,
            "require_admin_unlock": False,
            "source": "template",
            "runtime_available": has_npx,
            "runtime_hint": "npx",
        },
    ]


def discover_local_mcps(
    *,
    extra_config_paths: list[Path] | None = None,
    scan_folder: Path | None = None,
    mask_secrets: bool = True,
) -> dict[str, Any]:
    """Discover candidate MCP servers across known AI clients, optional folder, and starter templates."""
    locations = [(label, path) for label, path in default_client_config_locations()]
    if extra_config_paths:
        for p in extra_config_paths:
            locations.append(("custom_config", p))

    scanned_sources: list[dict[str, Any]] = []
    client_candidates: list[dict[str, Any]] = []

    for label, path in locations:
        exists = path.exists() and path.is_file()
        found = parse_mcp_servers_file(path, label, mask_secrets=mask_secrets) if exists else []
        scanned_sources.append({
            "source": label,
            "path": str(path),
            "exists": exists,
            "count": len(found),
        })
        client_candidates.extend(found)

    folder_candidates: list[dict[str, Any]] = []
    folder_error = ""
    if scan_folder is not None and str(scan_folder).strip():
        try:
            folder_candidates = scan_folder_for_mcp(scan_folder)
        except Exception as exc:
            folder_error = str(exc)

    path_artcraft = detect_artcraft_on_path()
    seen_folder_keys = {c["key"] for c in folder_candidates}
    for item in path_artcraft:
        if item["key"] not in seen_folder_keys:
            folder_candidates.append(item)

    return {
        "scanned_sources": scanned_sources,
        "client_candidates": client_candidates,
        "folder_candidates": folder_candidates,
        "folder_error": folder_error,
        "templates": starter_templates(),
    }


def resolve_unmasked_candidate(candidate_key: str, source: str, origin_file: str = "") -> AppPluginSpec | None:
    """Re-read an unmasked candidate from its original config file when the user confirms opt-in import."""
    if source == "template":
        for tmpl in starter_templates():
            if tmpl["key"] == candidate_key:
                from app_registry import parse_plugin_entry
                return parse_plugin_entry(tmpl)
        return None

    if origin_file:
        p = Path(origin_file)
        if p.is_file() and p.suffix.lower() == ".json":
            for item in parse_mcp_servers_file(p, source, mask_secrets=False):
                if item["key"] == candidate_key:
                    from app_registry import parse_plugin_entry
                    return parse_plugin_entry(item)
    return None
