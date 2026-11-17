"""Safe filesystem helpers, image thumbnailing, and CloudSync publishing."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
import fnmatch
import hashlib
import io
import os
from pathlib import Path
import re
import shutil
import time
from typing import Iterable

from PIL import Image

from app_registry import suggest_apps_for_extension
from config import GatewayConfig

# Sensitive filenames never exposed to remote MCP reads/writes
BLOCKED_FILENAMES = {
    ".env",
    ".env.local",
    ".env.production",
    "credentials.json",
    "secrets.json",
    "id_rsa",
    "id_ed25519",
}
BLOCKED_DIR_NAMES = {".git", ".venv", "node_modules", "__pycache__"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif", ".tiff", ".tif"}


@dataclass(frozen=True)
class PathPolicy:
    """Path access policy enforcing read roots, write/output root, and CloudSync folder."""

    read_roots: tuple[Path, ...]
    write_root: Path
    cloud_sync_dir: Path
    gdrive_mirror_dir: Path | None = None

    @classmethod
    def from_env(cls, cfg: GatewayConfig | None = None) -> "PathPolicy":
        cfg = cfg or GatewayConfig.from_env(reload_dotenv=False)
        for root in cfg.read_roots:
            root.mkdir(parents=True, exist_ok=True)
        cfg.write_root.mkdir(parents=True, exist_ok=True)
        cfg.cloud_sync_dir.mkdir(parents=True, exist_ok=True)
        return cls(
            read_roots=cfg.read_roots,
            write_root=cfg.write_root,
            cloud_sync_dir=cfg.cloud_sync_dir,
            gdrive_mirror_dir=cfg.gdrive_mirror_dir,
        )

    @property
    def default_read_root(self) -> Path:
        return self.read_roots[0]

    def resolve_read_path(self, raw_path: str, *, unrestricted: bool = False) -> Path:
        """Resolve a user/agent path for reading; relative paths resolve against default_read_root."""
        candidate = _parse_candidate(raw_path, self.default_read_root)
        allowed_roots = (*self.read_roots, self.write_root, self.cloud_sync_dir)
        if not unrestricted and not _is_under_any(candidate, allowed_roots):
            roots_str = ", ".join(str(r) for r in allowed_roots)
            raise PermissionError(f"Read path '{candidate}' is outside allowed roots ({roots_str}).")
        if candidate.name.lower() in BLOCKED_FILENAMES:
            raise PermissionError(f"Access to sensitive file '{candidate.name}' is blocked.")
        return candidate

    def resolve_write_path(self, raw_path: str, *, unrestricted: bool = False) -> Path:
        """Resolve a user/agent path for writing; relative paths resolve against write_root."""
        candidate = _parse_candidate(raw_path, self.write_root)
        if not unrestricted and not _is_under_any(candidate, (self.write_root,)):
            raise PermissionError(
                f"Write path '{candidate}' is outside output directory '{self.write_root}'. "
                f"All generated/edited outputs must be saved inside '{self.write_root}'."
            )
        if candidate.name.lower() in BLOCKED_FILENAMES:
            raise PermissionError(f"Writing sensitive file '{candidate.name}' is blocked.")
        return candidate

    def resolve_cloud_target(self, filename: str, subfolder: str = "") -> Path:
        """Resolve destination inside CloudSync without allowing path traversal."""
        clean_sub = Path(subfolder.strip()) if subfolder and subfolder.strip() else Path()
        if clean_sub.is_absolute() or ".." in clean_sub.parts:
            raise PermissionError(f"Invalid CloudSync subfolder: '{subfolder}'")
        clean_name = Path(filename).name
        if not clean_name or clean_name in (".", ".."):
            raise ValueError(f"Invalid filename: '{filename}'")
        target = (self.cloud_sync_dir / clean_sub / clean_name).resolve()
        if not _is_under_any(target, (self.cloud_sync_dir,)):
            raise PermissionError(f"CloudSync path escapes '{self.cloud_sync_dir}'.")
        return target


def _parse_candidate(raw_path: str, base: Path) -> Path:
    cleaned = (raw_path or "").strip()
    if not cleaned:
        return base
    p = Path(cleaned)
    if not p.is_absolute():
        p = base / p
    return p.resolve()


def _is_under_any(target: Path, roots: Iterable[Path]) -> bool:
    for root in roots:
        try:
            target.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _is_hidden_or_blocked(path: Path) -> bool:
    name_lower = path.name.lower()
    if name_lower in BLOCKED_FILENAMES:
        return True
    if path.is_dir() and name_lower in BLOCKED_DIR_NAMES:
        return True
    return False


def compress_image_to_png_base64(
    raw_bytes: bytes,
    max_side: int = 1024,
    max_bytes: int = 850_000,
) -> dict:
    """Resize/optimize an image to PNG within max_side and max_bytes for MCP ImageContent."""
    max_side = max(64, min(max_side, 2048))
    with Image.open(io.BytesIO(raw_bytes)) as src:
        orig_w, orig_h = src.size
        img = src.convert("RGBA") if src.mode in ("RGBA", "LA", "P") else src.convert("RGB")

        side = max_side
        png_bytes = b""
        final_w, final_h = img.size

        for attempt_side in (side, min(side, 768), min(side, 512), 384):
            cur = img
            if max(cur.size) > attempt_side:
                cur = cur.copy()
                cur.thumbnail((attempt_side, attempt_side), Image.Resampling.LANCZOS)
            buf = io.BytesIO()
            cur.save(buf, format="PNG", optimize=True)
            png_bytes = buf.getvalue()
            final_w, final_h = cur.size
            if len(png_bytes) <= max_bytes:
                break

    return {
        "mime_type": "image/png",
        "data_base64": base64.b64encode(png_bytes).decode("ascii"),
        "width": final_w,
        "height": final_h,
        "original_width": orig_w,
        "original_height": orig_h,
        "png_bytes": len(png_bytes),
    }


def list_directory(
    policy: PathPolicy, path: str = "", recursive: bool = False, max_entries: int = 200, *, unrestricted: bool = False
) -> dict:
    """List directory contents under an allowed read root (or anywhere when unrestricted=True)."""
    target = policy.resolve_read_path(path, unrestricted=unrestricted)
    if not target.exists():
        raise FileNotFoundError(f"Path not found: {target}")
    if not target.is_dir():
        raise NotADirectoryError(f"Not a directory: {target}")

    entries: list[dict] = []
    truncated = False

    def _walk(current: Path, depth: int) -> None:
        nonlocal truncated
        try:
            items = sorted(current.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        except PermissionError:
            return
        for item in items:
            if _is_hidden_or_blocked(item):
                continue
            if len(entries) >= max_entries:
                truncated = True
                return
            stat = item.stat()
            entries.append({
                "name": item.name,
                "path": str(item),
                "type": "dir" if item.is_dir() else "file",
                "size_bytes": None if item.is_dir() else stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
            })
            if recursive and item.is_dir() and depth < 5:
                _walk(item, depth + 1)
                if truncated:
                    return

    _walk(target, 0)
    return {
        "directory": str(target),
        "write_output_root": str(policy.write_root),
        "cloud_sync_dir": str(policy.cloud_sync_dir),
        "count": len(entries),
        "truncated": truncated,
        "entries": entries,
    }


def search_files(
    policy: PathPolicy, pattern: str, folder: str = "", max_results: int = 100, *, unrestricted: bool = False
) -> dict:
    """Search files under allowed read roots (or anywhere when unrestricted=True) by glob or substring."""
    root = policy.resolve_read_path(folder, unrestricted=unrestricted)
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"Search folder not found: {root}")

    pat = (pattern or "*").strip()
    is_glob = any(ch in pat for ch in "*?[]")
    pat_lower = pat.lower()

    matches: list[dict] = []
    truncated = False

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in sorted(dirnames) if d.lower() not in BLOCKED_DIR_NAMES]
        for fname in sorted(filenames):
            if fname.lower() in BLOCKED_FILENAMES:
                continue
            matched = (
                fnmatch.fnmatch(fname.lower(), pat_lower)
                if is_glob
                else pat_lower in fname.lower()
            )
            if not matched:
                continue
            full = Path(dirpath) / fname
            stat = full.stat()
            matches.append({
                "name": fname,
                "path": str(full),
                "size_bytes": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
                "suggested_plugins": suggest_apps_for_extension(full.suffix),
            })
            if len(matches) >= max_results:
                truncated = True
                break
        if truncated:
            break

    return {
        "search_root": str(root),
        "pattern": pat,
        "count": len(matches),
        "truncated": truncated,
        "matches": matches,
    }


def _decode_text_bytes(raw: bytes) -> str:
    """Decode text file bytes trying UTF-8 first, then Traditional/Simplified Windows encodings."""
    for enc in ("utf-8", "utf-8-sig", "cp950", "gbk", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def read_text_file(
    policy: PathPolicy, path: str, start_line: int = 1, max_lines: int = 200, *, unrestricted: bool = False
) -> dict:
    """Read a UTF-8/text file under allowed read roots (or anywhere when unrestricted=True) with line numbering."""
    target = policy.resolve_read_path(path, unrestricted=unrestricted)
    if not target.exists():
        raise FileNotFoundError(f"File not found: {target}")
    if target.is_dir():
        raise IsADirectoryError(f"Path is a directory: {target}")

    start_line = max(1, start_line)
    max_lines = max(1, min(max_lines, 500))

    raw = target.read_bytes()
    if b"\x00" in raw[:4096]:
        raise ValueError(
            f"'{target.name}' appears to be a binary file ({target.suffix}). "
            f"Suggested plugins: {suggest_apps_for_extension(target.suffix) or ['use file info']}."
        )

    text = _decode_text_bytes(raw)

    lines = text.splitlines()
    total_lines = len(lines)
    slice_lines = lines[start_line - 1 : start_line - 1 + max_lines]
    numbered = "\n".join(f"{start_line + idx}: {line}" for idx, line in enumerate(slice_lines))

    return {
        "path": str(target),
        "total_lines": total_lines,
        "start_line": start_line,
        "returned_lines": len(slice_lines),
        "has_more": (start_line - 1 + len(slice_lines)) < total_lines,
        "content": numbered,
    }


def preview_image_file(
    policy: PathPolicy, path: str, max_side: int = 1024, *, unrestricted: bool = False
) -> dict:
    """Load an image and return compressed PNG base64 + metadata."""
    target = policy.resolve_read_path(path, unrestricted=unrestricted)
    if not target.exists():
        raise FileNotFoundError(f"Image not found: {target}")
    if target.is_dir():
        raise IsADirectoryError(f"Path is a directory: {target}")
    if target.suffix.lower() not in IMAGE_EXTENSIONS:
        raise ValueError(f"Unsupported image extension '{target.suffix}'. Supported: {sorted(IMAGE_EXTENSIONS)}")

    compressed = compress_image_to_png_base64(target.read_bytes(), max_side=max_side)
    compressed["path"] = str(target)
    compressed["name"] = target.name
    return compressed


def get_file_info(policy: PathPolicy, path: str, *, unrestricted: bool = False) -> dict:
    """Return metadata and compatible plugins for a file or directory."""
    target = policy.resolve_read_path(path, unrestricted=unrestricted)
    if not target.exists():
        raise FileNotFoundError(f"Path not found: {target}")
    stat = target.stat()
    return {
        "path": str(target),
        "name": target.name,
        "type": "dir" if target.is_dir() else "file",
        "extension": target.suffix.lower() if target.is_file() else None,
        "size_bytes": None if target.is_dir() else stat.st_size,
        "created": datetime.fromtimestamp(stat.st_ctime).isoformat(timespec="seconds"),
        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
        "suggested_plugins": suggest_apps_for_extension(target.suffix) if target.is_file() else [],
        "writable": unrestricted or _is_under_any(target, (policy.write_root,)),
    }


def write_output_file(
    policy: PathPolicy, path: str, content: str, overwrite: bool = False, *, unrestricted: bool = False
) -> dict:
    """Write text content strictly inside COOP_WRITE_ROOT (or anywhere when unrestricted=True)."""
    target = policy.resolve_write_path(path, unrestricted=unrestricted)
    if target.exists() and not overwrite:
        raise FileExistsError(
            f"File already exists: {target}. Pass overwrite=True to replace it."
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return {
        "status": "written",
        "path": str(target),
        "bytes": target.stat().st_size,
    }


def edit_output_file(
    policy: PathPolicy,
    path: str,
    target: str,
    replacement: str,
    replace_all: bool = False,
    *,
    unrestricted: bool = False,
) -> dict:
    """Replace exact text in an existing file inside COOP_WRITE_ROOT (or anywhere when unrestricted=True)."""
    if not target:
        raise ValueError("target text must not be empty.")
    out_file = policy.resolve_write_path(path, unrestricted=unrestricted)
    if not out_file.exists():
        raise FileNotFoundError(f"File not found: {out_file}")
    if out_file.is_dir():
        raise IsADirectoryError(f"Path is a directory: {out_file}")

    raw = out_file.read_bytes()
    if b"\x00" in raw[:4096]:
        raise ValueError(f"Cannot text-edit binary file: {out_file.name}")

    content = _decode_text_bytes(raw)
    occurrences = content.count(target)
    if occurrences == 0:
        raise ValueError(f"Target text not found in {out_file.name}.")
    if occurrences > 1 and not replace_all:
        raise ValueError(
            f"Target text matched {occurrences} times in {out_file.name}; "
            "include more surrounding context or pass replace_all=True."
        )

    new_content = content.replace(target, replacement) if replace_all else content.replace(target, replacement, 1)
    out_file.write_text(new_content, encoding="utf-8")
    return {
        "status": "edited",
        "path": str(out_file),
        "replacements": occurrences if replace_all else 1,
        "bytes": out_file.stat().st_size,
    }


def search_text_in_files(
    policy: PathPolicy,
    query: str,
    folder: str = "",
    file_glob: str = "*",
    case_sensitive: bool = False,
    regex: bool = False,
    max_matches: int = 80,
    *,
    unrestricted: bool = False,
) -> dict:
    """Search inside text file contents under allowed read roots (or anywhere when unrestricted=True)."""
    if not query or not query.strip():
        raise ValueError("query must not be empty.")
    root = policy.resolve_read_path(folder, unrestricted=unrestricted)
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"Search folder not found: {root}")

    max_matches = max(1, min(int(max_matches), 200))
    glob_pat = (file_glob or "*").strip().lower()
    flags = 0 if case_sensitive else re.IGNORECASE
    pattern = re.compile(query if regex else re.escape(query), flags)

    matches: list[dict] = []
    files_scanned = 0
    truncated = False

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in sorted(dirnames) if d.lower() not in BLOCKED_DIR_NAMES]
        for fname in sorted(filenames):
            if fname.lower() in BLOCKED_FILENAMES:
                continue
            if glob_pat != "*" and not fnmatch.fnmatch(fname.lower(), glob_pat):
                continue
            full = Path(dirpath) / fname
            try:
                if full.stat().st_size > 2_000_000:
                    continue
                raw = full.read_bytes()
            except OSError:
                continue
            if b"\x00" in raw[:4096]:
                continue
            files_scanned += 1
            text = _decode_text_bytes(raw)
            for line_no, line in enumerate(text.splitlines(), start=1):
                if pattern.search(line):
                    matches.append({
                        "path": str(full),
                        "line": line_no,
                        "preview": line[:240],
                    })
                    if len(matches) >= max_matches:
                        truncated = True
                        break
            if truncated:
                break
        if truncated:
            break

    return {
        "search_root": str(root),
        "query": query,
        "files_scanned": files_scanned,
        "match_count": len(matches),
        "truncated": truncated,
        "matches": matches,
    }


def manage_output_path(
    policy: PathPolicy,
    action: str,
    path: str,
    destination: str = "",
    overwrite: bool = False,
    *,
    unrestricted: bool = False,
) -> dict:
    """Move/rename, copy, or delete files within COOP_WRITE_ROOT (or anywhere when unrestricted=True)."""
    act = (action or "").strip().lower()
    if act == "rename":
        act = "move"
    if act not in ("move", "copy", "delete"):
        raise ValueError("action must be one of: 'move', 'rename', 'copy', 'delete'.")

    protected = {policy.write_root.resolve(), policy.cloud_sync_dir.resolve()}

    if act == "copy":
        src = policy.resolve_read_path(path, unrestricted=unrestricted)
        if not src.exists():
            raise FileNotFoundError(f"Source path not found: {src}")
        if not destination.strip():
            raise ValueError("destination is required for 'copy'.")
        dest = policy.resolve_write_path(destination, unrestricted=unrestricted)
        if dest.exists() and not overwrite:
            raise FileExistsError(f"Destination already exists: {dest}. Pass overwrite=True to replace.")
        dest.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, dest, dirs_exist_ok=overwrite)
        else:
            shutil.copy2(src, dest)
        return {"status": "copied", "source": str(src), "destination": str(dest)}

    src_write = policy.resolve_write_path(path, unrestricted=unrestricted)
    if src_write.resolve() in protected:
        raise PermissionError(f"Protected directory cannot be modified or removed: {src_write}")
    if not src_write.exists():
        raise FileNotFoundError(f"Path not found: {src_write}")

    if act == "move":
        if not destination.strip():
            raise ValueError("destination is required for 'move'.")
        dest = policy.resolve_write_path(destination, unrestricted=unrestricted)
        if dest.exists():
            if not overwrite:
                raise FileExistsError(f"Destination already exists: {dest}. Pass overwrite=True to replace.")
            if dest.is_dir():
                shutil.rmtree(dest)
            else:
                dest.unlink()
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src_write), str(dest))
        return {"status": "moved", "source": str(src_write), "destination": str(dest)}

    if src_write.is_dir():
        shutil.rmtree(src_write)
    else:
        src_write.unlink()
    return {"status": "deleted", "path": str(src_write)}


def make_output_dir(policy: PathPolicy, path: str, *, unrestricted: bool = False) -> dict:
    """Create a directory inside COOP_WRITE_ROOT (or anywhere when unrestricted=True)."""
    target = policy.resolve_write_path(path, unrestricted=unrestricted)
    target.mkdir(parents=True, exist_ok=True)
    return {
        "status": "ready",
        "directory": str(target),
    }


def _wait_until_unlocked(path: Path, expected_size: int, timeout_seconds: float) -> bool:
    """Poll until the copied file has stable size and can be opened without sharing violation."""
    deadline = time.monotonic() + max(1.0, timeout_seconds)
    stable_hits = 0
    while time.monotonic() < deadline:
        try:
            cur_size = path.stat().st_size
            with open(path, "r+b"):
                pass
            if cur_size == expected_size:
                stable_hits += 1
                if stable_hits >= 2:
                    return True
            else:
                stable_hits = 0
        except OSError:
            stable_hits = 0
        time.sleep(0.15)
    return False


def publish_to_cloud(
    policy: PathPolicy,
    local_path: str,
    subfolder: str = "",
    overwrite: bool = True,
    timeout_seconds: float = 15.0,
    *,
    unrestricted: bool = False,
) -> dict:
    """Copy a local deliverable into CloudSync (and optional mirror directory) and verify unlock."""
    src = policy.resolve_read_path(local_path, unrestricted=unrestricted)
    if not src.exists():
        raise FileNotFoundError(f"Source file not found: {src}")
    if src.is_dir():
        raise IsADirectoryError(f"Expected a file, got directory: {src}")

    dest = policy.resolve_cloud_target(src.name, subfolder=subfolder)
    if dest.exists() and not overwrite:
        raise FileExistsError(f"Destination already exists in CloudSync: {dest}")

    dest.parent.mkdir(parents=True, exist_ok=True)
    if src.resolve() != dest.resolve():
        shutil.copy2(src, dest)

    expected_size = src.stat().st_size
    unlocked = _wait_until_unlocked(dest, expected_size, timeout_seconds=timeout_seconds)

    mirror_path_str: str | None = None
    mirror_unlocked: bool | None = None
    mirror_error: str | None = None

    if policy.gdrive_mirror_dir is not None:
        try:
            clean_sub = Path(subfolder.strip()) if subfolder and subfolder.strip() else Path()
            if clean_sub.is_absolute() or ".." in clean_sub.parts:
                raise PermissionError(f"Invalid mirror subfolder: '{subfolder}'")
            mirror_dir = policy.gdrive_mirror_dir / clean_sub
            mirror_dir.mkdir(parents=True, exist_ok=True)
            mirror_dest = mirror_dir / src.name
            shutil.copy2(src, mirror_dest)
            mirror_unlocked = _wait_until_unlocked(mirror_dest, expected_size, timeout_seconds=timeout_seconds)
            mirror_path_str = str(mirror_dest)
        except Exception as exc:
            mirror_error = str(exc)

    sha256 = hashlib.sha256(dest.read_bytes()).hexdigest()
    stat = dest.stat()

    if mirror_path_str and mirror_unlocked:
        sync_status = "ready_in_cloudsync_and_mirror"
        sync_note = (
            f"File saved, unlocked, and mirrored to {mirror_path_str} and local CloudSync."
        )
    elif unlocked:
        sync_status = "ready_in_local_cloudsync"
        sync_note = f"File copied and unlocked at {dest}; ready for cloud sync client upload."
    else:
        sync_status = "copied_wait_timeout"
        sync_note = f"File copied to {dest}, but lock release check timed out."

    result: dict = {
        "status": "published",
        "filename": dest.name,
        "source_path": str(src),
        "cloud_sync_path": str(dest),
        "cloud_sync_dir": str(policy.cloud_sync_dir),
        "size_bytes": stat.st_size,
        "sha256": sha256,
        "file_unlocked": unlocked,
        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
        "sync_status": sync_status,
        "sync_note": sync_note,
    }
    if mirror_path_str:
        result["mirror_path"] = mirror_path_str
        result["mirror_unlocked"] = mirror_unlocked
    if mirror_error:
        result["mirror_error"] = mirror_error
    return result
