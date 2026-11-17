"""Centralized configuration and path discovery for CoopMCP Gateway."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil

from dotenv import load_dotenv

APP_DIR = Path(__file__).resolve().parent
ASSETS_DIR = APP_DIR / "assets"
LOGS_DIR = APP_DIR / "logs"
ENV_PATH = APP_DIR / ".env"
ENV_EXAMPLE_PATH = APP_DIR / ".env.example"
SKILL_PATH = APP_DIR / "COOP_SKILL.md"
ADMIN_EPOCH_PATH = LOGS_DIR / ".admin_epoch"

DEFAULT_PUBLIC_URL = "http://127.0.0.1:8089"
DEFAULT_WORKSPACE_DIR = APP_DIR / "workspace"


def detect_blender_exe() -> Path:
    """Resolve Blender executable from env, newest installed Blender directory, or PATH."""
    override = os.getenv("COOP_BLENDER_EXE", "").strip()
    if override:
        return Path(override)

    program_files = Path(os.getenv("ProgramFiles", r"C:\Program Files"))
    blender_root = program_files / "Blender Foundation"
    if blender_root.exists():
        candidates = sorted(
            blender_root.glob("Blender */blender.exe"),
            key=lambda p: p.parent.name,
            reverse=True,
        )
        if candidates:
            return candidates[0]

    on_path = shutil.which("blender")
    if on_path:
        return Path(on_path)

    return blender_root / "Blender 5.1" / "blender.exe"


def _parse_bool(raw: str | None, default: bool) -> bool:
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class GatewayConfig:
    """Typed runtime configuration loaded from .env and environment variables."""

    host: str
    port: int
    public_url: str
    public_domain: str
    secret_key: str

    tunnel_mode: str
    ssh_host: str
    ssh_user: str
    ssh_key: str
    ssh_remote_port: int

    read_roots: tuple[Path, ...]
    write_root: Path
    cloud_sync_dir: Path
    gdrive_mirror_dir: Path | None
    apps_config_path: Path
    idle_timeout: int

    blender_exe: Path
    blender_host: str
    blender_port: int
    blender_headless_port: int
    blender_token: str

    require_oauth: bool
    oauth_client_id: str
    oauth_client_secret: str
    oauth_jwt_secret: str
    oauth_password_hash: str
    oauth_password_plain: str
    oauth_extra_redirect_hosts: tuple[str, ...]

    admin_pin_hash: str
    admin_pin_plain: str
    admin_token_ttl: int

    @classmethod
    def from_env(cls, *, reload_dotenv: bool = True) -> "GatewayConfig":
        if reload_dotenv and ENV_PATH.exists():
            load_dotenv(ENV_PATH, override=True, encoding="utf-8")

        public_url = (os.getenv("PUBLIC_URL") or DEFAULT_PUBLIC_URL).strip().rstrip("/")
        domain = public_url.removeprefix("https://").removeprefix("http://").split("/")[0]

        raw_reads = os.getenv("COOP_READ_ROOTS", "").strip()
        if raw_reads:
            read_roots = tuple(Path(p.strip()).resolve() for p in raw_reads.split(",") if p.strip())
        else:
            read_roots = (DEFAULT_WORKSPACE_DIR.resolve(),)

        raw_write = os.getenv("COOP_WRITE_ROOT", "").strip()
        write_root = Path(raw_write).resolve() if raw_write else (read_roots[0] / "output").resolve()

        raw_cloud = os.getenv("COOP_CLOUD_SYNC_DIR", "").strip()
        cloud_sync_dir = Path(raw_cloud).resolve() if raw_cloud else (write_root / "CloudSync").resolve()

        raw_mirror = os.getenv("COOP_GDRIVE_MIRROR_DIR", "").strip()
        gdrive_mirror_dir = Path(raw_mirror).resolve() if raw_mirror else None

        raw_apps_cfg = os.getenv("COOP_APPS_CONFIG", "apps.json").strip() or "apps.json"
        apps_cfg_path = Path(raw_apps_cfg)
        if not apps_cfg_path.is_absolute():
            apps_cfg_path = (APP_DIR / apps_cfg_path).resolve()

        raw_extra_hosts = os.getenv("COOP_OAUTH_ALLOWED_REDIRECT_HOSTS", "").strip()
        extra_hosts = tuple(h.strip().lower() for h in raw_extra_hosts.split(",") if h.strip())

        return cls(
            host=os.getenv("HOST", "127.0.0.1").strip() or "127.0.0.1",
            port=int(os.getenv("PORT", "8089") or "8089"),
            public_url=public_url,
            public_domain=domain,
            secret_key=os.getenv("MCP_SECRET_KEY", "").strip(),
            tunnel_mode=(os.getenv("COOP_TUNNEL_MODE", "cloudflared").strip().lower() or "cloudflared"),
            ssh_host=os.getenv("COOP_SSH_HOST", "").strip(),
            ssh_user=os.getenv("COOP_SSH_USER", "ubuntu").strip() or "ubuntu",
            ssh_key=os.getenv("COOP_SSH_KEY", "").strip(),
            ssh_remote_port=int(os.getenv("COOP_SSH_REMOTE_PORT", "18089") or "18089"),
            read_roots=read_roots,
            write_root=write_root,
            cloud_sync_dir=cloud_sync_dir,
            gdrive_mirror_dir=gdrive_mirror_dir,
            apps_config_path=apps_cfg_path,
            idle_timeout=int(os.getenv("COOP_IDLE_TIMEOUT", "900") or "900"),
            blender_exe=detect_blender_exe(),
            blender_host=os.getenv("COOP_BLENDER_HOST", "127.0.0.1").strip() or "127.0.0.1",
            blender_port=int(os.getenv("COOP_BLENDER_PORT", "9877") or "9877"),
            blender_headless_port=int(os.getenv("COOP_BLENDER_HEADLESS_PORT", "9878") or "9878"),
            blender_token=os.getenv("COOP_BLENDER_TOKEN", "").strip(),
            require_oauth=_parse_bool(os.getenv("COOP_REQUIRE_OAUTH"), True),
            oauth_client_id=os.getenv("COOP_OAUTH_CLIENT_ID", "coop-mcp-client").strip() or "coop-mcp-client",
            oauth_client_secret=os.getenv("COOP_OAUTH_CLIENT_SECRET", "").strip(),
            oauth_jwt_secret=os.getenv("COOP_OAUTH_JWT_SECRET", "").strip(),
            oauth_password_hash=os.getenv("COOP_OAUTH_PASSWORD_HASH", "").strip(),
            oauth_password_plain=os.getenv("COOP_OAUTH_PASSWORD", "").strip(),
            oauth_extra_redirect_hosts=extra_hosts,
            admin_pin_hash=os.getenv("COOP_ADMIN_PIN_HASH", "").strip(),
            admin_pin_plain=os.getenv("COOP_ADMIN_PIN", "").strip(),
            admin_token_ttl=max(60, min(int(os.getenv("COOP_ADMIN_TOKEN_TTL", "3600") or "3600"), 3600)),
        )
