"""Windows System Tray controller for CoopMCP Gateway + SSH/Cloudflared/Ngrok tunnel."""

from __future__ import annotations

import ctypes
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser

from PIL import Image
import pystray
from pystray import Menu, MenuItem

from config import APP_DIR, ASSETS_DIR, ENV_EXAMPLE_PATH, ENV_PATH, LOGS_DIR, GatewayConfig

CHICK_PNG = ASSETS_DIR / "chick.png"
CHICK_ICO = ASSETS_DIR / "chick.ico"

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
MUTEX_NAME = "Global\\CoopMcpTrayMutex"

LOGS_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("coop.tray")
logger.setLevel(logging.INFO)
_handler = RotatingFileHandler(LOGS_DIR / "tray.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8")
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
logger.addHandler(_handler)


def ensure_single_instance() -> int | None:
    """Acquire a Windows named mutex; returns handle or None if already running."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.CreateMutexW(None, False, MUTEX_NAME)
    if not handle:
        return None
    if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
        kernel32.CloseHandle(handle)
        return None
    return handle


def ensure_ico_from_png() -> None:
    """Create multi-size chick.ico from chick.png if needed."""
    if not CHICK_PNG.exists():
        return
    if CHICK_ICO.exists() and CHICK_ICO.stat().st_mtime >= CHICK_PNG.stat().st_mtime:
        return
    with Image.open(CHICK_PNG) as img:
        rgba = img.convert("RGBA")
        rgba.save(
            CHICK_ICO,
            format="ICO",
            sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (256, 256)],
        )


def ensure_env_config() -> dict[str, str]:
    """Ensure .env exists in UTF-8 without BOM and contains MCP_SECRET_KEY."""
    if not ENV_PATH.exists() and ENV_EXAMPLE_PATH.exists():
        ENV_PATH.write_text(ENV_EXAMPLE_PATH.read_text(encoding="utf-8"), encoding="utf-8")

    lines = ENV_PATH.read_text(encoding="utf-8-sig").splitlines() if ENV_PATH.exists() else []

    has_key = any(line.startswith("MCP_SECRET_KEY=") and line.split("=", 1)[1].strip() for line in lines)
    if not has_key:
        new_key = f"coop_key_{secrets.token_urlsafe(18)}"
        updated = False
        out_lines = []
        for line in lines:
            if line.startswith("MCP_SECRET_KEY="):
                out_lines.append(f"MCP_SECRET_KEY={new_key}")
                updated = True
            else:
                out_lines.append(line)
        if not updated:
            out_lines.append(f"MCP_SECRET_KEY={new_key}")
        ENV_PATH.write_text("\n".join(out_lines) + "\n", encoding="utf-8")

    gcfg = GatewayConfig.from_env(reload_dotenv=True)
    return {
        "secret_key": gcfg.secret_key,
        "public_url": gcfg.public_url,
        "public_domain": gcfg.public_domain,
        "host": gcfg.host,
        "port": str(gcfg.port),
        "write_root": str(gcfg.write_root),
        "tunnel_mode": gcfg.tunnel_mode,
        "ssh_host": gcfg.ssh_host,
        "ssh_user": gcfg.ssh_user,
        "ssh_key": gcfg.ssh_key,
        "ssh_remote_port": str(gcfg.ssh_remote_port),
        "require_oauth": "true" if gcfg.require_oauth else "false",
        "oauth_client_id": gcfg.oauth_client_id,
    }


def find_ssh_exe() -> str | None:
    for candidate in (
        shutil.which("ssh"),
        r"C:\Windows\System32\OpenSSH\ssh.exe",
    ):
        if candidate and Path(candidate).exists():
            return candidate
    return None


def find_cloudflared_exe() -> str | None:
    for candidate in (
        shutil.which("cloudflared"),
        r"C:\Program Files (x86)\cloudflared\cloudflared.exe",
        r"C:\Program Files\cloudflared\cloudflared.exe",
    ):
        if candidate and Path(candidate).exists():
            return candidate
    return None


def find_ngrok_exe() -> str | None:
    for candidate in (
        shutil.which("ngrok"),
        str(Path.home() / r"AppData\Local\Microsoft\WinGet\Links\ngrok.exe"),
    ):
        if candidate and Path(candidate).exists():
            return candidate
    return None


def copy_to_clipboard(text: str) -> None:
    """Copy UTF-8/Unicode string to clipboard without flashing a console."""
    subprocess.run(
        ["clip.exe"],
        input=text.encode("utf-16le"),
        check=False,
        creationflags=CREATE_NO_WINDOW,
    )


class CoopTrayController:
    """Supervises server.py + reverse tunnel and manages the system tray icon."""

    def __init__(self) -> None:
        self.cfg = ensure_env_config()
        self.stop_event = threading.Event()
        self.proc_lock = threading.Lock()
        self.server_proc: subprocess.Popen | None = None
        self.tunnel_proc: subprocess.Popen | None = None
        self._gateway_log_fh = None
        self._tunnel_log_fh = None
        self._last_e2e_check = 0.0
        self._e2e_ok = False
        self._reconnect_backoff = 3.0

        self.status_text = "Starting..."
        self.sandbox_text = "Sandbox: 🔒 Protected"
        self.active_apps_text = "Plugins: idle"
        self.icon: pystray.Icon | None = None

    @property
    def mcp_url(self) -> str:
        if self.cfg["require_oauth"] == "true":
            return f"{self.cfg['public_url']}/mcp"
        return f"{self.cfg['public_url']}/mcp?key={self.cfg['secret_key']}"

    def _start_tunnel_locked(self) -> None:
        mode = self.cfg["tunnel_mode"]
        if mode == "none":
            return
        if self._tunnel_log_fh is None:
            self._tunnel_log_fh = open(LOGS_DIR / "tunnel.log", "a", encoding="utf-8")

        if mode == "ssh":
            ssh_exe = find_ssh_exe()
            if not ssh_exe:
                logger.error("ssh.exe not found!")
                return
            if not self.cfg["ssh_host"]:
                logger.error("COOP_SSH_HOST is empty.")
                return
            cmd = [
                ssh_exe,
                "-T",
                "-N",
                "-i",
                self.cfg["ssh_key"],
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
                "BatchMode=yes",
                "-o",
                "ExitOnForwardFailure=yes",
                "-o",
                "ServerAliveInterval=30",
                "-o",
                "ServerAliveCountMax=3",
                "-o",
                "TCPKeepAlive=yes",
                "-R",
                f"127.0.0.1:{self.cfg['ssh_remote_port']}:{self.cfg['host']}:{self.cfg['port']}",
                f"{self.cfg['ssh_user']}@{self.cfg['ssh_host']}",
            ]
        elif mode == "cloudflared":
            cf_exe = find_cloudflared_exe()
            if not cf_exe:
                logger.error("cloudflared.exe not found!")
                return
            cmd = [cf_exe, "tunnel", "--url", f"http://{self.cfg['host']}:{self.cfg['port']}", "--no-autoupdate"]
        else:
            ngrok_exe = find_ngrok_exe()
            if not ngrok_exe:
                logger.error("ngrok.exe not found!")
                return
            cmd = [
                ngrok_exe,
                "http",
                f"--domain={self.cfg['public_domain']}",
                "--host-header=rewrite",
                self.cfg["port"],
                "--log=stdout",
            ]

        self.tunnel_proc = subprocess.Popen(
            cmd,
            cwd=str(APP_DIR),
            stdin=subprocess.DEVNULL,
            stdout=self._tunnel_log_fh,
            stderr=self._tunnel_log_fh,
            creationflags=CREATE_NO_WINDOW,
        )
        logger.info("Started %s tunnel (pid=%s)", mode, self.tunnel_proc.pid)

    def start_processes(self) -> None:
        with self.proc_lock:
            self.cfg = ensure_env_config()
            self._stop_processes_locked()

            python_exe = sys.executable
            if python_exe.lower().endswith("pythonw.exe"):
                py_cmd = python_exe
            else:
                pw = Path(python_exe).with_name("pythonw.exe")
                py_cmd = str(pw) if pw.exists() else python_exe

            self._gateway_log_fh = open(LOGS_DIR / "gateway.log", "a", encoding="utf-8")
            self.server_proc = subprocess.Popen(
                [
                    py_cmd,
                    "-u",
                    str(APP_DIR / "server.py"),
                    "--port",
                    self.cfg["port"],
                    "--host",
                    self.cfg["host"],
                    "--public-url",
                    self.cfg["public_url"],
                    "--log-level",
                    "INFO",
                ],
                cwd=str(APP_DIR),
                stdin=subprocess.DEVNULL,
                stdout=self._gateway_log_fh,
                stderr=self._gateway_log_fh,
                creationflags=CREATE_NO_WINDOW,
            )
            logger.info("Started server.py (pid=%s)", self.server_proc.pid)
            self._start_tunnel_locked()

    def _stop_processes_locked(self) -> None:
        for name, proc in ((self.cfg["tunnel_mode"], self.tunnel_proc), ("server", self.server_proc)):
            if proc is not None and proc.poll() is None:
                logger.info("Stopping %s (pid=%s)", name, proc.pid)
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        self.tunnel_proc = None
        self.server_proc = None

        for fh in (self._gateway_log_fh, self._tunnel_log_fh):
            if fh is not None:
                try:
                    fh.close()
                except OSError:
                    pass
        self._gateway_log_fh = None
        self._tunnel_log_fh = None

    def stop_processes(self) -> None:
        with self.proc_lock:
            self._stop_processes_locked()

    def _poll_health(self) -> tuple[bool, list[str], dict]:
        url = f"http://{self.cfg['host']}:{self.cfg['port']}/health?key={self.cfg['secret_key']}"
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    return True, list(data.get("apps", [])), dict(data.get("admin", {}))
        except Exception:
            pass
        return False, [], {}

    def _poll_tunnel(self) -> bool:
        mode = self.cfg["tunnel_mode"]
        if mode == "none":
            return True
        if mode == "ngrok":
            try:
                with urllib.request.urlopen("http://127.0.0.1:4040/api/tunnels", timeout=1.5) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        return len(data.get("tunnels", [])) > 0
            except Exception:
                return False
        with self.proc_lock:
            alive = self.tunnel_proc is not None and self.tunnel_proc.poll() is None
        if not alive:
            self._e2e_ok = False
            return False
        now = time.monotonic()
        if now - self._last_e2e_check >= 20.0 or not self._e2e_ok:
            self._last_e2e_check = now
            try:
                probe_url = f"{self.cfg['public_url']}/.well-known/oauth-protected-resource"
                with urllib.request.urlopen(probe_url, timeout=5) as resp:
                    self._e2e_ok = resp.status == 200
            except Exception:
                self._e2e_ok = False
        return self._e2e_ok

    def _reconnect_tunnel(self) -> None:
        with self.proc_lock:
            if self.stop_event.is_set():
                return
            if self.tunnel_proc is not None and self.tunnel_proc.poll() is None:
                return
            logger.warning("Tunnel process exited; restarting in %.0fs...", self._reconnect_backoff)
        if self.stop_event.wait(self._reconnect_backoff):
            return
        with self.proc_lock:
            if not self.stop_event.is_set():
                self._start_tunnel_locked()
        self._reconnect_backoff = min(self._reconnect_backoff * 1.5, 15.0)

    def monitor_loop(self) -> None:
        while not self.stop_event.is_set():
            gw_ok, active_apps, admin_info = self._poll_health()
            tun_ok = self._poll_tunnel()

            with self.proc_lock:
                srv_dead = self.server_proc is not None and self.server_proc.poll() is not None
                tun_dead = (
                    self.cfg["tunnel_mode"] != "none"
                    and self.tunnel_proc is not None
                    and self.tunnel_proc.poll() is not None
                )

            if tun_ok:
                self._reconnect_backoff = 3.0
            elif tun_dead and not self.stop_event.is_set():
                self._reconnect_tunnel()

            mode_label = self.cfg["tunnel_mode"].upper()
            auth_label = "OAuth" if self.cfg["require_oauth"] == "true" else "Key"
            if gw_ok and tun_ok:
                new_status = f"Running ({mode_label} | {auth_label})"
            elif gw_ok and not tun_ok:
                new_status = (
                    f"Reconnecting {mode_label} tunnel..." if tun_dead else f"Starting {mode_label} tunnel..."
                )
            elif not gw_ok and tun_ok:
                new_status = "Error: gateway stopped" if srv_dead else "Starting gateway..."
            else:
                new_status = "Stopped (click Restart)" if (srv_dead or tun_dead) else "Starting..."

            if admin_info.get("unlocked"):
                mins = max(1, (int(admin_info.get("remaining_seconds", 0)) + 59) // 60)
                new_sandbox = f"Sandbox: ⚠️ Admin Unlocked ({mins}m left)"
            else:
                new_sandbox = "Sandbox: 🔒 Protected"

            new_apps = f"Active plugins: {', '.join(active_apps)}" if active_apps else "Active plugins: none (idle)"

            changed = (
                (new_status != self.status_text)
                or (new_apps != self.active_apps_text)
                or (new_sandbox != self.sandbox_text)
            )
            self.status_text = new_status
            self.sandbox_text = new_sandbox
            self.active_apps_text = new_apps

            if self.icon is not None and changed:
                tip = f"CoopMCP - {self.status_text}"
                self.icon.title = tip[:60]
                self.icon.update_menu()

            self.stop_event.wait(4.0)

    # ── Menu Callbacks ────────────────────────────────────────────────────────

    def on_copy_url(self, _icon: pystray.Icon, _item: MenuItem) -> None:
        copy_to_clipboard(self.mcp_url)
        if self.icon is not None:
            try:
                self.icon.notify("Copied MCP endpoint URL to clipboard", "CoopMCP")
            except Exception:
                pass

    def on_copy_client_id(self, _icon: pystray.Icon, _item: MenuItem) -> None:
        copy_to_clipboard(self.cfg["oauth_client_id"])
        if self.icon is not None:
            try:
                self.icon.notify("Copied OAuth Client ID to clipboard", "CoopMCP")
            except Exception:
                pass

    def on_open_ui(self, _icon: pystray.Icon, _item: MenuItem) -> None:
        url = f"http://{self.cfg['host']}:{self.cfg['port']}/ui#key={self.cfg['secret_key']}"
        webbrowser.open(url)

    def on_open_output_dir(self, _icon: pystray.Icon, _item: MenuItem) -> None:
        out_dir = Path(self.cfg["write_root"])
        out_dir.mkdir(parents=True, exist_ok=True)
        os.startfile(str(out_dir))

    def on_open_logs(self, _icon: pystray.Icon, _item: MenuItem) -> None:
        os.startfile(str(LOGS_DIR))

    def on_revoke_admin(self, _icon: pystray.Icon, _item: MenuItem) -> None:
        url = f"http://{self.cfg['host']}:{self.cfg['port']}/admin/revoke?key={self.cfg['secret_key']}"
        req = urllib.request.Request(url, method="POST", data=b"")
        try:
            with urllib.request.urlopen(req, timeout=3):
                pass
            self.sandbox_text = "Sandbox: 🔒 Protected"
            if self.icon is not None:
                self.icon.update_menu()
                try:
                    self.icon.notify("Sandbox re-locked and all admin tokens revoked", "CoopMCP")
                except Exception:
                    pass
        except Exception as exc:
            logger.warning("Failed to revoke admin token: %s", exc)

    def on_restart(self, _icon: pystray.Icon, _item: MenuItem) -> None:
        self.status_text = "Restarting..."
        if self.icon is not None:
            self.icon.update_menu()
        threading.Thread(target=self.start_processes, daemon=True).start()

    def on_exit(self, icon: pystray.Icon, _item: MenuItem) -> None:
        logger.info("User selected Exit from tray menu.")
        self.stop_event.set()
        self.stop_processes()
        icon.stop()

    def open_ui_when_ready(self, timeout: float = 8.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not self.stop_event.is_set():
            gw_ok, _, _ = self._poll_health()
            if gw_ok:
                break
            time.sleep(0.25)
        webbrowser.open(f"http://{self.cfg['host']}:{self.cfg['port']}/ui#key={self.cfg['secret_key']}")

    def run(self, *, open_ui: bool = False) -> None:
        ensure_ico_from_png()
        self.start_processes()
        if open_ui:
            threading.Thread(target=self.open_ui_when_ready, daemon=True).start()

        if CHICK_PNG.exists():
            tray_image = Image.open(CHICK_PNG).convert("RGBA")
        else:
            tray_image = Image.new("RGBA", (64, 64), (255, 224, 71, 255))

        menu = Menu(
            MenuItem(lambda _item: f"Status: {self.status_text}", None, enabled=False),
            MenuItem(lambda _item: self.sandbox_text, None, enabled=False),
            MenuItem(lambda _item: self.active_apps_text, None, enabled=False),
            MenuItem(lambda _item: f"Domain: {self.cfg['public_domain']}", None, enabled=False),
            Menu.SEPARATOR,
            MenuItem("⚙️ Open Settings UI", self.on_open_ui, default=True),
            MenuItem("🔒 Lock Sandbox & Revoke Admin Tokens", self.on_revoke_admin),
            MenuItem("Copy MCP Endpoint URL", self.on_copy_url),
            MenuItem("Copy OAuth Client ID", self.on_copy_client_id),
            MenuItem("Open Output Folder", self.on_open_output_dir),
            MenuItem("Open Logs Folder", self.on_open_logs),
            MenuItem("Restart Gateway", self.on_restart),
            Menu.SEPARATOR,
            MenuItem("Exit", self.on_exit),
        )

        self.icon = pystray.Icon(
            name="CoopMcpTray",
            icon=tray_image,
            title="CoopMCP Gateway\nStarting...",
            menu=menu,
        )

        monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        monitor_thread.start()

        try:
            self.icon.run()
        finally:
            self.stop_event.set()
            self.stop_processes()


def main() -> None:
    open_ui = "--open-ui" in sys.argv[1:]
    mutex = ensure_single_instance()
    if mutex is None:
        logger.info("Another instance is already running; exiting.")
        if open_ui:
            cfg = ensure_env_config()
            webbrowser.open(f"http://{cfg['host']}:{cfg['port']}/ui#key={cfg['secret_key']}")
        return
    try:
        CoopTrayController().run(open_ui=open_ui)
    finally:
        ctypes.WinDLL("kernel32").CloseHandle(mutex)


if __name__ == "__main__":
    main()
