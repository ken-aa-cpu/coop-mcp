"""PIN-gated 1-hour admin credential manager and unrestricted command runner."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
from pathlib import Path
import re
import secrets
import time
from typing import Any

import jwt

from config import ADMIN_EPOCH_PATH, APP_DIR
from oauth_provider import verify_password

logger = logging.getLogger(__name__)

MAX_PIN_ATTEMPTS = 5
PIN_LOCKOUT_SECONDS = 900
MAX_CMD_OUTPUT_CHARS = 24_000

# Last-resort guardrails even while unlocked: prevent accidental OS wipe or gateway credential deletion
_DANGEROUS_CMD_PATTERNS = (
    re.compile(r"\bformat(\.com|\.exe)?\s+[a-z]:", re.IGNORECASE),
    re.compile(r"\b(rd|rmdir)\s+.*\\windows\b", re.IGNORECASE),
    re.compile(r"remove-item\s+.*\\windows(\\|\s|$)", re.IGNORECASE),
    re.compile(r"(del|erase|rm|remove-item)\s+.*(\.env\b|\.key\b)", re.IGNORECASE),
)


class AdminPrivilegeManager:
    """Manages 1-hour admin elevation JWTs, sandbox toggles, revocation, and shell execution."""

    def __init__(
        self,
        *,
        pin_hash: str,
        jwt_secret: str,
        ttl_seconds: int = 3600,
        epoch_file: Path = ADMIN_EPOCH_PATH,
    ) -> None:
        self.pin_hash = pin_hash
        self.jwt_secret = jwt_secret
        self.ttl_seconds = max(60, min(int(ttl_seconds), 3600))
        self.epoch_file = epoch_file

        self._sandbox_open = False
        self._open_until = 0.0
        self._open_epoch = 0
        self._failed_attempts: list[float] = []
        self._locked_until = 0.0

        self.epoch_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.epoch_file.exists():
            self.epoch_file.write_text("1", encoding="utf-8")

    @property
    def epoch(self) -> int:
        try:
            return int(self.epoch_file.read_text(encoding="utf-8").strip() or "1")
        except Exception:
            return 1

    def _bump_epoch(self) -> int:
        next_epoch = self.epoch + 1
        self.epoch_file.write_text(str(next_epoch), encoding="utf-8")
        return next_epoch

    def unlock_with_pin(self, pin: str) -> dict[str, Any]:
        """Verify admin PIN, open sandbox, and issue a 1-hour non-renewable admin_token."""
        if not self.pin_hash:
            raise RuntimeError("COOP_ADMIN_PIN_HASH is not configured in .env.")
        if not self.jwt_secret:
            raise RuntimeError("JWT secret is not configured.")

        now = time.time()
        if self._locked_until > now:
            wait_s = int(self._locked_until - now)
            raise PermissionError(f"Too many wrong PIN attempts. Locked for {wait_s}s.")

        self._failed_attempts = [t for t in self._failed_attempts if (now - t) < 600]
        if not verify_password(pin.strip(), self.pin_hash):
            self._failed_attempts.append(now)
            if len(self._failed_attempts) >= MAX_PIN_ATTEMPTS:
                self._locked_until = now + PIN_LOCKOUT_SECONDS
                logger.warning("Admin PIN locked out after %d failed attempts.", MAX_PIN_ATTEMPTS)
            remaining = max(0, MAX_PIN_ATTEMPTS - len(self._failed_attempts))
            raise PermissionError(f"Invalid admin PIN. Remaining attempts before lockout: {remaining}.")

        self._failed_attempts.clear()
        self._locked_until = 0.0

        iat = int(now)
        exp = iat + self.ttl_seconds
        cur_epoch = self.epoch
        token = jwt.encode(
            {
                "typ": "admin",
                "iat": iat,
                "exp": exp,
                "epoch": cur_epoch,
                "jti": secrets.token_hex(10),
            },
            self.jwt_secret,
            algorithm="HS256",
        )

        self._sandbox_open = True
        self._open_until = float(exp)
        self._open_epoch = cur_epoch

        expires_iso = datetime.fromtimestamp(exp, tz=timezone.utc).astimezone().isoformat(timespec="seconds")
        return {
            "status": "unlocked",
            "sandbox_open": True,
            "admin_token": token,
            "expires_in_seconds": self.ttl_seconds,
            "expires_at": expires_iso,
            "note": (
                "Token is valid for up to 1 hour. Use coop_set_sandbox(open=True/False, admin_token=...) "
                "or pass admin_token to coop_run_command; after expiry or tray revocation, re-request the user PIN."
            ),
        }

    def verify_admin_token(self, token: str) -> dict[str, Any] | None:
        if not token or not self.jwt_secret:
            return None
        try:
            payload = jwt.decode(token.strip(), self.jwt_secret, algorithms=["HS256"])
            if payload.get("typ") != "admin":
                return None
            if int(payload.get("epoch", -1)) != self.epoch:
                return None
            return payload
        except Exception:
            return None

    def set_sandbox(self, open_sandbox: bool, admin_token: str = "") -> dict[str, Any]:
        """Re-lock sandbox anytime, or re-open using an active 1-hour admin_token."""
        if not open_sandbox:
            self._sandbox_open = False
            self._open_until = 0.0
            return {
                "status": "locked",
                "sandbox_open": False,
                "message": "Sandbox locked back to safe mode. Your admin_token remains valid until expiry.",
            }

        payload = self.verify_admin_token(admin_token)
        if payload is None:
            raise PermissionError(
                "admin_token is invalid, expired (>1h), or revoked from the system tray. "
                "Ask the user for the PIN and call coop_unlock_system."
            )

        exp = float(payload["exp"])
        self._sandbox_open = True
        self._open_until = exp
        self._open_epoch = int(payload["epoch"])
        rem = max(0, int(exp - time.time()))
        return {
            "status": "unlocked",
            "sandbox_open": True,
            "remaining_seconds": rem,
            "message": f"Admin mode enabled ({rem}s remaining).",
        }

    def revoke_all(self) -> dict[str, Any]:
        """Immediately re-lock sandbox and invalidate every previously issued admin_token."""
        self._sandbox_open = False
        self._open_until = 0.0
        new_epoch = self._bump_epoch()
        logger.info("Admin sandbox locked and all admin_tokens revoked (epoch=%d).", new_epoch)
        return {"status": "revoked", "sandbox_open": False, "epoch": new_epoch}

    def is_unrestricted(self, admin_token: str = "") -> bool:
        """True if valid per-call admin_token is provided OR session sandbox is open within TTL."""
        if admin_token:
            return self.verify_admin_token(admin_token) is not None
        if not self._sandbox_open:
            return False
        if self._open_epoch != self.epoch or time.time() >= self._open_until:
            self._sandbox_open = False
            self._open_until = 0.0
            return False
        return True

    def status(self) -> dict[str, Any]:
        unlocked = self.is_unrestricted()
        rem = max(0, int(self._open_until - time.time())) if unlocked else 0
        return {
            "unlocked": unlocked,
            "remaining_seconds": rem,
            "epoch": self.epoch,
        }

    async def run_command(
        self,
        command: str,
        *,
        cwd: str = "",
        timeout_seconds: int = 30,
        shell: str = "powershell",
        admin_token: str = "",
    ) -> dict[str, Any]:
        """Run a shell command on Windows when sandbox is open or a valid admin_token is provided."""
        if not self.is_unrestricted(admin_token):
            raise PermissionError(
                "Command execution is locked in sandbox mode. Call coop_unlock_system(pin=...) first, "
                "or call coop_set_sandbox(open=True, admin_token=...)."
            )

        cmd_text = (command or "").strip()
        if not cmd_text:
            raise ValueError("command must not be empty.")
        for pat in _DANGEROUS_CMD_PATTERNS:
            if pat.search(cmd_text):
                raise PermissionError(
                    "Blocked potentially destructive command targeting Windows system directory or credentials."
                )

        work_dir = Path(cwd.strip()).resolve() if cwd and cwd.strip() else APP_DIR
        if not work_dir.exists() or not work_dir.is_dir():
            raise FileNotFoundError(f"Working directory not found: {work_dir}")

        sh = (shell or "powershell").strip().lower()
        if sh in ("powershell", "pwsh", "ps"):
            utf8_prefix = (
                "$OutputEncoding = [System.Text.UTF8Encoding]::new($false); "
                "[Console]::OutputEncoding = $OutputEncoding; "
            )
            argv = ["powershell", "-NoProfile", "-NonInteractive", "-Command", utf8_prefix + cmd_text]
        elif sh == "cmd":
            argv = ["cmd", "/c", cmd_text]
        else:
            raise ValueError("shell must be 'powershell' or 'cmd'.")

        timeout = max(1, min(int(timeout_seconds), 120))
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(work_dir),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        timed_out = False
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=float(timeout))
        except asyncio.TimeoutError:
            timed_out = True
            proc.kill()
            stdout_b, stderr_b = await proc.communicate()

        stdout = stdout_b.decode("utf-8", errors="replace")
        stderr = stderr_b.decode("utf-8", errors="replace")
        truncated = False
        if len(stdout) > MAX_CMD_OUTPUT_CHARS:
            stdout = stdout[:MAX_CMD_OUTPUT_CHARS] + "\n...[truncated]..."
            truncated = True
        if len(stderr) > MAX_CMD_OUTPUT_CHARS:
            stderr = stderr[:MAX_CMD_OUTPUT_CHARS] + "\n...[truncated]..."
            truncated = True

        return {
            "exit_code": proc.returncode,
            "timed_out": timed_out,
            "cwd": str(work_dir),
            "shell": sh,
            "truncated": truncated,
            "stdout": stdout,
            "stderr": stderr,
        }
