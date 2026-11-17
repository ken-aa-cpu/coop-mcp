"""Update COOP_OAUTH_PASSWORD_HASH or COOP_ADMIN_PIN_HASH (and generate secrets if missing) in .env."""

from __future__ import annotations

import argparse
import getpass
from pathlib import Path
import secrets
import sys

from oauth_provider import hash_password

APP_DIR = Path(__file__).resolve().parent
ENV_PATH = APP_DIR / ".env"
ENV_EXAMPLE_PATH = APP_DIR / ".env.example"


def _upsert_env(updates: dict[str, str], drop_keys: tuple[str, ...] = ()) -> None:
    if not ENV_PATH.exists() and ENV_EXAMPLE_PATH.exists():
        ENV_PATH.write_text(ENV_EXAMPLE_PATH.read_text(encoding="utf-8"), encoding="utf-8")

    lines = ENV_PATH.read_text(encoding="utf-8-sig").splitlines() if ENV_PATH.exists() else []
    existing: dict[str, str] = {}
    for line in lines:
        if "=" in line and not line.strip().startswith("#"):
            k, v = line.split("=", 1)
            existing[k.strip()] = v.strip()

    # Auto-provision OAuth client/JWT secrets on first setup if empty
    if not existing.get("COOP_OAUTH_CLIENT_SECRET") and "COOP_OAUTH_CLIENT_SECRET" not in updates:
        updates["COOP_OAUTH_CLIENT_SECRET"] = f"coop_sec_{secrets.token_urlsafe(24)}"
    if not existing.get("COOP_OAUTH_JWT_SECRET") and "COOP_OAUTH_JWT_SECRET" not in updates:
        updates["COOP_OAUTH_JWT_SECRET"] = secrets.token_urlsafe(36)

    out_lines: list[str] = []
    seen: set[str] = set()
    for line in lines:
        key = line.split("=", 1)[0].strip() if "=" in line else ""
        if key in drop_keys:
            continue
        if key in updates:
            out_lines.append(f"{key}={updates[key]}")
            seen.add(key)
        else:
            out_lines.append(line)
    for k, v in updates.items():
        if k not in seen:
            out_lines.append(f"{k}={v}")
    ENV_PATH.write_text("\n".join(out_lines) + "\n", encoding="utf-8")


def update_env_password(new_password: str, rotate_jwt: bool = True) -> None:
    if len(new_password) < 8:
        raise ValueError("Password must be at least 8 characters.")
    updates = {"COOP_OAUTH_PASSWORD_HASH": hash_password(new_password)}
    if rotate_jwt:
        updates["COOP_OAUTH_JWT_SECRET"] = secrets.token_urlsafe(36)
    _upsert_env(updates, drop_keys=("COOP_OAUTH_PASSWORD",))


def update_admin_pin(new_pin: str) -> None:
    if len(new_pin.strip()) < 4:
        raise ValueError("Admin PIN must be at least 4 characters.")
    _upsert_env({"COOP_ADMIN_PIN_HASH": hash_password(new_pin.strip())}, drop_keys=("COOP_ADMIN_PIN",))


def main() -> None:
    parser = argparse.ArgumentParser(description="Update CoopMCP OAuth password or Admin unlock PIN in .env")
    parser.add_argument("value", nargs="?", help="Optional new password or PIN (omit for hidden prompt)")
    parser.add_argument("--pin", action="store_true", help="Update COOP_ADMIN_PIN_HASH instead of OAuth password")
    parser.add_argument("--keep-sessions", action="store_true", help="Do not rotate JWT secret when changing OAuth password")
    args = parser.parse_args()

    label = "Admin unlock PIN (min 4 chars)" if args.pin else "OAuth login password (min 8 chars)"
    if args.value:
        secret = args.value
    else:
        secret = getpass.getpass(f"Enter new {label}: ")
        secret2 = getpass.getpass("Confirm: ")
        if secret != secret2:
            print("Values did not match; cancelled.", file=sys.stderr)
            sys.exit(1)

    if args.pin:
        update_admin_pin(secret)
        print("Updated COOP_ADMIN_PIN_HASH in .env (PBKDF2-SHA256). Restart the gateway/tray to apply.")
    else:
        update_env_password(secret, rotate_jwt=not args.keep_sessions)
        print("Updated COOP_OAUTH_PASSWORD_HASH in .env (PBKDF2-SHA256). Restart the gateway/tray to apply.")


if __name__ == "__main__":
    main()
