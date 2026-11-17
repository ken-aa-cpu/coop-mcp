"""Tests for 1h PIN-based admin credential, sandbox toggle, revocation, Skill, and unrestricted tools."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time

import jwt

ROOT_DIR = str(Path(__file__).resolve().parent.parent)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from admin_privilege import AdminPrivilegeManager
from config import SKILL_PATH
from files_tools import PathPolicy, read_text_file, write_output_file
from oauth_provider import hash_password
import server as gw_server


async def run_tests() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="coop_adm_"))
    try:
        epoch_file = tmp / ".admin_epoch"
        read_root = tmp / "workspace"
        write_root = read_root / "output"
        outside_dir = tmp / "outside_pc"
        read_root.mkdir()
        write_root.mkdir()
        outside_dir.mkdir()
        (outside_dir / "note.txt").write_text("outside ok", encoding="utf-8")

        policy = PathPolicy(
            read_roots=(read_root.resolve(),),
            write_root=write_root.resolve(),
            cloud_sync_dir=(write_root / "CloudSync").resolve(),
            gdrive_mirror_dir=None,
        )
        test_pin = "847291"
        jwt_secret = "admin_test_jwt_secret_0123456789abcdef012345"
        mgr = AdminPrivilegeManager(
            pin_hash=hash_password(test_pin),
            jwt_secret=jwt_secret,
            ttl_seconds=3600,
            epoch_file=epoch_file,
        )

        # 1. Skill exists and documents coop_unlock_system without leaking PINs
        assert SKILL_PATH.exists()
        skill_text = gw_server.coop_get_skill()
        assert test_pin not in skill_text
        assert "coop_unlock_system" in skill_text

        # 2. Locked by default: outside reads/writes and run_command blocked
        assert not mgr.is_unrestricted()
        try:
            read_text_file(policy, str(outside_dir / "note.txt"), unrestricted=mgr.is_unrestricted())
            raise AssertionError("Should block outside read when locked")
        except PermissionError:
            pass
        try:
            await mgr.run_command("Write-Output 'hi'")
            raise AssertionError("Should block run_command when locked")
        except PermissionError:
            pass

        # 3. Wrong PIN fails cleanly
        try:
            mgr.unlock_with_pin("000000")
            raise AssertionError("Wrong PIN should fail")
        except PermissionError:
            pass

        # 4. Correct PIN issues <= 1h admin_token and opens sandbox
        res = mgr.unlock_with_pin(test_pin)
        token = res["admin_token"]
        assert res["expires_in_seconds"] == 3600
        assert mgr.is_unrestricted()

        # Unrestricted read/write & run_command succeed
        out_r = read_text_file(policy, str(outside_dir / "note.txt"), unrestricted=mgr.is_unrestricted())
        assert "outside ok" in out_r["content"]
        out_w = write_output_file(
            policy,
            str(outside_dir / "written.txt"),
            "hello",
            overwrite=True,
            unrestricted=mgr.is_unrestricted(),
        )
        assert Path(out_w["path"]).exists()
        if os.name == "nt":
            cmd_res = await mgr.run_command("Write-Output 'COOP_CMD_OK'", cwd=str(outside_dir), shell="powershell")
        else:
            cmd_res = await mgr.run_command("echo COOP_CMD_OK", cwd=str(outside_dir), shell="sh")
        assert cmd_res["exit_code"] == 0 and "COOP_CMD_OK" in cmd_res["stdout"]

        # 5. Toggle locked -> re-open using admin_token (no PIN needed within 1h)
        mgr.set_sandbox(False)
        assert not mgr.is_unrestricted()
        reopen = mgr.set_sandbox(True, token)
        assert reopen["sandbox_open"] is True and mgr.is_unrestricted()

        # 6. Expired token rejected
        expired_tok = jwt.encode(
            {"typ": "admin", "iat": int(time.time()) - 4000, "exp": int(time.time()) - 10, "epoch": mgr.epoch},
            jwt_secret,
            algorithm="HS256",
        )
        try:
            mgr.set_sandbox(True, expired_tok)
            raise AssertionError("Expired token must be rejected")
        except PermissionError:
            pass

        # 7. Tray revoke_all invalidates previous valid token immediately
        rev = mgr.revoke_all()
        assert rev["sandbox_open"] is False and not mgr.is_unrestricted()
        try:
            mgr.set_sandbox(True, token)
            raise AssertionError("Revoked token must be rejected")
        except PermissionError:
            pass

        print("ALL_ADMIN_PRIVILEGE_TESTS_PASSED")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(run_tests())
