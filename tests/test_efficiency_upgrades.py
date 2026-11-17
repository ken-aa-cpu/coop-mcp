"""Tests for partial edit, content search, output management, path confinement, and plugin_batch_call."""

from __future__ import annotations

import asyncio
from pathlib import Path
import shutil
import sys
import tempfile

ROOT_DIR = str(Path(__file__).resolve().parent.parent)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app_registry import AppPluginSpec
from files_tools import (
    PathPolicy,
    edit_output_file,
    manage_output_path,
    search_text_in_files,
    write_output_file,
)
from plugin_router import PluginSessionManager


async def run_tests() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="coop_eff_"))
    try:
        read_root = tmp / "workspace"
        write_root = read_root / "output"
        cloud_dir = write_root / "CloudSync"
        read_root.mkdir()
        write_root.mkdir()
        cloud_dir.mkdir()

        (read_root / "spec.md").write_text("Header\nAlpha keyword here\nFooter\n", encoding="utf-8")
        (read_root / ".env").write_text("SECRET=Alpha keyword here\n", encoding="utf-8")
        (read_root / "bin.dat").write_bytes(b"\x00\x01Alpha\x02")
        (read_root / "existing.blend").write_bytes(b"BLENDER")

        policy = PathPolicy(
            read_roots=(read_root.resolve(),),
            write_root=write_root.resolve(),
            cloud_sync_dir=cloud_dir.resolve(),
            gdrive_mirror_dir=None,
        )

        # 1. search_text_in_files skips .env & binary files, finds spec.md
        sr = search_text_in_files(policy, "Alpha keyword")
        assert sr["match_count"] == 1
        assert sr["matches"][0]["path"].endswith("spec.md")
        assert sr["matches"][0]["line"] == 2

        # 2. edit_output_file partial replace & ambiguity check
        write_output_file(policy, "draft.md", "item A\nitem B\nitem A\n")
        try:
            edit_output_file(policy, "draft.md", "item A", "item X")
            raise AssertionError("Expected ambiguity error")
        except ValueError:
            pass
        ed = edit_output_file(policy, "draft.md", "item B", "item B_updated")
        assert ed["replacements"] == 1
        assert "item B_updated" in (write_root / "draft.md").read_text(encoding="utf-8")

        # 3. manage_output_path: copy from read_root -> write_root, rename, delete, block outside write_root
        cp = manage_output_path(policy, "copy", str(read_root / "spec.md"), "copied/spec_copy.md")
        assert Path(cp["destination"]).exists()
        mv = manage_output_path(policy, "rename", "copied/spec_copy.md", "copied/spec_v2.md")
        assert Path(mv["destination"]).exists() and not (write_root / "copied/spec_copy.md").exists()
        dl = manage_output_path(policy, "delete", "copied/spec_v2.md")
        assert not Path(dl["path"]).exists()

        try:
            manage_output_path(policy, "delete", str(read_root / "spec.md"))
            raise AssertionError("Should block deleting outside write_root")
        except PermissionError:
            pass
        try:
            manage_output_path(policy, "delete", str(cloud_dir))
            raise AssertionError("Should block deleting CloudSync")
        except PermissionError:
            pass

        # 4. plugin_router render path handling + real stdio batch_call against mock plugin
        mock_script = Path(__file__).resolve().parent / "mock_stdio_plugin.py"
        registry = {
            "mock": AppPluginSpec(
                key="mock",
                display_name="MockPlugin",
                category="Test",
                description="Mock stdio MCP plugin",
                command=(sys.executable, str(mock_script)),
                formats=(".txt", ".png"),
                root_mode="gateway_only",
            )
        }
        mgr = PluginSessionManager(policy, registry=registry)
        sanitized_render = mgr._enforce_path_arguments(
            registry["mock"],
            "render_something",
            {"path": str(read_root / "existing.blend"), "output_path": "renders/out.png"},
        )
        assert Path(sanitized_render["path"]) == (read_root / "existing.blend").resolve()
        assert str(write_root.resolve()) in sanitized_render["output_path"]

        try:
            tools_info = await mgr.list_tools("mock")
            assert tools_info["total_tools"] >= 2

            batch_res = await mgr.batch_call(
                "MockPlugin",
                [
                    {"tool_name": "echo_info", "arguments": {"message": "hello"}},
                    {"tool_name": "render_preview", "arguments": {}},
                ],
                include_final_image=True,
            )
            assert batch_res["all_ok"], f"Batch failed: {batch_res}"
            assert batch_res["completed_steps"] == 2
            assert len(batch_res.get("_images", [])) >= 1
        finally:
            await mgr.shutdown_all()

        print("ALL_EFFICIENCY_UPGRADE_TESTS_PASSED")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(run_tests())
