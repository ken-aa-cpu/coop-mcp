"""Headless Blender background runner for CoopMCP Blender Bridge."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import time

ADDON_DIR = str(Path(__file__).resolve().parent)
if ADDON_DIR not in sys.path:
    sys.path.insert(0, ADDON_DIR)

import coop_blender_mcp as addon  # noqa: E402


def main() -> None:
    host = os.getenv("COOP_BLENDER_HOST", "127.0.0.1").strip() or "127.0.0.1"
    port = int(os.getenv("COOP_BLENDER_HEADLESS_PORT", "9878"))

    srv = addon.CoopBlenderMCPServer(host=host, port=port)
    srv.start()
    try:
        while srv.running:
            srv._process_queue()
            time.sleep(0.03)
    except KeyboardInterrupt:
        pass
    finally:
        srv.stop()


if __name__ == "__main__":
    main()
