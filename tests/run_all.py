"""Run all CoopMCP Gateway test suites sequentially."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

TESTS_DIR = Path(__file__).resolve().parent
SUITES = [
    "test_efficiency_upgrades.py",
    "test_oauth.py",
    "test_admin_privilege.py",
    "test_ui_and_discovery.py",
    "test_external_ai_e2e.py",
]


def main() -> None:
    for name in SUITES:
        path = TESTS_DIR / name
        print(f"=== Running {name} ===", flush=True)
        res = subprocess.run([sys.executable, str(path)], check=False)
        if res.returncode != 0:
            raise SystemExit(res.returncode)
    print("ALL_TEST_SUITES_PASSED")


if __name__ == "__main__":
    main()
