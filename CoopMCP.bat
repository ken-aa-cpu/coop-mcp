@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\pythonw.exe" (
    where uv >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Neither .venv nor uv was found.
        echo Please install uv first: https://docs.astral.sh/uv/
        pause
        exit /b 1
    )
    echo [CoopMCP] First-time setup: installing dependencies with uv...
    uv sync --extra dev
    if errorlevel 1 (
        echo [ERROR] Dependency installation failed.
        pause
        exit /b 1
    )
)

start "" ".venv\Scripts\pythonw.exe" "tray_app.py" --open-ui
exit /b 0
