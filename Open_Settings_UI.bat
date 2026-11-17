@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\pythonw.exe" (
    call "%~dp0CoopMCP.bat"
    exit /b %errorlevel%
)

start "" ".venv\Scripts\pythonw.exe" "tray_app.py" --open-ui
exit /b 0
