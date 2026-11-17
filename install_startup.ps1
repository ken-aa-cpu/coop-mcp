param(
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$StartupDir = [Environment]::GetFolderPath("Startup")
$ShortcutPath = Join-Path $StartupDir "CoopMCP Gateway.lnk"

if ($Uninstall) {
    if (Test-Path $ShortcutPath) {
        Remove-Item $ShortcutPath -Force
        Write-Host "[ok] Removed startup shortcut: $ShortcutPath" -ForegroundColor Yellow
    } else {
        Write-Host "[info] Startup shortcut not found." -ForegroundColor Gray
    }
    exit 0
}

$Pythonw = Join-Path $ScriptDir ".venv\Scripts\pythonw.exe"
$TrayPy = Join-Path $ScriptDir "tray_app.py"
$IconPath = Join-Path $ScriptDir "assets\chick.ico"

if (-not (Test-Path $Pythonw)) { throw "pythonw.exe not found at $Pythonw (run 'uv sync' first)" }
if (-not (Test-Path $TrayPy)) { throw "tray_app.py not found at $TrayPy" }

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $Pythonw
$Shortcut.Arguments = "`"$TrayPy`""
$Shortcut.WorkingDirectory = $ScriptDir
if (Test-Path $IconPath) {
    $Shortcut.IconLocation = "$IconPath,0"
}
$Shortcut.Description = "CoopMCP Sandboxed PC & Plugin Tray Gateway"
$Shortcut.Save()

Write-Host "[ok] Registered Windows Startup shortcut:" -ForegroundColor Green
Write-Host "     $ShortcutPath" -ForegroundColor Cyan
