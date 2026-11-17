param(
    [ValidateSet("cloudflared", "ssh", "none")]
    [string]$Tunnel = "cloudflared"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$EnvPath = Join-Path $ScriptDir ".env"
if (-not (Test-Path $EnvPath)) {
    throw ".env not found. Copy .env.example to .env and configure your keys first (or run: uv run python set_oauth_password.py)."
}

$cfg = @{}
foreach ($line in ([System.IO.File]::ReadAllLines($EnvPath, [System.Text.UTF8Encoding]::new($false)))) {
    if ($line -match "^\s*#" -or $line -notmatch "=") { continue }
    $k, $v = $line.Split("=", 2)
    $cfg[$k.Trim()] = $v.Trim()
}

$Port = if ($cfg["PORT"]) { [int]$cfg["PORT"] } else { 8089 }
$BindHost = if ($cfg["HOST"]) { $cfg["HOST"] } else { "127.0.0.1" }
$PublicUrl = if ($cfg["PUBLIC_URL"]) { $cfg["PUBLIC_URL"].TrimEnd("/") } else { "http://${BindHost}:$Port" }

Write-Host "CoopMCP Gateway Launcher ($Tunnel) -> $PublicUrl" -ForegroundColor Cyan

$tunnelJob = $null
if ($Tunnel -eq "cloudflared") {
    $CfExe = (Get-Command cloudflared -ErrorAction SilentlyContinue).Source
    if (-not $CfExe) { $CfExe = "C:\Program Files (x86)\cloudflared\cloudflared.exe" }
    if (-not (Test-Path $CfExe)) { throw "cloudflared.exe not found." }
    $tunnelJob = Start-Job -ScriptBlock {
        param($exe, $h, $p)
        & $exe tunnel --url "http://${h}:$p" --no-autoupdate 2>&1
    } -ArgumentList $CfExe, $BindHost, $Port
} elseif ($Tunnel -eq "ssh") {
    $SshExe = (Get-Command ssh -ErrorAction SilentlyContinue).Source
    if (-not $SshExe) { $SshExe = "C:\Windows\System32\OpenSSH\ssh.exe" }
    $SshHost = $cfg["COOP_SSH_HOST"]
    $SshUser = $cfg["COOP_SSH_USER"]
    $SshKey = $cfg["COOP_SSH_KEY"]
    $RemotePort = if ($cfg["COOP_SSH_REMOTE_PORT"]) { $cfg["COOP_SSH_REMOTE_PORT"] } else { "18089" }
    if (-not $SshHost) { throw "COOP_SSH_HOST is not set in .env." }
    $tunnelJob = Start-Job -ScriptBlock {
        param($exe, $key, $rp, $h, $p, $u, $hostAddr)
        & $exe -T -N -i $key -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -R "127.0.0.1:${rp}:${h}:$p" "${u}@${hostAddr}" 2>&1
    } -ArgumentList $SshExe, $SshKey, $RemotePort, $BindHost, $Port, $SshUser, $SshHost
}

try {
    $PyExe = Join-Path $ScriptDir ".venv\Scripts\python.exe"
    if (Test-Path $PyExe) {
        & $PyExe -u (Join-Path $ScriptDir "server.py") --host $BindHost --port $Port --public-url $PublicUrl
    } else {
        uv run python -u (Join-Path $ScriptDir "server.py") --host $BindHost --port $Port --public-url $PublicUrl
    }
} finally {
    if ($tunnelJob) {
        Stop-Job $tunnelJob -ErrorAction SilentlyContinue
        Remove-Job $tunnelJob -Force -ErrorAction SilentlyContinue
    }
}
