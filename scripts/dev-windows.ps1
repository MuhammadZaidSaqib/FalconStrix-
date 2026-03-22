# FalconStrix local dev on Windows (MariaDB in Docker + venv).
# Kali/Linux: use scripts/dev-kali.sh
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

if (-not (Test-Path "$Root\.env")) {
    Copy-Item "$Root\.env.example" "$Root\.env"
    Write-Host "Created .env from .env.example"
}

$docker = Get-Command docker -ErrorAction SilentlyContinue
if ($docker) {
    docker compose -f "$Root\docker-compose.yml" up -d
    Write-Host "Waiting for MariaDB..."
    $deadline = (Get-Date).AddMinutes(2)
    do {
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $tcp.Connect("127.0.0.1", 3306)
            $tcp.Close()
            break
        } catch {
            Start-Sleep -Seconds 2
        }
        if ((Get-Date) -gt $deadline) {
            Write-Warning "MariaDB port 3306 not open; start Docker Desktop or run MySQL manually."
            break
        }
    } while ($true)
} else {
    Write-Warning "Docker not found. Install Docker Desktop or point .env at your MySQL/MariaDB instance."
}

if (-not (Test-Path "$Root\.venv\Scripts\python.exe")) {
    python -m venv "$Root\.venv"
}
& "$Root\.venv\Scripts\pip.exe" install -r "$Root\requirements.txt"
Write-Host "Ready. In separate terminals:"
Write-Host "  1) .\.venv\Scripts\python.exe backend\main_backend.py"
Write-Host "  2) .\.venv\Scripts\python.exe gui_dashboard\app.py"
Write-Host "  3) .\.venv\Scripts\python.exe red_team_py\attack_controller.py fifo_only"
