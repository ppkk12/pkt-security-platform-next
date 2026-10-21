# PKT Security Platform Next - Local Development Startup Script
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot = Split-Path -Parent $ScriptDir
$PidFile = Join-Path $RepoRoot ".dev-pids.json"

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " PKT Security Platform Next - Local Development Environment Launcher" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

# 1. Check PostgreSQL (Port 5432)
Write-Host "[1/4] Checking PostgreSQL connection on localhost:5432..." -ForegroundColor Yellow
$pgConnected = $false
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $iar = $tcp.BeginConnect("localhost", 5432, $null, $null)
    $success = $iar.AsyncWaitHandle.WaitOne(2000, $false)
    if ($success -and $tcp.Connected) {
        $tcp.EndConnect($iar)
        $pgConnected = $true
    }
    $tcp.Close()
} catch {
    $pgConnected = $false
}

if (-not $pgConnected) {
    Write-Host "[-] PostgreSQL is not responding on localhost:5432." -ForegroundColor Red
    Write-Host "    Please ensure PostgreSQL is running or run: docker compose up -d postgres" -ForegroundColor Yellow
    exit 1
}
Write-Host "[+] PostgreSQL is active and accepting connections." -ForegroundColor Green

# 2. Resolve dotnet CLI
$DotnetPath = "dotnet"
if (Test-Path "$env:USERPROFILE\.dotnet\dotnet.exe") {
    $DotnetPath = "$env:USERPROFILE\.dotnet\dotnet.exe"
}

# 3. Clean up any existing instances from previous run
if (Test-Path $PidFile) {
    Write-Host "[*] Cleaning up previously running processes..." -ForegroundColor DarkGray
    & (Join-Path $ScriptDir "stop-dev.ps1")
}

# 4. Start Backend API
Write-Host "[2/4] Starting PktSecurity.Api (http://localhost:5000)..." -ForegroundColor Yellow
$apiProc = Start-Process -FilePath $DotnetPath `
    -ArgumentList "run --project src/PktSecurity.Api -c Release --urls http://localhost:5000" `
    -WorkingDirectory $RepoRoot `
    -PassThru

# 5. Start Background Scan Worker
Write-Host "[3/4] Starting PktSecurity.Worker..." -ForegroundColor Yellow
$workerProc = Start-Process -FilePath $DotnetPath `
    -ArgumentList "run --project src/PktSecurity.Worker -c Release" `
    -WorkingDirectory $RepoRoot `
    -PassThru

# 6. Start Frontend Web UI
Write-Host "[4/4] Starting PktSecurity.Web (http://localhost:3000)..." -ForegroundColor Yellow
$webProc = Start-Process -FilePath "cmd.exe" `
    -ArgumentList "/c npm --prefix src/PktSecurity.Web run dev" `
    -WorkingDirectory $RepoRoot `
    -PassThru

# Save PIDs
$pidsData = @{
    ApiPid = $apiProc.Id
    WorkerPid = $workerProc.Id
    WebPid = $webProc.Id
    StartedAt = (Get-Date).ToString("o")
}
$pidsData | ConvertTo-Json | Set-Content -Path $PidFile -Encoding UTF8

Write-Host "`n================================================================================" -ForegroundColor Green
Write-Host " [SUCCESS] PKT Security Platform Next has been successfully launched!" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Green
Write-Host " * Web Dashboard UI:     http://localhost:3000" -ForegroundColor Cyan
Write-Host " * Backend API:          http://localhost:5000" -ForegroundColor Cyan
Write-Host " * Swagger API Docs:     http://localhost:5000/swagger" -ForegroundColor Cyan
Write-Host " * Health Readiness:     http://localhost:5000/health/ready" -ForegroundColor Cyan
Write-Host " * Health Liveness:      http://localhost:5000/health/live" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host " Initial Seeded Login Credentials (Tenant Alpha):" -ForegroundColor White
Write-Host "   - Tenant Admin:       admin@tenant-alpha.local     / AdminPassword123!" -ForegroundColor Yellow
Write-Host "   - Security Engineer:  seceng@tenant-alpha.local    / SecEngPassword123!" -ForegroundColor Yellow
Write-Host "   - Developer:          dev@tenant-alpha.local       / DevPassword123!" -ForegroundColor Yellow
Write-Host "   - Auditor:            auditor@tenant-alpha.local   / AuditorPassword123!" -ForegroundColor Yellow
Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host " To stop all services gracefully, run: .\scripts\stop-dev.ps1" -ForegroundColor Gray
Write-Host "================================================================================`n" -ForegroundColor Green
