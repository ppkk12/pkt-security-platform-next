# PKT Security Platform Next - Local Development Shutdown Script
[CmdletBinding()]
param()

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot = Split-Path -Parent $ScriptDir
$PidFile = Join-Path $RepoRoot ".dev-pids.json"

Write-Host "Stopping PKT Security Platform Next processes..." -ForegroundColor Yellow

if (Test-Path $PidFile) {
    try {
        $pidsData = Get-Content $PidFile -Raw | ConvertFrom-Json
        $pids = @($pidsData.ApiPid, $pidsData.WorkerPid, $pidsData.WebPid)
        
        foreach ($pidToStop in $pids) {
            if ($pidToStop) {
                try {
                    $proc = Get-Process -Id $pidToStop -ErrorAction SilentlyContinue
                    if ($proc) {
                        Write-Host "Stopping process PID: $pidToStop ($($proc.ProcessName))..." -ForegroundColor Gray
                        Stop-Process -Id $pidToStop -Force -ErrorAction SilentlyContinue
                    }
                } catch {
                    # Process might already be stopped
                }
            }
        }
    } catch {
        Write-Host "Failed to parse PID file: $_" -ForegroundColor DarkGray
    } finally {
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "No active .dev-pids.json found. Checking for any lingering processes on ports 5000 and 3000..." -ForegroundColor Gray
}

# Ensure port 5000 and 3000 are freed
$ports = @(5000, 3000)
foreach ($port in $ports) {
    $conns = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    foreach ($conn in $conns) {
        if ($conn.OwningProcess -gt 0) {
            Write-Host "Killing remaining process listening on port $port (PID: $($conn.OwningProcess))..." -ForegroundColor DarkYellow
            Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
        }
    }
}

Write-Host "All PKT Security Platform Next services have been stopped." -ForegroundColor Green
