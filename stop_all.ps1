<#
.SYNOPSIS
    AgentShield AI - Windows Platform Teardown Script.
.DESCRIPTION
    Cleanly stops all background services (FastAPI backend and Streamlit SOC dashboard),
    frees ports 8000 and 8501, and removes temporary launcher state.
#>
[CmdletBinding()]
param(
    [int]$PortBackend = 8000,
    [int]$PortDashboard = 8501
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$PidFile = Join-Path $ScriptDir ".launcher_pids.json"

Write-Host "Stopping AgentShield AI services..." -ForegroundColor Cyan

$stoppedCount = 0

# 1. Stop recorded PIDs
if (Test-Path $PidFile) {
    try {
        $pidsObj = Get-Content $PidFile -Raw | ConvertFrom-Json
        if ($pidsObj.BackendPid) {
            $p = Get-Process -Id $pidsObj.BackendPid -ErrorAction SilentlyContinue
            if ($p) {
                Write-Host "  Stopping Backend (PID $($pidsObj.BackendPid))..." -ForegroundColor Gray
                Stop-Process -Id $pidsObj.BackendPid -Force -ErrorAction SilentlyContinue
                $stoppedCount++
            }
        }
        if ($pidsObj.DashboardPid) {
            $p = Get-Process -Id $pidsObj.DashboardPid -ErrorAction SilentlyContinue
            if ($p) {
                Write-Host "  Stopping Dashboard (PID $($pidsObj.DashboardPid))..." -ForegroundColor Gray
                Stop-Process -Id $pidsObj.DashboardPid -Force -ErrorAction SilentlyContinue
                $stoppedCount++
            }
        }
    } catch {
        Write-Warning "Could not read $PidFile : $_"
    }
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
}

# 2. Release ports 8000 & 8501 if any lingering listeners remain
$ports = @($PortBackend, $PortDashboard)
foreach ($port in $ports) {
    try {
        $conns = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
        foreach ($conn in $conns) {
            if ($conn.OwningProcess -gt 0) {
                Write-Host "  Terminating process on port $port (PID $($conn.OwningProcess))..." -ForegroundColor Gray
                Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
                $stoppedCount++
            }
        }
    } catch {}
}

if ($stoppedCount -gt 0) {
    Write-Host "[OK] Stopped $stoppedCount active platform process(es)." -ForegroundColor Green
} else {
    Write-Host "[OK] No active platform processes were running." -ForegroundColor Green
}
