<#
.SYNOPSIS
    AgentShield AI - Windows Unified Platform Launcher.
.DESCRIPTION
    Starts the FastAPI Backend (port 8000), Streamlit SOC Dashboard (port 8501),
    or the Attack/Defense Demonstration smoothly on Windows.
.PARAMETER Mode
    Execution mode: 'All' (default), 'Backend', 'Dashboard', 'Demo', 'Status', or 'Stop'.
.PARAMETER NoBrowser
    Do not automatically open the browser when services are ready.
.PARAMETER PortBackend
    Port for the FastAPI backend (default: 8000).
.PARAMETER PortDashboard
    Port for the Streamlit dashboard (default: 8501).
.EXAMPLE
    .\launch_all.ps1
    .\launch_all.ps1 -Mode Demo
    .\launch_all.ps1 -Mode Backend
    .\launch_all.ps1 -Mode Stop
#>
[CmdletBinding()]
param(
    [ValidateSet("All", "Backend", "Dashboard", "Demo", "Status", "Stop")]
    [string]$Mode = "All",
    [switch]$NoBrowser,
    [int]$PortBackend = 8000,
    [int]$PortDashboard = 8501
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$PidFile = Join-Path $ScriptDir ".launcher_pids.json"

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor Cyan
    Write-Host "   $Text" -ForegroundColor Cyan
    Write-Host ("=" * 72) -ForegroundColor Cyan
    Write-Host ""
}

function Write-Success { param([string]$Msg) Write-Host "[OK] $Msg" -ForegroundColor Green }
function Write-Info    { param([string]$Msg) Write-Host "[*]  $Msg" -ForegroundColor Gray }
function Write-Warn    { param([string]$Msg) Write-Host "[!]  $Msg" -ForegroundColor Yellow }
function Write-ErrorMsg{ param([string]$Msg) Write-Host "[X]  $Msg" -ForegroundColor Red }

# Verify Python
function Test-PythonEnvironment {
    Write-Info "Checking Python environment..."
    try {
        $pyVersion = & python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')" 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Python command returned exit code $LASTEXITCODE"
        }
        Write-Success "Found Python $pyVersion"
        return $true
    } catch {
        Write-ErrorMsg "Python 3 is not installed or not in your system PATH."
        Write-ErrorMsg "Please install Python 3.10+ from https://www.python.org/ or the Microsoft Store."
        return $false
    }
}

# Stop running services
function Stop-PlatformServices {
    Write-Header "STOPPING RUNNING PLATFORM SERVICES"
    $stoppedAny = $false

    # 1. Check PID file
    if (Test-Path $PidFile) {
        try {
            $pidsObj = Get-Content $PidFile -Raw | ConvertFrom-Json
            if ($pidsObj.BackendPid) {
                Write-Info "Terminating Backend process (PID $($pidsObj.BackendPid))..."
                Stop-Process -Id $pidsObj.BackendPid -Force -ErrorAction SilentlyContinue
                $stoppedAny = $true
            }
            if ($pidsObj.DashboardPid) {
                Write-Info "Terminating Dashboard process (PID $($pidsObj.DashboardPid))..."
                Stop-Process -Id $pidsObj.DashboardPid -Force -ErrorAction SilentlyContinue
                $stoppedAny = $true
            }
        } catch {
            Write-Warn "Could not parse PID file: $_"
        }
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    }

    # 2. Free ports 8000 & 8501
    $portsToCheck = @($PortBackend, $PortDashboard)
    foreach ($p in $portsToCheck) {
        try {
            $connections = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue
            foreach ($conn in $connections) {
                if ($conn.OwningProcess -gt 0) {
                    Write-Info "Freeing port $p (PID $($conn.OwningProcess))..."
                    Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
                    $stoppedAny = $true
                }
            }
        } catch {}
    }

    if ($stoppedAny) {
        Write-Success "All platform processes stopped."
    } else {
        Write-Info "No active platform processes found on ports $PortBackend or $PortDashboard."
    }
}

# Check service status
function Show-Status {
    Write-Header "AGENTSHIELD PLATFORM STATUS"
    $bStatus = "INACTIVE"
    $dStatus = "INACTIVE"

    try {
        $bTest = Invoke-WebRequest -Uri "http://127.0.0.1:$PortBackend/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
        if ($bTest.StatusCode -eq 200) { $bStatus = "ACTIVE (HTTP 200)" }
    } catch {}

    try {
        $dTest = Invoke-WebRequest -Uri "http://localhost:$PortDashboard/" -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
        if ($dTest.StatusCode -eq 200) { $dStatus = "ACTIVE (HTTP 200)" }
    } catch {}

    Write-Host ("  Backend API  (port $PortBackend):  " + $bStatus) -ForegroundColor $(if ($bStatus -match "ACTIVE") { "Green" } else { "DarkGray" })
    Write-Host ("  SOC Dashboard(port $PortDashboard):  " + $dStatus) -ForegroundColor $(if ($dStatus -match "ACTIVE") { "Green" } else { "DarkGray" })
    Write-Host ""
}

# Run Security Demo
function Invoke-Demo {
    Write-Header "RUNNING LIVE SECURITY DEMONSTRATION"
    Write-Info "Starting attack vector & zero-trust firewall demonstration..."
    & python demo/run_demo.py
    Write-Host ""
    Write-Success "Demonstration execution finished."
}

# Main Execution Switch
if ($Mode -eq "Stop") {
    Stop-PlatformServices
    exit 0
}

if ($Mode -eq "Status") {
    Show-Status
    exit 0
}

if ($Mode -eq "Demo") {
    if (-not (Test-PythonEnvironment)) { exit 1 }
    Invoke-Demo
    exit 0
}

# For All, Backend, or Dashboard modes:
if (-not (Test-PythonEnvironment)) { exit 1 }

# Initialize database schema if not present
Write-Info "Verifying database and security policy schema..."
try {
    & python -c "from backend.app.database.connection import init_db; init_db()"
    Write-Success "Database initialized successfully."
} catch {
    Write-Warn "Database initialization warning: $_"
}

$backendProc = $null
$dashboardProc = $null

# Ensure ports are clean before starting
Write-Info "Cleaning up any stale processes on ports $PortBackend / $PortDashboard..."
Stop-PlatformServices | Out-Null

Write-Header "STARTING AGENTSHIELD AI SECURITY PLATFORM"

# 1. Start Backend if requested
if ($Mode -in @("All", "Backend")) {
    Write-Info "Launching FastAPI Backend on http://127.0.0.1:$PortBackend ..."
    $bArgs = "-m uvicorn backend.app.main:app --host 127.0.0.1 --port $PortBackend"
    $backendProc = Start-Process -FilePath "python" -ArgumentList $bArgs -PassThru -WindowStyle Hidden
    Write-Success "Backend started (PID $($backendProc.Id))."
}

# 2. Start Dashboard if requested
if ($Mode -in @("All", "Dashboard")) {
    Write-Info "Launching Streamlit SOC Dashboard on http://localhost:$PortDashboard ..."
    $dArgs = "run_dashboard.py"
    $dashboardProc = Start-Process -FilePath "python" -ArgumentList $dArgs -PassThru -WindowStyle Hidden
    Write-Success "Dashboard started (PID $($dashboardProc.Id))."
}

# Save PIDs
$pidsData = @{
    BackendPid = if ($backendProc) { $backendProc.Id } else { $null }
    DashboardPid = if ($dashboardProc) { $dashboardProc.Id } else { $null }
    StartedAt = (Get-Date).ToString("o")
}
$pidsData | ConvertTo-Json | Set-Content -Path $PidFile -Force

# Wait briefly for startup
Write-Info "Waiting for services to become ready..."
Start-Sleep -Seconds 3

# Display access URLs
Write-Header "AGENTSHIELD PLATFORM IS READY"
if ($Mode -in @("All", "Dashboard")) {
    Write-Host "  [+] Streamlit SOC Dashboard:   http://localhost:$PortDashboard" -ForegroundColor Green
}
if ($Mode -in @("All", "Backend")) {
    Write-Host "  [+] Backend REST API:          http://127.0.0.1:$PortBackend" -ForegroundColor Cyan
    Write-Host "  [+] Swagger API Documentation: http://127.0.0.1:$PortBackend/docs" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "  [i] Press Ctrl+C in this console or run '.\stop_all.ps1' to stop all services." -ForegroundColor Yellow
Write-Host ""

# Open browser if dashboard was started and -NoBrowser was not passed
if ($Mode -in @("All", "Dashboard") -and -not $NoBrowser) {
    Write-Info "Opening default browser to SOC Dashboard..."
    try {
        Start-Process "http://localhost:$PortDashboard"
    } catch {
        Write-Warn "Could not automatically launch browser: $_"
    }
}

# Monitor running loop until interrupted
try {
    while ($true) {
        Start-Sleep -Seconds 2
        # Check if child processes are still alive
        if ($backendProc -and $backendProc.HasExited) {
            Write-Warn "Backend process (PID $($backendProc.Id)) exited unexpectedly with code $($backendProc.ExitCode)."
            break
        }
        if ($dashboardProc -and $dashboardProc.HasExited) {
            Write-Warn "Dashboard process (PID $($dashboardProc.Id)) exited unexpectedly with code $($dashboardProc.ExitCode)."
            break
        }
    }
} finally {
    Write-Host ""
    Write-Info "Shutting down platform services..."
    Stop-PlatformServices
}
