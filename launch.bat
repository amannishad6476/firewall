@echo off
setlocal
cd /d "%~dp0"

echo ======================================================================
echo    AgentShield AI - AI Agent Firewall ^& SOC Monitoring Platform
echo ======================================================================
echo.

:: Check for python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python 3 is not found in your PATH.
    echo Please install Python 3.10+ from https://www.python.org/
    echo.
    pause
    exit /b 1
)

:: Launch via PowerShell with ExecutionPolicy Bypass
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0launch_all.ps1" %*

if errorlevel 1 (
    echo.
    echo Launcher encountered an error.
    pause
)
