<#
.SYNOPSIS
    Automated Windows Packaging & Distribution Script for AgentShield AI.
.DESCRIPTION
    1. Cleans cache files (__pycache__, *.pyc, .pytest_cache).
    2. Builds a standalone portable release package: dist\AgentShield-AI-v1.0.0-Windows-Portable.zip.
    3. Detects Inno Setup (ISCC.exe) and compiles installer\AgentShield_Setup.iss into
       dist\AgentShield-Setup-v1.0.0.exe if available.
#>
[CmdletBinding()]
param(
    [string]$Version = "1.0.0",
    [switch]$SkipZip,
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
Set-Location $ProjectRoot

$DistDir = Join-Path $ProjectRoot "dist"
$ZipName = "AgentShield-AI-v$Version-Windows-Portable.zip"
$ZipPath = Join-Path $DistDir $ZipName

Write-Host ""
Write-Host ("=" * 72) -ForegroundColor Cyan
Write-Host "   AGENTSHIELD AI - WINDOWS PACKAGING & DISTRIBUTION" -ForegroundColor Cyan
Write-Host ("=" * 72) -ForegroundColor Cyan
Write-Host ""

# 1. Clean build directory
Write-Host "[*] Cleaning build output folder ($DistDir)..." -ForegroundColor Gray
if (Test-Path $DistDir) {
    Remove-Item -Path $DistDir -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path $DistDir -Force | Out-Null

# 2. Clean python cache files
Write-Host "[*] Cleaning temporary Python bytecode and cache files..." -ForegroundColor Gray
Get-ChildItem -Path $ProjectRoot -Recurse -Filter "__pycache__" -Directory -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path $ProjectRoot -Recurse -Filter "*.pyc" -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path $ProjectRoot -Recurse -Filter ".pytest_cache" -Directory -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

# 3. Create Standalone Portable Zip Distribution
if (-not $SkipZip) {
    Write-Host "[*] Creating portable distribution package: $ZipName ..." -ForegroundColor Cyan
    
    $StagingDir = Join-Path $DistDir "AgentShield-AI-v$Version"
    if (Test-Path $StagingDir) { Remove-Item $StagingDir -Recurse -Force }
    New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null

    # Include platform directories and root files
    $FoldersToCopy = @("backend", "dashboard", "demo", "policies", "docs", "scripts", ".streamlit")
    foreach ($f in $FoldersToCopy) {
        $src = Join-Path $ProjectRoot $f
        if (Test-Path $src) {
            Copy-Item -Path $src -Destination (Join-Path $StagingDir $f) -Recurse -Force
        }
    }

    $FilesToCopy = @(
        "launch_all.ps1",
        "stop_all.ps1",
        "launch.bat",
        "run_dashboard.py",
        "run_backend.ps1",
        "run_frontend.ps1",
        "requirements.txt",
        "package.json",
        "README.md",
        ".env.example",
        "firewall.db"
    )
    foreach ($f in $FilesToCopy) {
        $src = Join-Path $ProjectRoot $f
        if (Test-Path $src) {
            Copy-Item -Path $src -Destination (Join-Path $StagingDir $f) -Force
        }
    }

    # Include installer script inside installer directory
    $InstDir = Join-Path $StagingDir "installer"
    New-Item -ItemType Directory -Path $InstDir -Force | Out-Null
    Copy-Item (Join-Path $ProjectRoot "installer\AgentShield_Setup.iss") $InstDir -Force

    # Clean cache from staging before archiving
    Get-ChildItem -Path $StagingDir -Recurse -Filter "__pycache__" -Directory -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path $StagingDir -Recurse -Filter "*.pyc" -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

    # Compress to ZIP
    Compress-Archive -Path "$StagingDir\*" -DestinationPath $ZipPath -CompressionLevel Optimal -Force
    Remove-Item $StagingDir -Recurse -Force

    $zipItem = Get-Item $ZipPath
    $zipMb = [math]::Round($zipItem.Length / 1MB, 2)
    Write-Host "[OK] Portable ZIP created: $ZipPath ($zipMb MB)" -ForegroundColor Green
}

# 4. Inno Setup Compilation (if ISCC is found)
if (-not $SkipInstaller) {
    Write-Host "[*] Checking for Inno Setup 6 Compiler (ISCC.exe)..." -ForegroundColor Gray
    
    $isccPath = $null
    $possiblePaths = @(
        "ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles}\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 5\ISCC.exe",
        "${env:ProgramFiles}\Inno Setup 5\ISCC.exe",
        "${env:LocalAppData}\Programs\Inno Setup 6\ISCC.exe"
    )

    foreach ($p in $possiblePaths) {
        if ($p -eq "ISCC.exe") {
            $cmd = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
            if ($cmd) {
                $isccPath = $cmd.Source
                break
            }
        } elseif (Test-Path $p) {
            $isccPath = $p
            break
        }
    }

    if ($isccPath) {
        Write-Host "[*] Found Inno Setup Compiler at: $isccPath" -ForegroundColor Cyan
        $issFile = Join-Path $ProjectRoot "installer\AgentShield_Setup.iss"
        Write-Host "[*] Compiling installer from: $issFile ..." -ForegroundColor Cyan
        
        & $isccPath $issFile
        if ($LASTEXITCODE -eq 0) {
            $exePath = Join-Path $DistDir "AgentShield-Setup-v$Version.exe"
            if (Test-Path $exePath) {
                $exeItem = Get-Item $exePath
                $exeMb = [math]::Round($exeItem.Length / 1MB, 2)
                Write-Host "[OK] Windows Installer compiled successfully: $exePath ($exeMb MB)" -ForegroundColor Green
            }
        } else {
            Write-Warning "Inno Setup compiler exited with error code $LASTEXITCODE."
        }
    } else {
        Write-Host "[i] Inno Setup compiler (ISCC.exe) not found on this system." -ForegroundColor Yellow
        Write-Host "    The Inno Setup script is ready at 'installer\AgentShield_Setup.iss'." -ForegroundColor Gray
        Write-Host "    To compile the .exe installer, install Inno Setup 6 from https://jrsoftware.org/isdl.php" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host ("=" * 72) -ForegroundColor Green
Write-Host "   PACKAGING COMPLETE" -ForegroundColor Green
Write-Host ("=" * 72) -ForegroundColor Green
Get-ChildItem -Path $DistDir | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
