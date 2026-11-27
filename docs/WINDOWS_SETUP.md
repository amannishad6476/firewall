# 🪟 Windows Setup, Launching & Packaging Guide

This guide describes how to run and package the **AgentShield AI (AI Agent Firewall & SOC Monitoring Platform)** on Microsoft Windows.

---

## ⚡ Quick Start on Windows

### Option 1: Double-Click Launcher (Batch)
Double-click `launch.bat` in the root folder.
- Launches the unified PowerShell launcher with execution policy bypass.
- Automatically initializes the database, starts the background services, and opens `http://localhost:8501` in your default browser.

### Option 2: PowerShell Unified Launcher (`launch_all.ps1`)
Open PowerShell in the project directory and run:

```powershell
# Start both Backend and SOC Dashboard (default)
.\launch_all.ps1

# Run without automatically opening the browser
.\launch_all.ps1 -NoBrowser

# Start only the FastAPI Backend (http://127.0.0.1:8000)
.\launch_all.ps1 -Mode Backend

# Start only the Streamlit SOC Dashboard (http://localhost:8501)
.\launch_all.ps1 -Mode Dashboard

# Run the live attack & zero-trust security demonstration
.\launch_all.ps1 -Mode Demo

# Check active service status on ports 8000 and 8501
.\launch_all.ps1 -Mode Status

# Cleanly stop all running platform services
.\launch_all.ps1 -Mode Stop
```

### Option 3: Dedicated Stop Script (`stop_all.ps1`)
To gracefully stop all running backend and dashboard processes and free ports `8000` and `8501`:

```powershell
.\stop_all.ps1
```

---

## 📦 Windows Packaging & Distribution

The repository includes both an **Inno Setup 6 installer script** (`installer/AgentShield_Setup.iss`) and an **automated packaging script** (`scripts/package_windows.ps1`).

### 1. Build Portable Distribution Package & Installer
Run the packaging automation script:

```powershell
.\scripts\package_windows.ps1
```

Or via npm:
```bash
npm run package:windows
```

This script will:
1. Clean all temporary `__pycache__`, `*.pyc`, and `.pytest_cache` directories.
2. Build a clean, portable release `.zip` package:
   - `dist\AgentShield-AI-v1.0.0-Windows-Portable.zip`
3. Automatically search for **Inno Setup 6 Compiler** (`ISCC.exe`). If installed, it compiles:
   - `dist\AgentShield-Setup-v1.0.0.exe` (Windows graphical installer).

### 2. Inno Setup 6 Script Details (`installer/AgentShield_Setup.iss`)
- **Target Application**: AgentShield AI
- **Installation Path**: `{autopf}\AgentShield AI` (per-user or system-wide)
- **Shortcuts Created**:
  - Start Menu: *AgentShield AI SOC Dashboard*
  - Start Menu: *Run Security Demonstration*
  - Start Menu: *Stop Platform Services*
  - Start Menu: *Uninstall AgentShield AI*
  - Desktop: *AgentShield AI SOC Dashboard* (optional task)
- **Prerequisite Check**:
  - Automatically tests for Python 3 availability during setup and alerts the user if Python 3.10+ is missing.
- **Post-Install Launch**:
  - Offers a one-click checkbox to launch the SOC dashboard immediately upon installation completion.

To manually compile using the Inno Setup IDE:
1. Download and install Inno Setup 6 from [jrsoftware.org](https://jrsoftware.org/isdl.php).
2. Right-click `installer\AgentShield_Setup.iss` and select **Compile**.
3. Output `.exe` will be generated in `dist\AgentShield-Setup-v1.0.0.exe`.

---

## 🔍 Verification & Diagnostics

To verify your environment and platform health at any time:

```powershell
# 1. Run all unit & integration tests (60/60 passing)
python -m pytest backend/tests/ -v

# 2. Run runtime verification across all 7 dashboard pages
python scripts/verify_all_pages_runtime.py
```
