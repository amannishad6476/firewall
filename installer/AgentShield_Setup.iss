; =====================================================================
; AgentShield AI - Inno Setup 6 Script
; Windows Installer for AI Agent Firewall & SOC Monitoring Platform
; =====================================================================

#define MyAppName "AgentShield AI"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Cybersecurity Engineering Team"
#define MyAppURL "https://github.com/agentshield/firewall"
#define MyAppExeName "launch.bat"

[Setup]
; Unique AppId generated for AgentShield AI
AppId={{E7538A20-8025-4DF4-95C4-9A4B7D46E971}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=no
LicenseFile=
OutputDir=..\dist
OutputBaseFilename=AgentShield-Setup-v{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "quicklaunchicon"; Description: "{cm:CreateQuickLaunchIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Distribute all platform source files, scripts, and configurations
Source: "..\\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "*.git*,*.pyc,__pycache__,*.pytest_cache,dist\\*,node_modules\\*,.launcher_pids.json,*.log,*.tmp"

[Icons]
; Start Menu shortcuts
Name: "{group}\{#MyAppName} SOC Dashboard"; Filename: "cmd.exe"; Parameters: "/c """"{app}\{#MyAppExeName}"""""; WorkingDir: "{app}"; Comment: "Launch AgentShield AI SOC Portal"
Name: "{group}\Run Security Demonstration"; Filename: "cmd.exe"; Parameters: "/c """"{app}\{#MyAppExeName}"" -Mode Demo"""; WorkingDir: "{app}"; Comment: "Compare Unprotected vs Protected Agent Execution"
Name: "{group}\Stop Platform Services"; Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File """"{app}\stop_all.ps1"""""; WorkingDir: "{app}"; Comment: "Stop Backend & Dashboard processes"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"

; Desktop shortcut
Name: "{autodesktop}\{#MyAppName} SOC Dashboard"; Filename: "cmd.exe"; Parameters: "/c """"{app}\{#MyAppExeName}"""""; WorkingDir: "{app}"; Tasks: desktopicon; Comment: "Launch AgentShield AI SOC Portal"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: postinstall shellexec skipifsilent nowait

[Code]
// Check if Python 3 is installed and accessible
function IsPythonInstalled(): Boolean;
var
  ResultCode: Integer;
begin
  // Attempt running python --version silently
  if Exec('cmd.exe', '/c python --version', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    Result := (ResultCode = 0);
  end
  else
  begin
    Result := False;
  end;
end;

// Pre-installation check hook
function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = wpReady then
  begin
    if not IsPythonInstalled() then
    begin
      MsgBox('Notice: Python 3 was not detected in your system PATH.' + #13#10 + #13#10 +
             'AgentShield AI requires Python 3.10 or newer to run.' + #13#10 +
             'You can continue installation, but please ensure Python 3.10+ is installed from https://www.python.org/ before launching.',
             mbInformation, MB_OK);
    end;
  end;
end;
