; =============================================================================
; Hotmart AppSec — InnoSetup Installer Script
; =============================================================================
; Generates a self-contained .exe installer for Workspace ONE distribution.
;
; Build:
;   1. Install InnoSetup (https://jrsoftware.org/isdl.php)
;   2. Open this file in InnoSetup Compiler
;   3. Click Build > Compile
;   Output: dist\HotmartAppSec-Setup-2.8.0.exe
;
; Or via command line:
;   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" setup.iss
;
; Workspace ONE Configuration:
;   Install Command:   HotmartAppSec-Setup-2.8.0.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
;   Uninstall Command: "C:\ProgramData\Hotmart\appsec\unins000.exe" /VERYSILENT /SUPPRESSMSGBOXES
;   Detection Rule:    Registry HKLM\SOFTWARE\Hotmart\AppSec "Version" exists
; =============================================================================

#define MyAppName "Hotmart AppSec"
#define MyAppVersion "2.8.0"
#define MyAppPublisher "Hotmart Cybersecurity"
#define MyAppURL "https://hotmart.com"

[Setup]
AppId={{B3F8A7D2-6E4C-4A91-9D3F-1C5E7B2A8F40}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName=C:\ProgramData\Hotmart\appsec
DisableDirPage=yes
DisableProgramGroupPage=yes
OutputDir=..\..\dist
OutputBaseFilename=HotmartAppSec-Setup-{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Silent install by default for MDM
DisableReadyPage=yes
DisableFinishedPage=yes
; Uninstall
CreateUninstallRegKey=yes
UninstallDisplayName={#MyAppName}
UninstallDisplayIcon={app}\icon.ico

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "portuguese"; MessagesFile: "compiler:Languages\Portuguese.isl"

[Files]
; Scripts
Source: "..\mdm-install.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\mdm-watchdog.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\mdm-uninstall.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\appsec-watchdog-task.xml"; DestDir: "{app}"; Flags: ignoreversion
; Opengrep binary (place in bin subfolder)
Source: "payload\bin\opengrep.exe"; DestDir: "{app}\bin"; Flags: ignoreversion; Check: OpenGrepExists
; Icon (optional)
Source: "..\..\media\icon.png"; DestDir: "{app}"; DestName: "icon.ico"; Flags: ignoreversion skipifsourcedoesntexist

[Registry]
; Detection rule for Workspace ONE
Root: HKLM; Subkey: "SOFTWARE\Hotmart\AppSec"; ValueType: string; ValueName: "Version"; ValueData: "{#MyAppVersion}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Hotmart\AppSec"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey

[Run]
; Post-install: install opengrep to PATH
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -NoProfile -Command ""$binDir='C:\ProgramData\Hotmart\bin'; New-Item -ItemType Directory -Path $binDir -Force | Out-Null; if (Test-Path '{app}\bin\opengrep.exe') {{ Copy-Item '{app}\bin\opengrep.exe' '$binDir\opengrep.exe' -Force }}; $p=[Environment]::GetEnvironmentVariable('PATH','Machine'); if ($p -notlike '*Hotmart\bin*') {{ [Environment]::SetEnvironmentVariable('PATH',""$p;$binDir"",'Machine') }}"""; Flags: runhidden waituntilterminated
; Post-install: run main installer
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -NoProfile -File ""{app}\mdm-install.ps1"""; Flags: runhidden waituntilterminated
; Post-install: register Scheduled Task
Filename: "schtasks.exe"; Parameters: "/Create /XML ""{app}\appsec-watchdog-task.xml"" /TN ""Hotmart\AppSecWatchdog"" /F"; Flags: runhidden waituntilterminated

[UninstallRun]
; Pre-uninstall: run uninstaller script
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -NoProfile -File ""{app}\mdm-uninstall.ps1"""; Flags: runhidden waituntilterminated

[UninstallDelete]
Type: filesandordirs; Name: "C:\ProgramData\Hotmart"

[Code]
// Check if opengrep.exe exists in the payload
function OpenGrepExists: Boolean;
begin
  Result := FileExists(ExpandConstant('{src}\payload\bin\opengrep.exe'));
end;
