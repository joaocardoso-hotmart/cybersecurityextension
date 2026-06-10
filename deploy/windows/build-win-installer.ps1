#Requires -Version 5.1
<#
.SYNOPSIS
    Build Windows installer for Workspace ONE distribution.

.DESCRIPTION
    Creates a self-contained installer package for Windows that:
    - Bundles opengrep binary (no internet dependency)
    - Includes all PowerShell scripts (install, watchdog, uninstall)
    - Includes the Scheduled Task XML
    - Creates a ZIP package ready for Workspace ONE deployment

    For MSI packaging, use WiX Toolset with the generated payload.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File build-win-installer.ps1

.NOTES
    Output: dist\hotmart-appsec-win-<version>.zip
    The ZIP contains the payload structure + install.cmd wrapper.

    Workspace ONE configuration:
      Install Command:  powershell -ExecutionPolicy Bypass -File "install.ps1"
      Uninstall Command: powershell -ExecutionPolicy Bypass -File "C:\ProgramData\Hotmart\appsec\mdm-uninstall.ps1"
      Detection: Registry HKLM\SOFTWARE\Hotmart\AppSec exists
#>

$VERSION = "2.8.0"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$OutputDir = Join-Path $ProjectDir "dist"
$BuildDir = Join-Path $OutputDir "win-build"

Write-Host ""
Write-Host ">>> Building Hotmart AppSec Windows Installer v$VERSION" -ForegroundColor Yellow
Write-Host ""

# Clean
if (Test-Path $BuildDir) { Remove-Item $BuildDir -Recurse -Force }
$null = New-Item -ItemType Directory -Path "$BuildDir\payload\appsec\bin" -Force
$null = New-Item -ItemType Directory -Path $OutputDir -Force

# ── Download opengrep for Windows ────────────────────────────────────────

Write-Host "  Downloading opengrep for Windows..." -ForegroundColor DarkCyan
$ogBundled = "$BuildDir\payload\appsec\bin\opengrep.exe"

try {
    $release = Invoke-RestMethod "https://api.github.com/repos/opengrep/opengrep/releases/latest" -UseBasicParsing -TimeoutSec 15
    $asset = $release.assets | Where-Object { $_.name -eq "opengrep_windows_x86.exe" } | Select-Object -First 1
    if ($asset) {
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $ogBundled -UseBasicParsing -TimeoutSec 120
        Write-Host "  [OK] opengrep bundled ($(([Math]::Round((Get-Item $ogBundled).Length / 1MB, 1))) MB)" -ForegroundColor Green
    } else {
        Write-Host "  [!!] No Windows opengrep binary in release — will download at install time" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [!!] Download failed: $_ — checking local..." -ForegroundColor Yellow
    $localOg = Get-Command opengrep -ErrorAction SilentlyContinue
    if ($localOg -and $localOg.Source -like "*.exe") {
        Copy-Item $localOg.Source $ogBundled
        Write-Host "  [OK] Using local opengrep binary" -ForegroundColor Green
    }
}

# ── Copy scripts ─────────────────────────────────────────────────────────

Write-Host "  [OK] Copying mdm-install.ps1" -ForegroundColor Green
Copy-Item "$ScriptDir\mdm-install.ps1" "$BuildDir\payload\appsec\"

Write-Host "  [OK] Copying mdm-watchdog.ps1" -ForegroundColor Green
Copy-Item "$ScriptDir\mdm-watchdog.ps1" "$BuildDir\payload\appsec\"

Write-Host "  [OK] Copying mdm-uninstall.ps1" -ForegroundColor Green
Copy-Item "$ScriptDir\mdm-uninstall.ps1" "$BuildDir\payload\appsec\"

Write-Host "  [OK] Copying watchdog task XML" -ForegroundColor Green
Copy-Item "$ScriptDir\appsec-watchdog-task.xml" "$BuildDir\payload\appsec\"

# ── Generate install wrapper ─────────────────────────────────────────────

Write-Host "  [OK] Generating install.ps1 wrapper" -ForegroundColor Green

$installWrapper = @"
#Requires -Version 5.1
# =============================================================================
# Hotmart AppSec — Windows Installer Wrapper (post-extract)
# =============================================================================
# This script is executed by Workspace ONE after extracting the package.
# It copies files to ProgramData and runs the main installer.
# =============================================================================

`$ErrorActionPreference = "Continue"
`$AppsecDir = "C:\ProgramData\Hotmart\appsec"
`$LogDir = "C:\ProgramData\Hotmart\logs"

`$null = New-Item -ItemType Directory -Path `$AppsecDir -Force
`$null = New-Item -ItemType Directory -Path "`$AppsecDir\bin" -Force
`$null = New-Item -ItemType Directory -Path `$LogDir -Force

`$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
"[`$ts] ===== Install wrapper started =====" | Add-Content "`$LogDir\appsec-install.log" -Encoding UTF8
"[`$ts] Running as: `$([Environment]::UserName)" | Add-Content "`$LogDir\appsec-install.log" -Encoding UTF8

# 1. Copy payload to ProgramData
`$srcDir = Split-Path -Parent `$MyInvocation.MyCommand.Path
`$srcAppsec = Join-Path `$srcDir "appsec"

Copy-Item "`$srcAppsec\mdm-install.ps1" `$AppsecDir -Force
Copy-Item "`$srcAppsec\mdm-watchdog.ps1" `$AppsecDir -Force
Copy-Item "`$srcAppsec\mdm-uninstall.ps1" `$AppsecDir -Force
Copy-Item "`$srcAppsec\appsec-watchdog-task.xml" `$AppsecDir -Force
if (Test-Path "`$srcAppsec\bin\opengrep.exe") {
    Copy-Item "`$srcAppsec\bin\opengrep.exe" "`$AppsecDir\bin\" -Force
}

# 2. Install opengrep bundled
`$binDir = "C:\ProgramData\Hotmart\bin"
`$null = New-Item -ItemType Directory -Path `$binDir -Force
if (Test-Path "`$AppsecDir\bin\opengrep.exe") {
    Copy-Item "`$AppsecDir\bin\opengrep.exe" "`$binDir\opengrep.exe" -Force
    `$syspath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    if (`$syspath -notlike "*`$binDir*") {
        [Environment]::SetEnvironmentVariable("PATH", "`$syspath;`$binDir", "Machine")
    }
    "[`$ts] opengrep installed to `$binDir" | Add-Content "`$LogDir\appsec-install.log" -Encoding UTF8
}

# 3. Run main installer
"[`$ts] Running mdm-install.ps1..." | Add-Content "`$LogDir\appsec-install.log" -Encoding UTF8
& powershell -ExecutionPolicy Bypass -NoProfile -File "`$AppsecDir\mdm-install.ps1" 2>&1 |
    Add-Content "`$LogDir\appsec-install.log" -Encoding UTF8

# 4. Register Scheduled Task (watchdog)
"[`$ts] Registering Scheduled Task..." | Add-Content "`$LogDir\appsec-install.log" -Encoding UTF8
schtasks /Create /XML "`$AppsecDir\appsec-watchdog-task.xml" /TN "Hotmart\AppSecWatchdog" /F 2>&1 |
    Add-Content "`$LogDir\appsec-install.log" -Encoding UTF8

# 5. Register in Add/Remove Programs
`$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\HotmartAppSec"
`$null = New-Item -Path `$regPath -Force
Set-ItemProperty `$regPath -Name "DisplayName" -Value "Hotmart AppSec"
Set-ItemProperty `$regPath -Name "DisplayVersion" -Value "$VERSION"
Set-ItemProperty `$regPath -Name "Publisher" -Value "Hotmart Cybersecurity"
Set-ItemProperty `$regPath -Name "UninstallString" -Value "powershell -ExecutionPolicy Bypass -File `"C:\ProgramData\Hotmart\appsec\mdm-uninstall.ps1`""
Set-ItemProperty `$regPath -Name "NoModify" -Value 1 -Type DWord
Set-ItemProperty `$regPath -Name "NoRepair" -Value 1 -Type DWord

"[`$ts] ===== Install wrapper complete =====" | Add-Content "`$LogDir\appsec-install.log" -Encoding UTF8
exit 0
"@

$installWrapper | Set-Content "$BuildDir\payload\install.ps1" -Encoding UTF8

# ── Generate install.cmd (for Workspace ONE) ─────────────────────────────

$installCmd = @"
@echo off
REM Hotmart AppSec — Workspace ONE Install Command
REM This .cmd is the entry point for MDM deployment
powershell -ExecutionPolicy Bypass -NoProfile -File "%~dp0install.ps1"
exit /b %ERRORLEVEL%
"@

$installCmd | Set-Content "$BuildDir\payload\install.cmd" -Encoding ASCII

# ── Package as ZIP ───────────────────────────────────────────────────────

Write-Host ""
Write-Host ">>> Packaging..." -ForegroundColor Yellow

$zipPath = Join-Path $OutputDir "hotmart-appsec-win-$VERSION.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

Compress-Archive -Path "$BuildDir\payload\*" -DestinationPath $zipPath -Force

$zipSize = [Math]::Round((Get-Item $zipPath).Length / 1MB, 1)

Write-Host ""
Write-Host "  [OK] Package: $zipPath ($zipSize MB)" -ForegroundColor Green
Write-Host ""
Write-Host "  Contents:" -ForegroundColor White
Write-Host "    - install.cmd (entry point for Workspace ONE)"
Write-Host "    - install.ps1 (wrapper: copies + installs + registers task)"
Write-Host "    - appsec\mdm-install.ps1 (main installer)"
Write-Host "    - appsec\mdm-watchdog.ps1 (persistence daemon)"
Write-Host "    - appsec\mdm-uninstall.ps1 (complete removal)"
Write-Host "    - appsec\appsec-watchdog-task.xml (Scheduled Task)"
if (Test-Path $ogBundled) { Write-Host "    - appsec\bin\opengrep.exe (bundled SAST engine)" }
Write-Host ""
Write-Host "  Workspace ONE Configuration:" -ForegroundColor Yellow
Write-Host "    Install Command:   install.cmd"
Write-Host "    Uninstall Command: powershell -ExecutionPolicy Bypass -File `"C:\ProgramData\Hotmart\appsec\mdm-uninstall.ps1`""
Write-Host "    Detection Rule:    Registry exists HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\HotmartAppSec"
Write-Host ""

# Cleanup
Remove-Item $BuildDir -Recurse -Force

Write-Host "  Done." -ForegroundColor Green
Write-Host ""
