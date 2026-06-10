@echo off
REM =============================================================================
REM Build Hotmart AppSec Windows Installer (.exe)
REM =============================================================================
REM Requirements:
REM   - InnoSetup 6 installed (https://jrsoftware.org/isdl.php)
REM   - Internet access (to download opengrep) OR local opengrep.exe
REM
REM Output: dist\HotmartAppSec-Setup-2.8.0.exe
REM
REM Usage: build.cmd
REM =============================================================================

setlocal enabledelayedexpansion

set VERSION=2.8.0
set SCRIPT_DIR=%~dp0
set PROJECT_DIR=%SCRIPT_DIR%..\..
set PAYLOAD_DIR=%SCRIPT_DIR%payload
set OUTPUT_DIR=%PROJECT_DIR%\dist

echo.
echo ================================================================
echo   Building Hotmart AppSec Windows Installer v%VERSION%
echo ================================================================
echo.

REM Clean payload
if exist "%PAYLOAD_DIR%" rmdir /s /q "%PAYLOAD_DIR%"
mkdir "%PAYLOAD_DIR%\bin" 2>nul

REM ── Download opengrep ──────────────────────────────────────────────────

echo   [..] Downloading opengrep for Windows...
powershell -NoProfile -Command ^
  "try { ^
    $r = Invoke-RestMethod 'https://api.github.com/repos/opengrep/opengrep/releases/latest' -TimeoutSec 15; ^
    $a = $r.assets | Where-Object { $_.name -eq 'opengrep_windows_x86.exe' } | Select-Object -First 1; ^
    if ($a) { ^
      Invoke-WebRequest $a.browser_download_url -OutFile '%PAYLOAD_DIR%\bin\opengrep.exe' -TimeoutSec 120; ^
      Write-Host '  [OK] opengrep downloaded' -ForegroundColor Green ^
    } else { Write-Host '  [!!] No Windows binary found' -ForegroundColor Yellow } ^
  } catch { Write-Host '  [!!] Download failed' -ForegroundColor Yellow }"

if not exist "%PAYLOAD_DIR%\bin\opengrep.exe" (
    echo   [..] Checking local opengrep...
    where opengrep.exe >nul 2>&1
    if !errorlevel! equ 0 (
        for /f "delims=" %%i in ('where opengrep.exe') do copy "%%i" "%PAYLOAD_DIR%\bin\opengrep.exe" >nul
        echo   [OK] Using local opengrep
    ) else (
        echo   [!!] WARNING: No opengrep binary available. Install will try to download at runtime.
    )
)

REM ── Compile with InnoSetup ─────────────────────────────────────────────

echo.
echo   [..] Compiling installer with InnoSetup...

set ISCC=
if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" set ISCC=C:\Program Files (x86)\Inno Setup 6\ISCC.exe
if exist "C:\Program Files\Inno Setup 6\ISCC.exe" set ISCC=C:\Program Files\Inno Setup 6\ISCC.exe

if "!ISCC!"=="" (
    echo.
    echo   [XX] InnoSetup not found!
    echo       Install from: https://jrsoftware.org/isdl.php
    echo       Or set ISCC environment variable to ISCC.exe path
    echo.
    echo   Alternatively, use the ZIP package:
    echo       powershell -File scripts\build-win-installer.ps1
    exit /b 1
)

"%ISCC%" "%SCRIPT_DIR%setup.iss"

if %errorlevel% neq 0 (
    echo   [XX] InnoSetup compilation failed!
    exit /b 1
)

echo.
echo   [OK] Installer built: %OUTPUT_DIR%\HotmartAppSec-Setup-%VERSION%.exe
echo.
echo   ================================================================
echo   Workspace ONE Configuration:
echo   ================================================================
echo     Install Command:
echo       HotmartAppSec-Setup-%VERSION%.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
echo.
echo     Uninstall Command:
echo       "C:\ProgramData\Hotmart\appsec\unins000.exe" /VERYSILENT /SUPPRESSMSGBOXES
echo.
echo     Detection Rule:
echo       Registry exists: HKLM\SOFTWARE\Hotmart\AppSec\Version
echo.
echo     Update:
echo       Upload new .exe with higher version
echo   ================================================================
echo.

REM Cleanup
rmdir /s /q "%PAYLOAD_DIR%" 2>nul

exit /b 0
