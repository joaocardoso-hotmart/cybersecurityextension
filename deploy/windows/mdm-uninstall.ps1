#Requires -Version 5.1
<#
.SYNOPSIS
    AppSec MDM Uninstaller — Hotmart Cybersecurity Extension (Windows)

.DESCRIPTION
    Completely removes all AppSec components:
      - Scheduled Task (watchdog)
      - Extensions from all IDEs
      - Steering/rules/hooks/gates
      - Pre-commit hooks
      - opengrep
      - AppSec directory

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File mdm-uninstall.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$EXTENSION_ID = "HotmartCybersecurity.cybersecurityextension"
$LogFile = "C:\ProgramData\Hotmart\logs\appsec-uninstall.log"

$null = New-Item -ItemType Directory -Path (Split-Path $LogFile) -Force

function Write-Log([string]$Msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$ts] $Msg" | Add-Content -Path $LogFile -Encoding UTF8
    Write-Host "  $Msg"
}

# ── User Detection ────────────────────────────────────────────────────────

function Get-ConsoleUserHome {
    $user = $null
    try {
        $sessions = query session 2>$null
        $active = $sessions | Where-Object { $_ -match "Active" }
        if ($active) {
            $user = ($active[0] -split '\s+' | Where-Object { $_ })[1]
            if ($user -eq "services") { $user = $null }
        }
    } catch {}
    if (-not $user) {
        try {
            $cs = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
            if ($cs.UserName) { $user = ($cs.UserName -split '\\')[-1] }
        } catch {}
    }
    if ($user) {
        $home = "C:\Users\$user"
        if (Test-Path $home) { return $home }
    }
    return $env:USERPROFILE
}

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Red
Write-Host "  AppSec MDM Uninstaller — Hotmart Cybersecurity (Windows)        " -ForegroundColor Red
Write-Host "==================================================================" -ForegroundColor Red
Write-Host ""

Write-Log "===== Uninstall started ====="

$UserHome = Get-ConsoleUserHome
Write-Log "User home: $UserHome"

# ── 1. Remove Scheduled Task ─────────────────────────────────────────────

Write-Log "[1/7] Removing Scheduled Task..."
try {
    schtasks /Delete /TN "Hotmart\AppSecWatchdog" /F 2>$null
    Write-Log "  OK Scheduled Task removed"
} catch {
    Write-Log "  -- Scheduled Task not found"
}

# ── 2. Uninstall extensions ──────────────────────────────────────────────

Write-Log "[2/7] Removing IDE extensions..."

function Uninstall-Ext([string]$Cli, [string]$Label) {
    if (-not $Cli -or -not (Test-Path $Cli)) { return }
    try {
        $existing = & $Cli --list-extensions 2>$null | Where-Object { $_ -ilike "*HotmartCybersecurity*" }
        if ($existing) {
            & $Cli --uninstall-extension $EXTENSION_ID 2>$null
            Write-Log "  OK $Label extension removed"
        } else {
            Write-Log "  -- $Label extension not installed"
        }
    } catch {
        Write-Log "  XX $Label uninstall failed: $_"
    }
}

$paths = @{
    "Kiro"     = @("$env:LOCALAPPDATA\Programs\Kiro\bin\kiro.cmd")
    "VS Code"  = @("$env:LOCALAPPDATA\Programs\Microsoft VS Code\bin\code.cmd","$env:ProgramFiles\Microsoft VS Code\bin\code.cmd")
    "Cursor"   = @("$env:LOCALAPPDATA\Programs\cursor\resources\app\bin\cursor.cmd")
    "Windsurf" = @("$env:LOCALAPPDATA\Programs\Windsurf\bin\windsurf.cmd")
}

foreach ($ide in $paths.Keys) {
    $cli = $paths[$ide] | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($cli) { Uninstall-Ext $cli $ide }
}

# ── 3. Remove configs ────────────────────────────────────────────────────

Write-Log "[3/7] Removing AppSec configs..."

$filesToRemove = @(
    "$UserHome\.kiro\steering\appsec-rules.md",
    "$UserHome\.kiro\hooks\appsec-gate.kiro.hook",
    "$UserHome\.cursor\rules\appsec-rules.mdc",
    "$UserHome\.windsurf\rules\appsec-rules.md",
    "$UserHome\.claude\rules\appsec-rules.md"
)

$dirsToRemove = @(
    "$UserHome\.cursor\appsec",
    "$UserHome\.windsurf\appsec",
    "$UserHome\.claude\appsec"
)

foreach ($f in $filesToRemove) {
    if (Test-Path $f) { Remove-Item $f -Force; Write-Log "  OK Removed $f" }
}
foreach ($d in $dirsToRemove) {
    if (Test-Path $d) { Remove-Item $d -Recurse -Force; Write-Log "  OK Removed $d" }
}

# Claude settings.json — remove only appsec hook
$claudeSettings = "$UserHome\.claude\settings.json"
if (Test-Path $claudeSettings) {
    try {
        $json = Get-Content $claudeSettings -Raw | ConvertFrom-Json
        if ($json.hooks -and $json.hooks.PreToolUse) {
            $json.hooks.PreToolUse = @($json.hooks.PreToolUse | Where-Object {
                $_.hooks | ForEach-Object { $_.command } | Where-Object { $_ -notlike "*appsec-gate*" }
            })
            if ($json.hooks.PreToolUse.Count -eq 0) { $json.hooks.PSObject.Properties.Remove("PreToolUse") }
            if (-not $json.hooks.PSObject.Properties.Count) { $json.PSObject.Properties.Remove("hooks") }
            $json | ConvertTo-Json -Depth 10 | Set-Content $claudeSettings -Encoding UTF8
            Write-Log "  OK Claude settings.json cleaned"
        }
    } catch { Write-Log "  -- Claude settings.json: $_" }
}

# ── 4. Remove pre-commit hooks ───────────────────────────────────────────

Write-Log "[4/7] Removing pre-commit hooks..."
$removed = 0
$searchDirs = @("$UserHome\Documents","$UserHome\projects","$UserHome\dev","$UserHome\workspace","$UserHome\repos","$UserHome\code")
foreach ($dir in $searchDirs) {
    if (-not (Test-Path $dir)) { continue }
    Get-ChildItem -Path $dir -Recurse -Depth 4 -Filter ".git" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $hook = Join-Path $_.FullName "hooks\pre-commit"
        if ((Test-Path $hook) -and (Select-String -Path $hook -Pattern "AppSec" -Quiet)) {
            Remove-Item $hook -Force
            $removed++
        }
    }
}
Write-Log "  Removed $removed pre-commit hook(s)"

# ── 5. Remove opengrep ───────────────────────────────────────────────────

Write-Log "[5/7] Removing opengrep..."
$ogPaths = @("C:\ProgramData\Hotmart\bin\opengrep.exe", "$env:LOCALAPPDATA\opengrep\opengrep.exe")
foreach ($og in $ogPaths) {
    if (Test-Path $og) { Remove-Item $og -Force; Write-Log "  OK Removed $og" }
}
# Clean PATH
$syspath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($syspath -like "*Hotmart\bin*") {
    $newPath = ($syspath -split ';' | Where-Object { $_ -notlike "*Hotmart\bin*" }) -join ';'
    [Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
    Write-Log "  OK Cleaned system PATH"
}

# ── 6. Remove AppSec directory ───────────────────────────────────────────

Write-Log "[6/7] Removing AppSec directory..."
$appsecDir = "C:\ProgramData\Hotmart\appsec"
if (Test-Path $appsecDir) {
    Remove-Item $appsecDir -Recurse -Force
    Write-Log "  OK $appsecDir removed"
}
# Remove parent if empty
$parentDir = "C:\ProgramData\Hotmart"
if ((Test-Path $parentDir) -and -not (Get-ChildItem $parentDir -Recurse -File)) {
    Remove-Item $parentDir -Recurse -Force -ErrorAction SilentlyContinue
}

# ── 7. Remove from Add/Remove Programs registry ─────────────────────────

Write-Log "[7/7] Removing registry entries..."
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\HotmartAppSec",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\HotmartAppSec"
)
foreach ($rp in $regPaths) {
    if (Test-Path $rp) { Remove-Item $rp -Force; Write-Log "  OK Registry entry removed" }
}

Write-Log "===== Uninstall complete ====="
Write-Host ""
Write-Host "  Done. All AppSec components removed." -ForegroundColor Green
Write-Host ""
exit 0
