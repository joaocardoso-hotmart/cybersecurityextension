#Requires -Version 5.1
<#
.SYNOPSIS
    AppSec Watchdog — Windows (lightweight)
    Verifies and restores the cybersecurity extension. Runs as SYSTEM via Task Scheduler.

.DESCRIPTION
    Optimized for minimal footprint:
      - Runs at Below Normal process/IO priority
      - Uses a state file to skip checks when nothing has changed
      - Checks extension folder directly (no --list-extensions spawn)
      - Bounded log (500 lines max)
      - No network calls unless a component is actually missing
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# ---------------------------------------------------------------------------
# Run at lowest priority — avoids competing with the dev's IDE/builds
# ---------------------------------------------------------------------------

try {
    $proc = [System.Diagnostics.Process]::GetCurrentProcess()
    $proc.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal

    # Set IO priority to low via P/Invoke
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class IoPriority {
    [DllImport("ntdll.dll")]
    public static extern int NtSetInformationProcess(IntPtr h, int cls, ref int val, int len);
    public static void SetLow() { int v = 1; NtSetInformationProcess(System.Diagnostics.Process.GetCurrentProcess().Handle, 33, ref v, 4); }
}
'@ -ErrorAction SilentlyContinue
    [IoPriority]::SetLow()
} catch {}

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

$AppsecDir    = "C:\ProgramData\Hotmart\appsec"
$StandardsDir = Join-Path $AppsecDir "standards"
$LogFile      = "C:\ProgramData\Hotmart\logs\appsec-watchdog.log"
$StateFile    = Join-Path $AppsecDir ".watchdog-state"
$VsixFile     = Get-ChildItem -Path $AppsecDir -Filter "cybersecurityextension-*.vsix" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName

$GIT_SEARCH_DEPTH = 4
$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# ---------------------------------------------------------------------------
# Logging — bounded to 500 lines
# ---------------------------------------------------------------------------

$null = New-Item -ItemType Directory -Path (Split-Path $LogFile) -Force

function Write-Log([string]$Level, [string]$Msg) {
    "[$Timestamp] [$Level] $Msg" | Add-Content -Path $LogFile -Encoding UTF8
}
function Log-Restored([string]$m) { Write-Log "RESTORED" $m }
function Log-Error([string]$m)    { Write-Log "ERROR   " $m }

function Trim-Log {
    if (-not (Test-Path $LogFile)) { return }
    $lines = Get-Content $LogFile -ErrorAction SilentlyContinue
    if ($lines.Count -gt 500) {
        $lines | Select-Object -Last 500 | Set-Content $LogFile -Encoding UTF8
    }
}

# ---------------------------------------------------------------------------
# State file — skip run if standards unchanged and last run < 4h ago
# ---------------------------------------------------------------------------

function Get-StandardsHash {
    $files = Get-ChildItem -Path $StandardsDir -Recurse -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -match "appsec-rules\.(md|mdc)|appsec-gate\.(sh|kiro\.hook)|^pre-commit$" } |
             Sort-Object FullName
    if (-not $files) { return "nohash" }
    $combined = ($files | ForEach-Object { (Get-FileHash $_.FullName -Algorithm MD5).Hash }) -join ""
    (Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($combined))) -Algorithm MD5).Hash
}

function Should-Skip {
    if (-not (Test-Path $StateFile)) { return $false }
    $parts = (Get-Content $StateFile -ErrorAction SilentlyContinue) -split '\|'
    if ($parts.Count -lt 2) { return $false }
    $storedHash = $parts[0]
    $lastRun    = [long]$parts[1]
    $now        = [long](Get-Date -UFormat %s)
    $elapsed    = $now - $lastRun

    # Always do a full run after 4 hours
    if ($elapsed -ge 14400) { return $false }
    return ($storedHash -eq (Get-StandardsHash))
}

function Save-State {
    "$(Get-StandardsHash)|$([long](Get-Date -UFormat %s))" | Set-Content $StateFile -Encoding UTF8
}

# ---------------------------------------------------------------------------
# Get the active console user (watchdog runs as SYSTEM)
# ---------------------------------------------------------------------------

function Get-ConsoleUser {
    try {
        $s = query session 2>$null | Where-Object { $_ -match "Active" -and $_ -notmatch "^>" }
        if ($s) { ($s[0] -split '\s+' | Where-Object { $_ })[1] }
    } catch { "" }
}

# ---------------------------------------------------------------------------
# File integrity — hash check before copy
# ---------------------------------------------------------------------------

function Ensure-File([string]$Src, [string]$Dst, [string]$Label) {
    if (-not (Test-Path $Src)) { return }
    $null = New-Item -ItemType Directory -Path (Split-Path $Dst) -Force

    if (-not (Test-Path $Dst)) {
        Copy-Item $Src $Dst -Force
        Log-Restored "$Label (missing)"
    } elseif ((Get-FileHash $Src -Algorithm MD5).Hash -ne (Get-FileHash $Dst -Algorithm MD5).Hash) {
        Copy-Item $Src $Dst -Force
        Log-Restored "$Label (modified)"
    }
    # Silent on OK
}

# ---------------------------------------------------------------------------
# opengrep
# ---------------------------------------------------------------------------

function Ensure-OpenGrep {
    if (Get-Command opengrep -ErrorAction SilentlyContinue) { return }
    Write-Log "RESTORE " "opengrep missing — reinstalling..."
    try {
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            winget install opengrep.opengrep --silent --accept-source-agreements --accept-package-agreements 2>$null
            if (Get-Command opengrep -ErrorAction SilentlyContinue) { Log-Restored "opengrep (winget)"; return }
        }
        $api   = Invoke-RestMethod "https://api.github.com/repos/opengrep/opengrep/releases/latest" -UseBasicParsing
        $asset = $api.assets | Where-Object { $_.name -like "*windows*amd64*" -or $_.name -like "*win64*" } | Select-Object -First 1
        if ($asset) {
            $binDir = "$env:ProgramData\Hotmart\bin"
            $null = New-Item -ItemType Directory -Path $binDir -Force
            Invoke-WebRequest -Uri $asset.browser_download_url -OutFile "$binDir\opengrep.exe" -UseBasicParsing
            $syspath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
            if ($syspath -notlike "*$binDir*") {
                [Environment]::SetEnvironmentVariable("PATH", "$syspath;$binDir", "Machine")
            }
            Log-Restored "opengrep"
        }
    } catch { Log-Error "opengrep reinstall failed: $_" }
}

# ---------------------------------------------------------------------------
# Extension — check folder directly, no --list-extensions spawn
# Each IDE stores extensions in a different folder:
#   Kiro    → %APPDATA%\kiro\extensions
#   VS Code → %USERPROFILE%\.vscode\extensions
#   Cursor  → %USERPROFILE%\.cursor\extensions
# ---------------------------------------------------------------------------

function Ensure-Extension([string]$Cli, [string]$ExtDir, [string]$Label) {
    if (-not (Test-Path $Cli)) { return }
    if (-not $VsixFile) { Log-Error "$Label — no .vsix found"; return }

    $null = New-Item -ItemType Directory -Path $ExtDir -Force -ErrorAction SilentlyContinue
    $installed = (Get-ChildItem -Path $ExtDir -Filter "hotmartcybersecurity.*" -ErrorAction SilentlyContinue).Count -gt 0

    if (-not $installed) {
        Write-Log "RESTORE " "$Label extension missing — reinstalling..."
        try {
            & $Cli --install-extension $VsixFile --force 2>$null
            Log-Restored "$Label extension"
        } catch { Log-Error "$Label install failed: $_" }
    }
}

# ---------------------------------------------------------------------------
# pre-commit hooks — bounded depth, no expensive pipeline
# ---------------------------------------------------------------------------

function Ensure-PreCommitHooks([string]$UserHome) {
    $hookSrc = Join-Path $StandardsDir "hooks\pre-commit"
    if (-not (Test-Path $hookSrc)) { return }
    $srcHash = (Get-FileHash $hookSrc -Algorithm MD5).Hash

    $searchDirs = @("$UserHome\Documents","$UserHome\projects","$UserHome\dev","$UserHome\workspace","$UserHome\repos","$UserHome\code","$UserHome\source")

    foreach ($dir in $searchDirs) {
        if (-not (Test-Path $dir)) { continue }
        Get-ChildItem -Path $dir -Recurse -Depth $GIT_SEARCH_DEPTH -Filter ".git" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $hookDst = Join-Path $_.FullName "hooks\pre-commit"
            $null = New-Item -ItemType Directory -Path (Split-Path $hookDst) -Force
            if (-not (Test-Path $hookDst)) {
                Copy-Item $hookSrc $hookDst -Force
                Log-Restored "pre-commit in $($_.Parent.FullName)"
            } elseif ((Get-FileHash $hookDst -Algorithm MD5).Hash -ne $srcHash) {
                Copy-Item $hookSrc $hookDst -Force
                Log-Restored "pre-commit modified in $($_.Parent.FullName)"
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if (Should-Skip) { exit 0 }

$ConsoleUser = Get-ConsoleUser
if (-not $ConsoleUser) {
    Ensure-OpenGrep
    Save-State
    exit 0
}

$UserHome             = "C:\Users\$ConsoleUser"
$env:LOCALAPPDATA     = "$UserHome\AppData\Local"
$env:APPDATA          = "$UserHome\AppData\Roaming"

Write-Log "======" "===== Watchdog run (user: $ConsoleUser) ====="

Ensure-OpenGrep

# IDE CLIs
$KiroCli   = @("$env:LOCALAPPDATA\Programs\Kiro\bin\kiro.exe","$env:LOCALAPPDATA\Programs\Kiro\kiro.exe")          | Where-Object { Test-Path $_ } | Select-Object -First 1
$VscodeCli = @("$env:LOCALAPPDATA\Programs\Microsoft VS Code\bin\code.cmd","$env:LOCALAPPDATA\Programs\Microsoft VS Code\Code.exe","$env:ProgramFiles\Microsoft VS Code\bin\code.cmd") | Where-Object { Test-Path $_ } | Select-Object -First 1
$CursorCli = @("$env:LOCALAPPDATA\Programs\cursor\resources\app\bin\cursor.cmd","$env:LOCALAPPDATA\Programs\cursor\cursor.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($KiroCli)   { Ensure-Extension $KiroCli   "$env:APPDATA\kiro\extensions"    "Kiro"    }
if ($VscodeCli) { Ensure-Extension $VscodeCli "$UserHome\.vscode\extensions"    "VS Code" }
if ($CursorCli) { Ensure-Extension $CursorCli "$UserHome\.cursor\extensions"    "Cursor"  }

if ($KiroCli) {
    Ensure-File (Join-Path $StandardsDir "kiro\steering\appsec-rules.md")    "$env:APPDATA\kiro\steering\appsec-rules.md"    "Kiro steering"
    Ensure-File (Join-Path $StandardsDir "hooks\kiro\appsec-gate.kiro.hook") "$env:APPDATA\kiro\hooks\appsec-gate.kiro.hook" "Kiro hook"
}
if ($CursorCli) {
    Ensure-File (Join-Path $StandardsDir "cursor\rules\appsec-rules.mdc")    "$UserHome\.cursor\rules\appsec-rules.mdc"      "Cursor rules"
    Ensure-File (Join-Path $StandardsDir "hooks\appsec-gate.sh")             "$UserHome\.cursor\appsec\appsec-gate.sh"       "Cursor appsec-gate.sh"
}
if (Test-Path "$UserHome\.claude") {
    Ensure-File (Join-Path $StandardsDir "claude\rules\appsec-rules.md")     "$UserHome\.claude\rules\appsec-rules.md"       "Claude rules"
    Ensure-File (Join-Path $StandardsDir "hooks\appsec-gate.sh")             "$UserHome\.claude\appsec\appsec-gate.sh"       "Claude appsec-gate.sh"
}

Ensure-PreCommitHooks $UserHome
Save-State
Trim-Log

Write-Log "======" "===== Watchdog complete ====="
