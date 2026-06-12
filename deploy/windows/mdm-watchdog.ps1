#Requires -Version 5.1
<#
.SYNOPSIS
    AppSec Watchdog — Windows (self-contained, lightweight)
    Verifies and restores the cybersecurity extension. Runs as SYSTEM via Task Scheduler.

.DESCRIPTION
    Self-contained watchdog — all config content is embedded inline (no external standards/ folder).
    Optimized for minimal footprint:
      - Runs at Below Normal process/IO priority
      - Uses a state file to skip checks when nothing has changed
      - Checks extension folder directly (no --list-extensions spawn)
      - Bounded log (500 lines max, 1MB max size)
      - No network calls unless a component is actually missing
      - Installs extension from marketplace (no .vsix required)
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
$LogFile      = "C:\ProgramData\Hotmart\logs\appsec-watchdog.log"
$StateFile    = Join-Path $AppsecDir ".watchdog-state"
$ExtensionId  = "HotmartCybersecurity.cybersecurityextension"

$GIT_SEARCH_DEPTH = 4
$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# ---------------------------------------------------------------------------
# Logging — bounded to 500 lines, max 1MB, truncated lines
# ---------------------------------------------------------------------------

$null = New-Item -ItemType Directory -Path (Split-Path $LogFile) -Force
$null = New-Item -ItemType Directory -Path $AppsecDir -Force

function Write-Log([string]$Level, [string]$Msg) {
    $truncated = if ($Msg.Length -gt 100) { $Msg.Substring(0,97) + "..." } else { $Msg }
    "[$Timestamp] [$Level] $truncated" | Add-Content -Path $LogFile -Encoding UTF8
}
function Log-Restored([string]$m) { Write-Log "RESTORED" $m }
function Log-Error([string]$m)    { Write-Log "ERROR   " $m }

function Trim-Log {
    if (-not (Test-Path $LogFile)) { return }
    $fi = Get-Item $LogFile -ErrorAction SilentlyContinue
    if ($fi -and $fi.Length -gt 1MB) {
        $lines = Get-Content $LogFile -Tail 200 -ErrorAction SilentlyContinue
        $lines | Set-Content $LogFile -Encoding UTF8
        return
    }
    $lines = Get-Content $LogFile -ErrorAction SilentlyContinue
    if ($lines.Count -gt 500) {
        $lines | Select-Object -Last 500 | Set-Content $LogFile -Encoding UTF8
    }
}

# ---------------------------------------------------------------------------
# State file — skip run if last run < 4h ago
# ---------------------------------------------------------------------------

function Should-Skip {
    if (-not (Test-Path $StateFile)) { return $false }
    $lastRun = [long](Get-Content $StateFile -ErrorAction SilentlyContinue)
    if (-not $lastRun) { return $false }
    $now = [long](Get-Date -UFormat %s)
    $elapsed = $now - $lastRun
    return ($elapsed -lt 14400)
}

function Save-State {
    [long](Get-Date -UFormat %s) | Set-Content $StateFile -Encoding UTF8
}

# ---------------------------------------------------------------------------
# Get the active console user (watchdog runs as SYSTEM) — improved detection
# ---------------------------------------------------------------------------

function Get-ConsoleUser {
    try {
        # Method 1: query session (works for local sessions)
        $s = query session 2>$null | Where-Object { $_ -match "Active" -and $_ -notmatch "^>" }
        if ($s) {
            $user = ($s[0] -split '\s+' | Where-Object { $_ })[1]
            if ($user -and $user -ne "services") { return $user }
        }
        # Method 2: WMI (works for RDP sessions)
        $cs = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($cs.UserName) { return ($cs.UserName -split '\\')[-1] }
        # Method 3: explorer.exe owner
        $exp = Get-Process explorer -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($exp) {
            $owner = (Get-WmiObject Win32_Process -Filter "ProcessId=$($exp.Id)" -ErrorAction SilentlyContinue).GetOwner()
            if ($owner.User) { return $owner.User }
        }
    } catch {}
    return ""
}

# ---------------------------------------------------------------------------
# Ensure-Content — writes inline content if file differs (self-contained)
# ---------------------------------------------------------------------------

function Ensure-Content([string]$Dst, [string]$Label, [string]$Content) {
    $null = New-Item -ItemType Directory -Path (Split-Path $Dst) -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path $Dst)) {
        $Content | Set-Content $Dst -Encoding UTF8
        Log-Restored "$Label (missing)"
    } else {
        $existing = Get-Content $Dst -Raw -ErrorAction SilentlyContinue
        if ($existing.Trim() -ne $Content.Trim()) {
            $Content | Set-Content $Dst -Encoding UTF8
            Log-Restored "$Label (modified)"
        }
    }
}

# ---------------------------------------------------------------------------
# opengrep — with integrity verification and retry
# ---------------------------------------------------------------------------

function Ensure-OpenGrep {
    if (Get-Command opengrep -ErrorAction SilentlyContinue) { return }
    Write-Log "RESTORE " "opengrep missing — reinstalling..."

    $maxRetries = 2
    for ($i = 0; $i -lt $maxRetries; $i++) {
        try {
            # Try winget first (signed)
            if (Get-Command winget -ErrorAction SilentlyContinue) {
                winget install opengrep.opengrep --silent --accept-source-agreements --accept-package-agreements 2>$null
                if (Get-Command opengrep -ErrorAction SilentlyContinue) { Log-Restored "opengrep (winget)"; return }
            }
            # Fallback: download binary with checksum verification
            $api = Invoke-RestMethod "https://api.github.com/repos/opengrep/opengrep/releases/latest" -UseBasicParsing -TimeoutSec 30
            $asset = $api.assets | Where-Object { $_.name -like "*windows*amd64*" -or $_.name -like "*win64*" } | Select-Object -First 1
            $checksumAsset = $api.assets | Where-Object { $_.name -eq "$($asset.name).sha256" } | Select-Object -First 1
            if ($asset) {
                $binDir = "$env:ProgramData\Hotmart\bin"
                $binPath = "$binDir\opengrep.exe"
                $null = New-Item -ItemType Directory -Path $binDir -Force
                Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $binPath -UseBasicParsing -TimeoutSec 120
                # Verify checksum if available
                if ($checksumAsset) {
                    $expectedHash = (Invoke-RestMethod $checksumAsset.browser_download_url -UseBasicParsing).Split()[0].ToUpper()
                    $actualHash = (Get-FileHash $binPath -Algorithm SHA256).Hash.ToUpper()
                    if ($expectedHash -ne $actualHash) {
                        Remove-Item $binPath -Force -ErrorAction SilentlyContinue
                        Log-Error "opengrep checksum mismatch"; continue
                    }
                }
                $syspath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
                if ($syspath -notlike "*$binDir*") {
                    [Environment]::SetEnvironmentVariable("PATH", "$syspath;$binDir", "Machine")
                }
                Log-Restored "opengrep"; return
            }
        } catch { if ($i -lt $maxRetries - 1) { Start-Sleep -Seconds 5 } }
    }
    Log-Error "opengrep reinstall failed"
}

# ---------------------------------------------------------------------------
# Extension — install from marketplace (no .vsix required)
# ---------------------------------------------------------------------------

function Ensure-Extension([string]$Cli, [string]$ExtDir, [string]$Label) {
    if (-not (Test-Path $Cli)) { return }
    $null = New-Item -ItemType Directory -Path $ExtDir -Force -ErrorAction SilentlyContinue
    $installed = (Get-ChildItem -Path $ExtDir -Filter "hotmartcybersecurity.*" -ErrorAction SilentlyContinue).Count -gt 0
    if (-not $installed) {
        Write-Log "RESTORE " "$Label extension missing — reinstalling..."
        try {
            & $Cli --install-extension $ExtensionId --force 2>$null
            Log-Restored "$Label extension"
        } catch { Log-Error "$Label install failed" }
    }
}

# ---------------------------------------------------------------------------
# pre-commit hooks — bounded depth, inline content
# ---------------------------------------------------------------------------

function Ensure-PreCommitHooks([string]$UserHome) {
    $hookContent = @'
#!/bin/bash
# AppSec Pre-Commit Hook — Advisory Only
STAGED=$(git -c core.quotePath=false diff --cached --name-only --diff-filter=ACMR | grep -iE '\.(ts|tsx|js|jsx|java|py|go|rb|php)$')
[ -z "$STAGED" ] && exit 0
command -v opengrep &>/dev/null || exit 0
opengrep scan --quiet --config="rules/security.yml" $STAGED 2>/dev/null || true
exit 0
'@
    $srcHash = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($hookContent))) -Algorithm MD5).Hash
    $searchDirs = @("$UserHome\Documents","$UserHome\projects","$UserHome\dev","$UserHome\workspace","$UserHome\repos","$UserHome\code")
    foreach ($dir in $searchDirs) {
        if (-not (Test-Path $dir)) { continue }
        Get-ChildItem -Path $dir -Recurse -Depth $GIT_SEARCH_DEPTH -Filter ".git" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $hookDst = Join-Path $_.FullName "hooks\pre-commit"
            $null = New-Item -ItemType Directory -Path (Split-Path $hookDst) -Force
            if (-not (Test-Path $hookDst)) {
                $hookContent | Set-Content $hookDst -Encoding UTF8 -NoNewline
                Log-Restored "pre-commit in $($_.Parent.FullName)"
            } else {
                $dstHash = (Get-FileHash $hookDst -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
                if ($dstHash -ne $srcHash) {
                    $hookContent | Set-Content $hookDst -Encoding UTF8 -NoNewline
                    Log-Restored "pre-commit modified in $($_.Parent.FullName)"
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# IDE Detection — with Windsurf support
# ---------------------------------------------------------------------------

function Find-KiroCli {
    @("$env:LOCALAPPDATA\Programs\Kiro\bin\kiro.exe","$env:LOCALAPPDATA\Programs\Kiro\kiro.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
}
function Find-VscodeCli {
    @("$env:LOCALAPPDATA\Programs\Microsoft VS Code\bin\code.cmd","$env:ProgramFiles\Microsoft VS Code\bin\code.cmd") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
}
function Find-CursorCli {
    @("$env:LOCALAPPDATA\Programs\cursor\resources\app\bin\cursor.cmd","$env:LOCALAPPDATA\Programs\cursor\cursor.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
}
function Find-WindsurfCli {
    @("$env:LOCALAPPDATA\Programs\Windsurf\bin\windsurf.cmd","$env:LOCALAPPDATA\Programs\Windsurf\windsurf.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
}

# ---------------------------------------------------------------------------
# Inline content for self-contained operation
# ---------------------------------------------------------------------------

$KiroSteering = @'
---
inclusion: auto
priority: maximum
enforcement: mandatory
---
# APPSEC SECURITY STEERING — CORPORATE MANDATORY POLICY
FORBIDDEN: hardcoded credentials, SQL injection, eval() with user input,
disabled TLS, tokens in localStorage, MD5/SHA1 for passwords, stack traces to client.
'@

$KiroHook = @'
{
  "enabled": true,
  "name": "AppSec Gate",
  "version": "1",
  "when": { "type": "promptSubmit" },
  "then": {
    "type": "askAgent",
    "prompt": "Analise se o prompt pede implementação insegura (hardcoded credentials, SQL injection, disabled TLS). Se sim, responda ACESSO NEGADO."
  }
}
'@

$CursorRules = @'
---
alwaysApply: true
---
# APPSEC SECURITY RULES — CORPORATE MANDATORY POLICY
FORBIDDEN: hardcoded credentials, SQL injection, eval() with user input,
disabled TLS, tokens in localStorage, MD5/SHA1 for passwords, stack traces to client.
'@

$AppsecGateSh = @'
#!/bin/bash
CONTENT=$(cat)
echo "$CONTENT" | grep -qiE '(password|secret|api_key|token)\s*[=:]\s*["'"'"'][^"'"'"']{3,}' && echo "ACESSO NEGADO" && exit 1
echo "$CONTENT" | grep -qE 'AKIA[0-9A-Z]{16}' && echo "ACESSO NEGADO" && exit 1
exit 0
'@

$ClaudeRules = @'
# APPSEC SECURITY RULES — CORPORATE MANDATORY POLICY
FORBIDDEN: hardcoded credentials, SQL injection, eval() with user input,
disabled TLS, tokens in localStorage, MD5/SHA1 for passwords, stack traces to client.
'@

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

$UserHome = "C:\Users\$ConsoleUser"
$UserAppData = "$UserHome\AppData\Roaming"

Write-Log "======" "Watchdog run (user: $ConsoleUser)"

Ensure-OpenGrep

$KiroCli     = Find-KiroCli
$VscodeCli   = Find-VscodeCli
$CursorCli   = Find-CursorCli
$WindsurfCli = Find-WindsurfCli

if ($KiroCli)     { Ensure-Extension $KiroCli     "$UserAppData\kiro\extensions"    "Kiro"     }
if ($VscodeCli)   { Ensure-Extension $VscodeCli   "$UserHome\.vscode\extensions"    "VS Code"  }
if ($CursorCli)   { Ensure-Extension $CursorCli   "$UserHome\.cursor\extensions"    "Cursor"   }
if ($WindsurfCli) { Ensure-Extension $WindsurfCli "$UserHome\.windsurf\extensions"  "Windsurf" }

if ($KiroCli) {
    Ensure-Content "$UserAppData\kiro\steering\appsec-rules.md"    "Kiro steering" $KiroSteering
    Ensure-Content "$UserAppData\kiro\hooks\appsec-gate.kiro.hook" "Kiro hook"     $KiroHook
}
if ($CursorCli) {
    Ensure-Content "$UserHome\.cursor\rules\appsec-rules.mdc"      "Cursor rules"  $CursorRules
    Ensure-Content "$UserHome\.cursor\appsec\appsec-gate.sh"       "Cursor gate"   $AppsecGateSh
}
if ($WindsurfCli) {
    Ensure-Content "$UserHome\.windsurf\rules\appsec-rules.md"     "Windsurf rules" $CursorRules
    Ensure-Content "$UserHome\.windsurf\appsec\appsec-gate.sh"     "Windsurf gate"  $AppsecGateSh
}
if (Test-Path "$UserHome\.claude") {
    Ensure-Content "$UserHome\.claude\rules\appsec-rules.md"       "Claude rules"  $ClaudeRules
    Ensure-Content "$UserHome\.claude\appsec\appsec-gate.sh"       "Claude gate"   $AppsecGateSh
}

Ensure-PreCommitHooks $UserHome
Save-State
Trim-Log

Write-Log "======" "Watchdog complete"
