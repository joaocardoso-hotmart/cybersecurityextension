#Requires -Version 5.1
<#
.SYNOPSIS
    AppSec MDM Installer — Hotmart Cybersecurity Extension (Windows)

.DESCRIPTION
    Self-contained installer. No external dependencies beyond this script.
    Installs the extension from the marketplace and writes all config files
    inline — no standards/ folder or .vsix required.

    Supported IDEs: Kiro, VS Code, Cursor, Windsurf, Claude Code

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File mdm-install.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$EXTENSION_ID = "HotmartCybersecurity.cybersecurityextension"

# ── Supply chain protection: Zscaler Root CA fingerprint ──────────────────
$TRUSTED_PROXY_CA_THUMBPRINT = "04F61F1D13AAE1D16573DC2C37F796FDF4AC97713A6959EBB11D2473958B1A53"
$TRUSTED_PROXY_CA_CN = "Zscaler Root CA"

# ── Logging ───────────────────────────────────────────────────────────────

$LogDir = "C:\ProgramData\Hotmart\logs"
$LogFile = Join-Path $LogDir "appsec-install.log"
$DetailLog = Join-Path $LogDir "appsec-install-detail.log"
$null = New-Item -ItemType Directory -Path $LogDir -Force

function Write-Log([string]$Msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$ts] $Msg" | Add-Content -Path $LogFile -Encoding UTF8
}

# ── Tracking ──────────────────────────────────────────────────────────────

$Installed = [System.Collections.Generic.List[string]]::new()
$Skipped   = [System.Collections.Generic.List[string]]::new()
$Failed    = [System.Collections.Generic.List[string]]::new()

function Write-Section([string]$Title) { Write-Host "`n>>> $Title" -ForegroundColor Yellow }
function Write-Ok([string]$Label)   { Write-Host "  [OK] $Label" -ForegroundColor Green; $Installed.Add($Label) }
function Write-Skip([string]$Label) { Write-Host "  [--] $Label" -ForegroundColor DarkGray; $Skipped.Add($Label) }
function Write-Fail([string]$Label) { Write-Host "  [XX] $Label" -ForegroundColor Red; $Failed.Add($Label) }

# ── User Detection ────────────────────────────────────────────────────────

function Get-ConsoleUserHome {
    # Detect the logged-in GUI user (not SYSTEM)
    $user = $null

    # Method 1: query session
    try {
        $sessions = query session 2>$null
        $active = $sessions | Where-Object { $_ -match "Active" }
        if ($active) {
            $user = ($active[0] -split '\s+' | Where-Object { $_ })[1]
            if ($user -eq "services" -or $user -eq ">services") { $user = $null }
        }
    } catch {}

    # Method 2: WMI
    if (-not $user) {
        try {
            $cs = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
            if ($cs.UserName) { $user = ($cs.UserName -split '\\')[-1] }
        } catch {}
    }

    # Method 3: explorer.exe owner
    if (-not $user) {
        try {
            $exp = Get-Process explorer -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($exp) {
                $owner = (Get-WmiObject Win32_Process -Filter "ProcessId=$($exp.Id)" -ErrorAction SilentlyContinue).GetOwner()
                if ($owner.User) { $user = $owner.User }
            }
        } catch {}
    }

    if ($user) {
        $home = "C:\Users\$user"
        if (Test-Path $home) { return $home }
    }

    # Fallback: only use $env:USERPROFILE if it's NOT the SYSTEM profile
    $profile = $env:USERPROFILE
    if ($profile -notlike "*systemprofile*" -and $profile -notlike "*system32*") {
        return $profile
    }

    return $null
}

# ── Certificate Pinning ───────────────────────────────────────────────────

function Get-TrustedCaCerts {
    $cert = Get-ChildItem -Path Cert:\LocalMachine\Root |
            Where-Object { $_.Subject -like "*CN=$TRUSTED_PROXY_CA_CN*" } |
            Select-Object -First 1

    if (-not $cert) {
        Write-Host "  [INFO] No corporate proxy CA found — skipping (direct internet)" -ForegroundColor DarkGray
        return $null
    }

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $certHash = [BitConverter]::ToString($sha256.ComputeHash($cert.RawData)).Replace("-", "")

    if ($certHash -ne $TRUSTED_PROXY_CA_THUMBPRINT) {
        Write-Host "  [SECURITY] CA fingerprint mismatch!" -ForegroundColor Red
        Write-Host "    Expected: $TRUSTED_PROXY_CA_THUMBPRINT" -ForegroundColor Red
        Write-Host "    Got:      $certHash" -ForegroundColor Red
        Write-Log "[SECURITY] CA fingerprint mismatch! Expected: $TRUSTED_PROXY_CA_THUMBPRINT Got: $certHash"
        return $null
    }

    $pemPath = Join-Path $env:TEMP "appsec-trusted-ca.pem"
    $b64 = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----" | Set-Content $pemPath -Encoding ASCII
    return $pemPath
}

# ── Extension Installation ────────────────────────────────────────────────

function Install-Extension([string]$Cli, [string]$Label) {
    if (-not (Test-Path $Cli)) { return }

    $caPem = Get-TrustedCaCerts

    try {
        Write-Log "  Installing $Label via $Cli"
        if ($caPem) { $env:NODE_EXTRA_CA_CERTS = $caPem }

        $listOutput = & $Cli --list-extensions 2>$null
        $existing = $listOutput | Where-Object { $_ -ilike "*HotmartCybersecurity*" }

        if ($existing) {
            $output = & $Cli --install-extension $EXTENSION_ID --force 2>&1
            "$output" | Add-Content -Path $DetailLog -Encoding UTF8
            if ($LASTEXITCODE -eq 0 -or "$output" -match "successfully") {
                Write-Ok "$Label (updated)"
            } else {
                Write-Fail "$Label (update failed)"
                Write-Log "  [ERROR] $Label update: $output"
            }
        } else {
            $output = & $Cli --install-extension $EXTENSION_ID 2>&1
            "$output" | Add-Content -Path $DetailLog -Encoding UTF8
            if ($LASTEXITCODE -eq 0 -or "$output" -match "successfully") {
                Write-Ok "$Label (installed)"
            } else {
                Write-Fail "$Label (install failed)"
                Write-Log "  [ERROR] $Label install: $output"
            }
        }
    } catch {
        Write-Fail "$Label ($_)"
        Write-Log "  [ERROR] $Label : $_"
    } finally {
        if ($caPem) {
            Remove-Item $caPem -Force -ErrorAction SilentlyContinue
            $env:NODE_EXTRA_CA_CERTS = $null
        }
    }
}

# ── Opengrep Installation ────────────────────────────────────────────────

function Install-OpenGrep {
    $env:PATH = "C:\ProgramData\Hotmart\bin;$env:PATH"

    if (Get-Command opengrep -ErrorAction SilentlyContinue) {
        $ver = (opengrep --version 2>$null | Select-Object -First 1)
        Write-Skip "opengrep ($ver)"
        return
    }

    Write-Host "  Installing opengrep..." -ForegroundColor DarkCyan

    # 1. Bundled binary
    $bundled = "C:\ProgramData\Hotmart\appsec\bin\opengrep.exe"
    if (Test-Path $bundled) {
        $binDir = "C:\ProgramData\Hotmart\bin"
        $null = New-Item -ItemType Directory -Path $binDir -Force
        Copy-Item $bundled "$binDir\opengrep.exe" -Force
        $syspath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
        if ($syspath -notlike "*$binDir*") {
            [Environment]::SetEnvironmentVariable("PATH", "$syspath;$binDir", "Machine")
        }
        if (Test-Path "$binDir\opengrep.exe") { Write-Ok "opengrep (bundled)"; return }
    }

    # 2. Download from GitHub
    try {
        $api = Invoke-RestMethod "https://api.github.com/repos/opengrep/opengrep/releases/latest" -UseBasicParsing -TimeoutSec 15
        $asset = $api.assets | Where-Object { $_.name -eq "opengrep_windows_x86.exe" } | Select-Object -First 1
        if ($asset) {
            $binDir = "C:\ProgramData\Hotmart\bin"
            $null = New-Item -ItemType Directory -Path $binDir -Force
            $binPath = "$binDir\opengrep.exe"
            Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $binPath -UseBasicParsing -TimeoutSec 120
            $syspath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
            if ($syspath -notlike "*$binDir*") {
                [Environment]::SetEnvironmentVariable("PATH", "$syspath;$binDir", "Machine")
            }
            Write-Ok "opengrep (downloaded)"
            return
        }
    } catch {}

    Write-Fail "opengrep (install failed — no bundled binary and no internet)"
}

# ── Write File (idempotent) ───────────────────────────────────────────────
# Uses [System.IO.File]::WriteAllText to guarantee content is written.
# Set-Content with -Encoding UTF8 adds BOM and can fail silently as SYSTEM.

function Write-ConfigFile([string]$Dst, [string]$Label, [string]$Content) {
    try {
        if ([string]::IsNullOrWhiteSpace($Content)) {
            Write-Fail "$Label (content is empty — bug in script)"
            Write-Log "  [ERROR] $Label : content is empty"
            return
        }
        if ([string]::IsNullOrWhiteSpace($Dst) -or $Dst -eq '\') {
            Write-Fail "$Label (destination path is invalid: '$Dst')"
            Write-Log "  [ERROR] $Label : invalid path '$Dst'"
            return
        }

        $dir = Split-Path $Dst
        if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path $dir)) {
            $null = New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop
        }

        if (Test-Path $Dst) {
            $existing = [System.IO.File]::ReadAllText($Dst, [System.Text.Encoding]::UTF8)
            if ($existing.Trim() -eq $Content.Trim()) {
                Write-Skip "$Label (already up to date)"
                return
            }
        }

        # Write without BOM using .NET directly
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($Dst, $Content, $utf8NoBom)

        $size = (Get-Item $Dst -ErrorAction SilentlyContinue).Length
        if ($size -gt 0) {
            Write-Ok $Label
            Write-Log "  [OK] Wrote $Label ($size bytes) to $Dst"
        } else {
            Write-Fail "$Label (file created but empty)"
            Write-Log "  [ERROR] $Label : file at $Dst is empty after write"
        }
    } catch {
        Write-Fail "$Label (error: $_)"
        Write-Log "  [ERROR] $Label at $Dst : $_"
    }
}

# ── IDE Detection ─────────────────────────────────────────────────────────
# All functions receive $UserHome as parameter to avoid dependency on
# global scope (which may not be initialized when functions are defined).

function Find-KiroCli([string]$UserHome) {
    $localAppData = "$UserHome\AppData\Local"
    $paths = @(
        "$localAppData\Programs\Kiro\resources\app\bin\kiro.cmd",
        "$localAppData\Programs\Kiro\bin\kiro.cmd",
        "$localAppData\Programs\Kiro\bin\kiro.exe"
    )
    foreach ($p in $paths) { if (Test-Path $p) { return $p } }
    foreach ($dir in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if (-not $dir) { continue }
        $found = Get-ChildItem "$dir\Kiro*" -ErrorAction SilentlyContinue |
                 ForEach-Object { Get-ChildItem $_.FullName -Recurse -Filter "kiro.cmd" -ErrorAction SilentlyContinue } |
                 Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    $cmd = Get-Command kiro -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Find-VscodeCli([string]$UserHome) {
    $localAppData = "$UserHome\AppData\Local"
    $paths = @(
        "$localAppData\Programs\Microsoft VS Code\bin\code.cmd",
        "$env:ProgramFiles\Microsoft VS Code\bin\code.cmd"
    )
    foreach ($p in $paths) { if (Test-Path $p) { return $p } }
    $cmd = Get-Command code -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Find-CursorCli([string]$UserHome) {
    $localAppData = "$UserHome\AppData\Local"
    $paths = @(
        "$localAppData\Programs\cursor\resources\app\bin\cursor.cmd",
        "$localAppData\Programs\Cursor\resources\app\bin\cursor.cmd",
        "$localAppData\cursor\cursor.exe"
    )
    foreach ($p in $paths) { if (Test-Path $p) { return $p } }
    $cmd = Get-Command cursor -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Find-WindsurfCli([string]$UserHome) {
    $localAppData = "$UserHome\AppData\Local"
    $paths = @(
        "$localAppData\Programs\Windsurf\bin\windsurf.cmd",
        "$localAppData\Programs\Windsurf\windsurf.exe"
    )
    foreach ($p in $paths) { if (Test-Path $p) { return $p } }
    $cmd = Get-Command windsurf -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Find-ClaudeCli([string]$UserHome) {
    $appData = "$UserHome\AppData\Roaming"
    $paths = @(
        "$appData\npm\claude.cmd",
        "$UserHome\.local\bin\claude.exe",
        "$UserHome\.claude\bin\claude.exe"
    )
    foreach ($p in $paths) { if (Test-Path $p) { return $p } }
    $cmd = Get-Command claude -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

# ── Pre-commit hooks ──────────────────────────────────────────────────────

function Install-PreCommitHooks([string]$UserHome) {
    $hookContent = @'
#!/bin/bash
# AppSec Pre-Commit Hook — Advisory Only
STATE_DIR=".appsec-state"
RULES_FILE="rules/security.yml"
mkdir -p "$STATE_DIR"
STAGED=$(git -c core.quotePath=false diff --cached --name-only --diff-filter=ACMR | grep -iE '\.(ts|tsx|js|jsx|java|py|go|rb|php|c|cpp|cs|swift|kt|rs|scala)$')
[ -z "$STAGED" ] && exit 0
if [ ! -f "$RULES_FILE" ]; then
  GIT_ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
  [ -f "$GIT_ROOT/rules/security.yml" ] && RULES_FILE="$GIT_ROOT/rules/security.yml" || exit 0
fi
command -v opengrep &>/dev/null || exit 0
opengrep scan --quiet --config="$RULES_FILE" $STAGED 2>/dev/null || true
exit 0
'@

    $searchDirs = @(
        "$UserHome\Documents", "$UserHome\projects", "$UserHome\dev",
        "$UserHome\workspace", "$UserHome\repos", "$UserHome\code", "$UserHome\source"
    )
    $count = 0
    foreach ($dir in $searchDirs) {
        if (-not (Test-Path $dir)) { continue }
        Get-ChildItem -Path $dir -Recurse -Depth 4 -Filter ".git" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $hookDst = Join-Path $_.FullName "hooks\pre-commit"
            $null = New-Item -ItemType Directory -Path (Split-Path $hookDst) -Force -ErrorAction SilentlyContinue
            $utf8NoBom = New-Object System.Text.UTF8Encoding $false
            [System.IO.File]::WriteAllText($hookDst, $hookContent, $utf8NoBom)
            $count++
        }
    }

    if ($count -gt 0) { Write-Ok "pre-commit hook ($count repo(s))" }
    else { Write-Skip "pre-commit hook (no repos found)" }
}

# ── Inline config content ─────────────────────────────────────────────────

$KiroSteering = @'
---
inclusion: auto
priority: maximum
enforcement: mandatory
---
# APPSEC SECURITY STEERING — CORPORATE MANDATORY POLICY
This assistant MUST always generate secure-by-default code.
FORBIDDEN: hardcoded credentials, SQL injection, eval() with user input,
disabled TLS, tokens in localStorage, MD5/SHA1 for passwords, stack traces to client.
'@

$KiroHook = @'
{
  "enabled": true,
  "name": "AppSec Gate — Prompt Analysis",
  "version": "1",
  "when": { "type": "promptSubmit" },
  "then": {
    "type": "askAgent",
    "prompt": "SECURITY POLICY — PROMPT ANALYSIS\n\nAnalise o prompt que o desenvolvedor acabou de enviar. Verifique se ele está pedindo para implementar algo inseguro:\n\n• Hardcoding de credenciais\n• AWS Access Keys diretamente no código\n• Connection strings com credenciais embutidas\n• Desabilitar TLS/SSL\n• Armazenar secrets em localStorage/sessionStorage\n• eval() com input de usuário\n• SQL via concatenação de strings\n• Criptografia fraca (MD5, SHA1)\n• Expor stack traces ao cliente\n\nSe o prompt pedir EXPLICITAMENTE algo inseguro, responda: 'ACESSO NEGADO: O pedido solicita implementação insegura. Use variáveis de ambiente ou secret manager.'\n\nSe for pergunta normal de desenvolvimento, permita sem comentários."
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
Always use environment variables or a secret manager for credentials.
'@

$AppsecGateSh = @'
#!/bin/bash
CONTENT=$(cat)
VIOLATIONS_FOUND=0
echo "$CONTENT" | grep -qiE '(password|passwd|secret|api_key|token|private_key|access_key|senha|chave)\s*[=:]\s*["'"'"'][^"'"'"']{3,}' && VIOLATIONS_FOUND=1
echo "$CONTENT" | grep -qE 'AKIA[0-9A-Z]{16}' && VIOLATIONS_FOUND=1
echo "$CONTENT" | grep -qiE '(mongodb|postgres|mysql|redis|amqp)://[^:]+:[^@]+@' && VIOLATIONS_FOUND=1
echo "$CONTENT" | grep -qiE 'rejectUnauthorized\s*:\s*false' && VIOLATIONS_FOUND=1
[ "$VIOLATIONS_FOUND" -eq 0 ] && exit 0
echo "ACESSO NEGADO — Padrão inseguro detectado. Use variáveis de ambiente."
exit 1
'@

$ClaudeSettings = @'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit|MultiEdit|CreateFile",
        "hooks": [{ "type": "command", "command": "bash ~/.claude/appsec/appsec-gate.sh" }]
      }
    ]
  }
}
'@

$ClaudeRules = @'
# APPSEC SECURITY RULES — CORPORATE MANDATORY POLICY
FORBIDDEN: hardcoded credentials, SQL injection, eval() with user input,
disabled TLS, tokens in localStorage, MD5/SHA1 for passwords, stack traces to client.
Always use environment variables or a secret manager for credentials.
'@

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Yellow
Write-Host "  AppSec MDM Installer — Hotmart Cybersecurity (Windows)          " -ForegroundColor Yellow
Write-Host "==================================================================" -ForegroundColor Yellow
Write-Host ""

"" | Add-Content -Path $DetailLog -Encoding UTF8
"===== $(Get-Date) — mdm-install.ps1 started =====" | Add-Content -Path $DetailLog -Encoding UTF8
"Running as: $([Environment]::UserName)" | Add-Content -Path $DetailLog -Encoding UTF8
"IsSystem: $([System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem)" | Add-Content -Path $DetailLog -Encoding UTF8

# Resolve user home FIRST — all other operations depend on this
$UserHome = Get-ConsoleUserHome

if ([string]::IsNullOrWhiteSpace($UserHome)) {
    Write-Log "CRITICAL: Could not resolve user home directory. Aborting."
    Write-Host "  [XX] Could not detect logged-in user home. Aborting." -ForegroundColor Red
    exit 1
}

Write-Host "User home: $UserHome" -ForegroundColor Cyan
Write-Log "User home: $UserHome | Running as: $([Environment]::UserName)"
"Resolved UserHome=$UserHome" | Add-Content -Path $DetailLog -Encoding UTF8

# ── opengrep ──────────────────────────────────────────────────────────────
Write-Section "opengrep (SAST engine)"
Install-OpenGrep

# ── Kiro ──────────────────────────────────────────────────────────────────
$KiroCli = Find-KiroCli $UserHome
if ($KiroCli) {
    Write-Section "Kiro ($KiroCli)"
    Install-Extension $KiroCli "Kiro extension"
    Write-ConfigFile "$UserHome\.kiro\steering\appsec-rules.md" "Kiro steering" $KiroSteering
    Write-ConfigFile "$UserHome\.kiro\hooks\appsec-gate.kiro.hook" "Kiro hook" $KiroHook
} else { Write-Skip "Kiro (not detected)" }

# ── VS Code ───────────────────────────────────────────────────────────────
$VscodeCli = Find-VscodeCli $UserHome
if ($VscodeCli) {
    Write-Section "VS Code ($VscodeCli)"
    Install-Extension $VscodeCli "VS Code extension"
} else { Write-Skip "VS Code (not detected)" }

# ── Cursor ────────────────────────────────────────────────────────────────
$CursorCli = Find-CursorCli $UserHome
if ($CursorCli) {
    Write-Section "Cursor ($CursorCli)"
    Install-Extension $CursorCli "Cursor extension"
    Write-ConfigFile "$UserHome\.cursor\rules\appsec-rules.mdc" "Cursor rules" $CursorRules
    Write-ConfigFile "$UserHome\.cursor\appsec\appsec-gate.sh" "Cursor appsec-gate" $AppsecGateSh
} else { Write-Skip "Cursor (not detected)" }

# ── Windsurf ──────────────────────────────────────────────────────────────
$WindsurfCli = Find-WindsurfCli $UserHome
if ($WindsurfCli) {
    Write-Section "Windsurf ($WindsurfCli)"
    Install-Extension $WindsurfCli "Windsurf extension"
    Write-ConfigFile "$UserHome\.windsurf\rules\appsec-rules.md" "Windsurf rules" $CursorRules
    Write-ConfigFile "$UserHome\.windsurf\appsec\appsec-gate.sh" "Windsurf appsec-gate" $AppsecGateSh
} else { Write-Skip "Windsurf (not detected)" }

# ── Claude Code ───────────────────────────────────────────────────────────
$ClaudeCli = Find-ClaudeCli $UserHome
if ($ClaudeCli) {
    Write-Section "Claude Code ($ClaudeCli)"
    $claudeDir = "$UserHome\.claude"
    $settingsFile = "$claudeDir\settings.json"
    if (-not (Test-Path $settingsFile) -or (Get-Content $settingsFile -Raw -ErrorAction SilentlyContinue) -notlike "*appsec-gate*") {
        Write-ConfigFile $settingsFile "Claude settings.json" $ClaudeSettings
    } else { Write-Skip "Claude settings.json (already configured)" }
    Write-ConfigFile "$claudeDir\rules\appsec-rules.md" "Claude rules" $ClaudeRules
    Write-ConfigFile "$claudeDir\appsec\appsec-gate.sh" "Claude appsec-gate" $AppsecGateSh
} else { Write-Skip "Claude Code (not detected)" }

# ── Pre-commit hooks ──────────────────────────────────────────────────────
Write-Section "Git pre-commit hook"
Install-PreCommitHooks $UserHome

# ── Summary ───────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "==================================================================" -ForegroundColor Yellow
Write-Host "  Summary" -ForegroundColor Yellow
Write-Host "==================================================================" -ForegroundColor Yellow
Write-Host "  Installed: $($Installed.Count)  Skipped: $($Skipped.Count)  Failed: $($Failed.Count)"
Write-Host ""

if ($Failed.Count -gt 0) {
    $Failed | ForEach-Object { Write-Host "  [XX] $_" -ForegroundColor Red }
    Write-Log "FAILED: $($Failed.Count) components"
    exit 1
}

Write-Host "  Done." -ForegroundColor Green
Write-Log "Install complete. Installed: $($Installed.Count) Skipped: $($Skipped.Count)"
exit 0
