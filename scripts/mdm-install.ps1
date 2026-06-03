#Requires -Version 5.1
<#
.SYNOPSIS
    AppSec MDM Installer — Hotmart Cybersecurity Extension (Windows)

.DESCRIPTION
    Distributes the cybersecurity extension and security standards to all
    AI IDEs detected on the developer's machine.

    Supported IDEs:
      - Kiro         -> extension (.vsix) + steering + hook
      - VS Code      -> extension (.vsix)
      - Cursor       -> extension (.vsix) + hooks.json + rules + hook
      - Claude Code  -> settings.json + rules + hook

.PARAMETER VsixUrl
    Optional URL to download the .vsix from a remote host.
    If not provided, uses the latest .vsix found in the script directory.

.EXAMPLE
    # Run locally (requires the .vsix in the same folder as the script)
    powershell -ExecutionPolicy Bypass -File mdm-install.ps1

    # Run with remote vsix
    powershell -ExecutionPolicy Bypass -File mdm-install.ps1 -VsixUrl "https://your-host/cybersecurityextension-latest.vsix"
#>

param(
    [string]$VsixUrl = $env:VSIX_URL
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot    = Split-Path -Parent $ScriptDir
$StandardsDir = Join-Path $RepoRoot "standards"

# Find latest .vsix in repo root
$VsixFile = Get-ChildItem -Path $RepoRoot -Filter "cybersecurityextension-*.vsix" |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1 -ExpandProperty FullName

# ---------------------------------------------------------------------------
# Tracking
# ---------------------------------------------------------------------------

$Installed = [System.Collections.Generic.List[string]]::new()
$Skipped   = [System.Collections.Generic.List[string]]::new()
$Failed    = [System.Collections.Generic.List[string]]::new()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-Section([string]$Title) {
    Write-Host "`n>>> $Title" -ForegroundColor Yellow
}

function Write-Ok([string]$Label) {
    Write-Host "  [OK] $Label" -ForegroundColor Green
    $Installed.Add($Label)
}

function Write-Skip([string]$Label) {
    Write-Host "  [--] $Label" -ForegroundColor DarkGray
    $Skipped.Add($Label)
}

function Write-Fail([string]$Label) {
    Write-Host "  [XX] $Label" -ForegroundColor Red
    $Failed.Add($Label)
}

function Install-File([string]$Src, [string]$Dst, [string]$Label) {
    if (-not (Test-Path $Src)) {
        Write-Fail "$Label (source not found: $Src)"
        return
    }
    $DstDir = Split-Path -Parent $Dst
    if (-not (Test-Path $DstDir)) {
        New-Item -ItemType Directory -Path $DstDir -Force | Out-Null
    }
    if ((Test-Path $Dst) -and ((Get-FileHash $Src).Hash -eq (Get-FileHash $Dst).Hash)) {
        Write-Skip "$Label (already up to date)"
    } else {
        Copy-Item -Path $Src -Destination $Dst -Force
        Write-Ok $Label
    }
}

function Get-ResolvedVsix {
    if ($VsixFile) { return $VsixFile }
    if ($VsixUrl) {
        $tmp = Join-Path $env:TEMP "cybersecurityextension-latest.vsix"
        Write-Host "  Downloading vsix from $VsixUrl..." -ForegroundColor DarkCyan
        Invoke-WebRequest -Uri $VsixUrl -OutFile $tmp -UseBasicParsing
        return $tmp
    }
    return $null
}

function Install-Vsix([string]$Cli, [string]$Label) {
    $vsix = Get-ResolvedVsix
    if (-not $vsix) {
        Write-Fail "$Label (no .vsix file found)"
        return
    }
    try {
        $existing = & $Cli --list-extensions 2>$null | Where-Object { $_ -ilike "*HotmartCybersecurity*" }
        $flag = if ($existing) { "--force" } else { "" }
        if ($flag) {
            & $Cli --install-extension $vsix --force | Out-Null
            Write-Ok "$Label (updated)"
        } else {
            & $Cli --install-extension $vsix | Out-Null
            Write-Ok "$Label (installed)"
        }
    } catch {
        Write-Fail "$Label ($_)"
    }
}

function Install-OpenGrep {
    if (Get-Command opengrep -ErrorAction SilentlyContinue) {
        $ver = (opengrep --version 2>$null | Select-Object -First 1)
        Write-Skip "opengrep (already installed: $ver)"
        return
    }
    Write-Host "  Installing opengrep..." -ForegroundColor DarkCyan
    try {
        # Try winget first
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            winget install opengrep.opengrep --silent --accept-source-agreements --accept-package-agreements 2>$null
            if (Get-Command opengrep -ErrorAction SilentlyContinue) {
                Write-Ok "opengrep (via winget)"
                return
            }
        }
        # Fallback: download binary from GitHub releases
        $api = "https://api.github.com/repos/opengrep/opengrep/releases/latest"
        $release = Invoke-RestMethod -Uri $api -UseBasicParsing
        $asset = $release.assets | Where-Object { $_.name -like "*windows*amd64*" -or $_.name -like "*win64*" } | Select-Object -First 1
        if ($asset) {
            $binDir = "$env:LOCALAPPDATA\opengrep"
            New-Item -ItemType Directory -Path $binDir -Force | Out-Null
            $binPath = Join-Path $binDir "opengrep.exe"
            Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $binPath -UseBasicParsing
            # Add to user PATH if not present
            $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
            if ($userPath -notlike "*$binDir*") {
                [Environment]::SetEnvironmentVariable("PATH", "$userPath;$binDir", "User")
            }
            Write-Ok "opengrep (downloaded to $binPath)"
        } else {
            Write-Fail "opengrep (no Windows binary found — install manually: https://github.com/opengrep/opengrep)"
        }
    } catch {
        Write-Fail "opengrep (install failed: $_ — install manually)"
    }
}

function Install-PreCommitHooks([string]$UserHome) {
    $hookSrc = Join-Path $StandardsDir "hooks\pre-commit"
    # Windows pre-commit hook wrapper (calls bash if available, else warn)
    $hookWinSrc = Join-Path $StandardsDir "hooks\pre-commit.cmd"

    $searchDirs = @(
        (Join-Path $UserHome "Documents"),
        (Join-Path $UserHome "projects"),
        (Join-Path $UserHome "dev"),
        (Join-Path $UserHome "workspace"),
        (Join-Path $UserHome "repos"),
        (Join-Path $UserHome "code"),
        (Join-Path $UserHome "source")
    )

    $count = 0
    foreach ($dir in $searchDirs) {
        if (-not (Test-Path $dir)) { continue }
        Get-ChildItem -Path $dir -Recurse -Depth 4 -Filter ".git" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $hooksDir = Join-Path $_.FullName "hooks"
            New-Item -ItemType Directory -Path $hooksDir -Force | Out-Null

            # Bash hook (works with Git Bash / WSL)
            $dst = Join-Path $hooksDir "pre-commit"
            if (Test-Path $hookSrc) {
                Copy-Item -Path $hookSrc -Destination $dst -Force
                $count++
            }
        }
    }

    if ($count -gt 0) {
        Write-Ok "pre-commit hook ($count repo(s))"
    } else {
        Write-Skip "pre-commit hook (no git repos found in common directories)"
    }
}

# ---------------------------------------------------------------------------
# IDE Detection
# ---------------------------------------------------------------------------

function Find-KiroCli {
    $candidates = @(
        # Standard Windows install path per your spec
        "$env:LOCALAPPDATA\Programs\Kiro\bin\kiro.exe",
        "$env:LOCALAPPDATA\Programs\Kiro\kiro.exe",
        # PATH fallback
        (Get-Command kiro -ErrorAction SilentlyContinue)?.Source
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) { return $c }
    }
    return $null
}

function Find-VscodeCli {
    $candidates = @(
        # Standard Windows install path
        "$env:LOCALAPPDATA\Programs\Microsoft VS Code\bin\code.cmd",
        "$env:LOCALAPPDATA\Programs\Microsoft VS Code\Code.exe",
        # System-wide install
        "$env:ProgramFiles\Microsoft VS Code\bin\code.cmd",
        (Get-Command code -ErrorAction SilentlyContinue)?.Source
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) { return $c }
    }
    return $null
}

function Find-CursorCli {
    $candidates = @(
        # Standard Windows install path
        "$env:LOCALAPPDATA\Programs\cursor\resources\app\bin\cursor.cmd",
        "$env:LOCALAPPDATA\Programs\cursor\cursor.exe",
        (Get-Command cursor -ErrorAction SilentlyContinue)?.Source
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) { return $c }
    }
    return $null
}

function Find-ClaudeCli {
    $candidates = @(
        "$env:APPDATA\npm\claude.cmd",
        "$env:LOCALAPPDATA\Programs\claude\claude.exe",
        (Get-Command claude -ErrorAction SilentlyContinue)?.Source
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) { return $c }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
Write-Host "║  AppSec MDM Installer — Hotmart Cybersecurity (Windows)     ║" -ForegroundColor Yellow
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
Write-Host ""

$UserHome = $env:USERPROFILE
Write-Host "User home: $UserHome" -ForegroundColor Cyan

# ── opengrep ──────────────────────────────────────────────────────────────
Write-Section "Installing opengrep (SAST engine)"
Install-OpenGrep

# ── Kiro ──────────────────────────────────────────────────────────────────
$KiroCli = Find-KiroCli
if ($KiroCli) {
    Write-Section "Kiro detected ($KiroCli)"

    # 1. Install .vsix
    Install-Vsix $KiroCli "Kiro extension (.vsix)"

    # 2. Steering → %APPDATA%\kiro\steering\appsec-rules.md
    $KiroSteering = Join-Path $env:APPDATA "kiro\steering"
    Install-File `
        (Join-Path $StandardsDir "kiro\steering\appsec-rules.md") `
        (Join-Path $KiroSteering "appsec-rules.md") `
        "Kiro steering (appsec-rules.md)"

    # 3. Hook → %APPDATA%\kiro\hooks\appsec-gate.kiro.hook
    $KiroHooks = Join-Path $env:APPDATA "kiro\hooks"
    Install-File `
        (Join-Path $StandardsDir "hooks\kiro\appsec-gate.kiro.hook") `
        (Join-Path $KiroHooks "appsec-gate.kiro.hook") `
        "Kiro hook (appsec-gate.kiro.hook)"
} else {
    Write-Skip "Kiro (not detected)"
}

# ── VS Code ───────────────────────────────────────────────────────────────
$VscodeCli = Find-VscodeCli
if ($VscodeCli) {
    Write-Section "VS Code detected ($VscodeCli)"
    Install-Vsix $VscodeCli "VS Code extension (.vsix)"
} else {
    Write-Skip "VS Code (not detected)"
}

# ── Cursor ────────────────────────────────────────────────────────────────
$CursorCli = Find-CursorCli
if ($CursorCli) {
    Write-Section "Cursor detected ($CursorCli)"

    # 1. Install .vsix
    Install-Vsix $CursorCli "Cursor extension (.vsix)"

    # 2. Rules → %USERPROFILE%\.cursor\rules\appsec-rules.mdc
    $CursorRules = Join-Path $UserHome ".cursor\rules"
    Install-File `
        (Join-Path $StandardsDir "cursor\rules\appsec-rules.mdc") `
        (Join-Path $CursorRules "appsec-rules.mdc") `
        "Cursor rules (appsec-rules.mdc)"

    # 3. appsec-gate.sh → %USERPROFILE%\.cursor\appsec\appsec-gate.sh
    $CursorAppsec = Join-Path $UserHome ".cursor\appsec"
    Install-File `
        (Join-Path $StandardsDir "hooks\appsec-gate.sh") `
        (Join-Path $CursorAppsec "appsec-gate.sh") `
        "Cursor appsec-gate.sh"
} else {
    Write-Skip "Cursor (not detected)"
}

# ── Claude Code ───────────────────────────────────────────────────────────
$ClaudeCli = Find-ClaudeCli
if ($ClaudeCli) {
    Write-Section "Claude Code detected ($ClaudeCli)"

    $ClaudeDir      = Join-Path $UserHome ".claude"
    $ClaudeSettings = Join-Path $ClaudeDir "settings.json"
    $ClaudeRules    = Join-Path $ClaudeDir "rules"
    $ClaudeAppsec   = Join-Path $ClaudeDir "appsec"

    # 1. settings.json — create or merge
    New-Item -ItemType Directory -Path $ClaudeDir -Force | Out-Null
    if (-not (Test-Path $ClaudeSettings)) {
        Copy-Item (Join-Path $StandardsDir "hooks\claude\settings.json") $ClaudeSettings -Force
        Write-Ok "Claude settings.json (created)"
    } else {
        $content = Get-Content $ClaudeSettings -Raw
        if ($content -notlike "*appsec-gate*") {
            $target = $content | ConvertFrom-Json
            $source = Get-Content (Join-Path $StandardsDir "hooks\claude\settings.json") -Raw | ConvertFrom-Json
            if (-not $target.hooks) { $target | Add-Member -NotePropertyName hooks -NotePropertyValue @{} }
            foreach ($key in $source.hooks.PSObject.Properties.Name) {
                if (-not $target.hooks.$key) {
                    $target.hooks | Add-Member -NotePropertyName $key -NotePropertyValue $source.hooks.$key
                }
            }
            $target | ConvertTo-Json -Depth 10 | Set-Content $ClaudeSettings -Encoding UTF8
            Write-Ok "Claude settings.json (hooks merged)"
        } else {
            Write-Skip "Claude settings.json (already configured)"
        }
    }

    # 2. Rules
    Install-File `
        (Join-Path $StandardsDir "claude\rules\appsec-rules.md") `
        (Join-Path $ClaudeRules "appsec-rules.md") `
        "Claude rules (appsec-rules.md)"

    # 3. appsec-gate.sh
    Install-File `
        (Join-Path $StandardsDir "hooks\appsec-gate.sh") `
        (Join-Path $ClaudeAppsec "appsec-gate.sh") `
        "Claude appsec-gate.sh"
} else {
    Write-Skip "Claude Code (not detected)"
}

# ── Pre-commit hook ────────────────────────────────────────────────────────
Write-Section "Git pre-commit hook"
Install-PreCommitHooks $UserHome

# ── Summary ───────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
Write-Host "║  Installation Summary                                        ║" -ForegroundColor Yellow
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Installed/updated : $($Installed.Count)" -ForegroundColor Green
Write-Host "  Skipped           : $($Skipped.Count)"   -ForegroundColor DarkGray

if ($Failed.Count -gt 0) {
    Write-Host "  Failed            : $($Failed.Count)" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Failed items:" -ForegroundColor Red
    $Failed | ForEach-Object { Write-Host "    [XX] $_" -ForegroundColor Red }
    Write-Host ""
    exit 1
}

Write-Host ""
Write-Host "  AppSec toolchain installed successfully." -ForegroundColor Green
Write-Host ""
