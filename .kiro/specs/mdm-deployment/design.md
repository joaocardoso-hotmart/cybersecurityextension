# Technical Design Document

## Overview

This document describes the technical architecture and design of the Hotmart AppSec MDM Deployment System. The system is implemented as a set of self-contained Bash scripts packaged into a macOS `.pkg` installer for distribution via Workspace ONE (Intelligent Hub). All components operate without external dependencies at install time.

## Architecture

### System Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Workspace ONE (UEM Console)                     │
│   Upload .pkg → Assign to Smart Group → Push to devices               │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ MDM Install Command
                                ▼
┌──────────────────────────────────────────────────────────────────────┐
│                      macOS Installer (runs as root)                    │
│                                                                        │
│  1. Copy payload to /Library/Application Support/Hotmart/appsec/       │
│  2. Copy plist to /Library/LaunchDaemons/                              │
│  3. Execute postinstall script                                         │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────────┐
│                         postinstall script                             │
│                                                                        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐   │
│  │ Install opengrep │→│ Run mdm-install  │→│ Load LaunchDaemon    │   │
│  │ to /usr/local/bin│  │ (as console user)│  │ (activates watchdog)│   │
│  └─────────────────┘  └────────┬────────┘  └─────────────────────┘   │
│                                 │                                      │
└─────────────────────────────────┼──────────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────────┐
│                      mdm-install.sh (main installer)                   │
│                                                                        │
│  ┌──────────────┐ ┌──────────────┐ ┌────────────┐ ┌──────────────┐   │
│  │ Detect User  │ │ Detect IDEs  │ │ Install    │ │ Configure    │   │
│  │ (console)    │ │ (paths +     │ │ Extensions │ │ IDE Security │   │
│  │              │ │  Spotlight)  │ │ (marketplace│ │ (steering/   │   │
│  │ Resolve HOME │ │              │ │  via CLI)  │ │  hooks/gates)│   │
│  └──────────────┘ └──────────────┘ └────────────┘ └──────────────┘   │
│                                                                        │
│  ┌──────────────┐ ┌──────────────────────────────────────────────┐    │
│  │ Install      │ │ Certificate Pinning (Zscaler SHA-256 verify) │    │
│  │ Pre-commit   │ │                                              │    │
│  │ Hooks        │ │ Extract CA → Verify fingerprint → Export PEM │    │
│  └──────────────┘ └──────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│                    mdm-watchdog.sh (LaunchDaemon)                      │
│                    Runs every 30 min as root (nice 19)                 │
│                                                                        │
│  ┌──────────────┐ ┌──────────────┐ ┌────────────┐ ┌──────────────┐   │
│  │ Ensure       │ │ Ensure       │ │ Ensure     │ │ Ensure       │   │
│  │ opengrep     │ │ Extensions   │ │ Config     │ │ Pre-commit   │   │
│  │ installed    │ │ installed    │ │ files      │ │ hooks        │   │
│  └──────────────┘ └──────────────┘ └────────────┘ └──────────────┘   │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│              mdm-uninstall.sh (triggered by Workspace ONE)             │
│                                                                        │
│  1. Unload + delete LaunchDaemon                                       │
│  2. Uninstall extensions from all IDEs                                 │
│  3. Remove steering/rules/hooks/gates                                  │
│  4. Remove pre-commit hooks                                            │
│  5. Remove opengrep                                                    │
│  6. Remove /Library/Application Support/Hotmart/appsec                 │
│  7. pkgutil --forget com.hotmart.appsec                                │
└──────────────────────────────────────────────────────────────────────┘
```

### Component Interactions

```
┌───────────────┐       ┌───────────────┐       ┌───────────────────┐
│  build-pkg.sh │──────▶│  .pkg file    │──────▶│  Workspace ONE    │
│  (dev machine)│       │  (artifact)   │       │  (MDM platform)   │
└───────────────┘       └───────────────┘       └────────┬──────────┘
                                                         │ distribute
                                                         ▼
                                                ┌───────────────────┐
                                                │  Target Machine   │
                                                │  (macOS device)   │
                                                └────────┬──────────┘
                                                         │
                                    ┌────────────────────┼────────────────────┐
                                    │                    │                    │
                                    ▼                    ▼                    ▼
                           ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
                           │ mdm-install  │    │ mdm-watchdog │    │ mdm-uninstall│
                           │ (one-time)   │    │ (persistent) │    │ (on-demand)  │
                           └──────────────┘    └──────────────┘    └──────────────┘
```

## Component Design

### 1. Package Builder (`scripts/build-pkg.sh`)

**Purpose:** Assembles a distributable `.pkg` for Workspace ONE.

**Process Flow:**
1. Download opengrep binary from GitHub (arm64) with local fallback
2. Copy scripts (install, watchdog, uninstall) into payload structure
3. Copy LaunchDaemon plist into payload
4. Generate postinstall script (inline in build)
5. Run `pkgbuild` to produce final `.pkg`

**Payload Structure:**
```
/
├── Library/
│   ├── Application Support/
│   │   └── Hotmart/
│   │       └── appsec/
│   │           ├── bin/
│   │           │   └── opengrep          (bundled binary)
│   │           ├── mdm-install.sh
│   │           ├── mdm-watchdog.sh
│   │           └── mdm-uninstall.sh
│   └── LaunchDaemons/
│       └── com.hotmart.appsec.watchdog.plist
```

**Key Design Decisions:**
- Version is defined in the script (`VERSION="X.Y.Z"`) and passed to `pkgbuild --version`
- Opengrep is downloaded at build time (not install time) for zero-internet installs
- Postinstall is generated inline (heredoc) rather than as a separate file

### 2. MDM Installer (`scripts/mdm-install.sh`)

**Purpose:** One-time installation of all components for the console user.

**Function Chain:**
```
main()
  ├── get_user_home()              → Resolve console user + home
  ├── install_opengrep()           → Install SAST engine
  ├── detect_kiro() / detect_vscode() / detect_cursor() / detect_windsurf() / detect_claude()
  │                                → Find IDE CLIs
  ├── install_extension()          → For each detected IDE
  │     ├── get_trusted_ca_certs() → Certificate pinning
  │     └── sudo -H -u ... env ... → User context execution
  ├── write_file()                 → IDE configurations (steering/rules/hooks)
  └── install_precommit_hooks()    → Git pre-commit in dev directories
```

**User Context Resolution (`get_user_home`):**
```
Priority 1: stat -f '%Su' /dev/console      (console owner)
Priority 2: $SUDO_USER                       (sudo context)
Priority 3: dscl . list /Users UniqueID      (first UID >= 500)
                     ↓
         dscl . -read /Users/<user> NFSHomeDirectory
```

**Extension Installation Flow:**
```
install_extension(cli, label)
  │
  ├── Resolve real_user + real_home (console user)
  ├── get_trusted_ca_certs()
  │     ├── security find-certificate -c "Zscaler Root CA"
  │     ├── openssl x509 -fingerprint -sha256
  │     ├── Compare with TRUSTED_PROXY_CA_FINGERPRINT
  │     └── Export to /tmp/appsec-trusted-ca.pem (if valid)
  │
  ├── Build env_cmd: "env HOME=<real_home> [NODE_EXTRA_CA_CERTS=<pem>]"
  │
  └── sudo -H -u <real_user> $env_cmd <cli> --install-extension <ID>
```

**IDE Detection Strategy:**
| IDE | Bundle ID | CLI relative path |
|-----|-----------|-------------------|
| Kiro | `com.amazon.kiro` | `Contents/Resources/app/bin/kiro` |
| VS Code | `com.microsoft.VSCode` | `Contents/Resources/app/bin/code` |
| Cursor | `com.todesktop.230313mzl4w4u92` | `Contents/Resources/app/bin/cursor` |
| Windsurf | `com.exafunction.windsurf` | `Contents/Resources/app/bin/windsurf` |
| Claude | N/A | `/usr/local/bin/claude` or `~/.claude/bin/claude` |

Detection priority:
1. Known paths (`/Applications`, `~/Applications`, `~/Downloads`)
2. Spotlight query (`mdfind "kMDItemCFBundleIdentifier == '<bundle_id>'"`)
3. System PATH (`command -v`)

### 3. MDM Watchdog (`scripts/mdm-watchdog.sh`)

**Purpose:** Periodic verification and restoration of all installed components.

**Execution Model:**
- Triggered by LaunchDaemon every 30 minutes
- Runs at nice 19 (lowest CPU priority)
- Has a 4-hour skip window: if last run < 4h ago, exits immediately
- Timeout at 5 minutes (enforced by launchd)

**State Management:**
```
STATE_FILE="/Library/Application Support/Hotmart/appsec/.watchdog-state"
  Contains: Unix timestamp of last successful run

should_skip():
  elapsed = now - last_run
  return elapsed < 14400  (4 hours)
```

**Verification Functions:**
| Function | Checks | Restores |
|----------|--------|----------|
| `ensure_opengrep()` | `command -v opengrep` | Bundled → brew → download |
| `ensure_extension()` | `ls <ext_dir>/hotmartcybersecurity.*` | CLI `--install-extension --force` |
| `ensure_content()` | File exists + content matches | Writes inline content |
| `ensure_precommit_hooks()` | Hook exists + hash matches | Writes inline hook |

**Log Management:**
```
LOG_FILE="/Library/Logs/Hotmart/appsec-watchdog.log"
Max size: 1 MB → trim to 200 lines
Max lines: 500 → trim to 500 lines
```

### 4. MDM Uninstaller (`scripts/mdm-uninstall.sh`)

**Purpose:** Complete removal triggered by Workspace ONE "Remove App" command.

**Removal Sequence (ordered for safety):**
1. Stop LaunchDaemon (`launchctl unload`) → prevent watchdog from restoring
2. Uninstall extensions from IDEs (while CLIs still available)
3. Remove config files (steering/rules/hooks/gates)
4. Remove pre-commit hooks (grep for "AppSec" marker)
5. Remove opengrep binary
6. Remove AppSec directory
7. Forget package receipt (`pkgutil --forget`)

**Important:** Each step handles missing files gracefully (no `set -e`; uses `set -uo pipefail` instead).

### 5. Security Rules (`rules/security.yml`)

**Format:** OpenGrep/Semgrep YAML rule format.

**Coverage Matrix:**
| CWE | Rule IDs | Languages | Severity |
|-----|----------|-----------|----------|
| CWE-798 | hardcoded-secret-*, aws-*, connection-string-*, generic-api-key-* | TS, JS | ERROR |
| CWE-89 | sql-injection-* | TS, JS | ERROR |
| CWE-78 | command-injection-* | TS, JS | ERROR |
| CWE-79 | xss-* | TS, JS | ERROR/WARNING |
| CWE-22 | path-traversal-* | TS, JS | ERROR |
| CWE-918 | ssrf-* | TS, JS | ERROR |
| CWE-327 | weak-crypto-*, weak-random | TS, JS | ERROR/WARNING |
| CWE-502 | insecure-deserialization | TS, JS | WARNING |
| CWE-922 | token-localstorage, token-sessionstorage | TS, JS | WARNING |
| CWE-601 | open-redirect | TS, JS | WARNING |
| CWE-209 | error-info-leak | TS, JS | WARNING |
| CWE-295 | tls-reject-unauthorized-disabled | TS, JS | ERROR |
| CWE-639 | idor-direct-object-reference | TS, JS | WARNING |
| CWE-94 | prototype-pollution-*, unsafe-require | TS, JS | WARNING |
| CWE-1333 | regex-dos | TS, JS | ERROR |

**Rule Structure:**
```yaml
- id: <unique-rule-id>
  patterns:
    - pattern-either: [...]       # Match any of these patterns
    - metavariable-regex:         # Optional: filter on variable content
        metavariable: $VAR
        regex: <pattern>
  message: "<human-readable description>"
  languages: [typescript, javascript]
  severity: ERROR | WARNING
  metadata:
    cwe: ["CWE-XXX"]
    fix: "<suggested fix>"
```

### 6. IDE Configuration Files

**Kiro Steering (`~/.kiro/steering/appsec-rules.md`):**
```yaml
---
inclusion: auto
priority: maximum
enforcement: mandatory
---
# Security rules as markdown
```

**Kiro Hook (`~/.kiro/hooks/appsec-gate.kiro.hook`):**
```json
{
  "enabled": true,
  "name": "AppSec Gate — Prompt Analysis",
  "version": "1",
  "when": { "type": "promptSubmit" },
  "then": {
    "type": "askAgent",
    "prompt": "<security analysis instructions>"
  }
}
```

**Cursor/Windsurf AppSec Gate (`appsec-gate.sh`):**
```bash
#!/bin/bash
# Reads stdin, checks for insecure patterns via grep
# Exit 0 = safe, Exit 1 = blocked
```

**Claude Code (`~/.claude/settings.json`):**
```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Write|Edit|MultiEdit|CreateFile",
      "hooks": [{ "type": "command", "command": "bash ~/.claude/appsec/appsec-gate.sh" }]
    }]
  }
}
```

### 7. Pre-Commit Hook

**Design:** Advisory-only (never blocks commits).

**Flow:**
```
git commit
  → pre-commit hook
    → git diff --cached (staged files)
    → Filter by supported extensions
    → opengrep scan --json --config=rules/security.yml
    → python3 inline script:
        - Load dismissed.json
        - Filter out dismissed findings
        - Print advisory warnings
    → exit 0 (always)
```

## File System Layout (Installed State)

```
/Library/
├── Application Support/
│   └── Hotmart/
│       └── appsec/
│           ├── bin/opengrep              (bundled SAST binary)
│           ├── mdm-install.sh            (initial installer)
│           ├── mdm-watchdog.sh           (persistence daemon)
│           ├── mdm-uninstall.sh          (removal script)
│           └── .watchdog-state           (last-run timestamp)
├── LaunchDaemons/
│   └── com.hotmart.appsec.watchdog.plist
└── Logs/
    └── Hotmart/
        ├── appsec-install.log            (postinstall output)
        ├── appsec-install-detail.log     (IDE CLI output)
        ├── appsec-watchdog.log           (watchdog activity)
        └── appsec-uninstall.log          (removal output)

/usr/local/bin/
└── opengrep                              (symlink or copy)

~/ (user home)
├── .kiro/
│   ├── steering/appsec-rules.md
│   └── hooks/appsec-gate.kiro.hook
├── .cursor/
│   ├── rules/appsec-rules.mdc
│   └── appsec/appsec-gate.sh
├── .windsurf/
│   ├── rules/appsec-rules.md
│   └── appsec/appsec-gate.sh
└── .claude/
    ├── rules/appsec-rules.md
    ├── appsec/appsec-gate.sh
    └── settings.json (modified)
```

## Security Design

### Certificate Pinning

```
┌─────────────────────────────────────────────────────────────┐
│ Supply Chain Protection: Certificate Pinning                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  TRUSTED_PROXY_CA_CN = "Zscaler Root CA"                     │
│  TRUSTED_PROXY_CA_FINGERPRINT = "04:F6:1F:1D:..."            │
│                                                              │
│  1. Extract cert by CN from System Keychain                  │
│  2. Calculate SHA-256 fingerprint                            │
│  3. Compare with hardcoded fingerprint                       │
│     ├── MATCH → Export to temp PEM → Set NODE_EXTRA_CA_CERTS │
│     └── MISMATCH → Log SECURITY alert → Refuse to trust     │
│  4. Cleanup temp PEM after use                               │
│                                                              │
│  THREAT MODEL:                                               │
│  - Attacker injects rogue CA into System Keychain            │
│  - Without pinning: script trusts rogue CA → MITM possible  │
│  - With pinning: fingerprint mismatch → rejected            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Privilege Model

| Operation | Runs as | Why |
|-----------|---------|-----|
| Copy payload to /Library | root (Installer) | System directory |
| Install opengrep to /usr/local/bin | root (postinstall) | System binary |
| Load LaunchDaemon | root (postinstall) | launchctl requires root |
| Install extensions | Console User (via sudo -H -u) | User extensions dir |
| Write config files | root (write to user's home) | Watchdog needs root |
| Uninstall extensions | Console User (via sudo -H -u) | User extensions dir |

### AppSec Gate Pattern Detection

All AppSec Gate scripts detect the same patterns:
1. `(password|secret|api_key|token|...) = "..."` — Hardcoded credentials
2. `AKIA[0-9A-Z]{16}` — AWS Access Keys
3. `(mongodb|postgres|...)://user:pass@` — Connection strings with credentials
4. `rejectUnauthorized: false` — Disabled TLS verification

## Workspace ONE Integration

### Package Configuration

| Setting | Value |
|---------|-------|
| Package Identifier | `com.hotmart.appsec` |
| Install Context | Device (runs as root) |
| Identifying Criteria | pkgutil receipt `com.hotmart.appsec` |
| Uninstall Script | `sudo bash "/Library/Application Support/Hotmart/appsec/mdm-uninstall.sh"` |
| Version Detection | pkgutil `--pkg-info com.hotmart.appsec` |

### Lifecycle

```
Install:    .pkg postinstall → mdm-install.sh → LaunchDaemon loaded
Update:     New .pkg (higher version) → postinstall re-runs → components updated
Uninstall:  Workspace ONE triggers uninstall script → complete removal
Reinstall:  Receipt forgotten → Workspace ONE sees as not-installed → re-push
```

## Error Handling

| Scenario | Behavior |
|----------|----------|
| IDE not found | Skip, log, continue |
| Extension install fails | Log to detail file, mark as failed, continue |
| Opengrep bundled missing | Try brew → try download → fail gracefully |
| Certificate pinning fails | Log security alert, skip CA export (may fail on TLS) |
| User not logged in (watchdog) | Only ensure opengrep, skip user-level operations |
| File permission denied | Log error, continue with remaining operations |
| Network unavailable | Use bundled binary, skip marketplace if needed |

## Constraints and Limitations

1. **macOS only** — Scripts use macOS-specific tools (launchctl, security, dscl, mdfind, pkgutil)
2. **Single user** — Only configures for the console user at install time; multi-user machines need the watchdog to catch additional logins
3. **arm64 only in bundled binary** — The build script downloads arm64; x86_64 machines fall back to brew or runtime download
4. **Marketplace dependency** — Extensions are installed from marketplace, not bundled; requires network for initial install (mitigated by watchdog retry)
5. **Certificate rotation** — If Zscaler rotates their Root CA, the hardcoded fingerprint must be updated and a new package deployed


## Components and Interfaces

### Component: Package Builder
- **File:** `scripts/build-pkg.sh`
- **Interface:** CLI — `bash scripts/build-pkg.sh`
- **Input:** Scripts in `scripts/`, opengrep binary (downloaded or local)
- **Output:** `dist/hotmart-appsec-<VERSION>.pkg`
- **Dependencies:** `pkgbuild` (macOS built-in), `curl`, `python3`

### Component: MDM Installer
- **File:** `scripts/mdm-install.sh`
- **Interface:** CLI — `sudo bash mdm-install.sh`
- **Input:** None (self-contained with inline configurations)
- **Output:** Extensions installed, config files written, pre-commit hooks deployed
- **Dependencies:** macOS tools (`stat`, `dscl`, `security`, `openssl`, `mdfind`), IDE CLIs

### Component: MDM Watchdog
- **File:** `scripts/mdm-watchdog.sh`
- **Interface:** LaunchDaemon — runs automatically via `launchd`
- **Input:** State file (`.watchdog-state`), console user detection
- **Output:** Restored components, log entries
- **Dependencies:** Same as MDM Installer + state file for skip logic

### Component: MDM Uninstaller
- **File:** `scripts/mdm-uninstall.sh`
- **Interface:** CLI — `sudo bash mdm-uninstall.sh` (called by Workspace ONE)
- **Input:** Installed components on the system
- **Output:** All AppSec artifacts removed, package receipt forgotten
- **Dependencies:** macOS tools, IDE CLIs, `pkgutil`

### Component: LaunchDaemon Plist
- **File:** `scripts/com.hotmart.appsec.watchdog.plist`
- **Interface:** macOS launchd configuration (XML plist)
- **Input:** N/A (declarative configuration)
- **Output:** Schedules watchdog execution

### Component: Security Rules
- **File:** `rules/security.yml`
- **Interface:** OpenGrep/Semgrep rule format (YAML)
- **Input:** Source code files (scanned by opengrep)
- **Output:** JSON findings with rule ID, severity, file, line, message

### Component: VS Code Extension
- **Files:** `src/extension.ts`, `src/scanner.ts`, `src/semgrep.ts`, `src/sidebar.ts`
- **Interface:** VS Code Extension API
- **Input:** Editor events, file saves
- **Output:** Diagnostics in IDE, sidebar panel with findings

### Internal Interfaces

| Caller | Callee | Mechanism |
|--------|--------|-----------|
| postinstall | mdm-install.sh | `bash` subprocess |
| launchd | mdm-watchdog.sh | LaunchDaemon schedule |
| Workspace ONE | mdm-uninstall.sh | MDM uninstall command |
| mdm-install.sh | IDE CLIs | `sudo -H -u <user> env ... <cli> --install-extension` |
| mdm-install.sh | System Keychain | `security find-certificate` |
| mdm-install.sh | openssl | `openssl x509 -fingerprint -sha256` |
| pre-commit hook | opengrep | `opengrep scan --json --config=rules/security.yml` |
| pre-commit hook | python3 | Inline script for JSON processing |

## Data Models

### Watchdog State File
- **Path:** `/Library/Application Support/Hotmart/appsec/.watchdog-state`
- **Format:** Plain text — single Unix timestamp (integer)
- **Example:** `1718034600`
- **Usage:** If `now - state_value < 14400`, watchdog skips execution

### Log Files
- **Format:** `[TIMESTAMP] MESSAGE` per line
- **Retention:** 500 lines max / 1 MB max (trimmed by watchdog)
- **Paths:**
  - `/Library/Logs/Hotmart/appsec-install.log`
  - `/Library/Logs/Hotmart/appsec-install-detail.log`
  - `/Library/Logs/Hotmart/appsec-watchdog.log`
  - `/Library/Logs/Hotmart/appsec-uninstall.log`

### Pre-Commit Dismissal File
- **Path:** `<repo>/.appsec-state/dismissed.json`
- **Format:** JSON array of dismissed findings
- **Schema:**
```json
[
  {
    "id": "security.rules.hardcoded-secret-const",
    "file": "src/config.ts",
    "line": 42
  }
]
```

### IDE Configuration Models

**Kiro Hook (JSON):**
```json
{
  "enabled": boolean,
  "name": string,
  "version": string,
  "when": { "type": "promptSubmit" },
  "then": { "type": "askAgent", "prompt": string }
}
```

**Claude Code Settings Hook (JSON):**
```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": string,  // regex matching tool names
      "hooks": [{ "type": "command", "command": string }]
    }]
  }
}
```

**Security Rule (YAML):**
```yaml
id: string
patterns: array
message: string
languages: [string]
severity: ERROR | WARNING
metadata:
  cwe: [string]
  fix: string (optional)
```

### Package Receipt
- **Registry:** macOS pkgutil database
- **Identifier:** `com.hotmart.appsec`
- **Version:** Semantic versioning (e.g., `2.7.0`)
- **Queried via:** `pkgutil --pkg-info com.hotmart.appsec`

## Correctness Properties

### Property 1: Idempotency
Running `mdm-install.sh` multiple times produces the same end state without errors or duplicate side effects.

**Validates: Requirements 14.1, 14.2, 14.3, 14.4, 14.5**

### Property 2: User Isolation
Extensions and config files are always written to the console user's home, never to `/var/root`, regardless of the effective UID during execution.

**Validates: Requirements 1.1, 1.4, 1.5**

### Property 3: Certificate Integrity
The system never trusts a CA certificate whose SHA-256 fingerprint does not match the hardcoded value.

**Validates: Requirements 5.2, 5.3**

### Property 4: Non-Blocking Commits
The pre-commit hook always exits with code 0, regardless of scan results.

**Validates: Requirements 10.4, 10.5**

### Property 5: Graceful Degradation
If any single component fails (IDE not found, network down, permission denied), the installer continues with remaining components and reports a summary.

**Validates: Requirements 2.5, 4.2, 4.3, 15.2**

### Property 6: Clean Removal
After uninstall, no AppSec artifacts remain on the system and the package receipt is forgotten, allowing clean reinstallation.

**Validates: Requirements 12.1, 12.2, 12.3, 12.6, 12.7, 12.8**

### Property 7: Watchdog Bounded Execution
The watchdog terminates within 5 minutes (enforced by launchd) and never runs more frequently than every 4 hours (enforced by state file).

**Validates: Requirements 11.6, 11.7, 17.4, 17.5**

## Testing Strategy

### Manual Verification (Primary)

Since this system deploys to macOS via MDM, testing is primarily manual on physical or virtual machines:

1. **Fresh install test:** Deploy `.pkg` to a clean macOS machine → verify all components installed
2. **Upgrade test:** Deploy new version over existing → verify components updated without duplication
3. **Uninstall test:** Trigger removal via Workspace ONE → verify all artifacts removed
4. **Reinstall test:** After uninstall, deploy again → verify clean install
5. **Watchdog test:** Remove an extension manually → wait 30 min → verify it's restored
6. **Multi-IDE test:** Machine with Kiro + VS Code + Cursor → verify all configured
7. **No-network test:** Deploy on machine without internet → verify bundled opengrep installs
8. **Certificate test:** Verify on Zscaler-proxied network → extensions install with pinned cert

### Log-Based Verification

After each operation, verify log contents:
- `/Library/Logs/Hotmart/appsec-install.log` should show `Post-install complete`
- `/Library/Logs/Hotmart/appsec-install-detail.log` should show no `EACCES` errors
- `pkgutil --pkg-info com.hotmart.appsec` should return correct version

### Smoke Test Commands

```bash
# Verify installed state
pkgutil --pkg-info com.hotmart.appsec
command -v opengrep && opengrep --version
launchctl list | grep hotmart
kiro --list-extensions | grep -i hotmart
cursor --list-extensions | grep -i hotmart
cat ~/.kiro/steering/appsec-rules.md
cat ~/.kiro/hooks/appsec-gate.kiro.hook

# Verify uninstalled state
pkgutil --pkg-info com.hotmart.appsec   # should fail
command -v opengrep                      # should fail
launchctl list | grep hotmart            # should return empty
ls /Library/Application\ Support/Hotmart # should not exist
```
