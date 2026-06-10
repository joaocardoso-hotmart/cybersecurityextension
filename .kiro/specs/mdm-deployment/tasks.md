# Implementation Plan: MDM Deployment System

## Overview

Implementation of the Hotmart AppSec MDM Deployment System for enterprise-wide distribution of the cybersecurity extension across macOS devices via Workspace ONE. The system comprises a package builder, installer, watchdog daemon, and uninstaller — all implemented as self-contained Bash scripts with inline configurations.

## Tasks

- [ ] 1. Implement core installer with user detection and opengrep installation
  - [ ] 1.1 Create `scripts/mdm-install.sh` with console user detection logic
    - Implement `get_user_home()` function using `/dev/console` stat, `SUDO_USER` fallback, and `dscl` UID >= 500 fallback
    - Resolve home directory via macOS Directory Service
    - Implement `write_file()` helper for idempotent file creation
    - Set up logging infrastructure (`/Library/Logs/Hotmart/appsec-install-detail.log`)
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 14.1, 15.1_

  - [ ] 1.2 Implement opengrep installation with multi-fallback strategy
    - Implement `install_opengrep()` with bundled binary from `/Library/Application Support/Hotmart/appsec/bin/opengrep`
    - Add Homebrew fallback if bundled binary not present
    - Add GitHub release download fallback (arm64/x86_64 detection)
    - Skip installation if already present (idempotency)
    - Ensure `/usr/local/bin` is in PATH during execution
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 14.3_

  - [ ] 1.3 Implement certificate pinning for corporate proxy (Zscaler)
    - Implement `get_trusted_ca_certs()` with SHA-256 fingerprint validation
    - Extract CA from macOS System Keychain by Common Name
    - Compare fingerprint against hardcoded trusted value
    - Export validated certificate to temp PEM file, set `NODE_EXTRA_CA_CERTS`
    - Refuse to trust mismatched fingerprints with security warning
    - Clean up temp PEM after use
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_

  - [ ]* 1.4 Write property test for idempotency (Property 1)
    - **Property 1: Idempotency**
    - Verify running `mdm-install.sh` multiple times produces same end state
    - **Validates: Requirements 14.1, 14.2, 14.3, 14.4, 14.5**

- [ ] 2. Implement IDE detection and extension marketplace installation
  - [ ] 2.1 Implement IDE detection functions for all supported IDEs
    - Create `detect_kiro()` — check known paths, Spotlight fallback (`com.amazon.kiro`), PATH
    - Create `detect_vscode()` — check known paths, Spotlight fallback (`com.microsoft.VSCode`), PATH
    - Create `detect_cursor()` — check known paths, Spotlight fallback (`com.todesktop.230313mzl4w4u92`), PATH
    - Create `detect_windsurf()` — check known paths, Spotlight fallback (`com.exafunction.windsurf`), PATH
    - Create `detect_claude()` — check `/usr/local/bin/claude`, `~/.claude/bin/claude`, PATH
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7_

  - [ ] 2.2 Implement extension installation via marketplace CLI
    - Implement `install_extension()` using `--install-extension` with marketplace ID `HotmartCybersecurity.cybersecurityextension`
    - Execute IDE CLI as console user via `sudo -H -u <user> env HOME=<home>`
    - Use `--force` flag when extension already installed (update)
    - Integrate certificate pinning for TLS via `NODE_EXTRA_CA_CERTS`
    - Log errors to detail log and continue with remaining IDEs
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

  - [ ]* 2.3 Write property test for user isolation (Property 2)
    - **Property 2: User Isolation**
    - Verify extensions and configs always target console user's home, never `/var/root`
    - **Validates: Requirements 1.1, 1.4, 1.5**

- [ ] 3. Implement IDE security configurations
  - [ ] 3.1 Implement Kiro security configuration
    - Write steering file to `~/.kiro/steering/appsec-rules.md` with `inclusion: auto`, `priority: maximum`, `enforcement: mandatory`
    - Write hook file to `~/.kiro/hooks/appsec-gate.kiro.hook` intercepting `promptSubmit` events
    - Include forbidden patterns in steering (hardcoded credentials, SQL injection, eval, disabled TLS, etc.)
    - _Requirements: 6.1, 6.2, 6.3_

  - [ ] 3.2 Implement Cursor security configuration
    - Write rules file to `~/.cursor/rules/appsec-rules.mdc` with `alwaysApply: true`
    - Write AppSec Gate script to `~/.cursor/appsec/appsec-gate.sh`, set executable
    - Gate detects hardcoded credentials, AWS keys (`AKIA[0-9A-Z]{16}`), connection strings, disabled TLS
    - _Requirements: 7.1, 7.2, 7.3_

  - [ ] 3.3 Implement Windsurf security configuration
    - Write rules file to `~/.windsurf/rules/appsec-rules.md` with `alwaysApply: true`
    - Write AppSec Gate script to `~/.windsurf/appsec/appsec-gate.sh`, set executable
    - Gate detects same patterns as Cursor gate
    - _Requirements: 8.1, 8.2, 8.3_

  - [ ] 3.4 Implement Claude Code security configuration
    - Write rules file to `~/.claude/rules/appsec-rules.md`
    - Write AppSec Gate script to `~/.claude/appsec/appsec-gate.sh`, set executable
    - Configure `~/.claude/settings.json` with `PreToolUse` hook matching `Write|Edit|MultiEdit|CreateFile`
    - Skip settings modification if AppSec Gate already configured
    - _Requirements: 9.1, 9.2, 9.3, 9.4_

  - [ ]* 3.5 Write property test for certificate integrity (Property 3)
    - **Property 3: Certificate Integrity**
    - Verify the system never trusts a CA with mismatched SHA-256 fingerprint
    - **Validates: Requirements 5.2, 5.3**

- [ ] 4. Implement Git pre-commit hooks
  - [ ] 4.1 Implement advisory-only pre-commit hook installation
    - Scan common development directories (`~/Documents`, `~/projects`, `~/dev`, `~/workspace`, `~/repos`, `~/code`) up to 4 levels deep
    - Install pre-commit hook script in `<repo>/.git/hooks/pre-commit`
    - Hook scans staged files using opengrep with `rules/security.yml`
    - Always exit 0 (advisory-only, never blocks commits)
    - Display formatted advisory message with vulnerability counts
    - Support dismissal mechanism via `.appsec-state/dismissed.json`
    - Filter by supported language extensions (ts, js, java, py, go, rb, php, c, cpp, cs, swift, kt, rs, scala)
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7_

  - [ ]* 4.2 Write property test for non-blocking commits (Property 4)
    - **Property 4: Non-Blocking Commits**
    - Verify hook always exits with code 0 regardless of scan results
    - **Validates: Requirements 10.4, 10.5**

- [ ] 5. Checkpoint - Verify installer completeness
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 6. Implement watchdog persistence daemon
  - [ ] 6.1 Create `scripts/mdm-watchdog.sh` with state management and skip logic
    - Implement `should_skip()` with 4-hour window via state file (Unix timestamp)
    - Implement `save_state()` to record last successful run
    - Set process to lowest priority (`renice -n 19`)
    - Implement log management (trim to 500 lines, cap at 1 MB)
    - Detect console user and resolve home directory
    - _Requirements: 11.6, 11.7, 11.8, 15.3, 15.5_

  - [ ] 6.2 Implement watchdog verification and restoration functions
    - `ensure_opengrep()` — verify binary exists, restore via bundled/brew/download
    - `ensure_extension()` — verify extension dir contains hotmartcybersecurity.*, reinstall via CLI
    - `ensure_content()` — verify config files exist with correct content, restore if missing/modified
    - `ensure_precommit_hooks()` — verify hooks exist with correct hash, restore if missing/modified
    - _Requirements: 11.2, 11.3, 11.4, 11.5, 14.4_

  - [ ] 6.3 Create LaunchDaemon plist (`scripts/com.hotmart.appsec.watchdog.plist`)
    - Set label `com.hotmart.appsec.watchdog`
    - Configure 30-minute `StartInterval` (1800 seconds)
    - Enable `RunAtLoad` for immediate execution on load
    - Set Nice 19 (lowest CPU priority) and IOSchedulingClass 0 (background IO)
    - Set TimeOut 300 seconds (5-minute kill)
    - Direct stdout/stderr to `/Library/Logs/Hotmart/appsec-watchdog.log`
    - Disable `KeepAlive`, run as root
    - _Requirements: 17.1, 17.2, 17.3, 17.4, 17.5, 17.6, 17.7_

  - [ ]* 6.4 Write property test for watchdog bounded execution (Property 7)
    - **Property 7: Watchdog Bounded Execution**
    - Verify watchdog terminates within 5 min and skips if last run < 4h ago
    - **Validates: Requirements 11.6, 11.7, 17.4, 17.5**

- [ ] 7. Implement uninstaller
  - [ ] 7.1 Create `scripts/mdm-uninstall.sh` with ordered removal sequence
    - Stop and remove LaunchDaemon (`launchctl unload` + delete plist)
    - Uninstall extensions from all detected IDEs via `--uninstall-extension`
    - Remove all steering/rules/hooks/gates for Kiro, Cursor, Windsurf, Claude Code
    - Clean Claude Code `settings.json` (remove only AppSec hook entries, preserve other settings)
    - Remove pre-commit hooks (grep for "AppSec" marker)
    - Remove opengrep from `/usr/local/bin` and `~/.local/bin`
    - Remove AppSec directory `/Library/Application Support/Hotmart/appsec`
    - Forget package receipt via `pkgutil --forget com.hotmart.appsec`
    - Handle missing components gracefully (no error exit codes)
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7, 12.8, 14.5, 15.4_

  - [ ]* 7.2 Write property test for clean removal (Property 6)
    - **Property 6: Clean Removal**
    - Verify no AppSec artifacts remain after uninstall and receipt is forgotten
    - **Validates: Requirements 12.1, 12.2, 12.3, 12.6, 12.7, 12.8**

- [ ] 8. Implement package builder and security rules
  - [ ] 8.1 Create `scripts/build-pkg.sh` for Workspace ONE distribution
    - Download opengrep binary for arm64 from latest GitHub release
    - Fallback to locally installed opengrep if download fails
    - Include mdm-install.sh, mdm-watchdog.sh, mdm-uninstall.sh in payload
    - Include LaunchDaemon plist at `/Library/LaunchDaemons/com.hotmart.appsec.watchdog.plist`
    - Generate postinstall script (set permissions, install opengrep, run installer, load daemon)
    - Run `pkgbuild` with identifier `com.hotmart.appsec` and version tag
    - Output to `dist/hotmart-appsec-<version>.pkg`
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6_

  - [ ] 8.2 Create `rules/security.yml` with OpenGrep/Semgrep YAML rules
    - CWE-798: Hardcoded credentials (variable declarations, object properties, AWS constructors)
    - CWE-89: SQL injection (string concatenation in queries)
    - CWE-78: OS command injection (user input in shell execution)
    - CWE-79: Cross-site scripting (unsanitized HTML rendering)
    - CWE-22: Path traversal (user input in file paths)
    - CWE-918: SSRF (user input in URL construction)
    - CWE-327: Weak cryptography (MD5, SHA1 for password hashing)
    - Ensure compatibility with opengrep/semgrep rule format
    - _Requirements: 16.1, 16.2, 16.3, 16.4, 16.5, 16.6, 16.7, 16.8_

  - [ ]* 8.3 Write property test for graceful degradation (Property 5)
    - **Property 5: Graceful Degradation**
    - Verify installer continues with remaining components when one fails
    - **Validates: Requirements 2.5, 4.2, 4.3, 15.2**

- [ ] 9. Checkpoint - Verify all components integrate correctly
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 10. Final integration and summary display
  - [ ] 10.1 Wire installer summary display and logging
    - Display formatted summary (installed/skipped/failed counts)
    - Log running user, console user, and resolved home at start
    - Ensure all operations produce detailed log entries
    - _Requirements: 15.1, 15.2_

  - [ ]* 10.2 Write integration tests for end-to-end deployment flow
    - Test fresh install → verify all components installed
    - Test idempotent re-run → verify no errors or duplicates
    - Test uninstall → verify clean removal
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5_

- [ ] 11. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- All scripts are implemented in Bash (macOS-specific tools: launchctl, dscl, mdfind, security, pkgutil)
- This is an existing, functional implementation — tasks serve as a reference for the current state

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "8.2"] },
    { "id": 1, "tasks": ["1.2", "1.3", "2.1", "6.3"] },
    { "id": 2, "tasks": ["2.2", "1.4"] },
    { "id": 3, "tasks": ["3.1", "3.2", "3.3", "3.4", "2.3"] },
    { "id": 4, "tasks": ["4.1", "3.5"] },
    { "id": 5, "tasks": ["4.2", "6.1"] },
    { "id": 6, "tasks": ["6.2", "6.4"] },
    { "id": 7, "tasks": ["7.1"] },
    { "id": 8, "tasks": ["7.2", "8.1"] },
    { "id": 9, "tasks": ["8.3", "10.1"] },
    { "id": 10, "tasks": ["10.2"] }
  ]
}
```
