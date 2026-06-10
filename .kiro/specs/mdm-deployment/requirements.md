# Requirements Document

## Introduction

This document specifies the requirements for the Hotmart AppSec Cybersecurity Extension MDM Deployment System. The system enables enterprise-wide deployment of a security extension across multiple AI-assisted IDEs (Kiro, VS Code, Cursor, Windsurf, Claude Code) on macOS via Mobile Device Management (Workspace ONE). It includes an installer, a persistence watchdog, a complete uninstaller, and a package builder — all designed to operate self-contained without external dependencies at install time.

## Glossary

- **MDM_Installer**: The shell script (`mdm-install.sh`) that performs initial installation of the extension, opengrep, IDE configurations, and pre-commit hooks for the GUI console user
- **MDM_Watchdog**: The LaunchDaemon-driven shell script (`mdm-watchdog.sh`) that periodically verifies and restores all installed components
- **MDM_Uninstaller**: The shell script (`mdm-uninstall.sh`) that completely removes all components installed by the system
- **Package_Builder**: The shell script (`build-pkg.sh`) that assembles a distributable `.pkg` file for Workspace ONE
- **Console_User**: The macOS GUI user currently logged in, detected via `/dev/console` stat
- **LaunchDaemon**: A macOS system-level background service managed by `launchctl`, running as root
- **Opengrep**: The SAST (Static Application Security Testing) engine binary used for scanning code
- **IDE_CLI**: The command-line interface binary of a supported IDE used to install/uninstall extensions
- **Steering_File**: A configuration file placed in an IDE's user directory that enforces security policies on AI-assisted code generation
- **AppSec_Gate**: A shell script hook that intercepts IDE tool calls or prompts to detect insecure patterns before code is written
- **Pre_Commit_Hook**: A Git hook script that runs opengrep SAST scans on staged files before commit, operating in advisory-only mode
- **Certificate_Pinning**: Validation of a proxy CA certificate by comparing its SHA-256 fingerprint against a known-good value before trusting it
- **Workspace_ONE**: VMware (Omnissa) MDM platform used to distribute the `.pkg` to managed macOS devices

## Requirements

### Requirement 1: Console User Detection

**User Story:** As an MDM administrator, I want the installer to correctly identify the GUI user even when running as root, so that extensions and configurations are installed in the correct user home directory.

#### Acceptance Criteria

1. WHEN the MDM_Installer runs as root, THE MDM_Installer SHALL detect the Console_User by reading the owner of `/dev/console`
2. IF the Console_User cannot be determined from `/dev/console`, THEN THE MDM_Installer SHALL fall back to the `SUDO_USER` environment variable
3. IF neither `/dev/console` nor `SUDO_USER` yields a non-root user, THEN THE MDM_Installer SHALL fall back to the first local user with UID >= 500
4. WHEN the Console_User is resolved, THE MDM_Installer SHALL resolve the user's home directory via the macOS Directory Service (`dscl`)
5. THE MDM_Installer SHALL execute all user-context operations using `sudo -H -u <Console_User>` with an explicit `HOME` environment variable set via the `env` command

### Requirement 2: Extension Marketplace Installation

**User Story:** As an MDM administrator, I want the extension installed from the marketplace rather than a bundled `.vsix`, so that developers always get the latest published version and updates flow through normal channels.

#### Acceptance Criteria

1. WHEN an IDE_CLI is detected on the system, THE MDM_Installer SHALL install the extension using the `--install-extension` flag with the marketplace identifier `HotmartCybersecurity.cybersecurityextension`
2. WHEN the extension is already installed, THE MDM_Installer SHALL update it using `--install-extension` with the `--force` flag
3. THE MDM_Installer SHALL support installation into Kiro, VS Code, Cursor, and Windsurf IDEs
4. WHEN running as root, THE MDM_Installer SHALL execute the IDE_CLI as the Console_User with the correct `HOME` directory to ensure extensions install in the user's extension directory
5. IF extension installation fails, THEN THE MDM_Installer SHALL log the error to `/Library/Logs/Hotmart/appsec-install-detail.log` and continue with remaining IDEs

### Requirement 3: IDE Detection

**User Story:** As an MDM administrator, I want the system to automatically detect all supported IDEs regardless of where they are installed, so that no manual configuration is required per machine.

#### Acceptance Criteria

1. THE MDM_Installer SHALL check for IDE_CLI binaries in `/Applications`, the Console_User's `~/Applications` directory, and the system `PATH`
2. WHEN an IDE is not found in standard locations, THE MDM_Installer SHALL use macOS Spotlight (`mdfind`) with the IDE's bundle identifier as a fallback detection method
3. THE MDM_Installer SHALL detect Kiro using bundle identifier `com.amazon.kiro`
4. THE MDM_Installer SHALL detect VS Code using bundle identifier `com.microsoft.VSCode`
5. THE MDM_Installer SHALL detect Cursor using bundle identifier `com.todesktop.230313mzl4w4u92`
6. THE MDM_Installer SHALL detect Windsurf using bundle identifier `com.exafunction.windsurf`
7. THE MDM_Installer SHALL detect Claude Code by checking known paths (`/usr/local/bin/claude`, `~/.claude/bin/claude`) and the system `PATH`

### Requirement 4: Opengrep Installation

**User Story:** As an MDM administrator, I want opengrep bundled in the package so that installation succeeds without internet access on corporate networks.

#### Acceptance Criteria

1. THE MDM_Installer SHALL first attempt to install opengrep from the bundled binary at `/Library/Application Support/Hotmart/appsec/bin/opengrep`
2. IF the bundled binary is not present, THEN THE MDM_Installer SHALL attempt installation via Homebrew as a second fallback
3. IF Homebrew is not available, THEN THE MDM_Installer SHALL attempt to download the latest release from the opengrep GitHub repository matching the system architecture (arm64 or x86_64)
4. THE MDM_Installer SHALL install the opengrep binary to `/usr/local/bin/opengrep` when running with root privileges
5. IF opengrep is already installed, THEN THE MDM_Installer SHALL skip installation and report the existing version
6. THE MDM_Installer SHALL ensure `/usr/local/bin` is in the PATH during execution

### Requirement 5: Corporate Proxy Certificate Handling

**User Story:** As a security engineer, I want the installer to handle corporate proxy (Zscaler) certificates via pinning rather than trusting all certificates, so that supply chain attacks through rogue CAs are prevented.

#### Acceptance Criteria

1. WHEN network access is required, THE MDM_Installer SHALL extract the corporate proxy CA certificate from the macOS System Keychain by its Common Name
2. THE MDM_Installer SHALL validate the extracted certificate by comparing its SHA-256 fingerprint against the hardcoded trusted fingerprint
3. IF the certificate fingerprint does not match the trusted fingerprint, THEN THE MDM_Installer SHALL refuse to use the certificate and log a security warning indicating a possible supply chain attack
4. WHEN the fingerprint validates successfully, THE MDM_Installer SHALL export the certificate to a temporary PEM file and set `NODE_EXTRA_CA_CERTS` for IDE_CLI processes
5. WHEN extension installation completes, THE MDM_Installer SHALL remove the temporary certificate PEM file

### Requirement 6: IDE Security Configuration — Kiro

**User Story:** As a security engineer, I want Kiro configured with mandatory security steering and a prompt analysis hook, so that AI-generated code follows corporate security policies.

#### Acceptance Criteria

1. WHEN Kiro is detected, THE MDM_Installer SHALL write a steering file to `~/.kiro/steering/appsec-rules.md` with `inclusion: auto`, `priority: maximum`, and `enforcement: mandatory` metadata
2. WHEN Kiro is detected, THE MDM_Installer SHALL write a hook file to `~/.kiro/hooks/appsec-gate.kiro.hook` that intercepts `promptSubmit` events and analyzes prompts for insecure patterns
3. THE Steering_File SHALL declare forbidden patterns including hardcoded credentials, SQL injection, eval with user input, disabled TLS, tokens in localStorage, weak cryptography for passwords, and stack traces exposed to clients

### Requirement 7: IDE Security Configuration — Cursor

**User Story:** As a security engineer, I want Cursor configured with always-applied security rules and a gate script, so that AI code suggestions follow corporate security policies.

#### Acceptance Criteria

1. WHEN Cursor is detected, THE MDM_Installer SHALL write a rules file to `~/.cursor/rules/appsec-rules.mdc` with `alwaysApply: true` metadata
2. WHEN Cursor is detected, THE MDM_Installer SHALL write an AppSec_Gate script to `~/.cursor/appsec/appsec-gate.sh` and set it as executable
3. THE AppSec_Gate SHALL detect hardcoded credentials, AWS access keys (pattern `AKIA[0-9A-Z]{16}`), connection strings with embedded credentials, and disabled TLS verification

### Requirement 8: IDE Security Configuration — Windsurf

**User Story:** As a security engineer, I want Windsurf configured with always-applied security rules and a gate script, so that AI code suggestions follow corporate security policies.

#### Acceptance Criteria

1. WHEN Windsurf is detected, THE MDM_Installer SHALL write a rules file to `~/.windsurf/rules/appsec-rules.md` with `alwaysApply: true` metadata
2. WHEN Windsurf is detected, THE MDM_Installer SHALL write an AppSec_Gate script to `~/.windsurf/appsec/appsec-gate.sh` and set it as executable
3. THE AppSec_Gate SHALL detect the same insecure patterns as the Cursor AppSec_Gate

### Requirement 9: IDE Security Configuration — Claude Code

**User Story:** As a security engineer, I want Claude Code configured with pre-tool-use hooks and security rules, so that write operations are intercepted and validated before execution.

#### Acceptance Criteria

1. WHEN Claude Code is detected, THE MDM_Installer SHALL write a rules file to `~/.claude/rules/appsec-rules.md`
2. WHEN Claude Code is detected, THE MDM_Installer SHALL write an AppSec_Gate script to `~/.claude/appsec/appsec-gate.sh` and set it as executable
3. WHEN Claude Code is detected, THE MDM_Installer SHALL configure `~/.claude/settings.json` with a `PreToolUse` hook matching `Write|Edit|MultiEdit|CreateFile` operations that invokes the AppSec_Gate
4. IF Claude Code settings.json already contains AppSec_Gate configuration, THEN THE MDM_Installer SHALL skip settings modification

### Requirement 10: Git Pre-Commit Hook Installation

**User Story:** As a security engineer, I want advisory-only pre-commit hooks installed in developer repositories, so that developers receive security feedback before commits without blocking their workflow.

#### Acceptance Criteria

1. THE MDM_Installer SHALL scan common development directories (`~/Documents`, `~/projects`, `~/dev`, `~/workspace`, `~/repos`, `~/code`) for Git repositories up to 4 levels deep
2. WHEN a Git repository is found, THE MDM_Installer SHALL install a pre-commit hook script in `<repo>/.git/hooks/pre-commit`
3. THE Pre_Commit_Hook SHALL scan staged files using opengrep with the security rules file
4. THE Pre_Commit_Hook SHALL always exit with code 0, ensuring commits are never blocked
5. THE Pre_Commit_Hook SHALL display detected vulnerabilities in a formatted advisory message
6. THE Pre_Commit_Hook SHALL support a dismissal mechanism via `.appsec-state/dismissed.json` to suppress previously acknowledged findings
7. THE Pre_Commit_Hook SHALL only scan files with extensions matching supported languages (TypeScript, JavaScript, Java, Python, Go, Ruby, PHP, C, C++, C#, Swift, Kotlin, Rust, Scala)

### Requirement 11: Watchdog Persistence

**User Story:** As an MDM administrator, I want a watchdog that restores removed components automatically, so that the security tooling remains consistently deployed even if users accidentally or intentionally remove it.

#### Acceptance Criteria

1. THE MDM_Watchdog SHALL run as a LaunchDaemon every 30 minutes at background CPU priority (nice 19) and background IO scheduling class
2. THE MDM_Watchdog SHALL verify and restore opengrep if the binary is missing
3. THE MDM_Watchdog SHALL verify and restore IDE extensions if they are not present in the extensions directory
4. THE MDM_Watchdog SHALL verify and restore Steering_Files, rules, and AppSec_Gate scripts if they are missing or modified
5. THE MDM_Watchdog SHALL verify and restore Pre_Commit_Hooks in repositories within the configured search directories
6. WHEN the previous successful run occurred less than 4 hours ago, THE MDM_Watchdog SHALL skip execution to reduce resource usage
7. THE MDM_Watchdog SHALL terminate after 5 minutes maximum (enforced by LaunchDaemon `TimeOut`)
8. THE MDM_Watchdog SHALL maintain a log file at `/Library/Logs/Hotmart/appsec-watchdog.log` bounded to 500 lines and 1 MB

### Requirement 12: Complete Uninstallation

**User Story:** As an MDM administrator, I want a single uninstall script that removes all traces of the deployment, so that the system can be cleanly removed via Workspace ONE when needed.

#### Acceptance Criteria

1. THE MDM_Uninstaller SHALL stop and remove the LaunchDaemon by unloading the plist and deleting the file
2. THE MDM_Uninstaller SHALL uninstall the extension from all detected IDEs using the IDE_CLI `--uninstall-extension` command
3. THE MDM_Uninstaller SHALL remove all Steering_Files, rules files, and AppSec_Gate scripts for Kiro, Cursor, Windsurf, and Claude Code
4. THE MDM_Uninstaller SHALL clean Claude Code `settings.json` by removing only the AppSec-related hook entries while preserving other user settings
5. THE MDM_Uninstaller SHALL remove Pre_Commit_Hooks from repositories by deleting hook files that contain the "AppSec" identifier
6. THE MDM_Uninstaller SHALL remove the opengrep binary from `/usr/local/bin` and `~/.local/bin`
7. THE MDM_Uninstaller SHALL remove the AppSec directory at `/Library/Application Support/Hotmart/appsec`
8. THE MDM_Uninstaller SHALL forget the macOS package receipt using `pkgutil --forget com.hotmart.appsec`

### Requirement 13: Package Building

**User Story:** As a release engineer, I want a build script that produces a self-contained `.pkg` file with all dependencies bundled, so that deployment via Workspace ONE requires no internet access on target machines.

#### Acceptance Criteria

1. THE Package_Builder SHALL download the opengrep binary for arm64 architecture from the latest GitHub release and bundle it in the package payload
2. IF the opengrep download fails, THEN THE Package_Builder SHALL fall back to copying the locally installed opengrep binary
3. THE Package_Builder SHALL include mdm-install.sh, mdm-watchdog.sh, mdm-uninstall.sh, and the LaunchDaemon plist in the package payload under `/Library/Application Support/Hotmart/appsec/`
4. THE Package_Builder SHALL generate a postinstall script that sets permissions, installs the bundled opengrep, runs mdm-install.sh, and loads the LaunchDaemon
5. THE Package_Builder SHALL produce the package using `pkgbuild` with identifier `com.hotmart.appsec` and output to `dist/hotmart-appsec-<version>.pkg`
6. THE Package_Builder SHALL place the LaunchDaemon plist in the payload at `/Library/LaunchDaemons/com.hotmart.appsec.watchdog.plist`

### Requirement 14: Idempotent Operations

**User Story:** As an MDM administrator, I want all scripts to be idempotent, so that repeated execution produces the same result without errors or duplicate installations.

#### Acceptance Criteria

1. WHEN a configuration file already exists with the expected content, THE MDM_Installer SHALL skip writing and report it as already up-to-date
2. WHEN the extension is already installed in an IDE, THE MDM_Installer SHALL update it using `--force` rather than failing
3. WHEN opengrep is already installed, THE MDM_Installer SHALL skip installation and report the existing version
4. THE MDM_Watchdog SHALL compare file content before overwriting to avoid unnecessary writes
5. THE MDM_Uninstaller SHALL handle missing components gracefully without returning error exit codes

### Requirement 15: Logging and Observability

**User Story:** As an MDM administrator, I want comprehensive logging of all installation and watchdog operations, so that I can troubleshoot deployment issues remotely.

#### Acceptance Criteria

1. THE MDM_Installer SHALL log detailed output to `/Library/Logs/Hotmart/appsec-install-detail.log` including the running user, Console_User, and resolved home directory
2. THE MDM_Installer SHALL display a formatted summary at the end showing counts of installed, skipped, and failed components
3. THE MDM_Watchdog SHALL log restoration actions with timestamps to `/Library/Logs/Hotmart/appsec-watchdog.log`
4. THE MDM_Uninstaller SHALL log all removal operations with timestamps to `/Library/Logs/Hotmart/appsec-uninstall.log`
5. THE MDM_Watchdog SHALL trim the log file to 500 lines and cap it at 1 MB to prevent unbounded growth

### Requirement 16: Security Rules Coverage

**User Story:** As a security engineer, I want the SAST rules to cover the most critical vulnerability classes across all languages used in the organization, so that developers receive consistent security feedback regardless of the language they work in.

#### Acceptance Criteria

1. THE Security_Rules SHALL include detection patterns for CWE-798 (Hardcoded Credentials) covering variable declarations, object property assignments, and AWS credential constructors
2. THE Security_Rules SHALL include detection patterns for CWE-89 (SQL Injection) covering string concatenation in query construction
3. THE Security_Rules SHALL include detection patterns for CWE-78 (OS Command Injection) covering user input in shell command execution
4. THE Security_Rules SHALL include detection patterns for CWE-79 (Cross-Site Scripting) covering unsanitized HTML rendering
5. THE Security_Rules SHALL include detection patterns for CWE-22 (Path Traversal) covering user input in file path construction
6. THE Security_Rules SHALL include detection patterns for CWE-918 (Server-Side Request Forgery) covering user input in URL construction
7. THE Security_Rules SHALL include detection patterns for CWE-327 (Weak Cryptography) covering use of MD5, SHA1 for password hashing
8. THE Security_Rules SHALL be compatible with the opengrep/semgrep rule format in YAML

### Requirement 17: LaunchDaemon Configuration

**User Story:** As an MDM administrator, I want the watchdog daemon configured for minimal system impact, so that it does not affect developer productivity or machine performance.

#### Acceptance Criteria

1. THE LaunchDaemon SHALL run as root user with label `com.hotmart.appsec.watchdog`
2. THE LaunchDaemon SHALL execute at 30-minute intervals via `StartInterval`
3. THE LaunchDaemon SHALL execute immediately upon load via `RunAtLoad`
4. THE LaunchDaemon SHALL run at the lowest CPU priority (nice 19) and background IO scheduling class (0)
5. THE LaunchDaemon SHALL terminate the watchdog process after 300 seconds via `TimeOut`
6. THE LaunchDaemon SHALL direct stdout and stderr to `/Library/Logs/Hotmart/appsec-watchdog.log`
7. THE LaunchDaemon SHALL not keep the process alive between intervals (`KeepAlive` set to false)
