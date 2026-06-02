#!/bin/bash
# =============================================================================
# AppSec Watchdog — macOS (self-contained, lightweight)
# =============================================================================
# Single-file watchdog. No standards/ folder required.
# All config content is embedded inline.
# Runs via LaunchDaemon at lowest CPU/IO priority every 30 minutes.
# =============================================================================

renice -n 19 $$ 2>/dev/null || true

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

APPSEC_DIR="/Library/Application Support/Hotmart/appsec"
VSIX_FILE=""   # Not used — extension installed from marketplace
LOG_FILE="/Library/Logs/Hotmart/appsec-watchdog.log"
STATE_FILE="$APPSEC_DIR/.watchdog-state"
EXTENSION_ID="HotmartCybersecurity.cybersecurityextension"
TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S')"
GIT_SEARCH_DEPTH=4

# ---------------------------------------------------------------------------
# Logging (append-only, bounded to 500 lines)
# ---------------------------------------------------------------------------

mkdir -p "$(dirname "$LOG_FILE")" "$APPSEC_DIR"

log() { echo "[$TIMESTAMP] $*" >> "$LOG_FILE"; }

trim_log() {
  local tmp; tmp="$(mktemp)"
  tail -n 500 "$LOG_FILE" > "$tmp" && mv "$tmp" "$LOG_FILE" || rm -f "$tmp"
}

# ---------------------------------------------------------------------------
# State file: skip run if last check was < 4h ago and no forced recheck
# ---------------------------------------------------------------------------

should_skip() {
  [ -f "$STATE_FILE" ] || return 1
  local last_run now elapsed
  last_run="$(cat "$STATE_FILE" 2>/dev/null || echo 0)"
  now="$(date +%s)"
  elapsed=$(( now - last_run ))
  [ "$elapsed" -lt 14400 ]
}

save_state() { date +%s > "$STATE_FILE"; }

# ---------------------------------------------------------------------------
# Resolve the logged-in user (runs as root via LaunchDaemon)
# ---------------------------------------------------------------------------

get_console_user() {
  stat -f '%Su' /dev/console 2>/dev/null || echo ""
}

get_user_home() {
  dscl . -read "/Users/$1" NFSHomeDirectory 2>/dev/null | awk '{print $2}'
}

# ---------------------------------------------------------------------------
# ensure_content <dst> <label> <<'EOF' ... EOF
# Writes content from stdin if file is missing or differs — inline, no src needed.
# ---------------------------------------------------------------------------
ensure_content() {
  local dst="$1" label="$2"
  local content; content="$(cat)"
  mkdir -p "$(dirname "$dst")"
  if [ ! -f "$dst" ]; then
    printf '%s\n' "$content" > "$dst"
    log "[RESTORED] $label (missing)"
  elif [ "$(cat "$dst")" != "$content" ]; then
    printf '%s\n' "$content" > "$dst"
    log "[RESTORED] $label (modified)"
  fi
}

# ---------------------------------------------------------------------------
# opengrep
# ---------------------------------------------------------------------------

ensure_opengrep() {
  command -v opengrep &>/dev/null && return
  log "[RESTORE] opengrep missing — reinstalling..."
  curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash >> "$LOG_FILE" 2>&1 \
    && log "[RESTORED] opengrep" \
    || log "[ERROR] opengrep reinstall failed"
}

# ---------------------------------------------------------------------------
# Extension — check via extension folder, install from marketplace if missing
# Each IDE stores extensions in a different folder:
#   Kiro    → ~/.kiro/extensions
#   VS Code → ~/.vscode/extensions
#   Cursor  → ~/.cursor/extensions
# ---------------------------------------------------------------------------

ensure_extension() {
  local cli="$1" ext_dir="$2" label="$3"
  [ -x "$cli" ] || return
  mkdir -p "$ext_dir"

  if ! ls "$ext_dir"/hotmartcybersecurity.* 2>/dev/null | grep -q .; then
    log "[RESTORE] $label extension missing — reinstalling from marketplace..."
    "$cli" --install-extension "$EXTENSION_ID" >> "$LOG_FILE" 2>&1 \
      && log "[RESTORED] $label extension" \
      || log "[ERROR] $label install failed"
  fi
}

# ---------------------------------------------------------------------------
# pre-commit — lightweight: only check if hook file exists and matches
# No recursive find across all repos — just the configured search dirs
# ---------------------------------------------------------------------------

ensure_precommit_hooks() {
  local user_home="$1"
  local hook_src="$STANDARDS_DIR/hooks/pre-commit"
  [ -f "$hook_src" ] || return

  local src_hash
  src_hash="$(md5 -q "$hook_src" 2>/dev/null)"

  local dirs=("$user_home/Documents" "$user_home/projects" "$user_home/dev" "$user_home/workspace" "$user_home/repos" "$user_home/code")

  for dir in "${dirs[@]}"; do
    [ -d "$dir" ] || continue
    # Use find with maxdepth to avoid deep traversal
    while IFS= read -r -d '' git_dir; do
      local hook_dst="$git_dir/hooks/pre-commit"
      if [ ! -f "$hook_dst" ]; then
        cp "$hook_src" "$hook_dst" && chmod +x "$hook_dst"
        log "[RESTORED] pre-commit in $(dirname "$git_dir")"
      elif [ "$(md5 -q "$hook_dst" 2>/dev/null)" != "$src_hash" ]; then
        cp "$hook_src" "$hook_dst" && chmod +x "$hook_dst"
        log "[RESTORED] pre-commit modified in $(dirname "$git_dir")"
      fi
    done < <(find "$dir" -maxdepth "$GIT_SEARCH_DEPTH" -name ".git" -type d -print0 2>/dev/null)
  done
}

# ---------------------------------------------------------------------------
# IDE detection
# ---------------------------------------------------------------------------

find_kiro()   { for c in "/Applications/Kiro.app/Contents/Resources/app/bin/kiro"           "$2/Applications/Kiro.app/Contents/Resources/app/bin/kiro";           do [ -x "$c" ] && echo "$c" && return; done; }
find_vscode() { for c in "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code" "$2/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code"; do [ -x "$c" ] && echo "$c" && return; done; }
find_cursor() { for c in "/Applications/Cursor.app/Contents/Resources/app/bin/cursor"       "$2/Applications/Cursor.app/Contents/Resources/app/bin/cursor";       do [ -x "$c" ] && echo "$c" && return; done; }

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Quick exit if nothing has changed recently
if should_skip; then
  exit 0
fi

CONSOLE_USER="$(get_console_user)"
if [ -z "$CONSOLE_USER" ] || [ "$CONSOLE_USER" = "root" ]; then
  ensure_opengrep
  save_state
  exit 0
fi

USER_HOME="$(get_user_home "$CONSOLE_USER")"

log "===== Watchdog run (user: $CONSOLE_USER) ====="

ensure_opengrep

KIRO_CLI="$(find_kiro   "" "$USER_HOME")"
VSCODE_CLI="$(find_vscode "" "$USER_HOME")"
CURSOR_CLI="$(find_cursor "" "$USER_HOME")"

[ -n "$KIRO_CLI" ]   && ensure_extension "$KIRO_CLI"   "$USER_HOME/.kiro/extensions"   "Kiro"
[ -n "$VSCODE_CLI" ] && ensure_extension "$VSCODE_CLI" "$USER_HOME/.vscode/extensions" "VS Code"
[ -n "$CURSOR_CLI" ] && ensure_extension "$CURSOR_CLI" "$USER_HOME/.cursor/extensions" "Cursor"

[ -n "$KIRO_CLI" ] && {
  ensure_content "$USER_HOME/.kiro/steering/appsec-rules.md" "Kiro steering" << 'EOF'
---
inclusion: auto
priority: maximum
enforcement: mandatory
---
# APPSEC SECURITY STEERING — CORPORATE MANDATORY POLICY
FORBIDDEN: hardcoded credentials, SQL injection, eval() with user input,
disabled TLS, tokens in localStorage, MD5/SHA1 for passwords, stack traces to client.
Always use environment variables or a secret manager for credentials.
EOF

  ensure_content "$USER_HOME/.kiro/hooks/appsec-gate.kiro.hook" "Kiro hook" << 'EOF'
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
EOF
}

[ -n "$CURSOR_CLI" ] && {
  ensure_content "$USER_HOME/.cursor/rules/appsec-rules.mdc" "Cursor rules" << 'EOF'
---
alwaysApply: true
---
# APPSEC SECURITY RULES — CORPORATE MANDATORY POLICY
FORBIDDEN: hardcoded credentials, SQL injection, eval() with user input,
disabled TLS, tokens in localStorage, MD5/SHA1 for passwords, stack traces to client.
Always use environment variables or a secret manager for credentials.
EOF

  ensure_content "$USER_HOME/.cursor/appsec/appsec-gate.sh" "Cursor appsec-gate.sh" << 'HOOK'
#!/bin/bash
CONTENT=$(cat)
VIOLATIONS_FOUND=0
echo "$CONTENT" | grep -qiE '(password|passwd|secret|api_key|token|private_key|access_key|senha|chave)\s*[=:]\s*["'"'"'][^"'"'"']{3,}' && VIOLATIONS_FOUND=1
echo "$CONTENT" | grep -qE 'AKIA[0-9A-Z]{16}' && VIOLATIONS_FOUND=1
echo "$CONTENT" | grep -qiE '(mongodb|postgres|mysql|redis|amqp)://[^:]+:[^@]+@' && VIOLATIONS_FOUND=1
echo "$CONTENT" | grep -qiE 'rejectUnauthorized\s*:\s*false' && VIOLATIONS_FOUND=1
[ "$VIOLATIONS_FOUND" -eq 0 ] && exit 0
echo "🚫 ACESSO NEGADO — Padrão inseguro detectado. Use variáveis de ambiente."
exit 1
HOOK
  chmod +x "$USER_HOME/.cursor/appsec/appsec-gate.sh" 2>/dev/null || true
}

[ -d "$USER_HOME/.claude" ] && {
  ensure_content "$USER_HOME/.claude/rules/appsec-rules.md" "Claude rules" << 'EOF'
# APPSEC SECURITY RULES — CORPORATE MANDATORY POLICY
FORBIDDEN: hardcoded credentials, SQL injection, eval() with user input,
disabled TLS, tokens in localStorage, MD5/SHA1 for passwords, stack traces to client.
Always use environment variables or a secret manager for credentials.
EOF

  ensure_content "$USER_HOME/.claude/appsec/appsec-gate.sh" "Claude appsec-gate.sh" << 'HOOK'
#!/bin/bash
CONTENT=$(cat)
VIOLATIONS_FOUND=0
echo "$CONTENT" | grep -qiE '(password|passwd|secret|api_key|token|private_key|access_key|senha|chave)\s*[=:]\s*["'"'"'][^"'"'"']{3,}' && VIOLATIONS_FOUND=1
echo "$CONTENT" | grep -qE 'AKIA[0-9A-Z]{16}' && VIOLATIONS_FOUND=1
echo "$CONTENT" | grep -qiE '(mongodb|postgres|mysql|redis|amqp)://[^:]+:[^@]+@' && VIOLATIONS_FOUND=1
echo "$CONTENT" | grep -qiE 'rejectUnauthorized\s*:\s*false' && VIOLATIONS_FOUND=1
[ "$VIOLATIONS_FOUND" -eq 0 ] && exit 0
echo "🚫 ACESSO NEGADO — Padrão inseguro detectado. Use variáveis de ambiente."
exit 1
HOOK
  chmod +x "$USER_HOME/.claude/appsec/appsec-gate.sh" 2>/dev/null || true
}

ensure_precommit_hooks "$USER_HOME"

save_state
trim_log

log "===== Watchdog complete ====="
