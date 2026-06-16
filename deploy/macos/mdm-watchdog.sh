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
# Logging (append-only, bounded to 500 lines and 1MB)
# ---------------------------------------------------------------------------

mkdir -p "$(dirname "$LOG_FILE")" "$APPSEC_DIR"

log() { echo "[$TIMESTAMP] $*" >> "$LOG_FILE"; }

trim_log() {
  [ -f "$LOG_FILE" ] || return
  # Check file size (max 1MB)
  local size; size="$(stat -f%z "$LOG_FILE" 2>/dev/null || echo 0)"
  if [ "$size" -gt 1048576 ]; then
    local tmp; tmp="$(mktemp)"
    tail -n 200 "$LOG_FILE" > "$tmp" && mv "$tmp" "$LOG_FILE" || rm -f "$tmp"
    return
  fi
  # Also cap at 500 lines
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
# opengrep — with verification and retry
# ---------------------------------------------------------------------------

ensure_opengrep() {
  command -v opengrep &>/dev/null && return

  log "[RESTORE] opengrep missing — reinstalling..."

  # 1. Tentar usar o binário bundled no pacote
  local bundled="$APPSEC_DIR/bin/opengrep"
  if [ -x "$bundled" ]; then
    cp "$bundled" /usr/local/bin/opengrep 2>/dev/null || {
      mkdir -p "$HOME/.local/bin"
      cp "$bundled" "$HOME/.local/bin/opengrep"
    }
    chmod +x /usr/local/bin/opengrep 2>/dev/null || true
    command -v opengrep &>/dev/null && log "[RESTORED] opengrep (bundled)" && return
  fi

  # 2. Fallback: brew
  if command -v brew &>/dev/null; then
    brew install opengrep >> "$LOG_FILE" 2>&1 && log "[RESTORED] opengrep (brew)" && return
  fi

  # 3. Último recurso: download com verificação
  local tmp_dir; tmp_dir="$(mktemp -d)"
  local arch; arch="$(uname -m)"
  local og_arch="arm64"
  [ "$arch" = "x86_64" ] && og_arch="x86"

  local release_json; release_json="$(curl -fsSL --connect-timeout 10 "https://api.github.com/repos/opengrep/opengrep/releases/latest" 2>/dev/null)"

  if [ -n "$release_json" ]; then
    local download_url; download_url="$(echo "$release_json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
target = 'opengrep_osx_${og_arch}'
for a in data.get('assets', []):
    if a['name'] == target:
        print(a['browser_download_url'])
        break
" 2>/dev/null || echo "")"

    if [ -n "$download_url" ]; then
      curl -fsSL -o "$tmp_dir/opengrep" "$download_url" 2>/dev/null
      if [ -f "$tmp_dir/opengrep" ] && [ -s "$tmp_dir/opengrep" ]; then
        chmod +x "$tmp_dir/opengrep"
        mv "$tmp_dir/opengrep" /usr/local/bin/opengrep 2>/dev/null || {
          mkdir -p "$HOME/.local/bin"
          mv "$tmp_dir/opengrep" "$HOME/.local/bin/opengrep"
        }
        rm -rf "$tmp_dir"
        command -v opengrep &>/dev/null && log "[RESTORED] opengrep (downloaded)" && return
      fi
    fi
  fi

  rm -rf "$tmp_dir"
  log "[ERROR] opengrep reinstall failed (sem binário bundled e sem internet)"
}

# ---------------------------------------------------------------------------
# Extension — install from marketplace (no .vsix needed)
# ---------------------------------------------------------------------------

ensure_extension() {
  local cli="$1" ext_dir="$2" label="$3"
  [ -x "$cli" ] || return
  mkdir -p "$ext_dir"

  if ! ls "$ext_dir"/hotmartcybersecurity.* 2>/dev/null | grep -q .; then
    log "[RESTORE] $label extension missing — reinstalling from marketplace..."
    "$cli" --install-extension "$EXTENSION_ID" --force >> "$LOG_FILE" 2>&1 \
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
  local found=0

  # Hook content inline (same as mdm-install.sh)
  local hook_content
  hook_content='#!/bin/bash
# AppSec Pre-Commit Hook — Advisory Only
STATE_DIR=".appsec-state"
DISMISSED_FILE="$STATE_DIR/dismissed.json"
RULES_FILE="rules/security.yml"
mkdir -p "$STATE_DIR"
STAGED_FILES=$(git -c core.quotePath=false diff --cached --name-only --diff-filter=ACMR | grep -iE '\''\.(ts|tsx|js|jsx|java|py|go|rb|php|c|cpp|cs|swift|kt|rs|scala)$'\'')
[ -z "$STAGED_FILES" ] && exit 0
if [ ! -f "$RULES_FILE" ]; then
  GIT_ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
  [ -f "$GIT_ROOT/rules/security.yml" ] && RULES_FILE="$GIT_ROOT/rules/security.yml" || exit 0
fi
command -v opengrep &>/dev/null || exit 0
TMPFILE=$(mktemp)
opengrep scan --json --quiet --config="$RULES_FILE" $STAGED_FILES > "$TMPFILE" 2>/dev/null || true
python3 - "$TMPFILE" "$DISMISSED_FILE" << '\''EOF'\''
import sys, json, os
tmpfile = sys.argv[1]
dismissed_file = sys.argv[2] if len(sys.argv) > 2 else None
try:
    with open(tmpfile) as f: results = json.load(f).get('\''results'\'', [])
except: sys.exit(0)
finally:
    os.path.exists(tmpfile) and os.unlink(tmpfile)
if not results: sys.exit(0)
dismissed_keys = set()
if dismissed_file and os.path.exists(dismissed_file):
    try:
        for d in json.load(open(dismissed_file)):
            rid = d.get('\''id'\'','\'''\''); rn = rid.split('\''.rules.'\'')[-1] if '\''.rules.'\'' in rid else rid.split('\''.'\'')[-1]
            dismissed_keys.update([(rn, d.get('\''file'\'','\'''\''), d.get('\''line'\'',0)), (rn, d.get('\''file'\'','\'''\''), 0)])
    except: pass
if dismissed_keys:
    results = [r for r in results if not any((cid:=r.get('\''check_id'\'','\'''\'').split('\''.rules.'\'')[-1] if '\''.rules.'\'' in r.get('\''check_id'\'','\'''\'') else r.get('\''check_id'\'','\'''\'').split('\''.'\'')[-1], r.get('\''path'\'','\'''\''), ln) in dismissed_keys for ln in [r.get('\''start'\'',{}).get('\''line'\'',0), 0])]
if not results: sys.exit(0)
total=len(results); Y='\''\033[33m'\''; B='\''\033[1m'\''; N='\''\033[0m'\''; D='\''\033[2m'\''
print(f'\''\\n  {B}{Y}⚠️  AppSec — {total} vulnerabilidade(s) detectada(s) no commit{N}\\n'\'')
for r in results:
    sev=r.get('\''extra'\'',{}).get('\''severity'\'','\''INFO'\'').upper(); rule=r.get('\''check_id'\'','\''?'\'').split('\''.'\'')[-1][:24]; f=r.get('\''path'\'','\''?'\''); ln=r.get('\''start'\'',{}).get('\''line'\'','\''?'\'')
    print(f'\''  {sev:<8} {rule:<26} {f} L{ln}'\'')
print(f'\''\\n  {D}O commit será aceito. O SAST da pipeline irá validar.{N}\\n'\'')
sys.exit(0)
EOF
exit 0'

  local hook_hash
  hook_hash="$(echo "$hook_content" | md5 2>/dev/null | awk '{print $NF}')"

  local dirs=("$user_home/Documents" "$user_home/projects" "$user_home/dev" "$user_home/workspace" "$user_home/repos" "$user_home/code")

  for dir in "${dirs[@]}"; do
    [ -d "$dir" ] || continue
    while IFS= read -r -d '' git_dir; do
      local hook_dst="$git_dir/hooks/pre-commit"
      if [ ! -f "$hook_dst" ]; then
        mkdir -p "$(dirname "$hook_dst")"
        printf '%s\n' "$hook_content" > "$hook_dst"
        chmod +x "$hook_dst"
        log "[RESTORED] pre-commit in $(dirname "$git_dir")"
        found=$((found + 1))
      elif [ "$(md5 -q "$hook_dst" 2>/dev/null)" != "$hook_hash" ]; then
        printf '%s\n' "$hook_content" > "$hook_dst"
        chmod +x "$hook_dst"
        log "[RESTORED] pre-commit modified in $(dirname "$git_dir")"
        found=$((found + 1))
      fi
    done < <(find "$dir" -maxdepth "$GIT_SEARCH_DEPTH" -name ".git" -type d -print0 2>/dev/null)
  done

  [ "$found" -gt 0 ] && log "[INFO] pre-commit hooks restored: $found repo(s)"
}

# ---------------------------------------------------------------------------
# IDE detection
# ---------------------------------------------------------------------------

find_kiro()     { for c in "/Applications/Kiro.app/Contents/Resources/app/bin/kiro"           "$2/Applications/Kiro.app/Contents/Resources/app/bin/kiro";           do [ -x "$c" ] && echo "$c" && return; done; }
find_vscode()   { for c in "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code" "$2/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code"; do [ -x "$c" ] && echo "$c" && return; done; }
find_cursor()   { for c in "/Applications/Cursor.app/Contents/Resources/app/bin/cursor"       "$2/Applications/Cursor.app/Contents/Resources/app/bin/cursor";       do [ -x "$c" ] && echo "$c" && return; done; }
find_windsurf() { for c in "/Applications/Windsurf.app/Contents/Resources/app/bin/windsurf"   "$2/Applications/Windsurf.app/Contents/Resources/app/bin/windsurf";   do [ -x "$c" ] && echo "$c" && return; done; }

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
WINDSURF_CLI="$(find_windsurf "" "$USER_HOME")"

[ -n "$KIRO_CLI" ]     && ensure_extension "$KIRO_CLI"     "$USER_HOME/.kiro/extensions"     "Kiro"
[ -n "$VSCODE_CLI" ]   && ensure_extension "$VSCODE_CLI"   "$USER_HOME/.vscode/extensions"   "VS Code"
[ -n "$CURSOR_CLI" ]   && ensure_extension "$CURSOR_CLI"   "$USER_HOME/.cursor/extensions"   "Cursor"
[ -n "$WINDSURF_CLI" ] && ensure_extension "$WINDSURF_CLI" "$USER_HOME/.windsurf/extensions" "Windsurf"

[ -n "$KIRO_CLI" ] && {
  mkdir -p "$USER_HOME/.kiro/steering"
  cat > "$USER_HOME/.kiro/steering/appsec-rules.md" << 'EOF'
---
inclusion: auto
description: "Regras de segurança corporativas que proíbem práticas inseguras na geração de código por IA."
---
# APPSEC SECURITY STEERING — CORPORATE MANDATORY POLICY

This assistant MUST always generate secure-by-default code.
FORBIDDEN: hardcoded credentials, SQL injection, eval() with user input,
disabled TLS, tokens in localStorage, MD5/SHA1 for passwords, stack traces to client.
Always use environment variables or a secret manager for credentials.
EOF
  log "[OK] Kiro steering ensured"

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

[ -n "$WINDSURF_CLI" ] && {
  ensure_content "$USER_HOME/.windsurf/rules/appsec-rules.md" "Windsurf rules" << 'EOF'
---
alwaysApply: true
---
# APPSEC SECURITY RULES — CORPORATE MANDATORY POLICY
FORBIDDEN: hardcoded credentials, SQL injection, eval() with user input,
disabled TLS, tokens in localStorage, MD5/SHA1 for passwords, stack traces to client.
Always use environment variables or a secret manager for credentials.
EOF

  ensure_content "$USER_HOME/.windsurf/appsec/appsec-gate.sh" "Windsurf appsec-gate.sh" << 'HOOK'
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
  chmod +x "$USER_HOME/.windsurf/appsec/appsec-gate.sh" 2>/dev/null || true
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
