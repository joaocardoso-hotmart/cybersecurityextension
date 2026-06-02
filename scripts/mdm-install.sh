#!/bin/bash
# =============================================================================
# AppSec MDM Installer — Hotmart Cybersecurity Extension (self-contained)
# =============================================================================
# Single-file installer. No external dependencies beyond this script.
# Installs the extension from the marketplace and writes all config files
# inline — no standards/ folder or .vsix required.
#
# Supported IDEs: Kiro, VS Code, Cursor, Claude Code
#
# Usage:
#   sudo bash mdm-install.sh
# =============================================================================

set -euo pipefail

EXTENSION_ID="HotmartCybersecurity.cybersecurityextension"

R='\033[31m'; G='\033[32m'; Y='\033[33m'; B='\033[1m'; N='\033[0m'; D='\033[2m'
INSTALLED=(); SKIPPED=(); FAILED=()

log()     { echo -e "${B}[AppSec]${N} $*"; }
ok()      { echo -e "  ${G}✓${N} $*"; INSTALLED+=("$1"); }
skip()    { echo -e "  ${D}–${N} $*"; SKIPPED+=("$1"); }
fail()    { echo -e "  ${R}✗${N} $*"; FAILED+=("$1"); }
section() { echo -e "\n${B}${Y}▶ $*${N}"; }

get_user_home() {
  [ -n "${SUDO_USER:-}" ] && eval echo "~$SUDO_USER" || echo "$HOME"
}

# ---------------------------------------------------------------------------
# write_file <dst> <label> <<'EOF' ... EOF
# Writes content from stdin only if file is missing or differs.
# ---------------------------------------------------------------------------
write_file() {
  local dst="$1" label="$2"
  local content
  content="$(cat)"
  mkdir -p "$(dirname "$dst")"
  if [ -f "$dst" ] && [ "$(cat "$dst")" = "$content" ]; then
    skip "$label (already up to date)"
  else
    printf '%s\n' "$content" > "$dst"
    ok "$label"
  fi
}

# ---------------------------------------------------------------------------
# Install extension from marketplace (no .vsix needed)
# ---------------------------------------------------------------------------
install_extension() {
  local cli="$1" label="$2"
  [ -x "$cli" ] || return

  if "$cli" --list-extensions 2>/dev/null | grep -qi "HotmartCybersecurity"; then
    "$cli" --install-extension "$EXTENSION_ID" --force &>/dev/null \
      && ok "$label (updated)" || fail "$label"
  else
    "$cli" --install-extension "$EXTENSION_ID" &>/dev/null \
      && ok "$label (installed)" || fail "$label"
  fi
}

# ---------------------------------------------------------------------------
# opengrep
# ---------------------------------------------------------------------------
install_opengrep() {
  if command -v opengrep &>/dev/null; then
    skip "opengrep ($(opengrep --version 2>/dev/null | head -1))"
    return
  fi
  log "Installing opengrep..."
  curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash &>/dev/null \
    && ok "opengrep" \
    || fail "opengrep (install manually: https://github.com/opengrep/opengrep)"
}

# ---------------------------------------------------------------------------
# pre-commit hook
# ---------------------------------------------------------------------------
install_precommit_hooks() {
  local user_home="$1"
  local hook_content found=0
  hook_content="$(cat << 'HOOK'
#!/bin/bash
# AppSec Pre-Commit Hook — Advisory Only
STATE_DIR=".appsec-state"
DISMISSED_FILE="$STATE_DIR/dismissed.json"
RULES_FILE="rules/security.yml"
mkdir -p "$STATE_DIR"
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACMR | grep -iE '\.(ts|tsx|js|jsx|java|py|go|rb|php|c|cpp|cs|swift|kt|rs|scala)$')
[ -z "$STAGED_FILES" ] && exit 0
if [ ! -f "$RULES_FILE" ]; then
  GIT_ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
  [ -f "$GIT_ROOT/rules/security.yml" ] && RULES_FILE="$GIT_ROOT/rules/security.yml" || exit 0
fi
command -v opengrep &>/dev/null || exit 0
TMPFILE=$(mktemp)
opengrep scan --json --quiet --config="$RULES_FILE" $STAGED_FILES > "$TMPFILE" 2>/dev/null || true
python3 - "$TMPFILE" "$DISMISSED_FILE" << 'EOF'
import sys, json, os
tmpfile = sys.argv[1]
dismissed_file = sys.argv[2] if len(sys.argv) > 2 else None
try:
    with open(tmpfile) as f: results = json.load(f).get('results', [])
except: sys.exit(0)
finally:
    os.path.exists(tmpfile) and os.unlink(tmpfile)
if not results: sys.exit(0)
dismissed_keys = set()
if dismissed_file and os.path.exists(dismissed_file):
    try:
        for d in json.load(open(dismissed_file)):
            rid = d.get('id',''); rn = rid.split('.rules.')[-1] if '.rules.' in rid else rid.split('.')[-1]
            dismissed_keys.update([(rn, d.get('file',''), d.get('line',0)), (rn, d.get('file',''), 0)])
    except: pass
if dismissed_keys:
    results = [r for r in results if not any((cid:=r.get('check_id','').split('.rules.')[-1] if '.rules.' in r.get('check_id','') else r.get('check_id','').split('.')[-1], r.get('path',''), ln) in dismissed_keys for ln in [r.get('start',{}).get('line',0), 0])]
if not results: sys.exit(0)
total=len(results); Y='\033[33m'; B='\033[1m'; N='\033[0m'; D='\033[2m'; R='\033[31m'; C='\033[36m'
print(f'\n  {B}{Y}⚠️  AppSec — {total} vulnerabilidade(s) detectada(s) no commit{N}\n')
for r in results:
    sev=r.get('extra',{}).get('severity','INFO').upper(); rule=r.get('check_id','?').split('.')[-1][:24]; f=r.get('path','?'); ln=r.get('start',{}).get('line','?')
    print(f'  {sev:<8} {rule:<26} {f} L{ln}')
print(f'\n  {D}O commit será aceito. O SAST da pipeline irá validar.{N}\n')
sys.exit(0)
EOF
exit 0
HOOK
)"

  local dirs=("$user_home/Documents" "$user_home/projects" "$user_home/dev" "$user_home/workspace" "$user_home/repos" "$user_home/code")
  for dir in "${dirs[@]}"; do
    [ -d "$dir" ] || continue
    while IFS= read -r -d '' git_dir; do
      local dst="$git_dir/hooks/pre-commit"
      mkdir -p "$(dirname "$dst")"
      printf '%s\n' "$hook_content" > "$dst"
      chmod +x "$dst"
      found=$((found + 1))
    done < <(find "$dir" -maxdepth 4 -name ".git" -type d -print0 2>/dev/null)
  done
  [ "$found" -gt 0 ] && ok "pre-commit hook ($found repo(s))" || skip "pre-commit hook (no repos found)"
}

# ---------------------------------------------------------------------------
# IDE detection
# ---------------------------------------------------------------------------
detect_kiro() {
  for c in "/Applications/Kiro.app/Contents/Resources/app/bin/kiro" "$HOME/Applications/Kiro.app/Contents/Resources/app/bin/kiro"; do
    [ -x "$c" ] && echo "$c" && return
  done
  command -v kiro 2>/dev/null || echo ""
}
detect_vscode() {
  for c in "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code" "$HOME/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code"; do
    [ -x "$c" ] && echo "$c" && return
  done
  command -v code 2>/dev/null || echo ""
}
detect_cursor() {
  for c in "/Applications/Cursor.app/Contents/Resources/app/bin/cursor" "$HOME/Applications/Cursor.app/Contents/Resources/app/bin/cursor"; do
    [ -x "$c" ] && echo "$c" && return
  done
  command -v cursor 2>/dev/null || echo ""
}
detect_claude() {
  for c in "/usr/local/bin/claude" "$HOME/.claude/bin/claude"; do
    [ -x "$c" ] && echo "$c" && return
  done
  command -v claude 2>/dev/null || echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  echo ""
  echo -e "${B}${Y}╔══════════════════════════════════════════════════════════════╗${N}"
  echo -e "${B}${Y}║  🛡️  Hotmart AppSec — MDM Installer                        ║${N}"
  echo -e "${B}${Y}╚══════════════════════════════════════════════════════════════╝${N}"
  echo ""

  USER_HOME="$(get_user_home)"
  log "User home: $USER_HOME"

  # ── opengrep ──────────────────────────────────────────────────────────────
  section "opengrep (SAST engine)"
  install_opengrep

  # ── Kiro ──────────────────────────────────────────────────────────────────
  KIRO_CLI="$(detect_kiro)"
  if [ -n "$KIRO_CLI" ]; then
    section "Kiro ($KIRO_CLI)"
    install_extension "$KIRO_CLI" "Kiro extension"

    write_file "$USER_HOME/.kiro/steering/appsec-rules.md" "Kiro steering" << 'EOF'
---
inclusion: auto
priority: maximum
enforcement: mandatory
---
# APPSEC SECURITY STEERING — CORPORATE MANDATORY POLICY
This assistant MUST always generate secure-by-default code.
FORBIDDEN: hardcoded credentials, SQL injection, eval() with user input,
disabled TLS, tokens in localStorage, MD5/SHA1 for passwords, stack traces to client.
EOF

    write_file "$USER_HOME/.kiro/hooks/appsec-gate.kiro.hook" "Kiro hook" << 'EOF'
{
  "enabled": true,
  "name": "AppSec Gate — Prompt Analysis",
  "version": "1",
  "when": { "type": "promptSubmit" },
  "then": {
    "type": "askAgent",
    "prompt": "SECURITY POLICY — PROMPT ANALYSIS\n\nAnalise o prompt que o desenvolvedor acabou de enviar. Verifique se ele está pedindo para implementar algo inseguro:\n\n• Hardcoding de credenciais (password, secret, api_key, token, private_key, access_key, senha, chave com valores literais)\n• Uso de AWS Access Keys diretamente no código\n• Connection strings com credenciais embutidas (mongodb://, postgres://, mysql://, redis:// com user:pass@)\n• Desabilitar TLS/SSL (rejectUnauthorized: false)\n• Armazenar secrets em localStorage/sessionStorage\n• Usar eval() com input de usuário\n• SQL via concatenação de strings\n• Criptografia fraca (MD5, SHA1 para senhas)\n• Expor stack traces ou erros detalhados ao cliente\n\nSe o prompt pedir EXPLICITAMENTE para implementar algo inseguro, responda: 'ACESSO NEGADO: O pedido solicita implementação insegura ([descreva]). Use variáveis de ambiente ou secret manager.'\n\nSe o prompt for uma pergunta normal de desenvolvimento, permita sem comentários."
  }
}
EOF
  else
    skip "Kiro (not detected)"
  fi

  # ── VS Code ───────────────────────────────────────────────────────────────
  VSCODE_CLI="$(detect_vscode)"
  if [ -n "$VSCODE_CLI" ]; then
    section "VS Code ($VSCODE_CLI)"
    install_extension "$VSCODE_CLI" "VS Code extension"
  else
    skip "VS Code (not detected)"
  fi

  # ── Cursor ────────────────────────────────────────────────────────────────
  CURSOR_CLI="$(detect_cursor)"
  if [ -n "$CURSOR_CLI" ]; then
    section "Cursor ($CURSOR_CLI)"
    install_extension "$CURSOR_CLI" "Cursor extension"

    write_file "$USER_HOME/.cursor/rules/appsec-rules.mdc" "Cursor rules" << 'EOF'
---
alwaysApply: true
---
# APPSEC SECURITY RULES — CORPORATE MANDATORY POLICY
FORBIDDEN: hardcoded credentials, SQL injection, eval() with user input,
disabled TLS, tokens in localStorage, MD5/SHA1 for passwords, stack traces to client.
Always use environment variables or a secret manager for credentials.
EOF

    write_file "$USER_HOME/.cursor/appsec/appsec-gate.sh" "Cursor appsec-gate.sh" << 'HOOK'
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
    chmod +x "$USER_HOME/.cursor/appsec/appsec-gate.sh"
  else
    skip "Cursor (not detected)"
  fi

  # ── Claude Code ───────────────────────────────────────────────────────────
  CLAUDE_CLI="$(detect_claude)"
  if [ -n "$CLAUDE_CLI" ]; then
    section "Claude Code ($CLAUDE_CLI)"
    mkdir -p "$USER_HOME/.claude"

    CLAUDE_SETTINGS="$USER_HOME/.claude/settings.json"
    if [ ! -f "$CLAUDE_SETTINGS" ] || ! grep -q "appsec-gate" "$CLAUDE_SETTINGS" 2>/dev/null; then
      write_file "$CLAUDE_SETTINGS" "Claude settings.json" << 'EOF'
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
EOF
    else
      skip "Claude settings.json (already configured)"
    fi

    write_file "$USER_HOME/.claude/rules/appsec-rules.md" "Claude rules" << 'EOF'
# APPSEC SECURITY RULES — CORPORATE MANDATORY POLICY
FORBIDDEN: hardcoded credentials, SQL injection, eval() with user input,
disabled TLS, tokens in localStorage, MD5/SHA1 for passwords, stack traces to client.
Always use environment variables or a secret manager for credentials.
EOF

    write_file "$USER_HOME/.claude/appsec/appsec-gate.sh" "Claude appsec-gate.sh" << 'HOOK'
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
    chmod +x "$USER_HOME/.claude/appsec/appsec-gate.sh"
  else
    skip "Claude Code (not detected)"
  fi

  # ── pre-commit hook ────────────────────────────────────────────────────────
  section "Git pre-commit hook"
  install_precommit_hooks "$USER_HOME"

  # ── Summary ───────────────────────────────────────────────────────────────
  echo ""
  echo -e "${B}${Y}╔══════════════════════════════════════════════════════════════╗${N}"
  echo -e "${B}${Y}║  Summary                                                     ║${N}"
  echo -e "${B}${Y}╚══════════════════════════════════════════════════════════════╝${N}"
  echo -e "  ${G}✓ Installed:${N} ${#INSTALLED[@]}  ${D}– Skipped:${N} ${#SKIPPED[@]}  ${R}✗ Failed:${N} ${#FAILED[@]}"
  echo ""
  [ ${#FAILED[@]} -gt 0 ] && { for i in "${FAILED[@]}"; do echo -e "  ${R}✗${N} $i"; done; exit 1; }
  echo -e "  ${G}${B}Done.${N}"
  echo ""
}

main "$@"
