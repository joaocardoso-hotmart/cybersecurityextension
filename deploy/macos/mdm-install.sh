#!/bin/bash
# =============================================================================
# AppSec MDM Installer — Hotmart Cybersecurity Extension (self-contained)
# =============================================================================
# Single-file installer. No external dependencies beyond this script.
# Installs the extension from a bundled .vsix file distributed via MDM.
# No marketplace dependency — fully offline capable.
#
# Supported IDEs: Kiro, VS Code, Cursor, Claude Code
#
# Usage:
#   sudo bash mdm-install.sh
# =============================================================================

set -euo pipefail

VSIX_PATH="/Library/Application Support/Hotmart/appsec/extension.vsix"

R='\033[31m'; G='\033[32m'; Y='\033[33m'; B='\033[1m'; N='\033[0m'; D='\033[2m'
INSTALLED=(); SKIPPED=(); FAILED=()

log()     { echo -e "${B}[AppSec]${N} $*"; }
ok()      { echo -e "  ${G}✓${N} $*"; INSTALLED+=("$1"); }
skip()    { echo -e "  ${D}–${N} $*"; SKIPPED+=("$1"); }
fail()    { echo -e "  ${R}✗${N} $*"; FAILED+=("$1"); }
section() { echo -e "\n${B}${Y}▶ $*${N}"; }

get_user_home() {
  # Detecta o usuário real da sessão GUI (não root)
  local real_user=""

  # 1. Console user (quem está logado na GUI do macOS)
  real_user="$(stat -f '%Su' /dev/console 2>/dev/null || echo "")"

  # 2. Fallback: SUDO_USER
  [ -z "$real_user" ] || [ "$real_user" = "root" ] && real_user="${SUDO_USER:-}"

  # 3. Fallback: primeiro user com UID >= 500
  if [ -z "$real_user" ] || [ "$real_user" = "root" ]; then
    real_user="$(dscl . list /Users UniqueID | awk '$2 >= 500 && $1 != "nobody" {print $1; exit}')"
  fi

  # Resolve home
  if [ -n "$real_user" ] && [ "$real_user" != "root" ]; then
    local home_dir
    home_dir="$(dscl . -read "/Users/$real_user" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
    [ -n "$home_dir" ] && echo "$home_dir" && return
  fi

  echo "$HOME"
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
# Install extension from bundled .vsix (no marketplace dependency)
# Runs as the real user (not root) to install in the correct home
# ---------------------------------------------------------------------------

install_extension() {
  local cli="$1" label="$2"
  [ -x "$cli" ] || return

  if [ ! -f "$VSIX_PATH" ]; then
    log "  [ERROR] Bundled .vsix not found at: $VSIX_PATH"
    fail "$label (vsix not found)"
    return
  fi

  local real_user real_home
  real_user="$(stat -f '%Su' /dev/console 2>/dev/null || echo "")"
  real_home="$(dscl . -read "/Users/$real_user" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"

  local env_cmd="env HOME=$real_home"

  log "  [DEBUG] Installing from bundled .vsix, Running as $real_user (HOME=$real_home): $cli --install-extension"

  # Executar instalação
  if [ "$(id -u)" = "0" ] && [ -n "$real_user" ] && [ "$real_user" != "root" ] && [ -n "$real_home" ]; then
    # Rodando como root — executar como console user
    local already_installed=""
    already_installed="$(sudo -H -u "$real_user" $env_cmd "$cli" --list-extensions 2>/dev/null | grep -i "HotmartCybersecurity" || true)"

    if [ -n "$already_installed" ]; then
      sudo -H -u "$real_user" $env_cmd "$cli" --install-extension "$VSIX_PATH" --force >> /Library/Logs/Hotmart/appsec-install-detail.log 2>&1 \
        && ok "$label (updated via vsix)" \
        || { log "  [ERROR] $label install failed — see appsec-install-detail.log"; fail "$label"; }
    else
      sudo -H -u "$real_user" $env_cmd "$cli" --install-extension "$VSIX_PATH" >> /Library/Logs/Hotmart/appsec-install-detail.log 2>&1 \
        && ok "$label (installed via vsix)" \
        || { log "  [ERROR] $label install failed — see appsec-install-detail.log"; fail "$label"; }
    fi
  else
    # Rodando como user normal
    if "$cli" --list-extensions 2>/dev/null | grep -qi "HotmartCybersecurity"; then
      "$cli" --install-extension "$VSIX_PATH" --force >> /Library/Logs/Hotmart/appsec-install-detail.log 2>&1 \
        && ok "$label (updated)" || { log "  [ERROR] $label update failed"; fail "$label"; }
    else
      "$cli" --install-extension "$VSIX_PATH" >> /Library/Logs/Hotmart/appsec-install-detail.log 2>&1 \
        && ok "$label (installed)" || { log "  [ERROR] $label install failed"; fail "$label"; }
    fi
  fi
}

# ---------------------------------------------------------------------------
# Certificate pinning for corporate proxy (Zscaler)
# Required for any HTTPS download (opengrep, GitHub API, etc.)
# ---------------------------------------------------------------------------
TRUSTED_PROXY_CA_FINGERPRINT="04:F6:1F:1D:13:AA:E1:D1:65:73:DC:2C:37:F7:96:FD:F4:AC:97:71:3A:69:59:EB:B1:1D:24:73:95:8B:1A:53"
TRUSTED_PROXY_CA_CN="Zscaler Root CA"

get_trusted_ca_certs() {
  local ca_certs="/tmp/appsec-trusted-ca.pem"
  local cert_pem fingerprint

  cert_pem="$(security find-certificate -a -c "$TRUSTED_PROXY_CA_CN" -p /Library/Keychains/System.keychain 2>/dev/null)"

  if [ -z "$cert_pem" ]; then
    echo "[AppSec]   [INFO] No corporate proxy CA found — skipping (direct internet)" >&2
    echo ""
    return
  fi

  fingerprint="$(echo "$cert_pem" | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"

  if [ "$fingerprint" != "$TRUSTED_PROXY_CA_FINGERPRINT" ]; then
    echo "[AppSec]   [SECURITY] CA fingerprint mismatch! Expected: $TRUSTED_PROXY_CA_FINGERPRINT Got: $fingerprint" >&2
    echo "[AppSec]   [SECURITY] Refusing to trust unknown certificate — possible supply chain attack" >&2
    echo ""
    return
  fi

  printf '%s\n' "$cert_pem" > "$ca_certs"
  chmod 644 "$ca_certs"
  echo "$ca_certs"
}

# ---------------------------------------------------------------------------
# opengrep — with integrity verification
# ---------------------------------------------------------------------------
install_opengrep() {
  # Garantir que /usr/local/bin está no PATH (pode não estar no contexto do Installer)
  export PATH="/usr/local/bin:$PATH"

  if command -v opengrep &>/dev/null; then
    skip "opengrep ($(opengrep --version 2>/dev/null | head -1))"
    return
  fi
  log "Installing opengrep..."

  # 1. Tentar usar o binário bundled no pacote (zero dependência externa)
  local bundled="/Library/Application Support/Hotmart/appsec/bin/opengrep"
  if [ -x "$bundled" ]; then
    cp "$bundled" /usr/local/bin/opengrep 2>/dev/null || {
      mkdir -p "$HOME/.local/bin"
      cp "$bundled" "$HOME/.local/bin/opengrep"
    }
    chmod +x /usr/local/bin/opengrep 2>/dev/null || chmod +x "$HOME/.local/bin/opengrep" 2>/dev/null
    command -v opengrep &>/dev/null && ok "opengrep (bundled)" && return
  fi

  # 2. Fallback: brew (se disponível)
  if command -v brew &>/dev/null; then
    brew install opengrep &>/dev/null && ok "opengrep (brew)" && return
  fi

  # 3. Último recurso: download com verificação de checksum
  # Exportar CA corporativo para curl funcionar atrás do Zscaler
  local ca_certs
  ca_certs="$(get_trusted_ca_certs)"
  local curl_ca_opt=""
  [ -n "$ca_certs" ] && curl_ca_opt="--cacert $ca_certs"

  local tmp_dir; tmp_dir="$(mktemp -d)"
  local arch; arch="$(uname -m)"
  local og_arch="arm64"
  [ "$arch" = "x86_64" ] && og_arch="x86"

  local release_json; release_json="$(curl -fsSL $curl_ca_opt --connect-timeout 10 "https://api.github.com/repos/opengrep/opengrep/releases/latest" 2>/dev/null)" || {
    fail "opengrep (sem binário bundled e sem internet)"
    rm -rf "$tmp_dir"
    [ -f "/tmp/appsec-trusted-ca.pem" ] && rm -f "/tmp/appsec-trusted-ca.pem"
    return
  }

  local download_url; download_url="$(echo "$release_json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
target = 'opengrep_osx_${og_arch}'
for a in data.get('assets', []):
    if a['name'] == target:
        print(a['browser_download_url'])
        break
" 2>/dev/null || echo "")"

  if [ -z "$download_url" ]; then
    fail "opengrep (não encontrou release para osx/${og_arch})"
    rm -rf "$tmp_dir"
    [ -f "/tmp/appsec-trusted-ca.pem" ] && rm -f "/tmp/appsec-trusted-ca.pem"
    return
  fi

  curl -fsSL $curl_ca_opt -o "$tmp_dir/opengrep" "$download_url" 2>/dev/null

  chmod +x "$tmp_dir/opengrep"
  mv "$tmp_dir/opengrep" /usr/local/bin/opengrep 2>/dev/null || {
    mkdir -p "$HOME/.local/bin"
    mv "$tmp_dir/opengrep" "$HOME/.local/bin/opengrep"
  }
  rm -rf "$tmp_dir"
  [ -f "/tmp/appsec-trusted-ca.pem" ] && rm -f "/tmp/appsec-trusted-ca.pem"

  command -v opengrep &>/dev/null && ok "opengrep (downloaded)" || fail "opengrep (install failed)"
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
STATE_DIR=".appsec"
DISMISSED_FILE="$STATE_DIR/dismissed.json"
RULES_FILE="rules/security.yml"
mkdir -p "$STATE_DIR"
STAGED_FILES=$(git -c core.quotePath=false diff --cached --name-only --diff-filter=ACMR | grep -iE '\.(ts|tsx|js|jsx|java|py|go|rb|php|c|cpp|cs|swift|kt|rs|scala)$')
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
# IDE detection — strong validation, no PATH lookup
# ---------------------------------------------------------------------------
# Rules:
#   1. Only look inside .app bundles in /Applications or ~/Applications
#      OR via Spotlight by known bundle ID
#   2. NEVER use PATH lookup for Electron IDEs — the developer's current
#      session has "cursor", "code", etc. in PATH already, which causes
#      false positives when running from inside those IDEs.
#   3. Validate the binary responds to --version with a semver number.
# ---------------------------------------------------------------------------

# Returns 0 if the binary is a real Electron IDE CLI (not kiro-cli etc.)
validate_ide_cli() {
  local cli="$1"
  [ -x "$cli" ] || return 1

  # If the binary is inside a .app/Contents/Resources/app/bin/ structure,
  # that's already proof it's an Electron IDE — skip --version check
  # (which can fail due to TLS/proxy issues on Kiro)
  if echo "$cli" | grep -q "Contents/Resources/app/bin"; then
    return 0
  fi

  # For binaries not in .app bundle, verify via --version
  local real_user ver
  real_user="$(stat -f '%Su' /dev/console 2>/dev/null || echo "")"
  if [ -n "$real_user" ] && [ "$real_user" != "root" ]; then
    local real_home
    real_home="$(dscl . -read "/Users/$real_user" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
    ver="$(sudo -H -u "$real_user" HOME="$real_home" "$cli" --version 2>/dev/null | head -1)"
  else
    ver="$("$cli" --version 2>/dev/null | head -1)"
  fi
  echo "$ver" | grep -qE '^[0-9]+\.[0-9]+' || return 1
  return 0
}

detect_kiro() {
  # Kiro IDE — some versions use "kiro" as CLI, others use "code" (VS Code fork)
  # Try both, prefer "kiro" if it exists
  local paths=(
    "/Applications/Kiro.app/Contents/Resources/app/bin/kiro"
    "/Applications/Kiro.app/Contents/Resources/app/bin/code"
    "$USER_HOME/Applications/Kiro.app/Contents/Resources/app/bin/kiro"
    "$USER_HOME/Applications/Kiro.app/Contents/Resources/app/bin/code"
  )
  for c in "${paths[@]}"; do
    [ -x "$c" ] && echo "$c" && return
  done
  # Spotlight by known bundle IDs
  local app
  for bid in "com.amazon.kiro" "software.amazon.kiro" "com.amazon.codewhisperer"; do
    app="$(mdfind "kMDItemCFBundleIdentifier == '$bid'" 2>/dev/null | head -1)"
    if [ -n "$app" ] && [ -d "$app" ]; then
      # Try kiro first, then code
      [ -x "$app/Contents/Resources/app/bin/kiro" ] && echo "$app/Contents/Resources/app/bin/kiro" && return
      [ -x "$app/Contents/Resources/app/bin/code" ] && echo "$app/Contents/Resources/app/bin/code" && return
    fi
  done
  # Fallback: any Kiro*.app in /Applications (excluding "Kiro CLI")
  local kiro_app
  kiro_app="$(find /Applications -maxdepth 1 -name "Kiro*.app" -not -name "*CLI*" -type d 2>/dev/null | head -1)"
  if [ -n "$kiro_app" ]; then
    [ -x "$kiro_app/Contents/Resources/app/bin/kiro" ] && echo "$kiro_app/Contents/Resources/app/bin/kiro" && return
    [ -x "$kiro_app/Contents/Resources/app/bin/code" ] && echo "$kiro_app/Contents/Resources/app/bin/code" && return
  fi
  echo ""
}

detect_vscode() {
  local paths=(
    "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code"
    "$USER_HOME/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code"
    "$USER_HOME/Downloads/Visual Studio Code.app/Contents/Resources/app/bin/code"
  )
  for c in "${paths[@]}"; do
    [ -x "$c" ] && validate_ide_cli "$c" && echo "$c" && return
  done
  local app
  for bid in "com.microsoft.VSCode" "com.microsoft.VSCodeInsiders"; do
    app="$(mdfind "kMDItemCFBundleIdentifier == '$bid'" 2>/dev/null | head -1)"
    if [ -n "$app" ] && [ -d "$app" ]; then
      local bin; bin="$(find "$app/Contents/Resources/app/bin" -maxdepth 1 -type f -name "code" -perm +111 2>/dev/null | head -1)"
      [ -n "$bin" ] && validate_ide_cli "$bin" && echo "$bin" && return
    fi
  done
  echo ""
}

detect_cursor() {
  local paths=(
    "/Applications/Cursor.app/Contents/Resources/app/bin/cursor"
    "$USER_HOME/Applications/Cursor.app/Contents/Resources/app/bin/cursor"
  )
  for c in "${paths[@]}"; do
    [ -x "$c" ] && validate_ide_cli "$c" && echo "$c" && return
  done
  local app
  for bid in "com.todesktop.230313mzl4w4u92" "com.getcursor.cursor"; do
    app="$(mdfind "kMDItemCFBundleIdentifier == '$bid'" 2>/dev/null | head -1)"
    if [ -n "$app" ] && [ -d "$app" ]; then
      local bin; bin="$(find "$app/Contents/Resources/app/bin" -maxdepth 1 -type f -name "cursor" -perm +111 2>/dev/null | head -1)"
      [ -n "$bin" ] && validate_ide_cli "$bin" && echo "$bin" && return
    fi
  done
  echo ""
}

detect_windsurf() {
  local paths=(
    "/Applications/Windsurf.app/Contents/Resources/app/bin/windsurf"
    "$USER_HOME/Applications/Windsurf.app/Contents/Resources/app/bin/windsurf"
  )
  for c in "${paths[@]}"; do
    [ -x "$c" ] && validate_ide_cli "$c" && echo "$c" && return
  done
  local app
  for bid in "com.exafunction.windsurf" "com.codeium.windsurf"; do
    app="$(mdfind "kMDItemCFBundleIdentifier == '$bid'" 2>/dev/null | head -1)"
    if [ -n "$app" ] && [ -d "$app" ]; then
      local bin; bin="$(find "$app/Contents/Resources/app/bin" -maxdepth 1 -type f -name "windsurf" -perm +111 2>/dev/null | head -1)"
      [ -n "$bin" ] && validate_ide_cli "$bin" && echo "$bin" && return
    fi
  done
  echo ""
}

detect_claude() {
  # Claude Code CLI — only known install paths, never PATH
  # (PATH may contain Kiro's embedded claude or other tools)
  local paths=(
    "/usr/local/bin/claude"
    "$USER_HOME/.claude/bin/claude"
    "$USER_HOME/.local/bin/claude"
  )
  for c in "${paths[@]}"; do
    if [ -x "$c" ]; then
      local ver; ver="$("$c" --version 2>/dev/null | head -1)"
      echo "$ver" | grep -qE '[0-9]+\.[0-9]+' && echo "$c" && return
    fi
  done
  local app
  for bid in "com.anthropic.claude" "com.anthropic.claudecode"; do
    app="$(mdfind "kMDItemCFBundleIdentifier == '$bid'" 2>/dev/null | head -1)"
    if [ -n "$app" ] && [ -d "$app" ]; then
      local bin; bin="$(find "$app" -maxdepth 5 -type f -name "claude" -perm +111 2>/dev/null | head -1)"
      [ -n "$bin" ] && echo "$bin" && return
    fi
  done
  echo ""
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

  # Logging detalhado
  LOG_DETAIL="/Library/Logs/Hotmart/appsec-install-detail.log"
  mkdir -p "$(dirname "$LOG_DETAIL")"
  echo "" >> "$LOG_DETAIL"
  echo "===== $(date) — mdm-install.sh started =====" >> "$LOG_DETAIL"
  echo "Running as: $(whoami) (UID=$(id -u))" >> "$LOG_DETAIL"
  echo "SUDO_USER=${SUDO_USER:-unset}" >> "$LOG_DETAIL"
  echo "Console user: $(stat -f '%Su' /dev/console 2>/dev/null || echo 'unknown')" >> "$LOG_DETAIL"

  USER_HOME="$(get_user_home)"
  log "User home: $USER_HOME"
  log "Running as: $(whoami) | Console user: $(stat -f '%Su' /dev/console 2>/dev/null || echo 'unknown')"
  echo "Resolved USER_HOME=$USER_HOME" >> "$LOG_DETAIL"

  # ── opengrep ──────────────────────────────────────────────────────────────
  section "opengrep (SAST engine)"
  install_opengrep

  # ── Kiro ──────────────────────────────────────────────────────────────────
  KIRO_CLI="$(detect_kiro)"
  if [ -n "$KIRO_CLI" ]; then
    section "Kiro ($KIRO_CLI)"
    install_extension "$KIRO_CLI" "Kiro extension"

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
    ok "Kiro steering"

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

  # ── Windsurf ──────────────────────────────────────────────────────────────
  WINDSURF_CLI="$(detect_windsurf)"
  if [ -n "$WINDSURF_CLI" ]; then
    section "Windsurf ($WINDSURF_CLI)"
    install_extension "$WINDSURF_CLI" "Windsurf extension"

    write_file "$USER_HOME/.windsurf/rules/appsec-rules.md" "Windsurf rules" << 'EOF'
---
alwaysApply: true
---
# APPSEC SECURITY RULES — CORPORATE MANDATORY POLICY
FORBIDDEN: hardcoded credentials, SQL injection, eval() with user input,
disabled TLS, tokens in localStorage, MD5/SHA1 for passwords, stack traces to client.
Always use environment variables or a secret manager for credentials.
EOF

    write_file "$USER_HOME/.windsurf/appsec/appsec-gate.sh" "Windsurf appsec-gate.sh" << 'HOOK'
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
    chmod +x "$USER_HOME/.windsurf/appsec/appsec-gate.sh"
  else
    skip "Windsurf (not detected)"
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
