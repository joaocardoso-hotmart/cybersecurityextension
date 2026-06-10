#!/bin/bash
# =============================================================================
# AppSec MDM Uninstaller — Hotmart Cybersecurity Extension
# =============================================================================
# Remove completamente tudo que foi instalado pelo AppSec MDM:
#   - LaunchDaemon (watchdog)
#   - Extensão das IDEs (VS Code, Cursor, Kiro, Windsurf)
#   - Steering/rules/hooks (Kiro, Cursor, Windsurf, Claude)
#   - Pre-commit hooks
#   - opengrep
#   - Diretório do AppSec
#   - Package receipt
#
# Executado pelo Workspace ONE como root.
# Detecta o console user para operar no home correto.
#
# Uso: sudo bash mdm-uninstall.sh
# =============================================================================

set -uo pipefail

# ── PATH e variáveis ─────────────────────────────────────────────────────────

export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

EXTENSION_ID="HotmartCybersecurity.cybersecurityextension"
PLIST="/Library/LaunchDaemons/com.hotmart.appsec.watchdog.plist"
APPSEC_DIR="/Library/Application Support/Hotmart/appsec"
LOG="/Library/Logs/Hotmart/appsec-uninstall.log"

mkdir -p "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1

echo ""
echo "[$(date)] ===== AppSec Uninstall started ====="

# ── Detectar console user ────────────────────────────────────────────────────

CONSOLE_USER="$(stat -f '%Su' /dev/console 2>/dev/null || echo "")"

if [ -z "$CONSOLE_USER" ] || [ "$CONSOLE_USER" = "root" ]; then
  # Fallback: primeiro user com UID >= 500
  CONSOLE_USER="$(dscl . list /Users UniqueID | awk '$2 >= 500 && $1 != "nobody" {print $1; exit}')"
fi

if [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != "root" ]; then
  USER_HOME="$(dscl . -read "/Users/$CONSOLE_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
else
  USER_HOME=""
fi

echo "[$(date)] Console user: $CONSOLE_USER | Home: $USER_HOME"

# ── 1. Stop and remove LaunchDaemon ──────────────────────────────────────────

echo "[$(date)] [1/7] Removing LaunchDaemon..."
if [ -f "$PLIST" ]; then
  launchctl unload "$PLIST" 2>/dev/null || true
  rm -f "$PLIST"
  echo "[$(date)]   ✓ LaunchDaemon stopped and removed"
else
  echo "[$(date)]   – LaunchDaemon not present"
fi

# ── 2. Remove extensions from IDEs ──────────────────────────────────────────

echo "[$(date)] [2/7] Removing IDE extensions..."

uninstall_ext() {
  local cli="$1" label="$2"
  [ -x "$cli" ] || return 1

  if [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != "root" ]; then
    if sudo -u "$CONSOLE_USER" "$cli" --list-extensions 2>/dev/null | grep -qi "HotmartCybersecurity"; then
      sudo -u "$CONSOLE_USER" "$cli" --uninstall-extension "$EXTENSION_ID" 2>/dev/null \
        && echo "[$(date)]   ✓ $label extension removed" \
        || echo "[$(date)]   ✗ $label uninstall failed"
    else
      echo "[$(date)]   – $label extension not installed"
    fi
  else
    if "$cli" --list-extensions 2>/dev/null | grep -qi "HotmartCybersecurity"; then
      "$cli" --uninstall-extension "$EXTENSION_ID" 2>/dev/null \
        && echo "[$(date)]   ✓ $label extension removed" \
        || echo "[$(date)]   ✗ $label uninstall failed"
    fi
  fi
}

# Kiro
for c in "/Applications/Kiro.app/Contents/Resources/app/bin/kiro" "${USER_HOME}/Applications/Kiro.app/Contents/Resources/app/bin/kiro"; do
  [ -x "$c" ] && { uninstall_ext "$c" "Kiro"; break; }
done

# VS Code
for c in "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code" "${USER_HOME}/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code"; do
  [ -x "$c" ] && { uninstall_ext "$c" "VS Code"; break; }
done

# Cursor
for c in "/Applications/Cursor.app/Contents/Resources/app/bin/cursor" "${USER_HOME}/Applications/Cursor.app/Contents/Resources/app/bin/cursor"; do
  [ -x "$c" ] && { uninstall_ext "$c" "Cursor"; break; }
done

# Windsurf
for c in "/Applications/Windsurf.app/Contents/Resources/app/bin/windsurf" "${USER_HOME}/Applications/Windsurf.app/Contents/Resources/app/bin/windsurf"; do
  [ -x "$c" ] && { uninstall_ext "$c" "Windsurf"; break; }
done

# ── 3. Remove steering/rules/hooks ──────────────────────────────────────────

echo "[$(date)] [3/7] Removing AppSec configs..."

if [ -n "$USER_HOME" ] && [ -d "$USER_HOME" ]; then
  # Kiro
  rm -f "$USER_HOME/.kiro/steering/appsec-rules.md" 2>/dev/null && echo "[$(date)]   ✓ Kiro steering"
  rm -f "$USER_HOME/.kiro/hooks/appsec-gate.kiro.hook" 2>/dev/null && echo "[$(date)]   ✓ Kiro hook"

  # Cursor
  rm -f "$USER_HOME/.cursor/rules/appsec-rules.mdc" 2>/dev/null && echo "[$(date)]   ✓ Cursor rules"
  rm -rf "$USER_HOME/.cursor/appsec" 2>/dev/null && echo "[$(date)]   ✓ Cursor appsec dir"

  # Windsurf
  rm -f "$USER_HOME/.windsurf/rules/appsec-rules.md" 2>/dev/null && echo "[$(date)]   ✓ Windsurf rules"
  rm -rf "$USER_HOME/.windsurf/appsec" 2>/dev/null && echo "[$(date)]   ✓ Windsurf appsec dir"

  # Claude Code
  rm -f "$USER_HOME/.claude/rules/appsec-rules.md" 2>/dev/null && echo "[$(date)]   ✓ Claude rules"
  rm -rf "$USER_HOME/.claude/appsec" 2>/dev/null && echo "[$(date)]   ✓ Claude appsec dir"

  # Claude settings.json — remove only the appsec hook, not the whole file
  if [ -f "$USER_HOME/.claude/settings.json" ]; then
    python3 -c "
import json
f = '$USER_HOME/.claude/settings.json'
try:
    with open(f) as fh: data = json.load(fh)
    hooks = data.get('hooks', {}).get('PreToolUse', [])
    data['hooks']['PreToolUse'] = [h for h in hooks if 'appsec-gate' not in str(h.get('hooks', []))]
    if not data['hooks']['PreToolUse']: del data['hooks']['PreToolUse']
    if not data.get('hooks'): data.pop('hooks', None)
    with open(f, 'w') as fh: json.dump(data, fh, indent=2)
except: pass
" 2>/dev/null && echo "[$(date)]   ✓ Claude settings.json cleaned"
  fi
else
  echo "[$(date)]   – Cannot resolve user home, skipping config removal"
fi

# ── 4. Remove pre-commit hooks ──────────────────────────────────────────────

echo "[$(date)] [4/7] Removing pre-commit hooks..."
REMOVED=0
if [ -n "$USER_HOME" ] && [ -d "$USER_HOME" ]; then
  DIRS=("$USER_HOME/Documents" "$USER_HOME/projects" "$USER_HOME/dev" "$USER_HOME/workspace" "$USER_HOME/repos" "$USER_HOME/code")
  for dir in "${DIRS[@]}"; do
    [ -d "$dir" ] || continue
    while IFS= read -r -d '' git_dir; do
      hook="$git_dir/hooks/pre-commit"
      if [ -f "$hook" ] && grep -q "AppSec" "$hook" 2>/dev/null; then
        rm -f "$hook"
        REMOVED=$((REMOVED + 1))
      fi
    done < <(find "$dir" -maxdepth 4 -name ".git" -type d -print0 2>/dev/null)
  done
fi
echo "[$(date)]   Removed $REMOVED pre-commit hook(s)"

# ── 5. Remove opengrep ──────────────────────────────────────────────────────

echo "[$(date)] [5/7] Removing opengrep..."
if [ -f /usr/local/bin/opengrep ]; then
  rm -f /usr/local/bin/opengrep
  echo "[$(date)]   ✓ /usr/local/bin/opengrep removed"
fi
if [ -n "$USER_HOME" ] && [ -f "$USER_HOME/.local/bin/opengrep" ]; then
  rm -f "$USER_HOME/.local/bin/opengrep"
  echo "[$(date)]   ✓ ~/.local/bin/opengrep removed"
fi

# ── 6. Remove AppSec directory ───────────────────────────────────────────────

echo "[$(date)] [6/7] Removing AppSec directory..."
if [ -d "$APPSEC_DIR" ]; then
  rm -rf "$APPSEC_DIR"
  echo "[$(date)]   ✓ $APPSEC_DIR removed"
fi

# Remove parent if empty
rmdir "/Library/Application Support/Hotmart" 2>/dev/null || true

# ── 7. Forget package receipt ────────────────────────────────────────────────

echo "[$(date)] [7/7] Forgetting package receipt..."
pkgutil --forget com.hotmart.appsec 2>/dev/null \
  && echo "[$(date)]   ✓ Receipt forgotten" \
  || echo "[$(date)]   – Receipt not found"

# ── Done ─────────────────────────────────────────────────────────────────────

echo "[$(date)] ===== AppSec Uninstall complete ====="
echo ""
exit 0
