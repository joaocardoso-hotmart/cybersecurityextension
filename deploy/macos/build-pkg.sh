#!/bin/bash
# =============================================================================
# Build .pkg para distribuição via Workspace ONE (macOS)
# =============================================================================
# Uso: bash scripts/build-pkg.sh
# Saída: dist/hotmart-appsec-<version>.pkg
#
# Inclui o binário do opengrep (universal: arm64 + x86_64) no pacote.
# Se não conseguir baixar, tenta usar o binário local.
# =============================================================================

set -euo pipefail

VERSION="2.9.4"
PKG_ID="com.hotmart.appsec"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$PROJECT_DIR/dist/pkg-build"
OUTPUT_DIR="$PROJECT_DIR/dist"

R='\033[31m'; G='\033[32m'; Y='\033[33m'; B='\033[1m'; N='\033[0m'

echo -e "${B}${Y}▶ Building Hotmart AppSec .pkg v${VERSION}${N}"
echo ""

# Limpa build anterior
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/payload/Library/Application Support/Hotmart/appsec/bin"
mkdir -p "$BUILD_DIR/payload/Library/LaunchDaemons"
mkdir -p "$BUILD_DIR/scripts"
mkdir -p "$OUTPUT_DIR"

# ── Opengrep binary ─────────────────────────────────────────────────────────

echo -e "  ${Y}↓${N} Obtendo binário do opengrep..."

OPENGREP_BUNDLED="$BUILD_DIR/payload/Library/Application Support/Hotmart/appsec/bin/opengrep"

# Tenta baixar a release mais recente para arm64 (maioria dos Macs corporativos)
RELEASE_JSON="$(curl -fsSL --connect-timeout 15 "https://api.github.com/repos/opengrep/opengrep/releases/latest" 2>/dev/null || echo "")"

if [ -n "$RELEASE_JSON" ]; then
  # Asset name pattern: opengrep_osx_arm64
  DOWNLOAD_URL="$(echo "$RELEASE_JSON" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for a in data.get('assets', []):
    if a['name'] == 'opengrep_osx_arm64':
        print(a['browser_download_url'])
        break
" 2>/dev/null || echo "")"

  if [ -n "$DOWNLOAD_URL" ]; then
    curl -fsSL --connect-timeout 30 -o "$OPENGREP_BUNDLED" "$DOWNLOAD_URL" 2>/dev/null

    # Verificar assinatura se disponível
    SIG_URL="${DOWNLOAD_URL}.sig"
    CERT_URL="${DOWNLOAD_URL}.cert"
    if [ -f "$OPENGREP_BUNDLED" ] && [ -s "$OPENGREP_BUNDLED" ]; then
      echo -e "  ${G}✓${N} Download OK"
    else
      rm -f "$OPENGREP_BUNDLED"
    fi
  fi
fi

# Fallback: copiar o binário local se download falhou
if [ ! -f "$OPENGREP_BUNDLED" ] || [ ! -s "$OPENGREP_BUNDLED" ]; then
  LOCAL_OPENGREP="$(command -v opengrep 2>/dev/null || echo "")"
  if [ -n "$LOCAL_OPENGREP" ] && [ -x "$LOCAL_OPENGREP" ]; then
    echo -e "  ${Y}!${N} Download falhou — usando binário local: $LOCAL_OPENGREP"
    cp "$LOCAL_OPENGREP" "$OPENGREP_BUNDLED"
  else
    echo -e "  ${R}✗${N} AVISO: Não foi possível incluir opengrep no pacote"
    echo -e "    O install vai tentar baixar em runtime (precisa de internet)"
    rm -f "$OPENGREP_BUNDLED"
  fi
fi

if [ -f "$OPENGREP_BUNDLED" ]; then
  chmod +x "$OPENGREP_BUNDLED"
  OG_SIZE="$(du -h "$OPENGREP_BUNDLED" | awk '{print $1}')"
  echo -e "  ${G}✓${N} opengrep bundled (${OG_SIZE})"
fi

# ── Payload ─────────────────────────────────────────────────────────────────

echo -e "  ${G}✓${N} Copiando mdm-install.sh"
cp "$SCRIPT_DIR/mdm-install.sh" "$BUILD_DIR/payload/Library/Application Support/Hotmart/appsec/"

echo -e "  ${G}✓${N} Copiando mdm-watchdog.sh"
cp "$SCRIPT_DIR/mdm-watchdog.sh" "$BUILD_DIR/payload/Library/Application Support/Hotmart/appsec/"

echo -e "  ${G}✓${N} Copiando mdm-uninstall.sh"
cp "$SCRIPT_DIR/mdm-uninstall.sh" "$BUILD_DIR/payload/Library/Application Support/Hotmart/appsec/"

echo -e "  ${G}✓${N} Copiando LaunchDaemon plist"
cp "$SCRIPT_DIR/com.hotmart.appsec.watchdog.plist" "$BUILD_DIR/payload/Library/LaunchDaemons/"

# ── Bundled .vsix (para instalar sem internet/marketplace) ───────────────
VSIX_FILE="$(ls "$PROJECT_DIR"/cybersecurityextension-*.vsix 2>/dev/null | sort -V | tail -1)"
if [ -n "$VSIX_FILE" ] && [ -f "$VSIX_FILE" ]; then
  cp "$VSIX_FILE" "$BUILD_DIR/payload/Library/Application Support/Hotmart/appsec/extension.vsix"
  echo -e "  ${G}✓${N} Bundled .vsix ($(basename "$VSIX_FILE"))"
else
  echo -e "  ${Y}!${N} No .vsix found — extension will be installed from marketplace (requires internet)"
fi

# ── Post-install script ──────────────────────────────────────────────────────

echo -e "  ${G}✓${N} Gerando postinstall script"
cat > "$BUILD_DIR/scripts/postinstall" << 'EOF'
#!/bin/bash
# =============================================================================
# Post-Install — Hotmart AppSec
# =============================================================================
# Executado automaticamente pelo macOS Installer após copiar o payload.
# Ordem: opengrep (bundled) → mdm-install.sh (extensões) → watchdog daemon
# =============================================================================

# macOS Installer roda com PATH mínimo — garantir que /usr/local/bin está disponível
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

APPSEC_DIR="/Library/Application Support/Hotmart/appsec"
PLIST_SRC="/Library/LaunchDaemons/com.hotmart.appsec.watchdog.plist"
LOG="/Library/Logs/Hotmart/appsec-install.log"

mkdir -p "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1

echo "[$(date)] ===== Post-install started ====="
echo "[$(date)] Running as: $(whoami) | Console user: $(stat -f '%Su' /dev/console 2>/dev/null || echo 'unknown')"
echo "[$(date)] PATH=$PATH"

# 1. Permissões corretas
chmod +x "$APPSEC_DIR/mdm-install.sh"
chmod +x "$APPSEC_DIR/mdm-watchdog.sh"
[ -f "$APPSEC_DIR/mdm-uninstall.sh" ] && chmod +x "$APPSEC_DIR/mdm-uninstall.sh"
chmod 644 "$PLIST_SRC"
chown root:wheel "$PLIST_SRC"

# 2. Instalar opengrep bundled (se presente no pacote)
if [ -x "$APPSEC_DIR/bin/opengrep" ]; then
  echo "[$(date)] Installing bundled opengrep to /usr/local/bin..."
  mkdir -p /usr/local/bin
  cp "$APPSEC_DIR/bin/opengrep" /usr/local/bin/opengrep
  chmod +x /usr/local/bin/opengrep
  echo "[$(date)] ✓ opengrep installed: $(/usr/local/bin/opengrep --version 2>/dev/null || echo 'binary copied')"
fi

# 3. Executa instalação (extensões + hooks + pre-commit)
echo "[$(date)] Running mdm-install.sh..."
bash "$APPSEC_DIR/mdm-install.sh" 2>&1 || echo "[WARN] mdm-install.sh exited with code $?"

# 4. Descarrega daemon anterior se existir (idempotente)
launchctl unload "$PLIST_SRC" 2>/dev/null || true

# 5. Carrega o watchdog daemon
echo "[$(date)] Loading LaunchDaemon..."
launchctl load "$PLIST_SRC"

if launchctl list | grep -q "com.hotmart.appsec.watchdog"; then
  echo "[$(date)] ✓ Watchdog daemon active"
else
  echo "[$(date)] ✗ Watchdog daemon failed to load"
fi

echo "[$(date)] ===== Post-install complete ====="
exit 0
EOF

chmod +x "$BUILD_DIR/scripts/postinstall"

# ── Build .pkg ───────────────────────────────────────────────────────────────

echo ""
echo -e "${B}${Y}▶ Empacotando .pkg${N}"

pkgbuild \
  --identifier "$PKG_ID" \
  --version "$VERSION" \
  --root "$BUILD_DIR/payload" \
  --scripts "$BUILD_DIR/scripts" \
  --install-location / \
  "$OUTPUT_DIR/hotmart-appsec-${VERSION}.pkg"

PKG_SIZE="$(du -h "$OUTPUT_DIR/hotmart-appsec-${VERSION}.pkg" | awk '{print $1}')"

echo ""
echo -e "  ${G}${B}✓ Pacote gerado:${N} $OUTPUT_DIR/hotmart-appsec-${VERSION}.pkg (${PKG_SIZE})"
echo ""
echo -e "  ${B}Conteúdo:${N}"
echo -e "    • mdm-install.sh (instalação inicial)"
echo -e "    • mdm-watchdog.sh (persistência a cada 30min)"
echo -e "    • mdm-uninstall.sh (remoção completa)"
echo -e "    • com.hotmart.appsec.watchdog.plist (LaunchDaemon)"
[ -f "$OPENGREP_BUNDLED" ] && echo -e "    • opengrep binary (${OG_SIZE}, bundled)"
echo ""
echo -e "  ${B}Workspace ONE — Configuração:${N}"
echo -e "    ${Y}Install:${N}  Automático (postinstall no .pkg)"
echo -e "    ${Y}Update:${N}   Subir novo .pkg com versão incrementada"
echo -e "    ${Y}Uninstall:${N} Configurar Remove Script no Workspace ONE:"
echo -e "             sudo bash \"/Library/Application Support/Hotmart/appsec/mdm-uninstall.sh\""
echo ""
echo -e "  ${B}Próximos passos:${N}"
echo -e "  1. Suba o .pkg no Workspace ONE (Resources > Apps > Internal)"
echo -e "  2. Em 'Scripts' tab → Pre/Post Install: já embutido no .pkg"
echo -e "  3. Em 'Scripts' tab → Uninstall Script: cole o comando acima"
echo -e "  4. Assign para o Smart Group desejado"
echo ""

# Limpa build intermediário
rm -rf "$BUILD_DIR"
