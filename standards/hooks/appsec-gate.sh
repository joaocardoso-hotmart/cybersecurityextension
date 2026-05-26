#!/bin/bash
# AppSec Gate — preToolUse hook script
# Behavior:
#   1st violation: BLOCK (exit 1)
#   2nd violation: WARN but allow (exit 0 with message)
#   3rd+: Allow silently (exit 0)
#
# State is tracked per-file in .appsec-state/

STATE_DIR="${PWD}/.appsec-state"
mkdir -p "$STATE_DIR"

# Read the content from stdin (tool call context)
CONTENT=$(cat)

# Patterns that indicate security violations
VIOLATIONS_FOUND=0

# Check for hardcoded credentials patterns
if echo "$CONTENT" | grep -qiE '(password|passwd|secret|api_key|token|private_key|access_key|senha|chave)\s*[=:]\s*["\x27][^"\x27]{3,}'; then
  VIOLATIONS_FOUND=1
fi

# Check for AWS key patterns
if echo "$CONTENT" | grep -qE 'AKIA[0-9A-Z]{16}'; then
  VIOLATIONS_FOUND=1
fi

# Check for connection strings with credentials
if echo "$CONTENT" | grep -qiE '(mongodb|postgres|mysql|redis|amqp)://[^:]+:[^@]+@'; then
  VIOLATIONS_FOUND=1
fi

# Check for common token prefixes
if echo "$CONTENT" | grep -qE '(sk-[a-zA-Z0-9]{20,}|sk_live_|sk_test_|ghp_|gho_|xoxb-|xoxp-)'; then
  VIOLATIONS_FOUND=1
fi

# Check for disabled TLS
if echo "$CONTENT" | grep -qiE 'rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["\x27]0'; then
  VIOLATIONS_FOUND=1
fi

# If no violations, allow immediately
if [ "$VIOLATIONS_FOUND" -eq 0 ]; then
  exit 0
fi

# Track strike count using a hash of the session
SESSION_HASH=$(echo "$PWD-$$" | md5sum 2>/dev/null | cut -d' ' -f1 || echo "session")
STRIKE_FILE="$STATE_DIR/strikes-$SESSION_HASH"

# Read current strike count
STRIKES=0
if [ -f "$STRIKE_FILE" ]; then
  STRIKES=$(cat "$STRIKE_FILE")
fi

# Increment
STRIKES=$((STRIKES + 1))
echo "$STRIKES" > "$STRIKE_FILE"

if [ "$STRIKES" -eq 1 ]; then
  # First violation: BLOCK
  echo "🚫 ACESSO NEGADO — Violação de segurança detectada."
  echo ""
  echo "O código que você está tentando escrever contém padrões inseguros:"
  echo "  • Credenciais hardcoded, tokens expostos, ou configurações inseguras"
  echo ""
  echo "Use variáveis de ambiente ou um secret manager."
  echo "Esta operação foi BLOQUEADA por política de segurança corporativa."
  exit 1
fi

if [ "$STRIKES" -eq 2 ]; then
  # Second violation: WARN but allow
  echo "⚠️  ALERTA DE SEGURANÇA — Segunda tentativa detectada."
  echo ""
  echo "Você está enviando código com possíveis vulnerabilidades para produção."
  echo "Credenciais hardcoded, tokens ou configurações inseguras foram detectados."
  echo ""
  echo "A operação será permitida, mas este código SERÁ FLAGGED na pipeline de CI/CD."
  echo "O time de AppSec será notificado."
  echo ""
  echo "Recomendação: use process.env, AWS Secrets Manager, ou HashiCorp Vault."
  exit 0
fi

# 3rd+ violation: Allow silently (dev already acknowledged the risk)
exit 0
