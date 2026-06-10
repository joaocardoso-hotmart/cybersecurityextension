# 🛡️ Hotmart AppSec — Cybersecurity Extension

Extensão de segurança corporativa que protege o código em tempo real direto nas IDEs com IA.  
Distribuída automaticamente via MDM (Workspace ONE) para todas as máquinas de desenvolvedores.

---

## O que faz

- **Scan de código em tempo real** — Detecta vulnerabilidades enquanto você escreve (SAST via OpenGrep)
- **Proteção nas IDEs com IA** — Bloqueia prompts inseguros no Kiro, Cursor, Windsurf e Claude Code
- **Pre-commit advisory** — Avisa sobre vulnerabilidades antes do commit (sem bloquear)
- **Auto-deploy via MDM** — Instalação silenciosa e persistente sem ação do dev

---

## IDEs Suportadas

| IDE | Extensão | AI Gate | Rules |
|-----|----------|---------|-------|
| Kiro | ✅ | ✅ Steering + Hook | ✅ |
| VS Code | ✅ | — | — |
| Cursor | ✅ | ✅ appsec-gate.sh | ✅ .mdc |
| Windsurf | ✅ | ✅ appsec-gate.sh | ✅ |
| Claude Code | — | ✅ PreToolUse hook | ✅ |

---

## Vulnerabilidades Detectadas

| CWE | Categoria | Severidade |
|-----|-----------|------------|
| CWE-798 | Credenciais hardcoded | 🔴 ERROR |
| CWE-89 | SQL Injection | 🔴 ERROR |
| CWE-78 | Command Injection | 🔴 ERROR |
| CWE-79 | Cross-Site Scripting (XSS) | 🔴 ERROR |
| CWE-22 | Path Traversal | 🔴 ERROR |
| CWE-918 | Server-Side Request Forgery | 🔴 ERROR |
| CWE-327 | Criptografia fraca | 🟡 WARNING |
| CWE-295 | TLS desabilitado | 🔴 ERROR |
| CWE-922 | Tokens em localStorage | 🟡 WARNING |
| CWE-601 | Open Redirect | 🟡 WARNING |
| CWE-209 | Stack trace exposto | 🟡 WARNING |
| CWE-94 | Prototype Pollution | 🟡 WARNING |
| CWE-1333 | ReDoS | 🔴 ERROR |

---

## Estrutura do Repositório

```
.
├── src/                     # Código da extensão VS Code
│   ├── extension.ts         # Entry point da extensão
│   ├── scanner.ts           # Scanner de vulnerabilidades
│   ├── semgrep.ts           # Integração com OpenGrep/Semgrep
│   └── sidebar.ts           # Painel lateral da extensão
│
├── rules/
│   └── security.yml         # Regras SAST (OpenGrep/Semgrep format)
│
├── deploy/                  # Scripts de distribuição MDM
│   ├── macos/               # Instalador macOS (.pkg)
│   │   ├── build-pkg.sh     # Gera o .pkg para Workspace ONE
│   │   ├── mdm-install.sh   # Instalador principal
│   │   ├── mdm-watchdog.sh  # Daemon de persistência (30 min)
│   │   ├── mdm-uninstall.sh # Desinstalador completo
│   │   └── com.hotmart.appsec.watchdog.plist  # LaunchDaemon config
│   │
│   └── windows/             # Instalador Windows (.exe)
│       ├── build.cmd         # Gera o .exe via InnoSetup
│       ├── setup.iss         # InnoSetup script
│       ├── mdm-install.ps1   # Instalador principal
│       ├── mdm-watchdog.ps1  # Scheduled Task (30 min)
│       ├── mdm-uninstall.ps1 # Desinstalador completo
│       ├── build-win-installer.ps1  # Build alternativo (ZIP)
│       └── appsec-watchdog-task.xml # Task Scheduler config
│
├── media/                   # Ícones e assets
├── dist/                    # Artefatos gerados (não comitar)
├── .github/workflows/       # CI/CD (GitHub Actions)
└── .kiro/specs/             # Spec-Driven Documentation
    └── mdm-deployment/
        ├── requirements.md  # Requisitos do sistema (17 reqs)
        ├── design.md        # Arquitetura técnica
        └── tasks.md         # Plano de implementação
```

---

## Deploy via MDM

### macOS (Workspace ONE)

```bash
# Gera o .pkg (roda na máquina do dev)
bash deploy/macos/build-pkg.sh
# Saída: dist/hotmart-appsec-<version>.pkg
```

| Config no Workspace ONE | Valor |
|---|---|
| Package | `hotmart-appsec-X.Y.Z.pkg` |
| Install Context | Device |
| Uninstall Script | `sudo bash "/Library/Application Support/Hotmart/appsec/mdm-uninstall.sh"` |
| Detection | Receipt: `com.hotmart.appsec` |

### Windows (Workspace ONE)

```cmd
REM Gera o .exe (roda no Windows com InnoSetup instalado)
deploy\windows\build.cmd
REM Saída: dist\HotmartAppSec-Setup-<version>.exe
```

| Config no Workspace ONE | Valor |
|---|---|
| Install Command | `HotmartAppSec-Setup-X.Y.Z.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART` |
| Uninstall Command | `"C:\ProgramData\Hotmart\appsec\unins000.exe" /VERYSILENT` |
| Detection | Registry: `HKLM\SOFTWARE\Hotmart\AppSec\Version` |

---

## Como funciona

```
┌──────────────────────────────────────────────────────────┐
│                    Workspace ONE                           │
│            (distribui .pkg / .exe silenciosamente)         │
└───────────────────────────┬──────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────┐
│                  Post-Install Script                       │
│   1. Instala opengrep (bundled, sem internet)             │
│   2. Detecta IDEs instaladas                              │
│   3. Instala extensão do marketplace                      │
│   4. Configura steering/rules/hooks por IDE               │
│   5. Instala pre-commit hooks nos repos                   │
│   6. Ativa watchdog (LaunchDaemon / Scheduled Task)       │
└──────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────┐
│                  Watchdog (a cada 30 min)                  │
│   • Verifica se opengrep está instalado                   │
│   • Verifica se extensões estão nas IDEs                  │
│   • Restaura configs se removidos                         │
│   • CPU mínima (nice 19 / Below Normal)                   │
└──────────────────────────────────────────────────────────┘
```

---

## Segurança

### Certificate Pinning (Supply Chain Protection)

O instalador opera em redes com proxy SSL corporativo (Zscaler).  
Para evitar supply chain attacks, o certificado é validado por **SHA-256 fingerprint pinning**:

1. Busca o certificado pelo CN exato no cert store do sistema
2. Calcula o SHA-256 do certificado encontrado
3. Compara com o fingerprint hardcoded no script
4. Se não bater → **recusa** e loga alerta de segurança
5. Se não existir (sem proxy) → ignora e instala normalmente

### Princípios

- **Zero internet no install** — opengrep bundled no pacote
- **Advisory-only** — pre-commit nunca bloqueia commits
- **Idempotente** — rodar múltiplas vezes produz o mesmo resultado
- **Graceful degradation** — se uma IDE não é encontrada, continua com as outras
- **Clean removal** — uninstall remove 100% dos artefatos

---

## Spec-Driven Documentation

Este projeto segue um modelo **spec-driven** — toda mudança deve respeitar os documentos em `.kiro/specs/mdm-deployment/`:

| Documento | O que contém |
|-----------|-------------|
| [`requirements.md`](.kiro/specs/mdm-deployment/requirements.md) | 17 requisitos com acceptance criteria (formato EARS) |
| [`design.md`](.kiro/specs/mdm-deployment/design.md) | Arquitetura, componentes, modelos de dados, fluxos |
| [`tasks.md`](.kiro/specs/mdm-deployment/tasks.md) | Plano de implementação com dependency graph |

**Para contribuir:**
1. Leia o `requirements.md` para entender o que o sistema faz
2. Consulte o `design.md` para entender como funciona
3. Siga o `tasks.md` para implementar mudanças

---

## Desenvolvimento

```bash
# Instalar dependências
npm install

# Compilar a extensão
npm run compile

# Lint
npm run lint
```

### Testar localmente (macOS)

```bash
# Instalar manualmente (sem MDM)
sudo bash deploy/macos/mdm-install.sh

# Verificar estado
opengrep --version
kiro --list-extensions | grep -i hotmart
```

### Logs

| Plataforma | Caminho |
|---|---|
| macOS | `/Library/Logs/Hotmart/appsec-install.log` |
| macOS | `/Library/Logs/Hotmart/appsec-watchdog.log` |
| Windows | `C:\ProgramData\Hotmart\logs\appsec-install.log` |
| Windows | `C:\ProgramData\Hotmart\logs\appsec-watchdog.log` |

---

## Licença

Proprietary — Hotmart Cybersecurity Team
