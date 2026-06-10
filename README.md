# 🛡️ Hotmart Cybersecurity Extension

**Security standards, delivered where developers work.**

A extensão centraliza e distribui padrões de segurança diretamente nas IDEs e AI coding assistants, garantindo que todo código produzido (por humanos ou por IA) siga as guidelines de AppSec da Hotmart desde o primeiro keystroke.

---

## O que a extensão faz

### Distribuição de Padrões

- **Steering files** — Regras de segurança injetadas automaticamente no contexto de AI assistants (Visual Studio, Kiro, Cursor, Copilot)
- **Skills** — Instruções especializadas para que LLMs apliquem práticas seguras (input validation, auth patterns, secrets handling)
- **Guidelines de AppSec** — Checklists e padrões corporativos acessíveis sem sair do editor

### Secure-by-Default

- Templates e snippets com padrões seguros pré-configurados
- Validação de input, output encoding e parameterized queries como padrão
- Configurações de segurança aplicadas automaticamente em novos projetos

### Bootstrap de Projetos

- Configuração automática de steering files para AI IDEs
- Estrutura de segurança pronta para novos repositórios
- Integração com pipelines de CI/CD security checks

### Governança Técnica

- Versionamento de padrões corporativos de segurança
- Atualização centralizada — um push atualiza todos os projetos
- Rastreabilidade de qual versão dos padrões cada projeto utiliza

---

## Compatibilidade

| Plataforma | Suporte |
|------------|---------|
| VS Code | ✅ |
| Kiro | ✅ |
| Cursor | ✅ |
| GitHub Copilot | ✅ |

---

## Instalação

### Via Marketplace

1. Abra o VS Code / Kiro / Cursor
2. Vá em **Extensions** (`Ctrl+Shift+X` / `Cmd+Shift+X`)
3. Busque por **Hotmart Cybersecurity**
4. Clique em **Install**

### Via CLI

```bash
code --install-extension HotmartCybersecurity.cybersecurityextension
```

---

## Quick Start

Após instalar, abra a paleta de comandos (`Ctrl+Shift+P` / `Cmd+Shift+P`) e execute:

| Comando | O que faz |
|---------|-----------|
| `Cybersecurity: Bootstrap Project` | Configura steering files e padrões de segurança no projeto atual |
| `Cybersecurity: Update Standards` | Atualiza para a versão mais recente dos padrões |
| `Cybersecurity: Show Guidelines` | Exibe as guidelines de AppSec aplicáveis ao contexto |

---

## Como funciona

```
┌─────────────────────────────────────────────────┐
│           Hotmart Cybersecurity Extension        │
├─────────────────────────────────────────────────┤
│                                                 │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐   │
│  │  Steering │  │   Skills  │  │ Templates │   │
│  │   Files   │  │    .md    │  │ & Snippets│   │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘   │
│        │               │               │        │
│        ▼               ▼               ▼        │
│  ┌─────────────────────────────────────────┐    │
│  │         Project Workspace               │    │
│  │  .kiro/steering/ · .cursor/rules/ ·     │    │
│  │  .github/copilot/ · .vscode/            │    │
│  └─────────────────────────────────────────┘    │
│                                                 │
└─────────────────────────────────────────────────┘
```

A extensão atua como uma **camada de distribuição centralizada**: os padrões são mantidos e versionados no repositório da extensão, e entregues automaticamente nos diretórios que cada AI IDE espera.

---

## Padrões Distribuídos

Os padrões cobrem áreas críticas de segurança:

- **Autenticação e Autorização** — OAuth, JWT validation, session management
- **Input Validation** — Sanitização, encoding, type checking
- **Secrets Management** — Detecção de hardcoded secrets, vault patterns
- **API Security** — Rate limiting, CORS, authentication headers
- **Data Protection** — Encryption at rest/transit, PII handling
- **Dependency Security** — Supply chain, version pinning, vulnerability checks
- **Infrastructure** — Least privilege IAM, network segmentation, logging

---

## Contribuindo

Os padrões de segurança são mantidos pelo time de Cybersecurity. Para sugerir alterações:

1. Abra uma issue descrevendo a mudança proposta
2. Submeta um PR com a alteração no padrão
3. O time de AppSec revisa e aprova

---

## Licença

MIT — veja [LICENSE](LICENSE).

---

## Estrutura do Projeto

```
cybersecurityextension/
├── .github/workflows/     # CI/CD (publish, appsec-guard)
├── .kiro/                 # Kiro steering & hooks (this repo's config)
│   ├── hooks/
│   └── steering/
├── media/                 # Icons e assets
├── rules/                 # Regras SAST (opengrep/semgrep)
│   └── security.yml
├── scripts/               # MDM deployment scripts
│   ├── mdm-install.sh     # macOS/Linux installer
│   ├── mdm-install.ps1    # Windows installer  
│   ├── mdm-watchdog.sh    # macOS persistence daemon
│   ├── mdm-watchdog.ps1   # Windows persistence task
│   ├── com.hotmart.appsec.watchdog.plist  # macOS LaunchDaemon
│   └── appsec-watchdog-task.xml           # Windows Task Scheduler
├── src/                   # Extension source code
│   ├── extension.ts
│   ├── scanner.ts
│   ├── semgrep.ts
│   └── sidebar.ts
├── package.json
└── README.md
```

---

## MDM Deployment

A extensão pode ser instalada de forma forçada via MDM (Jamf, Intune, etc).

### macOS

```bash
# 1. Deploy scripts
sudo mkdir -p "/Library/Application Support/Hotmart/appsec"
sudo cp mdm-watchdog.sh "/Library/Application Support/Hotmart/appsec/"
sudo cp com.hotmart.appsec.watchdog.plist /Library/LaunchDaemons/

# 2. Set permissions
sudo chmod 644 /Library/LaunchDaemons/com.hotmart.appsec.watchdog.plist
sudo chown root:wheel /Library/LaunchDaemons/com.hotmart.appsec.watchdog.plist

# 3. Load daemon
sudo launchctl load /Library/LaunchDaemons/com.hotmart.appsec.watchdog.plist

# 4. Initial install
sudo bash mdm-install.sh
```

### Windows

```powershell
# 1. Deploy scripts
New-Item -ItemType Directory -Path "C:\ProgramData\Hotmart\appsec" -Force
Copy-Item mdm-watchdog.ps1 "C:\ProgramData\Hotmart\appsec\"
Copy-Item appsec-watchdog-task.xml "C:\ProgramData\Hotmart\appsec\"

# 2. Register task
schtasks /Create /XML "C:\ProgramData\Hotmart\appsec\appsec-watchdog-task.xml" /TN "Hotmart\AppSecWatchdog" /F

# 3. Initial install
powershell -ExecutionPolicy Bypass -File mdm-install.ps1
```

O watchdog garante que a extensão permaneça instalada e as configurações de segurança não sejam alteradas pelo desenvolvedor.

### IDEs Suportadas pelo MDM

| IDE | Extension | Steering/Rules | Hooks |
|-----|-----------|----------------|-------|
| Kiro | ✅ | ✅ | ✅ |
| VS Code | ✅ | — | — |
| Cursor | ✅ | ✅ | ✅ |
| Windsurf | ✅ | ✅ | ✅ |
| Claude Code | — | ✅ | ✅ |
