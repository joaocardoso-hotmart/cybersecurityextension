---
inclusion: fileMatch
fileMatchPattern: "**/*hook*,**/*pre-commit*,**/*pre-push*,**/appsec-gate*"
description: "Padrões obrigatórios para scripts de git hooks — garante compatibilidade com nomes de arquivo Unicode."
---
# Git Hooks — Padrões Obrigatórios

## Regra: core.quotePath=false em comandos git

Ao listar ou processar nomes de arquivos via `git diff`, `git ls-files`, ou qualquer outro comando git dentro de hooks/scripts, **sempre** usar `git -c core.quotePath=false` para evitar escape de caracteres Unicode.

### Problema
O git por padrão escapa caracteres non-ASCII (acentos, cedilha, etc.) nos nomes de arquivo usando octais entre aspas. Exemplo:
- Nome real: `TesteExtensão.js`
- Saída escapada: `"TesteExtens\303\243o.js"`

Isso quebra qualquer `grep` ou filtro que dependa da extensão do arquivo (ex: `\.js$` não faz match com `...js"`).

### Padrão correto

```bash
# ✅ CORRETO — sempre usar core.quotePath=false
STAGED_FILES=$(git -c core.quotePath=false diff --cached --name-only --diff-filter=ACMR | grep -iE '\.(ts|tsx|js|jsx|java|py|go|rb|php)$')

# ❌ ERRADO — vai escapar nomes com acentos/unicode
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACMR | grep -iE '\.(ts|tsx|js|jsx|java|py|go|rb|php)$')
```

### Checklist para todo hook que lista arquivos

1. Usar `git -c core.quotePath=false` em qualquer comando que retorna paths
2. Se usar `git diff --name-only`, adicionar a flag
3. Se usar `git ls-files`, adicionar a flag
4. Se usar `git status --porcelain`, considerar `--no-renames` também
5. Testar com arquivos que tenham acentos no nome (é, ã, ç, ñ, ü)

### Aplicação

Esta regra se aplica a:
- `.git/hooks/pre-commit`
- `.appsec/appsec-gate.sh`
- `standards/hooks/appsec-gate.sh`
- Qualquer script que processe output de comandos git contendo file paths
