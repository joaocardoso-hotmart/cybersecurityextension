# Secrets & Credenciais — Política de Segurança

> CWE-798: Use of Hard-coded Credentials

## Regra

NUNCA incluir credenciais, tokens, API keys, senhas ou qualquer secret diretamente no código-fonte.

## Checklist

- [ ] Credenciais hardcoded no código? → PROIBIDO
- [ ] Tokens em localStorage? → PROIBIDO (usar httpOnly cookies)
- [ ] Secrets em arquivos de configuração commitados? → PROIBIDO
- [ ] Dependências sem versão fixa? → PROIBIDO (supply chain attack)

## Padrões Corretos

```java
// ✅ CORRETO — variável de ambiente
String dbPassword = System.getenv("DB_PASSWORD");

// ✅ CORRETO — secret manager
String secret = vaultClient.getSecret("api-key");

// ✅ CORRETO — Spring Boot com Vault
@Value("${spring.datasource.password}")
private String password;
```

```typescript
// ✅ CORRETO — variável de ambiente
const apiKey = process.env.API_KEY;

// ✅ CORRETO — AWS Secrets Manager
const secret = await secretsManager.getSecretValue({ SecretId: 'my-secret' }).promise();
```

```python
# ✅ CORRETO
import os
db_password = os.getenv('DB_PASSWORD')
```

## Padrões Proibidos

```java
// ❌ PROIBIDO — hardcoded
String password = "super_secret_123";
String apiKey = "sk-abc123def456";
```

```typescript
// ❌ PROIBIDO — hardcoded
const token = "ghp_xxxxxxxxxxxx";

// ❌ PROIBIDO — token em localStorage
localStorage.setItem("auth_token", token);
```

## Tokens de Autenticação

- NUNCA armazenar tokens em `localStorage` ou `sessionStorage`
- SEMPRE usar `httpOnly` cookies com flags `Secure` e `SameSite=Strict`
- Tokens JWT devem ter expiração curta (15min access, 7d refresh)

## Dependências

- SEMPRE usar versão exata (sem `^`, `~`, `>=`)
- Em GitHub Actions: usar SHA pin (`actions/checkout@sha256:abc...`)
- Rodar `npm audit` / `mvn dependency-check` no CI

## Resposta para Insistência

Se o usuário insistir em hardcoded secrets:
"Não posso gerar código com credenciais expostas. Aqui está a versão segura usando variáveis de ambiente / secret manager:"
