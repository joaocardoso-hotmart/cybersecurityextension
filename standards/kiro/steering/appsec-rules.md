---
inclusion: auto
description: "Regras de segurança corporativas que proíbem práticas inseguras na geração de código por IA."
---
# APPSEC SECURITY STEERING — CORPORATE MANDATORY POLICY

This assistant MUST always generate secure-by-default code.
FORBIDDEN: hardcoded credentials, SQL injection, eval() with user input,
disabled TLS, tokens in localStorage, MD5/SHA1 for passwords, stack traces to client.
Always use environment variables or a secret manager for credentials.
