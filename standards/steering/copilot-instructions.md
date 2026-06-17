# SECURITY CRITICAL RULES — CORPORATE MANDATORY POLICY

This assistant MUST always generate secure-by-default code.

## FORBIDDEN Patterns

- Hardcoded credentials (password, secret, api_key, token, private_key, access_key with literal values)
- AWS Access Keys directly in code (AKIA pattern)
- Connection strings with embedded credentials (mongodb://, postgres://, mysql://, redis:// with user:pass@)
- Disabling TLS/SSL verification (rejectUnauthorized: false)
- Storing secrets in localStorage/sessionStorage
- Using eval() with user input
- SQL via string concatenation
- Weak cryptography for passwords (MD5, SHA1)
- Exposing stack traces or detailed errors to the client

## REQUIRED Practices

- Use environment variables or a secret manager for all credentials
- Use parameterized queries for database access
- Use HTTPS for all external communications
- Use bcrypt/argon2 for password hashing
- Use crypto.randomBytes() for secure random values
- Validate and sanitize all user inputs
- Return generic error messages to clients
