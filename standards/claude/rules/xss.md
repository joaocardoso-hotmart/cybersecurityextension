# Cross-Site Scripting (XSS) — Política de Segurança

> CWE-79: Improper Neutralization of Input During Web Page Generation

## Regra

NUNCA inserir dados não sanitizados em contextos HTML, JavaScript ou atributos DOM.

## Checklist

- [ ] `innerHTML` com dados dinâmicos? → PROIBIDO
- [ ] `document.write()` com input externo? → PROIBIDO
- [ ] `dangerouslySetInnerHTML` sem sanitização? → PROIBIDO
- [ ] Output sem encoding em templates server-side? → PROIBIDO
- [ ] URLs dinâmicas sem validação de scheme? → PROIBIDO (`javascript:` XSS)
- [ ] CORS wildcard? → PROIBIDO
- [ ] CSP ausente ou insegura (`unsafe-inline`, `unsafe-eval`)? → PROIBIDO

---

## Padrões Corretos

### Frontend (React/TypeScript)

```tsx
// ✅ CORRETO — React escapa automaticamente
function UserGreeting({ name }: { name: string }) {
  return <h1>Olá, {name}</h1>;
}

// ✅ CORRETO — DOMPurify quando HTML é necessário
import DOMPurify from 'dompurify';

function RichContent({ html }: { html: string }) {
  const clean = DOMPurify.sanitize(html, { ALLOWED_TAGS: ['b', 'i', 'a', 'p'] });
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}

// ✅ CORRETO — textContent para texto puro
const el = document.getElementById('output');
el.textContent = userInput; // Seguro — não interpreta HTML
```

### Frontend (Vanilla JS)

```javascript
// ✅ CORRETO — textContent
document.getElementById('name').textContent = userData.name;

// ✅ CORRETO — setAttribute para atributos
link.setAttribute('href', validatedUrl);

// ✅ CORRETO — DOMPurify para HTML dinâmico
import DOMPurify from 'dompurify';
container.innerHTML = DOMPurify.sanitize(untrustedHtml);
```

### Backend (Java/Spring)

```java
// ✅ CORRETO — Thymeleaf escapa por padrão com th:text
<span th:text="${userInput}">safe</span>

// ✅ CORRETO — OWASP Java Encoder
import org.owasp.encoder.Encode;
String safe = Encode.forHtml(userInput);
String safeJs = Encode.forJavaScript(userInput);
String safeUrl = Encode.forUriComponent(userInput);
```

### Backend (Node.js)

```typescript
// ✅ CORRETO — escape-html
import escapeHtml from 'escape-html';
const safe = escapeHtml(userInput);

// ✅ CORRETO — helmet para headers de segurança
import helmet from 'helmet';
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    }
  }
}));
```

---

## Padrões Proibidos

```typescript
// ❌ PROIBIDO — innerHTML com dados do usuário
element.innerHTML = userInput;
element.innerHTML = `<div>${response.data}</div>`;

// ❌ PROIBIDO — document.write
document.write(userData);

// ❌ PROIBIDO — dangerouslySetInnerHTML sem sanitização
<div dangerouslySetInnerHTML={{ __html: userContent }} />

// ❌ PROIBIDO — eval com dados externos
eval(userScript);
new Function(userCode)();

// ❌ PROIBIDO — URL sem validação de scheme
<a href={userUrl}>Link</a>  // pode ser javascript:alert(1)
```

```java
// ❌ PROIBIDO — output sem encoding
response.getWriter().write(userInput);

// ❌ PROIBIDO — Thymeleaf unescaped
<span th:utext="${userInput}">unsafe</span>
```

---

## CORS e CSP

### CORS

```typescript
// ✅ CORRETO — origins específicos
app.use(cors({
  origin: ['https://app.hotmart.com', 'https://admin.hotmart.com'],
  credentials: true,
}));

// ❌ PROIBIDO — wildcard
app.use(cors({ origin: '*' }));
```

### Content Security Policy

```typescript
// ✅ CORRETO — CSP restritiva
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'nonce-abc123'"],
    objectSrc: ["'none'"],
    baseUri: ["'self'"],
  }
}));
```

---

## Validação de URLs

```typescript
// ✅ CORRETO — validar scheme antes de usar em href/src
function isSafeUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return ['https:', 'http:'].includes(parsed.protocol);
  } catch {
    return false;
  }
}
```

## Resposta para Insistência

Se o usuário insistir em innerHTML sem sanitização:
"Não posso gerar código vulnerável a XSS. Aqui está a versão segura com DOMPurify / textContent / output encoding:"
