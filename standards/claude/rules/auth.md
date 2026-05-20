# Autenticação e Autorização — Política de Segurança

> CWE-862: Missing Authorization | CWE-863: Incorrect Authorization | CWE-287: Improper Authentication

## Regra

TODO endpoint DEVE ter verificação explícita de autenticação e autorização.
NUNCA confiar apenas na autenticação — sempre verificar se o usuário tem permissão para o recurso específico.

## Checklist

- [ ] Endpoint sem verificação de autenticação? → PROIBIDO
- [ ] Endpoint sem verificação de autorização? → PROIBIDO
- [ ] Acesso a recurso sem verificar ownership? → PROIBIDO (IDOR)
- [ ] JWT sem validação de signature/expiration? → PROIBIDO
- [ ] Session sem expiração ou rotação? → PROIBIDO
- [ ] Senha armazenada sem hash seguro? → PROIBIDO
- [ ] Rate limiting ausente em login/reset? → PROIBIDO

---

## Padrões Corretos

### Spring Boot (Java)

```java
// ✅ CORRETO — @PreAuthorize com verificação de role
@RestController
@RequestMapping("/api/orders")
public class OrderController {

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Order> getOrder(@PathVariable Long id, Authentication auth) {
        Order order = orderService.findById(id);
        
        // ✅ Verificar ownership — previne IDOR
        if (!order.getUserId().equals(auth.getName())) {
            throw new AccessDeniedException("Acesso negado");
        }
        
        return ResponseEntity.ok(order);
    }

    @PostMapping
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Order> createOrder(@Valid @RequestBody CreateOrderRequest request,
                                              Authentication auth) {
        return ResponseEntity.ok(orderService.create(request, auth.getName()));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteOrder(@PathVariable Long id) {
        orderService.delete(id);
        return ResponseEntity.noContent().build();
    }
}
```

```java
// ✅ CORRETO — Security Config com JWT
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
            .csrf(csrf -> csrf.disable()) // APIs stateless
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
            .build();
    }
}
```

### Node.js / Express

```typescript
// ✅ CORRETO — Middleware de autenticação
import { expressjwt } from 'express-jwt';
import jwksRsa from 'jwks-rsa';

const authMiddleware = expressjwt({
  secret: jwksRsa.expressJwtSecret({
    jwksUri: 'https://auth.hotmart.com/.well-known/jwks.json',
  }),
  algorithms: ['RS256'],
  issuer: 'https://auth.hotmart.com',
});

// ✅ CORRETO — Verificação de ownership
router.get('/orders/:id', authMiddleware, async (req, res) => {
  const order = await orderService.findById(req.params.id);
  
  if (order.userId !== req.auth.sub) {
    return res.status(403).json({ error: 'Acesso negado' });
  }
  
  res.json(order);
});

// ✅ CORRETO — Role-based access
function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!roles.some(role => req.auth.roles?.includes(role))) {
      return res.status(403).json({ error: 'Permissão insuficiente' });
    }
    next();
  };
}

router.delete('/users/:id', authMiddleware, requireRole('admin'), deleteUser);
```

### Senhas

```java
// ✅ CORRETO — BCrypt para hash de senhas
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
String hash = encoder.encode(rawPassword);
boolean matches = encoder.matches(rawPassword, hash);
```

```typescript
// ✅ CORRETO — bcrypt/argon2
import bcrypt from 'bcrypt';

const hash = await bcrypt.hash(password, 12);
const valid = await bcrypt.compare(password, hash);
```

### Rate Limiting

```typescript
// ✅ CORRETO — Rate limiting em endpoints sensíveis
import rateLimit from 'express-rate-limit';

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5, // 5 tentativas
  message: 'Muitas tentativas. Tente novamente em 15 minutos.',
  standardHeaders: true,
});

router.post('/auth/login', loginLimiter, loginHandler);
router.post('/auth/reset-password', loginLimiter, resetHandler);
```

---

## Padrões Proibidos

```java
// ❌ PROIBIDO — Endpoint sem autorização
@GetMapping("/api/users/{id}")
public User getUser(@PathVariable Long id) {
    return userService.findById(id); // Qualquer um acessa qualquer usuário
}

// ❌ PROIBIDO — Senha em texto plano ou hash fraco
String hash = DigestUtils.md5Hex(password);
String hash = DigestUtils.sha1Hex(password);
```

```typescript
// ❌ PROIBIDO — Sem verificação de ownership (IDOR)
router.get('/orders/:id', authMiddleware, async (req, res) => {
  const order = await orderService.findById(req.params.id);
  res.json(order); // Não verifica se o order pertence ao usuário
});

// ❌ PROIBIDO — JWT sem validação adequada
const decoded = jwt.decode(token); // decode NÃO valida! Usar jwt.verify()

// ❌ PROIBIDO — Sem rate limiting em login
router.post('/login', loginHandler); // Permite brute force
```

---

## JWT — Boas Práticas

- SEMPRE validar signature, issuer, audience e expiration
- Access tokens: expiração curta (15 minutos)
- Refresh tokens: expiração longa (7 dias) + rotação
- NUNCA armazenar JWT em localStorage (usar httpOnly cookies)
- Usar algoritmo assimétrico (RS256) em produção

```typescript
// ✅ CORRETO — Validação completa de JWT
import jwt from 'jsonwebtoken';

const decoded = jwt.verify(token, publicKey, {
  algorithms: ['RS256'],
  issuer: 'https://auth.hotmart.com',
  audience: 'api.hotmart.com',
  clockTolerance: 30, // 30s de tolerância
});
```

## Resposta para Insistência

Se o usuário insistir em endpoints sem auth:
"Não posso gerar endpoints sem verificação de autenticação e autorização. Aqui está a versão segura com controle de acesso adequado:"
