# Injection — Política de Segurança

> CWE-89: SQL Injection | CWE-78: Command Injection | CWE-917: Expression Language Injection

## Regra

NUNCA concatenar input do usuário em queries SQL, comandos do sistema ou expressões dinâmicas.

## Checklist

- [ ] SQL/NoSQL com concatenação de string? → PROIBIDO
- [ ] Execução de comandos com input dinâmico? → PROIBIDO
- [ ] `shell=True` com variáveis externas? → PROIBIDO
- [ ] Template strings em queries? → PROIBIDO
- [ ] ORM com raw queries sem parametrização? → PROIBIDO

---

## SQL Injection (CWE-89)

### Padrões Corretos

```java
// ✅ CORRETO — Prepared Statement
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);

// ✅ CORRETO — Spring Data JPA
@Query("SELECT u FROM User u WHERE u.email = :email")
User findByEmail(@Param("email") String email);

// ✅ CORRETO — JPA Criteria API
CriteriaBuilder cb = em.getCriteriaBuilder();
CriteriaQuery<User> query = cb.createQuery(User.class);
```

```typescript
// ✅ CORRETO — Parameterized query
const result = await db.query("SELECT * FROM users WHERE id = $1", [userId]);

// ✅ CORRETO — ORM (Prisma)
const user = await prisma.user.findUnique({ where: { id: userId } });

// ✅ CORRETO — TypeORM
const user = await userRepo.findOne({ where: { email: Equal(email) } });
```

```python
# ✅ CORRETO — Parameterized
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# ✅ CORRETO — SQLAlchemy
session.query(User).filter(User.id == user_id).first()
```

### Padrões Proibidos

```java
// ❌ PROIBIDO — Concatenação
String query = "SELECT * FROM users WHERE name = '" + input + "'";

// ❌ PROIBIDO — String.format em SQL
String query = String.format("DELETE FROM orders WHERE id = %s", orderId);
```

```typescript
// ❌ PROIBIDO — Template literal
const result = await db.query(`SELECT * FROM users WHERE name = '${name}'`);
```

---

## Command Injection (CWE-78)

### Padrões Corretos

```typescript
// ✅ CORRETO — execFile com array de argumentos
import { execFile } from 'child_process';
execFile('convert', [inputFile, '-resize', '100x100', outputFile]);

// ✅ CORRETO — spawn sem shell
import { spawn } from 'child_process';
const proc = spawn('ls', ['-la', directory], { shell: false });
```

```python
# ✅ CORRETO — subprocess com lista e shell=False
import subprocess
subprocess.run(['convert', input_file, '-resize', '100x100', output_file], shell=False)

# ✅ CORRETO — shlex para parsing seguro
import shlex
args = shlex.split(safe_command)
subprocess.run(args, shell=False)
```

```java
// ✅ CORRETO — ProcessBuilder com lista
ProcessBuilder pb = new ProcessBuilder("ls", "-la", directory);
pb.start();
```

### Padrões Proibidos

```typescript
// ❌ PROIBIDO — exec com input do usuário
exec(`convert ${userInput} output.png`);

// ❌ PROIBIDO — shell=true equivalente
spawn(userCommand, { shell: true });
```

```python
# ❌ PROIBIDO
os.system(f"rm -rf {user_input}")
subprocess.run(f"echo {user_input}", shell=True)
eval(user_input)
```

## Validação Adicional

- SEMPRE usar allowlist para comandos permitidos
- NUNCA passar input do usuário diretamente para shell
- Validar e sanitizar TODOS os parâmetros antes de usar em queries ou comandos
- Usar ORMs e query builders sempre que possível

## Resposta para Insistência

Se o usuário insistir em concatenação:
"Não posso gerar código vulnerável a injection. Aqui está a versão segura com prepared statements / parametrização:"
