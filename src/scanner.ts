import * as vscode from 'vscode';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface SecurityFinding {
	id: string;
	severity: Severity;
	title: string;
	description: string;
	cwe: string;
	file: string;
	line: number;
	column: number;
	snippet: string;
	suggestion: string;
}

interface ScanRule {
	id: string;
	severity: Severity;
	title: string;
	cwe: string;
	pattern: RegExp;
	description: string;
	suggestion: string;
	filePatterns?: RegExp[];
}

const SCAN_RULES: ScanRule[] = [
	// CWE-798: Hardcoded Credentials
	{
		id: 'HARDCODED_SECRET',
		severity: 'critical',
		title: 'Credencial hardcoded detectada',
		cwe: 'CWE-798',
		pattern: /(?:password|passwd|secret|api_key|apikey|token|private_key)\s*[:=]\s*['"][^'"]{3,}['"]/i,
		description: 'Credenciais ou secrets não devem ser hardcoded no código-fonte.',
		suggestion: 'Use variáveis de ambiente (process.env.SECRET) ou um secret manager (Vault, AWS Secrets Manager).',
		filePatterns: [/\.(ts|js|tsx|jsx|java|py|rb|go|php|yaml|yml|json|properties|env\.example)$/i],
	},
	// CWE-89: SQL Injection
	{
		id: 'SQL_INJECTION',
		severity: 'critical',
		title: 'Possível SQL Injection',
		cwe: 'CWE-89',
		pattern: /(?:query|execute|exec|raw)\s*\(\s*[`'"](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)[\s\S]*?\$\{|(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\+\s*(?:req\.|input|param|args|user)/i,
		description: 'Concatenação de input do usuário em queries SQL permite injeção de código.',
		suggestion: 'Use prepared statements ou parameterized queries. Ex: db.query("SELECT * FROM users WHERE id = $1", [userId])',
	},
	// CWE-79: XSS
	{
		id: 'XSS_INNERHTML',
		severity: 'high',
		title: 'Possível XSS via innerHTML',
		cwe: 'CWE-79',
		pattern: /\.innerHTML\s*=\s*(?!['"`]\s*['"`]).*(?:input|param|req|user|data|response|result|value)/i,
		description: 'Uso de innerHTML com dados dinâmicos pode permitir Cross-Site Scripting.',
		suggestion: 'Use textContent para texto puro ou DOMPurify.sanitize() para HTML. Em React, evite dangerouslySetInnerHTML.',
	},
	{
		id: 'XSS_DANGEROUSLY',
		severity: 'high',
		title: 'Possível XSS via dangerouslySetInnerHTML',
		cwe: 'CWE-79',
		pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/,
		description: 'dangerouslySetInnerHTML injeta HTML sem sanitização.',
		suggestion: 'Sanitize o conteúdo com DOMPurify.sanitize() antes de usar dangerouslySetInnerHTML, ou use uma biblioteca de renderização segura.',
		filePatterns: [/\.(tsx|jsx|ts|js)$/i],
	},
	// CWE-78: Command Injection
	{
		id: 'COMMAND_INJECTION',
		severity: 'critical',
		title: 'Possível Command Injection',
		cwe: 'CWE-78',
		pattern: /(?:exec|execSync|spawn|spawnSync|system|popen)\s*\(\s*(?:[`'"].*\$\{|.*\+\s*(?:req|input|param|user|args))/i,
		description: 'Execução de comandos do sistema com input dinâmico permite injeção de comandos.',
		suggestion: 'Use execFile/spawnSync com array de argumentos (sem shell). Valide input com allowlist. Em Python: subprocess.run([cmd, arg], shell=False).',
	},
	// CWE-22: Path Traversal
	{
		id: 'PATH_TRAVERSAL',
		severity: 'high',
		title: 'Possível Path Traversal',
		cwe: 'CWE-22',
		pattern: /(?:readFile|writeFile|createReadStream|open|access|stat)\s*\(\s*(?:.*\+\s*(?:req|input|param|user)|.*\$\{(?:req|input|param|user))/i,
		description: 'Uso de input do usuário em caminhos de arquivo sem validação permite acesso a arquivos arbitrários.',
		suggestion: 'Use path.resolve() + verifique que o caminho resultante começa com o diretório base esperado (startsWith(baseDir)).',
	},
	// CWE-918: SSRF
	{
		id: 'SSRF',
		severity: 'high',
		title: 'Possível SSRF',
		cwe: 'CWE-918',
		pattern: /(?:fetch|axios|request|http\.get|https\.get|got)\s*\(\s*(?:req\.|input|param|user|args|body)\./i,
		description: 'Requisições HTTP com URL controlada pelo usuário podem acessar recursos internos.',
		suggestion: 'Valide o scheme (apenas https), bloqueie redes internas (10/8, 172.16/12, 192.168/16, 127.0.0.1) e use allowlist de domínios.',
	},
	// CWE-16: CORS Misconfiguration
	{
		id: 'CORS_WILDCARD',
		severity: 'medium',
		title: 'CORS com wildcard',
		cwe: 'CWE-16',
		pattern: /(?:Access-Control-Allow-Origin|allowedOrigins?|origin)\s*[:=]\s*['"`]\*['"`]/i,
		description: 'CORS com wildcard (*) permite que qualquer domínio faça requisições à API.',
		suggestion: 'Restrinja para domínios específicos: allowedOrigins("https://app.empresa.com").',
	},
	// CWE-327: Weak Cryptography
	{
		id: 'WEAK_CRYPTO',
		severity: 'medium',
		title: 'Criptografia fraca detectada',
		cwe: 'CWE-327',
		pattern: /(?:createHash|MessageDigest\.getInstance|hashlib\.)\s*\(\s*['"`](?:md5|sha1|des)['"`]/i,
		description: 'MD5, SHA1 e DES são algoritmos criptográficos considerados inseguros.',
		suggestion: 'Para senhas: use bcrypt ou argon2. Para hashing: SHA-256+. Para criptografia simétrica: AES-256-GCM.',
	},
	// CWE-502: Insecure Deserialization
	{
		id: 'INSECURE_DESERIALIZATION',
		severity: 'high',
		title: 'Desserialização insegura',
		cwe: 'CWE-502',
		pattern: /(?:pickle\.loads?|yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)|ObjectInputStream|unserialize|eval\s*\()/i,
		description: 'Desserialização de dados não confiáveis pode levar a execução remota de código.',
		suggestion: 'Use JSON + schema validation (zod, pydantic, Jackson typed). Para YAML: yaml.safe_load(). Nunca use eval() com input externo.',
	},
	// CWE-862: Missing Authorization
	{
		id: 'MISSING_AUTH',
		severity: 'medium',
		title: 'Endpoint possivelmente sem autorização',
		cwe: 'CWE-862',
		pattern: /(?:@(?:Get|Post|Put|Delete|Patch)Mapping|@RequestMapping|router\.(?:get|post|put|delete|patch))\s*\(/i,
		description: 'Endpoints HTTP devem ter verificação de autorização explícita.',
		suggestion: 'Adicione @PreAuthorize, middleware de auth, ou verificação de ownership em cada endpoint.',
		filePatterns: [/\.(java|ts|js|py|go)$/i],
	},
	// Dependency pinning
	{
		id: 'UNPINNED_DEPENDENCY',
		severity: 'low',
		title: 'Dependência sem versão fixa',
		cwe: 'CWE-1357',
		pattern: /["'][\w@/.-]+["']\s*:\s*["'][\^~><=]/,
		description: 'Dependências com range de versão (^, ~, >) podem introduzir vulnerabilidades em atualizações automáticas.',
		suggestion: 'Use versão exata (sem ^, ~). Ex: "lodash": "4.17.21". Em GitHub Actions, use SHA pin.',
		filePatterns: [/package\.json$/i],
	},
	// Container security
	{
		id: 'CONTAINER_ROOT',
		severity: 'medium',
		title: 'Container rodando como root',
		cwe: 'CWE-250',
		pattern: /^\s*USER\s+root\s*$/im,
		description: 'Containers não devem rodar como root para limitar o impacto de uma exploração.',
		suggestion: 'Use USER non-root (ex: USER 1001 ou USER node). Adicione: RUN adduser -D appuser && USER appuser.',
		filePatterns: [/Dockerfile/i],
	},
	{
		id: 'CONTAINER_LATEST',
		severity: 'low',
		title: 'Imagem Docker sem versão fixa',
		cwe: 'CWE-1357',
		pattern: /^\s*FROM\s+\S+:latest\s*$/im,
		description: 'Usar :latest em imagens Docker pode introduzir mudanças inesperadas e vulnerabilidades.',
		suggestion: 'Use tag específica com SHA. Ex: FROM node:20.11.0-alpine@sha256:abc123...',
		filePatterns: [/Dockerfile/i],
	},
	// localStorage tokens
	{
		id: 'TOKEN_LOCALSTORAGE',
		severity: 'medium',
		title: 'Token armazenado em localStorage',
		cwe: 'CWE-922',
		pattern: /localStorage\.setItem\s*\(\s*['"`](?:token|access_token|auth_token|jwt|session)['"`]/i,
		description: 'Tokens em localStorage são acessíveis via XSS. Qualquer script malicioso pode roubar a sessão.',
		suggestion: 'Use httpOnly cookies para armazenar tokens de autenticação. Eles não são acessíveis via JavaScript.',
		filePatterns: [/\.(ts|js|tsx|jsx)$/i],
	},
];

const SEVERITY_ORDER: Record<Severity, number> = {
	critical: 0,
	high: 1,
	medium: 2,
	low: 3,
	info: 4,
};

export function sortBySeverity(findings: SecurityFinding[]): SecurityFinding[] {
	return findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}

export async function scanWorkspace(): Promise<SecurityFinding[]> {
	const findings: SecurityFinding[] = [];
	const workspaceFolders = vscode.workspace.workspaceFolders;

	if (!workspaceFolders) {
		return findings;
	}

	const excludePattern = '{**/node_modules/**,**/out/**,**/dist/**,**/.git/**,**/vendor/**,**/target/**,**/*.min.js,**/*.bundle.js}';
	const includePattern = '**/*.{ts,tsx,js,jsx,java,py,go,rb,php,yaml,yml,json,properties,Dockerfile}';

	const files = await vscode.workspace.findFiles(includePattern, excludePattern, 500);

	for (const fileUri of files) {
		const document = await vscode.workspace.openTextDocument(fileUri);
		const text = document.getText();
		const filePath = vscode.workspace.asRelativePath(fileUri);

		for (const rule of SCAN_RULES) {
			// Check file pattern filter
			if (rule.filePatterns && !rule.filePatterns.some(fp => fp.test(fileUri.fsPath))) {
				continue;
			}

			const lines = text.split('\n');
			for (let i = 0; i < lines.length; i++) {
				const line = lines[i];
				const match = rule.pattern.exec(line);
				if (match) {
					findings.push({
						id: rule.id,
						severity: rule.severity,
						title: rule.title,
						description: rule.description,
						cwe: rule.cwe,
						file: filePath,
						line: i + 1,
						column: match.index + 1,
						snippet: line.trim(),
						suggestion: rule.suggestion,
					});
				}
			}
		}
	}

	return sortBySeverity(findings);
}

export async function scanDocument(document: vscode.TextDocument): Promise<SecurityFinding[]> {
	const findings: SecurityFinding[] = [];
	const text = document.getText();
	const filePath = vscode.workspace.asRelativePath(document.uri);

	for (const rule of SCAN_RULES) {
		if (rule.filePatterns && !rule.filePatterns.some(fp => fp.test(document.uri.fsPath))) {
			continue;
		}

		const lines = text.split('\n');
		for (let i = 0; i < lines.length; i++) {
			const line = lines[i];
			const match = rule.pattern.exec(line);
			if (match) {
				findings.push({
					id: rule.id,
					severity: rule.severity,
					title: rule.title,
					description: rule.description,
					cwe: rule.cwe,
					file: filePath,
					line: i + 1,
					column: match.index + 1,
					snippet: line.trim(),
					suggestion: rule.suggestion,
				});
			}
		}
	}

	return sortBySeverity(findings);
}
