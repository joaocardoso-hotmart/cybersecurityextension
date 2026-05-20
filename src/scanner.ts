import * as vscode from 'vscode';
import { execSync } from 'child_process';
import * as path from 'path';

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
	endColumn: number;
	snippet: string;
	suggestion: string;
	suggestedFix?: string;
}

interface ScanRule {
	id: string;
	severity: Severity;
	title: string;
	cwe: string;
	pattern: RegExp;
	description: string;
	suggestion: string;
	suggestedFix?: (match: RegExpExecArray, line: string) => string;
	filePatterns?: RegExp[];
}

const SCAN_RULES: ScanRule[] = [
	{
		id: 'HARDCODED_SECRET',
		severity: 'critical',
		title: 'Credencial hardcoded detectada',
		cwe: 'CWE-798',
		pattern: /(?:password|passwd|secret|api_key|apikey|token|private_key)\s*[:=]\s*['"][^'"]{3,}['"]/i,
		description: 'Credenciais ou secrets não devem ser hardcoded no código-fonte.',
		suggestion: 'Use variáveis de ambiente (process.env.SECRET) ou um secret manager (Vault, AWS Secrets Manager).',
		suggestedFix: (match, line) => {
			const keyMatch = line.match(/(password|passwd|secret|api_key|apikey|token|private_key)/i);
			const key = keyMatch ? keyMatch[1].toUpperCase() : 'SECRET';
			return line.replace(/['"][^'"]{3,}['"]/, `process.env.${key}`);
		},
		filePatterns: [/\.(ts|js|tsx|jsx|java|py|rb|go|php|yaml|yml|json|properties)$/i],
	},
	{
		id: 'SQL_INJECTION',
		severity: 'critical',
		title: 'Possível SQL Injection',
		cwe: 'CWE-89',
		pattern: /(?:query|execute|exec|raw)\s*\(\s*[`'"](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)[\s\S]*?\$\{|(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\+\s*(?:req\.|input|param|args|user)/i,
		description: 'Concatenação de input do usuário em queries SQL permite injeção de código.',
		suggestion: 'Use prepared statements ou parameterized queries. Ex: db.query("SELECT * FROM users WHERE id = $1", [userId])',
	},
	{
		id: 'XSS_INNERHTML',
		severity: 'high',
		title: 'Possível XSS via innerHTML',
		cwe: 'CWE-79',
		pattern: /\.innerHTML\s*=\s*(?!['"`]\s*['"`]).*(?:input|param|req|user|data|response|result|value)/i,
		description: 'Uso de innerHTML com dados dinâmicos pode permitir Cross-Site Scripting.',
		suggestion: 'Use textContent para texto puro ou DOMPurify.sanitize() para HTML.',
		suggestedFix: (_match, line) => {
			return line.replace(/\.innerHTML\s*=/, '.textContent =');
		},
	},
	{
		id: 'XSS_DANGEROUSLY',
		severity: 'high',
		title: 'Possível XSS via dangerouslySetInnerHTML',
		cwe: 'CWE-79',
		pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/,
		description: 'dangerouslySetInnerHTML injeta HTML sem sanitização.',
		suggestion: 'Sanitize com DOMPurify.sanitize() antes de usar, ou use uma biblioteca de renderização segura.',
		filePatterns: [/\.(tsx|jsx|ts|js)$/i],
	},
	{
		id: 'COMMAND_INJECTION',
		severity: 'critical',
		title: 'Possível Command Injection',
		cwe: 'CWE-78',
		pattern: /(?:exec|execSync|spawn|spawnSync|system|popen)\s*\(\s*(?:[`'"].*\$\{|.*\+\s*(?:req|input|param|user|args))/i,
		description: 'Execução de comandos do sistema com input dinâmico permite injeção de comandos.',
		suggestion: 'Use execFile/spawnSync com array de argumentos (sem shell). Valide input com allowlist.',
	},
	{
		id: 'PATH_TRAVERSAL',
		severity: 'high',
		title: 'Possível Path Traversal',
		cwe: 'CWE-22',
		pattern: /(?:readFile|writeFile|createReadStream|open|access|stat)\s*\(\s*(?:.*\+\s*(?:req|input|param|user)|.*\$\{(?:req|input|param|user))/i,
		description: 'Uso de input do usuário em caminhos de arquivo sem validação permite acesso a arquivos arbitrários.',
		suggestion: 'Use path.resolve() + verifique que o caminho começa com o diretório base (startsWith(baseDir)).',
	},
	{
		id: 'SSRF',
		severity: 'high',
		title: 'Possível SSRF',
		cwe: 'CWE-918',
		pattern: /(?:fetch|axios|request|http\.get|https\.get|got)\s*\(\s*(?:req\.|input|param|user|args|body)\./i,
		description: 'Requisições HTTP com URL controlada pelo usuário podem acessar recursos internos.',
		suggestion: 'Valide o scheme (apenas https), bloqueie redes internas e use allowlist de domínios.',
	},
	{
		id: 'CORS_WILDCARD',
		severity: 'medium',
		title: 'CORS com wildcard',
		cwe: 'CWE-16',
		pattern: /(?:Access-Control-Allow-Origin|allowedOrigins?|origin)\s*[:=]\s*['"`]\*['"`]/i,
		description: 'CORS com wildcard (*) permite que qualquer domínio faça requisições à API.',
		suggestion: 'Restrinja para domínios específicos: allowedOrigins("https://app.empresa.com").',
		suggestedFix: (_match, line) => {
			return line.replace(/['"`]\*['"`]/, '"https://app.empresa.com"');
		},
	},
	{
		id: 'WEAK_CRYPTO',
		severity: 'medium',
		title: 'Criptografia fraca detectada',
		cwe: 'CWE-327',
		pattern: /(?:createHash|MessageDigest\.getInstance|hashlib\.)\s*\(\s*['"`](?:md5|sha1|des)['"`]/i,
		description: 'MD5, SHA1 e DES são algoritmos criptográficos considerados inseguros.',
		suggestion: 'Para senhas: bcrypt/argon2. Para hashing: SHA-256+. Para criptografia: AES-256-GCM.',
		suggestedFix: (_match, line) => {
			return line.replace(/['"`](?:md5|sha1|des)['"`]/i, '"sha256"');
		},
	},
	{
		id: 'INSECURE_DESERIALIZATION',
		severity: 'high',
		title: 'Desserialização insegura',
		cwe: 'CWE-502',
		pattern: /(?:pickle\.loads?|yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)|ObjectInputStream|unserialize|eval\s*\()/i,
		description: 'Desserialização de dados não confiáveis pode levar a execução remota de código.',
		suggestion: 'Use JSON + schema validation (zod, pydantic, Jackson typed). Para YAML: yaml.safe_load().',
	},
	{
		id: 'MISSING_AUTH',
		severity: 'medium',
		title: 'Endpoint possivelmente sem autorização',
		cwe: 'CWE-862',
		pattern: /(?:@(?:Get|Post|Put|Delete|Patch)Mapping|@RequestMapping|router\.(?:get|post|put|delete|patch))\s*\(/i,
		description: 'Endpoints HTTP devem ter verificação de autorização explícita.',
		suggestion: 'Adicione @PreAuthorize, middleware de auth, ou verificação de ownership.',
		filePatterns: [/\.(java|ts|js|py|go)$/i],
	},
	{
		id: 'UNPINNED_DEPENDENCY',
		severity: 'low',
		title: 'Dependência sem versão fixa',
		cwe: 'CWE-1357',
		pattern: /["'][\w@/.-]+["']\s*:\s*["'][\^~><=]/,
		description: 'Dependências com range de versão podem introduzir vulnerabilidades.',
		suggestion: 'Use versão exata (sem ^, ~). Em GitHub Actions, use SHA pin.',
		filePatterns: [/package\.json$/i],
	},
	{
		id: 'CONTAINER_ROOT',
		severity: 'medium',
		title: 'Container rodando como root',
		cwe: 'CWE-250',
		pattern: /^\s*USER\s+root\s*$/im,
		description: 'Containers não devem rodar como root.',
		suggestion: 'Use USER non-root (ex: USER 1001).',
		suggestedFix: (_match, _line) => 'USER 1001',
		filePatterns: [/Dockerfile/i],
	},
	{
		id: 'CONTAINER_LATEST',
		severity: 'low',
		title: 'Imagem Docker sem versão fixa',
		cwe: 'CWE-1357',
		pattern: /^\s*FROM\s+\S+:latest\s*$/im,
		description: 'Usar :latest pode introduzir mudanças inesperadas e vulnerabilidades.',
		suggestion: 'Use tag específica com SHA. Ex: FROM node:20-alpine@sha256:...',
		filePatterns: [/Dockerfile/i],
	},
	{
		id: 'TOKEN_LOCALSTORAGE',
		severity: 'medium',
		title: 'Token armazenado em localStorage',
		cwe: 'CWE-922',
		pattern: /localStorage\.setItem\s*\(\s*['"`](?:token|access_token|auth_token|jwt|session)['"`]/i,
		description: 'Tokens em localStorage são acessíveis via XSS.',
		suggestion: 'Use httpOnly cookies para armazenar tokens de autenticação.',
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

/**
 * Represents a changed line from git diff.
 */
interface ChangedLine {
	file: string;
	lineNumber: number;
}

/**
 * Gets the list of changed/added lines from git diff (staged + unstaged).
 * Only returns lines that were ADDED (not removed).
 */
export function getChangedLines(workspaceFolder: string): ChangedLine[] {
	const changedLines: ChangedLine[] = [];

	try {
		// Get both staged and unstaged changes
		const diffOutputs: string[] = [];

		// Unstaged changes (working tree vs index)
		try {
			const unstaged = execSync('git diff -U0 --no-color', {
				cwd: workspaceFolder,
				encoding: 'utf-8',
				maxBuffer: 10 * 1024 * 1024,
			});
			if (unstaged) { diffOutputs.push(unstaged); }
		} catch { /* no unstaged changes */ }

		// Staged changes (index vs HEAD)
		try {
			const staged = execSync('git diff --cached -U0 --no-color', {
				cwd: workspaceFolder,
				encoding: 'utf-8',
				maxBuffer: 10 * 1024 * 1024,
			});
			if (staged) { diffOutputs.push(staged); }
		} catch { /* no staged changes */ }

		// New untracked files
		try {
			const untracked = execSync('git ls-files --others --exclude-standard', {
				cwd: workspaceFolder,
				encoding: 'utf-8',
				maxBuffer: 10 * 1024 * 1024,
			});
			if (untracked.trim()) {
				const files = untracked.trim().split('\n');
				for (const file of files) {
					const filePath = path.join(workspaceFolder, file);
					try {
						const content = require('fs').readFileSync(filePath, 'utf-8');
						const lines = content.split('\n');
						for (let i = 0; i < lines.length; i++) {
							changedLines.push({ file, lineNumber: i + 1 });
						}
					} catch { /* skip unreadable files */ }
				}
			}
		} catch { /* no untracked files */ }

		// Parse unified diff output
		for (const diffOutput of diffOutputs) {
			let currentFile = '';
			const lines = diffOutput.split('\n');

			for (const line of lines) {
				// Match file header: +++ b/path/to/file
				const fileMatch = line.match(/^\+\+\+ b\/(.+)$/);
				if (fileMatch) {
					currentFile = fileMatch[1];
					continue;
				}

				// Match hunk header: @@ -old,count +new,count @@
				const hunkMatch = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/);
				if (hunkMatch && currentFile) {
					const startLine = parseInt(hunkMatch[1], 10);
					const lineCount = hunkMatch[2] ? parseInt(hunkMatch[2], 10) : 1;

					for (let i = 0; i < lineCount; i++) {
						changedLines.push({
							file: currentFile,
							lineNumber: startLine + i,
						});
					}
				}
			}
		}
	} catch {
		// Not a git repo or git not available
	}

	return changedLines;
}

/**
 * Scans only the changed/new lines in the workspace.
 * Uses git diff to determine what was modified.
 */
export async function scanChangedLines(): Promise<SecurityFinding[]> {
	const findings: SecurityFinding[] = [];
	const workspaceFolders = vscode.workspace.workspaceFolders;

	if (!workspaceFolders) {
		return findings;
	}

	const workspaceFolder = workspaceFolders[0].uri.fsPath;
	const changedLines = getChangedLines(workspaceFolder);

	if (changedLines.length === 0) {
		return findings;
	}

	// Group changed lines by file
	const fileChanges = new Map<string, Set<number>>();
	for (const change of changedLines) {
		if (!fileChanges.has(change.file)) {
			fileChanges.set(change.file, new Set());
		}
		fileChanges.get(change.file)!.add(change.lineNumber);
	}

	// Scan only changed lines in each file
	for (const [filePath, lineNumbers] of fileChanges) {
		const fullPath = path.join(workspaceFolder, filePath);
		let document: vscode.TextDocument;

		try {
			const uri = vscode.Uri.file(fullPath);
			document = await vscode.workspace.openTextDocument(uri);
		} catch {
			continue;
		}

		const text = document.getText();
		const lines = text.split('\n');

		for (const rule of SCAN_RULES) {
			if (rule.filePatterns && !rule.filePatterns.some(fp => fp.test(fullPath))) {
				continue;
			}

			for (const lineNum of lineNumbers) {
				const lineIndex = lineNum - 1;
				if (lineIndex < 0 || lineIndex >= lines.length) {
					continue;
				}

				const line = lines[lineIndex];
				const match = rule.pattern.exec(line);
				if (match) {
					const finding: SecurityFinding = {
						id: rule.id,
						severity: rule.severity,
						title: rule.title,
						description: rule.description,
						cwe: rule.cwe,
						file: filePath,
						line: lineNum,
						column: match.index + 1,
						endColumn: match.index + match[0].length + 1,
						snippet: line.trim(),
						suggestion: rule.suggestion,
					};

					if (rule.suggestedFix) {
						finding.suggestedFix = rule.suggestedFix(match, line);
					}

					findings.push(finding);
				}
			}
		}
	}

	return sortBySeverity(findings);
}
