import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { SecuritySidebarProvider } from './sidebar';
import { scanChangedLines, SecurityFinding, Severity, setExtensionPath } from './scanner';
import { ensureOpenGrep } from './semgrep';

const KIRO_FILES = ['appsec-rules.md'];
const CURSOR_FILES = ['appsec-rules.mdc'];

const CLAUDE_FILES = {
	rules: ['appsec-rules.md'],
};

const GITHUB_WORKFLOW_FILES = ['appsec-guard.yml'];

const IDE_CONFIGS: Record<string, { targetDir: string; sourceDir: string; files: string[] }> = {
	kiro: { targetDir: '.kiro/steering', sourceDir: 'standards/kiro/steering', files: KIRO_FILES },
	cursor: { targetDir: '.cursor/rules', sourceDir: 'standards/cursor/rules', files: CURSOR_FILES },
	vscode: { targetDir: '.github', sourceDir: 'standards/steering', files: ['copilot-instructions.md'] },
};

/**
 * Detects which IDE is running based on vscode.env.uriScheme.
 */
function detectIDE(): string {
	const scheme = vscode.env.uriScheme;
	if (scheme === 'kiro') { return 'kiro'; }
	if (scheme === 'cursor') { return 'cursor'; }
	return 'vscode';
}

// Diagnostics collection for security findings
let diagnosticCollection: vscode.DiagnosticCollection;
let currentFindings: SecurityFinding[] = [];

export function activate(context: vscode.ExtensionContext) {
	console.log('Hotmart Cybersecurity Extension activated');

	// Set extension path for scanner to find rules
	setExtensionPath(context.extensionPath);

	// Create diagnostics collection for inline underlines
	diagnosticCollection = vscode.languages.createDiagnosticCollection('cybersecurity');
	context.subscriptions.push(diagnosticCollection);

	// Register sidebar webview provider
	const sidebarProvider = new SecuritySidebarProvider(context.extensionUri);
	context.subscriptions.push(
		vscode.window.registerWebviewViewProvider(
			SecuritySidebarProvider.viewType,
			sidebarProvider
		)
	);

	// Register commands
	const bootstrapCmd = vscode.commands.registerCommand(
		'cybersecurityextension.bootstrap',
		() => bootstrapProject(context)
	);

	const updateCmd = vscode.commands.registerCommand(
		'cybersecurityextension.updateStandards',
		() => updateStandards(context)
	);

	const showGuidelinesCmd = vscode.commands.registerCommand(
		'cybersecurityextension.showGuidelines',
		() => showGuidelines(context)
	);

	context.subscriptions.push(bootstrapCmd, updateCmd, showGuidelinesCmd);

	// Command to apply fix via AI prompt
	const applyFixCmd = vscode.commands.registerCommand(
		'cybersecurityextension.applyFixWithAI',
		(...args: unknown[]) => applyFixWithAI(args[0])
	);
	context.subscriptions.push(applyFixCmd);

	// Command to dismiss a finding as false positive
	const dismissCmd = vscode.commands.registerCommand(
		'cybersecurityextension.dismissFinding',
		(...args: unknown[]) => dismissFinding(args[0], sidebarProvider)
	);
	context.subscriptions.push(dismissCmd);

	// Register hover provider for security findings
	context.subscriptions.push(
		vscode.languages.registerHoverProvider('*', new SecurityHoverProvider())
	);

	// Register code action provider for quick fixes
	context.subscriptions.push(
		vscode.languages.registerCodeActionsProvider('*', new SecurityCodeActionProvider(), {
			providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
		})
	);

	// Watch for git operations (commit / staging)
	registerGitWatcher(context, sidebarProvider);

	// Ensure OpenGrep is installed
	ensureOpenGrep();

	// Auto-apply steering files on workspace open
	autoApplyIfNeeded(context);

	// Ensure preToolUse hook exists (runs on every activation)
	ensureSecurityHook(context);
}

// ─── AUTO-INSTALL SECURITY HOOK ───────────────────────────────────────────────

function ensureSecurityHook(context: vscode.ExtensionContext): void {
	const workspaceFolder = getWorkspaceFolder();
	if (!workspaceFolder) {
		return;
	}

	const currentIde = detectIDE();

	// Install Kiro hook if running in Kiro
	if (currentIde === 'kiro') {
		installKiroHookOnActivate(context, workspaceFolder);
	}

	// Always install Claude Code hook (Claude Code is used alongside any IDE)
	installClaudeHookOnActivate(context, workspaceFolder);

	// Always install git pre-commit hook
	installGitPreCommitHook(context, workspaceFolder);
}

function installKiroHookOnActivate(context: vscode.ExtensionContext, workspaceFolder: string): void {
	const hooksDir = path.join(workspaceFolder, '.kiro', 'hooks');
	const hookFile = path.join(hooksDir, 'appsec-gate.json');

	if (fs.existsSync(hookFile)) {
		return;
	}

	const sourceFile = path.join(context.extensionPath, 'standards', 'hooks', 'kiro', 'appsec-gate.json');
	if (!fs.existsSync(sourceFile)) {
		return;
	}

	if (!fs.existsSync(hooksDir)) {
		fs.mkdirSync(hooksDir, { recursive: true });
	}

	fs.copyFileSync(sourceFile, hookFile);
	console.log('[Hotmart AppSec] Kiro hook installed at .kiro/hooks/appsec-gate.json');
}

function installClaudeHookOnActivate(context: vscode.ExtensionContext, workspaceFolder: string): void {
	// Install .claude/settings.json with PreToolUse hook
	const claudeDir = path.join(workspaceFolder, '.claude');
	const settingsFile = path.join(claudeDir, 'settings.json');

	if (fs.existsSync(settingsFile)) {
		return;
	}

	const sourceFile = path.join(context.extensionPath, 'standards', 'hooks', 'claude', 'settings.json');
	if (!fs.existsSync(sourceFile)) {
		return;
	}

	if (!fs.existsSync(claudeDir)) {
		fs.mkdirSync(claudeDir, { recursive: true });
	}

	fs.copyFileSync(sourceFile, settingsFile);

	// Install the gate script
	const appsecDir = path.join(workspaceFolder, '.appsec');
	const scriptDest = path.join(appsecDir, 'appsec-gate.sh');

	if (!fs.existsSync(scriptDest)) {
		const scriptSource = path.join(context.extensionPath, 'standards', 'hooks', 'appsec-gate.sh');
		if (fs.existsSync(scriptSource)) {
			if (!fs.existsSync(appsecDir)) {
				fs.mkdirSync(appsecDir, { recursive: true });
			}
			fs.copyFileSync(scriptSource, scriptDest);
			fs.chmodSync(scriptDest, 0o755);
		}
	}

	console.log('[Hotmart AppSec] Claude Code hook installed at .claude/settings.json');
}

function installGitPreCommitHook(context: vscode.ExtensionContext, workspaceFolder: string): void {
	const gitHooksDir = path.join(workspaceFolder, '.git', 'hooks');
	const preCommitFile = path.join(gitHooksDir, 'pre-commit');

	// Only install if .git exists (it's a git repo)
	if (!fs.existsSync(path.join(workspaceFolder, '.git'))) {
		return;
	}

	// Don't overwrite if already exists
	if (fs.existsSync(preCommitFile)) {
		return;
	}

	const sourceFile = path.join(context.extensionPath, 'standards', 'hooks', 'pre-commit');
	if (!fs.existsSync(sourceFile)) {
		return;
	}

	if (!fs.existsSync(gitHooksDir)) {
		fs.mkdirSync(gitHooksDir, { recursive: true });
	}

	fs.copyFileSync(sourceFile, preCommitFile);
	fs.chmodSync(preCommitFile, 0o755);
	console.log('[Hotmart AppSec] Git pre-commit hook installed');
}

// ─── SECURITY SCAN (only changed lines) ───────────────────────────────────────

async function runSecurityScan(sidebarProvider: SecuritySidebarProvider): Promise<SecurityFinding[]> {
	const findings = await scanChangedLines();
	currentFindings = findings;

	// Update diagnostics (red underlines)
	updateDiagnostics(findings);

	// Update sidebar
	sidebarProvider.updateFindings(findings);

	return findings;
}

function updateDiagnostics(findings: SecurityFinding[]): void {
	diagnosticCollection.clear();

	const workspaceFolders = vscode.workspace.workspaceFolders;
	if (!workspaceFolders) {
		return;
	}

	// Group findings by file
	const findingsByFile = new Map<string, SecurityFinding[]>();
	for (const finding of findings) {
		if (!findingsByFile.has(finding.file)) {
			findingsByFile.set(finding.file, []);
		}
		findingsByFile.get(finding.file)!.push(finding);
	}

	// Create diagnostics per file
	for (const [filePath, fileFindings] of findingsByFile) {
		const fullPath = path.join(workspaceFolders[0].uri.fsPath, filePath);
		const uri = vscode.Uri.file(fullPath);
		const diagnostics: vscode.Diagnostic[] = [];

		for (const finding of fileFindings) {
			const range = new vscode.Range(
				finding.line - 1, finding.column - 1,
				finding.line - 1, finding.endColumn - 1
			);

			const severity = mapSeverity(finding.severity);
			const diagnostic = new vscode.Diagnostic(range, finding.title, severity);
			diagnostic.code = finding.cwe;
			diagnostic.source = 'Hotmart AppSec';
			diagnostic.relatedInformation = [
				new vscode.DiagnosticRelatedInformation(
					new vscode.Location(uri, range),
					finding.suggestion
				),
			];

			diagnostics.push(diagnostic);
		}

		diagnosticCollection.set(uri, diagnostics);
	}
}

function mapSeverity(severity: Severity): vscode.DiagnosticSeverity {
	switch (severity) {
		case 'critical':
		case 'high':
			return vscode.DiagnosticSeverity.Error;
		case 'medium':
			return vscode.DiagnosticSeverity.Warning;
		case 'low':
		case 'info':
			return vscode.DiagnosticSeverity.Information;
	}
}

// ─── HOVER PROVIDER ───────────────────────────────────────────────────────────

class SecurityHoverProvider implements vscode.HoverProvider {
	provideHover(document: vscode.TextDocument, position: vscode.Position): vscode.Hover | undefined {
		const filePath = vscode.workspace.asRelativePath(document.uri);
		const lineNum = position.line + 1;

		const finding = currentFindings.find(f =>
			f.file === filePath &&
			f.line === lineNum &&
			position.character >= f.column - 1 &&
			position.character <= f.endColumn - 1
		);

		if (!finding) {
			return undefined;
		}

		const markdown = new vscode.MarkdownString();
		markdown.isTrusted = true;
		markdown.supportHtml = true;

		const severityBadge = getSeverityBadge(finding.severity);
		const escapedSnippet = escapeHtml(finding.snippet);
		const escapedSuggestion = escapeHtml(finding.suggestion);

		// Build the command link for the copy prompt button
		// VS Code command links in MarkdownString expect the argument as a JSON-encoded array after '?'
		const findingData = JSON.stringify({
			file: finding.file,
			line: finding.line,
			title: finding.title,
			cwe: finding.cwe,
			description: finding.description,
			suggestion: finding.suggestion,
			suggestedFix: finding.suggestedFix || null,
			snippet: finding.snippet,
		});
		const encodedFinding = encodeURIComponent(JSON.stringify([findingData]));
		const copyButton = `[$(clippy) Copiar prompt de correção](command:cybersecurityextension.applyFixWithAI?${encodedFinding} "Copia o prompt para colar no chat da IA")`;
		const dismissButton = `[$(close) Falso Positivo](command:cybersecurityextension.dismissFinding?${encodeURIComponent(JSON.stringify([JSON.stringify({ id: finding.id, file: finding.file, line: finding.line })]))} "Ignorar este finding")`;

		// Premium hover design using HTML
		markdown.appendMarkdown(`<span style="color:#e6edf3;">**🛡️ ${escapeHtml(finding.title)}**</span>&nbsp;&nbsp;`);
		markdown.appendMarkdown(`<span style="color:${severityBadge.color};font-size:0.85em;">●</span> `);
		markdown.appendMarkdown(`<span style="color:${severityBadge.color};font-size:0.85em;font-weight:600;">${finding.severity.toUpperCase()}</span>&nbsp;&nbsp;`);
		markdown.appendMarkdown(`<span style="color:#6e7681;font-size:0.85em;">${finding.cwe}</span>\n\n`);

		// Description
		markdown.appendMarkdown(`<span style="color:#9da7b3;">${escapeHtml(finding.description)}</span>\n\n`);

		// Vulnerable code
		markdown.appendMarkdown(`---\n\n`);
		markdown.appendMarkdown(`<span style="color:#6e7681;font-size:0.85em;">⚠️ CÓDIGO VULNERÁVEL</span>\n\n`);
		markdown.appendCodeblock(finding.snippet, document.languageId);

		// Fix section
		markdown.appendMarkdown(`\n<span style="color:#6e7681;font-size:0.85em;">💡 CORREÇÃO</span>\n\n`);
		markdown.appendMarkdown(`<span style="color:#e6edf3;">${escapedSuggestion}</span>\n\n`);

		if (finding.suggestedFix) {
			markdown.appendCodeblock(finding.suggestedFix, document.languageId);
		}

		// Action buttons (always visible at bottom)
		markdown.appendMarkdown(`\n---\n\n${copyButton} &nbsp;&nbsp; ${dismissButton}\n`);

		return new vscode.Hover(markdown, new vscode.Range(
			finding.line - 1, finding.column - 1,
			finding.line - 1, finding.endColumn - 1
		));
	}
}

function getSeverityBadge(severity: Severity): { color: string; label: string } {
	switch (severity) {
		case 'critical': return { color: '#f85149', label: 'CRITICAL' };
		case 'high': return { color: '#db6d28', label: 'HIGH' };
		case 'medium': return { color: '#d29922', label: 'MEDIUM' };
		case 'low': return { color: '#3fb950', label: 'LOW' };
		case 'info': return { color: '#58a6ff', label: 'INFO' };
	}
}

function escapeHtml(text: string): string {
	return text
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;');
}

// ─── CODE ACTION PROVIDER (Quick Fix) ────────────────────────────────────────

class SecurityCodeActionProvider implements vscode.CodeActionProvider {
	provideCodeActions(
		document: vscode.TextDocument,
		range: vscode.Range | vscode.Selection,
	): vscode.CodeAction[] | undefined {
		const filePath = vscode.workspace.asRelativePath(document.uri);
		const actions: vscode.CodeAction[] = [];

		for (const finding of currentFindings) {
			if (finding.file !== filePath) {
				continue;
			}
			if (finding.line - 1 < range.start.line || finding.line - 1 > range.end.line) {
				continue;
			}

			// Always offer the AI-assisted fix action
			const aiAction = new vscode.CodeAction(
				`🛡️ Copiar prompt: ${finding.title}`,
				vscode.CodeActionKind.QuickFix
			);
			aiAction.command = {
				command: 'cybersecurityextension.applyFixWithAI',
				title: 'Aplicar correção via IA',
				arguments: [JSON.stringify({
					file: finding.file,
					line: finding.line,
					title: finding.title,
					cwe: finding.cwe,
					description: finding.description,
					suggestion: finding.suggestion,
					suggestedFix: finding.suggestedFix || null,
					snippet: finding.snippet,
				})],
			};
			aiAction.isPreferred = true;
			aiAction.diagnostics = diagnosticCollection.get(document.uri)?.filter(
				d => d.range.start.line === finding.line - 1
			) as vscode.Diagnostic[] | undefined;

			actions.push(aiAction);
		}

		return actions;
	}
}

// ─── APPLY FIX WITH AI PROMPT ─────────────────────────────────────────────────

async function applyFixWithAI(findingArg: unknown): Promise<void> {
	let finding: {
		file: string;
		line: number;
		title: string;
		cwe: string;
		description: string;
		suggestion: string;
		suggestedFix: string | null;
		snippet: string;
	};

	try {
		if (typeof findingArg === 'string') {
			finding = JSON.parse(findingArg);
		} else if (typeof findingArg === 'object' && findingArg !== null) {
			// When called from hover command link, VS Code may pass it as parsed object
			finding = findingArg as typeof finding;
		} else {
			throw new Error('Invalid argument type');
		}
	} catch (err) {
		// Try URL-decoded version
		try {
			const decoded = decodeURIComponent(String(findingArg));
			finding = JSON.parse(decoded);
		} catch {
			vscode.window.showErrorMessage('Erro ao processar finding de segurança.');
			console.error('applyFixWithAI error:', err, 'arg:', findingArg);
			return;
		}
	}

	// Build the AI prompt
	const prompt = buildFixPrompt(finding);

	// Copy to clipboard
	await vscode.env.clipboard.writeText(prompt);
	vscode.window.showInformationMessage('🛡️ Prompt de correção copiado! Cole no chat da IA (Cmd+V).');
}

function buildFixPrompt(finding: {
	file: string;
	line: number;
	title: string;
	cwe: string;
	description: string;
	suggestion: string;
	suggestedFix: string | null;
	snippet: string;
}): string {
	let prompt = `🛡️ **Correção de Segurança — ${finding.cwe}**\n\n`;
	prompt += `**Vulnerabilidade encontrada:** ${finding.title}\n`;
	prompt += `**Arquivo:** ${finding.file}, linha ${finding.line}\n`;
	prompt += `**Código vulnerável:**\n\`\`\`\n${finding.snippet}\n\`\`\`\n\n`;
	prompt += `**Problema:** ${finding.description}\n\n`;
	prompt += `**Como corrigir:** ${finding.suggestion}\n\n`;

	if (finding.suggestedFix) {
		prompt += `**Correção sugerida:**\n\`\`\`\n${finding.suggestedFix}\n\`\`\`\n\n`;
	}

	prompt += `Por favor, aplique essa correção no arquivo \`${finding.file}\` na linha ${finding.line}. `;
	prompt += `Explique brevemente por que essa mudança é necessária do ponto de vista de segurança `;
	prompt += `e garanta que a correção não quebre a funcionalidade existente.`;

	return prompt;
}

// ─── DISMISS FINDING (False Positive) ─────────────────────────────────────────

async function dismissFinding(findingArg: unknown, sidebarProvider: SecuritySidebarProvider): Promise<void> {
	let findingInfo: { id: string; file: string; line: number };

	try {
		if (typeof findingArg === 'string') {
			findingInfo = JSON.parse(findingArg);
		} else if (typeof findingArg === 'object' && findingArg !== null) {
			findingInfo = findingArg as typeof findingInfo;
		} else {
			throw new Error('Invalid');
		}
	} catch {
		try {
			findingInfo = JSON.parse(decodeURIComponent(String(findingArg)));
		} catch {
			return;
		}
	}

	// Remove from current findings
	currentFindings = currentFindings.filter(f =>
		!(f.id === findingInfo.id && f.file === findingInfo.file && f.line === findingInfo.line)
	);

	// Update diagnostics and sidebar
	updateDiagnostics(currentFindings);
	sidebarProvider.updateFindings(currentFindings);

	vscode.window.showInformationMessage(`🛡️ Finding ignorado como falso positivo.`);
}

// ─── GIT WATCHER (triggers scan on commit/stage) ─────────────────────────────

function registerGitWatcher(context: vscode.ExtensionContext, sidebarProvider: SecuritySidebarProvider): void {
	const workspaceFolder = getWorkspaceFolder();
	if (!workspaceFolder) {
		return;
	}

	const gitDir = path.join(workspaceFolder, '.git');
	if (!fs.existsSync(gitDir)) {
		return;
	}

	// Capture the current index mtime at activation so we don't trigger on reload
	let lastIndexSize = 0;
	try {
		const stat = fs.statSync(path.join(gitDir, 'index'));
		lastIndexSize = stat.size;
	} catch { /* */ }

	// Grace period: ignore all events in the first 5 seconds after activation
	// to avoid triggering on reload/startup
	let ready = false;
	const readyTimer = setTimeout(() => { ready = true; }, 5000);

	let debounceTimer: NodeJS.Timeout | undefined;

	const watcher = fs.watch(gitDir, (eventType, filename) => {
		if (!filename) { return; }
		if (!ready) { return; }

		// Only trigger on index (git add) or COMMIT_EDITMSG (git commit)
		if (filename !== 'index' && filename !== 'COMMIT_EDITMSG') {
			return;
		}

		// For index changes, verify the file size actually changed
		// (a real git add modifies the index size; git status reads don't)
		if (filename === 'index') {
			try {
				const stat = fs.statSync(path.join(gitDir, 'index'));
				if (stat.size === lastIndexSize) {
					return;
				}
				lastIndexSize = stat.size;
			} catch { return; }
		}

		// Debounce to batch rapid git operations
		if (debounceTimer) {
			clearTimeout(debounceTimer);
		}
		debounceTimer = setTimeout(() => {
			onGitOperation(sidebarProvider);
		}, 2000);
	});

	context.subscriptions.push({
		dispose: () => {
			watcher.close();
			clearTimeout(readyTimer);
			if (debounceTimer) { clearTimeout(debounceTimer); }
		}
	});
}

// Track last notification fingerprint to avoid repeated popups
let lastNotificationFingerprint = '';

async function onGitOperation(sidebarProvider: SecuritySidebarProvider): Promise<void> {
	const findings = await runSecurityScan(sidebarProvider);

	if (findings.length === 0) {
		// Clear the fingerprint when no findings
		lastNotificationFingerprint = '';
		return;
	}

	// Create a fingerprint of current findings to avoid duplicate notifications
	const fingerprint = findings.map(f => `${f.file}:${f.line}:${f.id}`).sort().join('|');

	// Only show popup if findings changed since last notification
	if (fingerprint === lastNotificationFingerprint) {
		return;
	}
	lastNotificationFingerprint = fingerprint;

	const criticalCount = findings.filter(f => f.severity === 'critical').length;
	const highCount = findings.filter(f => f.severity === 'high').length;
	const otherCount = findings.length - criticalCount - highCount;

	let summary = '🛡️ Heads up! ';
	const parts: string[] = [];
	if (criticalCount > 0) { parts.push(`${criticalCount} critical`); }
	if (highCount > 0) { parts.push(`${highCount} high`); }
	if (otherCount > 0) { parts.push(`${otherCount} other`); }

	summary += `Encontrei ${parts.join(', ')} finding(s) nas suas alterações. `;
	summary += 'Vale dar uma olhada — a pipeline pode reclamar depois. 😉';

	const action = await vscode.window.showWarningMessage(
		summary,
		'Ver Findings',
		'Seguir em Frente'
	);

	if (action === 'Ver Findings') {
		await vscode.commands.executeCommand('cybersecurity.findingsView.focus');
	}
}

// ─── STEERING FILES DISTRIBUTION ─────────────────────────────────────────────

async function bootstrapProject(context: vscode.ExtensionContext): Promise<void> {
	const workspaceFolder = getWorkspaceFolder();
	if (!workspaceFolder) {
		vscode.window.showErrorMessage('Nenhum workspace aberto. Abra uma pasta para aplicar os padrões.');
		return;
	}

	const currentIde = detectIDE();

	let applied = 0;

	// Apply steering/rules only for the detected IDE
	applied += await applyIdeFiles(context, workspaceFolder, currentIde);

	// Always apply Claude rules (Claude Code can be used alongside any IDE)
	applied += await applyClaudeFiles(context, workspaceFolder);

	// Install preToolUse hooks only for the detected IDE
	applied += await applySecurityHooks(context, workspaceFolder, [currentIde]);

	// GitHub workflow is IDE-agnostic (CI/CD protection)
	applied += await applyGitHubWorkflow(context, workspaceFolder);

	vscode.window.showInformationMessage(
		`✅ Padrões de segurança aplicados: ${applied} arquivo(s) para ${currentIde}.`
	);
}

async function updateStandards(context: vscode.ExtensionContext): Promise<void> {
	const workspaceFolder = getWorkspaceFolder();
	if (!workspaceFolder) {
		vscode.window.showErrorMessage('Nenhum workspace aberto.');
		return;
	}

	let updated = 0;
	const currentIde = detectIDE();

	// Update only current IDE files
	const config = IDE_CONFIGS[currentIde];
	if (config) {
		const targetDir = path.join(workspaceFolder, config.targetDir);
		if (fs.existsSync(targetDir)) {
			updated += await applyIdeFiles(context, workspaceFolder, currentIde, true);
		}
	}

	// Always update Claude rules
	const claudeRulesDir = path.join(workspaceFolder, '.claude', 'rules');
	if (fs.existsSync(claudeRulesDir)) {
		updated += await applyClaudeFiles(context, workspaceFolder, true);
	}

	if (updated > 0) {
		vscode.window.showInformationMessage(`✅ Padrões atualizados: ${updated} arquivo(s) sincronizado(s) para ${currentIde}.`);
	} else {
		vscode.window.showInformationMessage('Nenhum padrão encontrado para atualizar. Execute "Bootstrap Project" primeiro.');
	}
}

async function showGuidelines(context: vscode.ExtensionContext): Promise<void> {
	const guidelinePath = path.join(context.extensionPath, 'standards', 'steering', 'copilot-instructions.md');
	const doc = await vscode.workspace.openTextDocument(guidelinePath);
	await vscode.window.showTextDocument(doc, { preview: true });
}

async function autoApplyIfNeeded(context: vscode.ExtensionContext): Promise<void> {
	const workspaceFolder = getWorkspaceFolder();
	if (!workspaceFolder) {
		return;
	}

	const config = vscode.workspace.getConfiguration('hotmartCybersecurity');
	const autoApply = config.get<boolean>('autoApplyOnOpen', true);

	if (!autoApply) {
		return;
	}

	await applyToAllTargets(context, workspaceFolder, true);
}

async function applyToAllTargets(context: vscode.ExtensionContext, workspaceFolder: string, silent: boolean = false): Promise<void> {
	let applied = 0;
	const currentIde = detectIDE();

	// Apply only for the current IDE — no cross-IDE pollution
	applied += await applyIdeFiles(context, workspaceFolder, currentIde, silent);

	// Always apply Claude rules (Claude Code can be used alongside any IDE)
	applied += await applyClaudeFiles(context, workspaceFolder, silent);

	// Install security hooks only for the current IDE
	applied += await applySecurityHooks(context, workspaceFolder, [currentIde]);

	// GitHub workflow is IDE-agnostic (CI/CD protection)
	applied += await applyGitHubWorkflow(context, workspaceFolder, silent);

	if (!silent && applied > 0) {
		vscode.window.showInformationMessage(`✅ Padrões de segurança aplicados: ${applied} arquivo(s) para ${currentIde}.`);
	}
}

// ─── SECURITY HOOKS INSTALLATION ──────────────────────────────────────────────

async function applySecurityHooks(
	context: vscode.ExtensionContext,
	workspaceFolder: string,
	targets: string[]
): Promise<number> {
	let count = 0;

	for (const target of targets) {
		switch (target) {
			case 'kiro':
				count += await installKiroHook(context, workspaceFolder);
				break;
			case 'claude':
				count += await installClaudeHook(context, workspaceFolder);
				break;
			// Cursor and VS Code don't support preToolUse hooks natively
		}
	}

	return count;
}

async function installKiroHook(context: vscode.ExtensionContext, workspaceFolder: string): Promise<number> {
	const hooksDir = path.join(workspaceFolder, '.kiro', 'hooks');
	const hookFile = path.join(hooksDir, 'appsec-gate.json');

	// Don't overwrite if already exists
	if (fs.existsSync(hookFile)) {
		return 0;
	}

	const sourceFile = path.join(context.extensionPath, 'standards', 'hooks', 'kiro', 'appsec-gate.json');
	if (!fs.existsSync(sourceFile)) {
		return 0;
	}

	if (!fs.existsSync(hooksDir)) {
		fs.mkdirSync(hooksDir, { recursive: true });
	}

	fs.copyFileSync(sourceFile, hookFile);
	return 1;
}

async function installClaudeHook(context: vscode.ExtensionContext, workspaceFolder: string): Promise<number> {
	let count = 0;

	// Install the gate script
	const appsecDir = path.join(workspaceFolder, '.appsec');
	const scriptDest = path.join(appsecDir, 'appsec-gate.sh');

	if (!fs.existsSync(scriptDest)) {
		const scriptSource = path.join(context.extensionPath, 'standards', 'hooks', 'appsec-gate.sh');
		if (fs.existsSync(scriptSource)) {
			if (!fs.existsSync(appsecDir)) {
				fs.mkdirSync(appsecDir, { recursive: true });
			}
			fs.copyFileSync(scriptSource, scriptDest);
			fs.chmodSync(scriptDest, 0o755);
			count++;
		}
	}

	// Install Claude Code hooks in .claude/settings.json
	const claudeSettingsDir = path.join(workspaceFolder, '.claude');
	const settingsFile = path.join(claudeSettingsDir, 'settings.json');

	if (!fs.existsSync(settingsFile)) {
		const sourceFile = path.join(context.extensionPath, 'standards', 'hooks', 'claude', 'settings.json');
		if (fs.existsSync(sourceFile)) {
			if (!fs.existsSync(claudeSettingsDir)) {
				fs.mkdirSync(claudeSettingsDir, { recursive: true });
			}
			fs.copyFileSync(sourceFile, settingsFile);
			count++;
		}
	}

	return count;
}

// ─── GITHUB WORKFLOW ──────────────────────────────────────────────────────────

async function applyGitHubWorkflow(
	context: vscode.ExtensionContext,
	workspaceFolder: string,
	overwrite: boolean = false
): Promise<number> {
	const targetDir = path.join(workspaceFolder, '.github', 'workflows');
	const sourceDir = path.join(context.extensionPath, 'standards', 'github', 'workflows');

	if (!fs.existsSync(targetDir)) {
		fs.mkdirSync(targetDir, { recursive: true });
	}

	let count = 0;
	for (const file of GITHUB_WORKFLOW_FILES) {
		const source = path.join(sourceDir, file);
		const dest = path.join(targetDir, file);
		if (!fs.existsSync(source)) { continue; }
		count += await copySingleFile(source, dest, file, overwrite);
	}

	return count;
}

async function applyIdeFiles(
	context: vscode.ExtensionContext,
	workspaceFolder: string,
	ide: string,
	overwrite: boolean = false
): Promise<number> {
	const config = IDE_CONFIGS[ide];
	if (!config) { return 0; }

	const targetDir = path.join(workspaceFolder, config.targetDir);
	const sourceDir = path.join(context.extensionPath, config.sourceDir);

	if (!fs.existsSync(targetDir)) {
		fs.mkdirSync(targetDir, { recursive: true });
	}

	let count = 0;
	for (const file of config.files) {
		const source = path.join(sourceDir, file);
		const dest = path.join(targetDir, file);

		// Try primary source path
		if (fs.existsSync(source)) {
			count += await copySingleFile(source, dest, file, overwrite);
			continue;
		}

		// Fallback: try standards/steering/ (generic)
		const fallbackSource = path.join(context.extensionPath, 'standards', 'steering', file);
		if (fs.existsSync(fallbackSource)) {
			count += await copySingleFile(fallbackSource, dest, file, overwrite);
			continue;
		}

		console.warn(`[Hotmart AppSec] Source file not found: ${source}`);
	}

	return count;
}

async function applyClaudeFiles(
	context: vscode.ExtensionContext,
	workspaceFolder: string,
	overwrite: boolean = false
): Promise<number> {
	const claudeSourceDir = path.join(context.extensionPath, 'standards', 'claude');
	let count = 0;

	const rulesDir = path.join(workspaceFolder, '.claude', 'rules');
	if (!fs.existsSync(rulesDir)) {
		fs.mkdirSync(rulesDir, { recursive: true });
	}

	for (const file of CLAUDE_FILES.rules) {
		const source = path.join(claudeSourceDir, 'rules', file);
		const dest = path.join(rulesDir, file);
		if (!fs.existsSync(source)) { continue; }
		count += await copySingleFile(source, dest, file, overwrite);
	}

	return count;
}

async function copySingleFile(source: string, dest: string, fileName: string, overwrite: boolean): Promise<number> {
	const sourceContent = fs.readFileSync(source, 'utf-8');

	if (fs.existsSync(dest)) {
		const destContent = fs.readFileSync(dest, 'utf-8');
		if (sourceContent === destContent) { return 0; }

		if (!overwrite) {
			const action = await vscode.window.showWarningMessage(
				`O arquivo "${fileName}" já existe e é diferente da versão corporativa. Sobrescrever?`,
				'Sobrescrever',
				'Manter atual'
			);
			if (action !== 'Sobrescrever') { return 0; }
		}
	}

	fs.writeFileSync(dest, sourceContent, 'utf-8');
	return 1;
}

function getWorkspaceFolder(): string | undefined {
	const folders = vscode.workspace.workspaceFolders;
	if (!folders || folders.length === 0) {
		return undefined;
	}
	return folders[0].uri.fsPath;
}

export function deactivate() {
	if (diagnosticCollection) {
		diagnosticCollection.dispose();
	}
}
