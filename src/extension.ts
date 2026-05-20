import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { SecuritySidebarProvider } from './sidebar';
import { scanChangedLines, SecurityFinding, Severity } from './scanner';

const CLAUDE_FILES = {
	root: ['CLAUDE.md'],
	rules: ['appsec-rules.md'],
};

const KIRO_FILES = ['appsec-rules.md'];

const CURSOR_FILES = ['appsec-rules.mdc'];

const IDE_TARGETS: Record<string, string> = {
	kiro: '.kiro/steering',
	cursor: '.cursor/rules',
	vscode: '.vscode/steering',
};

// Diagnostics collection for security findings
let diagnosticCollection: vscode.DiagnosticCollection;
let currentFindings: SecurityFinding[] = [];

export function activate(context: vscode.ExtensionContext) {
	console.log('Hotmart Cybersecurity Extension activated');

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

	const refreshScanCmd = vscode.commands.registerCommand(
		'cybersecurityextension.refreshScan',
		() => runSecurityScan(sidebarProvider)
	);

	context.subscriptions.push(bootstrapCmd, updateCmd, showGuidelinesCmd, refreshScanCmd);

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

	// Auto-apply steering files on workspace open
	autoApplyIfNeeded(context);
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

		markdown.appendMarkdown(`## 🛡️ ${finding.title}\n\n`);
		markdown.appendMarkdown(`**Severidade:** ${getSeverityEmoji(finding.severity)} ${finding.severity.toUpperCase()}\n\n`);
		markdown.appendMarkdown(`**${finding.cwe}** — ${finding.description}\n\n`);
		markdown.appendMarkdown(`---\n\n`);
		markdown.appendMarkdown(`### 💡 Como corrigir\n\n`);
		markdown.appendMarkdown(`${finding.suggestion}\n\n`);

		if (finding.suggestedFix) {
			markdown.appendMarkdown(`**Correção sugerida:**\n\n`);
			markdown.appendCodeblock(finding.suggestedFix, document.languageId);
		}

		return new vscode.Hover(markdown, new vscode.Range(
			finding.line - 1, finding.column - 1,
			finding.line - 1, finding.endColumn - 1
		));
	}
}

function getSeverityEmoji(severity: Severity): string {
	switch (severity) {
		case 'critical': return '🔴';
		case 'high': return '🟠';
		case 'medium': return '🟡';
		case 'low': return '🟢';
		case 'info': return '🔵';
	}
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
			if (!finding.suggestedFix) {
				continue;
			}

			const action = new vscode.CodeAction(
				`🛡️ Fix: ${finding.title}`,
				vscode.CodeActionKind.QuickFix
			);

			const edit = new vscode.WorkspaceEdit();
			const lineRange = new vscode.Range(
				finding.line - 1, 0,
				finding.line - 1, document.lineAt(finding.line - 1).text.length
			);
			edit.replace(document.uri, lineRange, finding.suggestedFix);
			action.edit = edit;
			action.isPreferred = true;
			action.diagnostics = diagnosticCollection.get(document.uri)?.filter(
				d => d.range.start.line === finding.line - 1
			) as vscode.Diagnostic[] | undefined;

			actions.push(action);
		}

		return actions;
	}
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

	// Watch COMMIT_EDITMSG (created on git commit)
	const commitWatcher = vscode.workspace.createFileSystemWatcher(
		new vscode.RelativePattern(gitDir, 'COMMIT_EDITMSG')
	);

	commitWatcher.onDidCreate(() => onGitOperation(sidebarProvider));
	commitWatcher.onDidChange(() => onGitOperation(sidebarProvider));
	context.subscriptions.push(commitWatcher);

	// Watch index (changes on git add)
	const indexWatcher = vscode.workspace.createFileSystemWatcher(
		new vscode.RelativePattern(gitDir, 'index')
	);

	indexWatcher.onDidChange(() => onGitOperation(sidebarProvider));
	context.subscriptions.push(indexWatcher);
}

async function onGitOperation(sidebarProvider: SecuritySidebarProvider): Promise<void> {
	const findings = await runSecurityScan(sidebarProvider);

	if (findings.length === 0) {
		return;
	}

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

	const selectedTargets = await vscode.window.showQuickPick(
		[
			{ label: 'Kiro', description: '.kiro/steering/', id: 'kiro', picked: true },
			{ label: 'Cursor', description: '.cursor/rules/', id: 'cursor', picked: true },
			{ label: 'VS Code', description: '.vscode/steering/', id: 'vscode', picked: true },
			{ label: 'Claude', description: 'CLAUDE.md + .claude/rules/', id: 'claude', picked: true },
		],
		{
			canPickMany: true,
			placeHolder: 'Selecione as IDEs para aplicar os padrões de segurança',
		}
	);

	if (!selectedTargets || selectedTargets.length === 0) {
		return;
	}

	let applied = 0;
	for (const target of selectedTargets) {
		if (target.id === 'claude') {
			applied += await applyClaudeFiles(context, workspaceFolder);
		} else {
			applied += await applyIdeFiles(context, workspaceFolder, target.id);
		}
	}

	vscode.window.showInformationMessage(
		`✅ Padrões de segurança aplicados: ${applied} arquivo(s) em ${selectedTargets.length} IDE(s).`
	);
}

async function updateStandards(context: vscode.ExtensionContext): Promise<void> {
	const workspaceFolder = getWorkspaceFolder();
	if (!workspaceFolder) {
		vscode.window.showErrorMessage('Nenhum workspace aberto.');
		return;
	}

	let updated = 0;

	for (const [ide, targetPath] of Object.entries(IDE_TARGETS)) {
		const targetDir = path.join(workspaceFolder, targetPath);
		if (fs.existsSync(targetDir)) {
			updated += await applyIdeFiles(context, workspaceFolder, ide, true);
		}
	}

	const claudeRulesDir = path.join(workspaceFolder, '.claude', 'rules');
	if (fs.existsSync(claudeRulesDir) || fs.existsSync(path.join(workspaceFolder, 'CLAUDE.md'))) {
		updated += await applyClaudeFiles(context, workspaceFolder, true);
	}

	if (updated > 0) {
		vscode.window.showInformationMessage(`✅ Padrões atualizados: ${updated} arquivo(s) sincronizado(s).`);
	} else {
		vscode.window.showInformationMessage('Nenhum padrão encontrado para atualizar. Execute "Bootstrap Project" primeiro.');
	}
}

async function showGuidelines(context: vscode.ExtensionContext): Promise<void> {
	const guidelinePath = path.join(context.extensionPath, 'standards', 'steering', 'appsec-rules.md');
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

	applied += await applyIdeFiles(context, workspaceFolder, 'kiro', silent);
	applied += await applyIdeFiles(context, workspaceFolder, 'cursor', silent);
	applied += await applyIdeFiles(context, workspaceFolder, 'vscode', silent);
	applied += await applyClaudeFiles(context, workspaceFolder, silent);

	if (!silent && applied > 0) {
		vscode.window.showInformationMessage(`✅ Padrões de segurança aplicados: ${applied} arquivo(s).`);
	}
}

async function applyIdeFiles(
	context: vscode.ExtensionContext,
	workspaceFolder: string,
	ide: string,
	overwrite: boolean = false
): Promise<number> {
	const targetDir = path.join(workspaceFolder, IDE_TARGETS[ide]);
	let sourceDir: string;
	let files: string[];

	switch (ide) {
		case 'kiro':
			sourceDir = path.join(context.extensionPath, 'standards', 'kiro', 'steering');
			files = KIRO_FILES;
			break;
		case 'cursor':
			sourceDir = path.join(context.extensionPath, 'standards', 'cursor', 'rules');
			files = CURSOR_FILES;
			break;
		case 'vscode':
			sourceDir = path.join(context.extensionPath, 'standards', 'kiro', 'steering');
			files = KIRO_FILES;
			break;
		default:
			return 0;
	}

	if (!fs.existsSync(targetDir)) {
		fs.mkdirSync(targetDir, { recursive: true });
	}

	let count = 0;
	for (const file of files) {
		const source = path.join(sourceDir, file);
		const dest = path.join(targetDir, file);
		if (!fs.existsSync(source)) { continue; }
		count += await copySingleFile(source, dest, file, overwrite);
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

	for (const file of CLAUDE_FILES.root) {
		const source = path.join(claudeSourceDir, file);
		const dest = path.join(workspaceFolder, file);
		if (!fs.existsSync(source)) { continue; }
		count += await copySingleFile(source, dest, file, overwrite);
	}

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
