import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { SecuritySidebarProvider } from './sidebar';
import { scanWorkspace, SecurityFinding } from './scanner';

const STEERING_FILES = ['appsec-rules.md', 'executive.md'];

const CLAUDE_FILES = {
	root: ['CLAUDE.md'],
	rules: ['secrets-exposure.md', 'injection.md', 'xss.md', 'auth.md'],
};

const AMAZONQ_FILES = ['secrets-exposure.md', 'injection.md', 'xss.md', 'auth.md'];

const KIRO_FILES = ['secrets-exposure.md', 'injection.md', 'xss.md', 'auth.md'];

const CURSOR_FILES = ['secrets-exposure.mdc', 'injection.mdc', 'xss.mdc', 'auth.mdc'];

const IDE_TARGETS: Record<string, string> = {
	kiro: '.kiro/steering',
	cursor: '.cursor/rules',
	vscode: '.vscode/steering',
	amazonq: '.amazonq/rules',
};

export function activate(context: vscode.ExtensionContext) {
	console.log('Hotmart Cybersecurity Extension activated');

	// Register sidebar webview provider
	const sidebarProvider = new SecuritySidebarProvider(context.extensionUri);
	context.subscriptions.push(
		vscode.window.registerWebviewViewProvider(
			SecuritySidebarProvider.viewType,
			sidebarProvider
		)
	);

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
		() => sidebarProvider.refresh()
	);

	context.subscriptions.push(bootstrapCmd, updateCmd, showGuidelinesCmd, refreshScanCmd);

	// Re-scan when files are saved
	context.subscriptions.push(
		vscode.workspace.onDidSaveTextDocument(() => {
			sidebarProvider.refresh();
		})
	);

	// Pre-commit security guard
	registerPreCommitGuard(context, sidebarProvider);

	// Auto-apply on workspace open if not already present
	autoApplyIfNeeded(context);
}

function registerPreCommitGuard(context: vscode.ExtensionContext, sidebarProvider: SecuritySidebarProvider): void {
	// Listen for git commit via the VS Code Git extension API
	const gitExtension = vscode.extensions.getExtension('vscode.git');
	if (!gitExtension) {
		return;
	}

	const activateGitExtension = async () => {
		const git = gitExtension.isActive ? gitExtension.exports : await gitExtension.activate();
		const api = git.getAPI(1);

		if (!api) {
			return;
		}

		// Register a post-commit command that warns — but the real magic is the pre-commit hook
		// We intercept via onDidChangeState or by wrapping the commit command
		context.subscriptions.push(
			api.onDidOpenRepository((repo: { onDidCommit: (cb: () => void) => vscode.Disposable }) => {
				// For each repo, we can't block commit via API, so we use a file watcher on .git/COMMIT_EDITMSG
				watchForCommitAttempt(context, sidebarProvider);
			})
		);

		// Also watch immediately for existing repos
		if (api.repositories.length > 0) {
			watchForCommitAttempt(context, sidebarProvider);
		}
	};

	activateGitExtension();
}

function watchForCommitAttempt(context: vscode.ExtensionContext, sidebarProvider: SecuritySidebarProvider): void {
	const workspaceFolder = getWorkspaceFolder();
	if (!workspaceFolder) {
		return;
	}

	// Watch for COMMIT_EDITMSG which is created when git commit starts
	const commitMsgPath = path.join(workspaceFolder, '.git', 'COMMIT_EDITMSG');
	const gitDir = path.join(workspaceFolder, '.git');

	if (!fs.existsSync(gitDir)) {
		return;
	}

	const watcher = vscode.workspace.createFileSystemWatcher(
		new vscode.RelativePattern(gitDir, 'COMMIT_EDITMSG')
	);

	watcher.onDidCreate(() => showPreCommitWarning(sidebarProvider));
	watcher.onDidChange(() => showPreCommitWarning(sidebarProvider));

	context.subscriptions.push(watcher);
}

async function showPreCommitWarning(sidebarProvider: SecuritySidebarProvider): Promise<void> {
	// Run a fresh scan to get current findings
	const findings = await scanWorkspace();

	if (findings.length === 0) {
		return;
	}

	const criticalCount = findings.filter(f => f.severity === 'critical').length;
	const highCount = findings.filter(f => f.severity === 'high').length;
	const otherCount = findings.length - criticalCount - highCount;

	let summary = '🛡️ Heads up! ';
	const parts: string[] = [];
	if (criticalCount > 0) {
		parts.push(`${criticalCount} critical`);
	}
	if (highCount > 0) {
		parts.push(`${highCount} high`);
	}
	if (otherCount > 0) {
		parts.push(`${otherCount} other`);
	}
	summary += `Encontrei ${parts.join(', ')} finding(s) de segurança no código. `;
	summary += 'Vale dar uma olhada antes de commitar — a pipeline pode reclamar depois. 😉';

	const action = await vscode.window.showWarningMessage(
		summary,
		'Ver Findings',
		'Commitar Mesmo Assim'
	);

	if (action === 'Ver Findings') {
		// Focus the sidebar
		await vscode.commands.executeCommand('cybersecurity.findingsView.focus');
	}
}

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
			{ label: 'Amazon Q', description: '.amazonq/rules/', id: 'amazonq', picked: true },
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

	// Update each IDE target if directory exists
	for (const [ide, targetPath] of Object.entries(IDE_TARGETS)) {
		const targetDir = path.join(workspaceFolder, targetPath);
		if (fs.existsSync(targetDir)) {
			updated += await applyIdeFiles(context, workspaceFolder, ide, true);
		}
	}

	// Update Claude files if they exist
	const claudeRulesDir = path.join(workspaceFolder, '.claude', 'rules');
	if (fs.existsSync(claudeRulesDir) || fs.existsSync(path.join(workspaceFolder, 'CLAUDE.md'))) {
		updated += await applyClaudeFiles(context, workspaceFolder, true);
	}

	if (updated > 0) {
		vscode.window.showInformationMessage(
			`✅ Padrões atualizados: ${updated} arquivo(s) sincronizado(s).`
		);
	} else {
		vscode.window.showInformationMessage(
			'Nenhum padrão encontrado para atualizar. Execute "Bootstrap Project" primeiro.'
		);
	}
}

async function showGuidelines(context: vscode.ExtensionContext): Promise<void> {
	const standardsDir = path.join(context.extensionPath, 'standards', 'steering');

	const files = STEERING_FILES.map(f => ({
		label: f.replace('.md', '').replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
		description: f,
		file: path.join(standardsDir, f),
	}));

	const selected = await vscode.window.showQuickPick(files, {
		placeHolder: 'Selecione a guideline para visualizar',
	});

	if (selected) {
		const doc = await vscode.workspace.openTextDocument(selected.file);
		await vscode.window.showTextDocument(doc, { preview: true });
	}
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

	// Apply steering files silently — always keep them in sync
	await applyToAllTargets(context, workspaceFolder, true);
}

async function applyToAllTargets(context: vscode.ExtensionContext, workspaceFolder: string, silent: boolean = false): Promise<void> {
	let applied = 0;

	// Apply Kiro files
	applied += await applyIdeFiles(context, workspaceFolder, 'kiro', silent);

	// Apply Cursor files
	applied += await applyIdeFiles(context, workspaceFolder, 'cursor', silent);

	// Apply VS Code files (uses same as Kiro)
	applied += await applyIdeFiles(context, workspaceFolder, 'vscode', silent);

	// Apply Amazon Q files
	applied += await applyIdeFiles(context, workspaceFolder, 'amazonq', silent);

	// Apply Claude files
	applied += await applyClaudeFiles(context, workspaceFolder, silent);

	if (!silent && applied > 0) {
		vscode.window.showInformationMessage(
			`✅ Padrões de segurança aplicados: ${applied} arquivo(s).`
		);
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
			// VS Code uses same files as Kiro
			sourceDir = path.join(context.extensionPath, 'standards', 'kiro', 'steering');
			files = KIRO_FILES;
			break;
		case 'amazonq':
			sourceDir = path.join(context.extensionPath, 'standards', 'amazonq');
			files = AMAZONQ_FILES;
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

		if (!fs.existsSync(source)) {
			continue;
		}

		count += await copySingleFile(source, dest, file, overwrite);
	}

	// Also copy legacy steering files (appsec-rules.md, executive.md) for backward compat
	const legacyDir = path.join(context.extensionPath, 'standards', 'steering');
	for (const file of STEERING_FILES) {
		const source = path.join(legacyDir, file);
		const dest = path.join(targetDir, file);

		if (!fs.existsSync(source)) {
			continue;
		}

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

	// Copy CLAUDE.md to project root
	for (const file of CLAUDE_FILES.root) {
		const source = path.join(claudeSourceDir, file);
		const dest = path.join(workspaceFolder, file);

		if (!fs.existsSync(source)) {
			continue;
		}

		count += await copySingleFile(source, dest, file, overwrite);
	}

	// Copy rules to .claude/rules/
	const rulesDir = path.join(workspaceFolder, '.claude', 'rules');
	if (!fs.existsSync(rulesDir)) {
		fs.mkdirSync(rulesDir, { recursive: true });
	}

	for (const file of CLAUDE_FILES.rules) {
		const source = path.join(claudeSourceDir, 'rules', file);
		const dest = path.join(rulesDir, file);

		if (!fs.existsSync(source)) {
			continue;
		}

		count += await copySingleFile(source, dest, file, overwrite);
	}

	return count;
}

async function copySingleFile(
	source: string,
	dest: string,
	fileName: string,
	overwrite: boolean
): Promise<number> {
	const sourceContent = fs.readFileSync(source, 'utf-8');

	if (fs.existsSync(dest)) {
		const destContent = fs.readFileSync(dest, 'utf-8');
		if (sourceContent === destContent) {
			return 0;
		}

		if (!overwrite) {
			const action = await vscode.window.showWarningMessage(
				`O arquivo "${fileName}" já existe e é diferente da versão corporativa. Sobrescrever?`,
				'Sobrescrever',
				'Manter atual'
			);

			if (action !== 'Sobrescrever') {
				return 0;
			}
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

export function deactivate() {}
