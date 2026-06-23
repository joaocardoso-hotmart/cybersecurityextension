import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import * as https from 'https';
import { execFile, execSync } from 'child_process';
import { promisify } from 'util';
import { SecuritySidebarProvider } from './sidebar';
import { scanChangedLines, SecurityFinding, Severity, setExtensionPath } from './scanner';
import { ensureOpenGrep, runOpenGrep } from './semgrep';

const execFileAsync = promisify(execFile);

/**
 * Runs a git command asynchronously, returns trimmed stdout or empty string on error.
 */
async function gitCmd(args: string[], cwd: string): Promise<string> {
	try {
		const { stdout } = await execFileAsync('git', args, { cwd, encoding: 'utf-8', timeout: 10000 });
		return stdout.trim();
	} catch {
		return '';
	}
}

/**
 * Quick check for paths that should never be scanned on save.
 */
function isExcludedFilePath(filePath: string): boolean {
	return /^(\.kiro|\.cursor|\.claude|\.vscode|\.github|node_modules|out|dist|build)\//i.test(filePath)
		|| /\.(lock|min\.js|bundle\.js)$/.test(filePath);
}

/**
 * Checks whether a workspace folder contains at least one source code file.
 * Scans up to 2 levels deep to stay fast, skipping typical non-code directories.
 * Returns true as soon as one code file is found.
 */
function hasCodeFiles(workspaceFolder: string): boolean {
	const CODE_EXTENSIONS = /\.(ts|tsx|js|jsx|mjs|cjs|java|kt|kts|py|pyi|go|rb|php|c|h|cpp|hpp|cs|swift|rs|scala|vue|svelte|dart)$/i;
	const SKIP_DIRS = new Set([
		'node_modules', '.git', '.kiro', '.cursor', '.claude', '.vscode',
		'.github', 'out', 'dist', 'build', '.appsec', '__pycache__', '.next',
		'vendor', 'target', '.gradle', 'bin', 'obj',
	]);

	function scanDir(dir: string, depth: number): boolean {
		if (depth > 2) { return false; }
		let entries: fs.Dirent[];
		try {
			entries = fs.readdirSync(dir, { withFileTypes: true });
		} catch {
			return false;
		}
		for (const entry of entries) {
			if (entry.isFile() && CODE_EXTENSIONS.test(entry.name)) {
				return true;
			}
			if (entry.isDirectory() && !SKIP_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
				const child = path.normalize(path.join(dir, entry.name));
				if (!child.startsWith(workspaceFolder + path.sep)) { continue; }
				if (scanDir(child, depth + 1)) {
					return true;
				}
			}
		}
		return false;
	}

	return scanDir(workspaceFolder, 0);
}

const CLAUDE_FILES = {
	rules: ['appsec-rules.md'],
};

/**
 * Returns true when running on Windows.
 */
function isWindows(): boolean {
	return process.platform === 'win32';
}

/**
 * Returns the gate script command appropriate for the current OS.
 * On Windows uses PowerShell with -ExecutionPolicy Bypass; on macOS/Linux uses bash.
 */
function gateCommand(scriptRelativePath: string): string {
	if (isWindows()) {
		// Use -NoProfile to skip user profile scripts and -ExecutionPolicy Bypass
		// to ensure the script runs even in locked-down corporate environments.
		const ps1Path = scriptRelativePath.replace(/\.sh$/, '.ps1');
		return `powershell -NoProfile -ExecutionPolicy Bypass -File "${ps1Path}"`;
	}
	return `bash ${scriptRelativePath}`;
}

/**
 * Returns the file extension for gate scripts on the current platform.
 */
function gateScriptExtension(): string {
	return isWindows() ? '.ps1' : '.sh';
}

/**
 * Detects which IDE is running based on vscode.env.uriScheme.
 */
function detectIDE(): string {
	const scheme = vscode.env.uriScheme;
	console.log(`[Hotmart AppSec] detectIDE: uriScheme=${scheme}`);
	if (scheme === 'kiro') { return 'kiro'; }
	if (scheme === 'cursor') { return 'cursor'; }
	return 'vscode';
}

// Diagnostics collection for security findings
let diagnosticCollection: vscode.DiagnosticCollection;
let currentFindings: SecurityFinding[] = [];
let _extensionContext: vscode.ExtensionContext;

export function activate(context: vscode.ExtensionContext) {
	console.log('Hotmart Cybersecurity Extension activated');

	_extensionContext = context;

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

	// Command to mark a finding as fixed
	const markFixedCmd = vscode.commands.registerCommand(
		'cybersecurityextension.markFindingFixed',
		(...args: unknown[]) => markFindingFixed(args[0], sidebarProvider)
	);
	context.subscriptions.push(markFixedCmd);

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

	// Watch for file saves — re-scan to auto-remove fixed findings
	registerFileSaveWatcher(context, sidebarProvider);

	// Watch for git operations (commit / staging)
	registerGitWatcher(context, sidebarProvider);

	// Ensure OpenGrep is installed
	ensureOpenGrep();

	// Detect install/update of the extension to force hook re-installation
	const installState = detectInstallOrUpdate(context);
	const force = installState !== 'none';

	// Migrate legacy .appsec-state/ folder into .appsec/ (consolidation in v0.9+)
	if (force) {
		migrateLegacyAppsecState();
		cleanupLegacyWorkflows();
	}

	// Always clean up legacy hooks that cause performance issues (runs fast, no-op if absent)
	cleanupLegacyGlobalKiroHook();

	// Fix global steering file if it exists but is missing description (legacy MDM installs)
	ensureGlobalSteeringFile(context);

	// Auto-apply steering files on workspace open (only if workspace has code)
	autoApplyIfNeeded(context, force).catch(err => {
		console.error('[Hotmart AppSec] autoApplyIfNeeded failed:', err);
	});

	// On install/update: remove security files from workspaces that have no code
	if (force) {
		cleanupSecurityFilesIfNoCode();
	}

	// Ensure preToolUse hook exists (runs on every activation, forces overwrite on install/update)
	ensureSecurityHookAllWorkspaces(context, force);

	// Direct IDE rule file creation (safety net, forces overwrite on install/update)
	ensureIdeRuleFilesAllWorkspaces(context, force);

	// Watch for new code files being created — apply security if workspace becomes a code project
	registerCodeFileCreationWatcher(context);

	// Notify the user when the extension is freshly installed or updated
	if (installState === 'install') {
		vscode.window.showInformationMessage(
			'[Hotmart AppSec] 🛡️ Extensão instalada com sucesso! Os hooks de segurança corporativa foram configurados nos seus workspaces. Estamos aqui pra te ajudar a manter o código seguro. 💪'
		);
		// On Windows, alert the user about PowerShell execution policy
		if (isWindows()) {
			notifyWindowsExecutionPolicy();
		}
	} else if (installState === 'update') {
		vscode.window.showInformationMessage(
			'[Hotmart AppSec] 🛡️ Extensão atualizada! Hooks e padrões de segurança corporativa sincronizados. Tudo certo por aqui. ✨'
		);
	}

	// React to workspace folder changes so newly added folders also get the hooks
	context.subscriptions.push(
		vscode.workspace.onDidChangeWorkspaceFolders(() => {
			ensureSecurityHookAllWorkspaces(context, false);
			ensureIdeRuleFilesAllWorkspaces(context, false);
		})
	);

	// Check for newer version in the marketplace and alert the user
	checkForExtensionUpdate(context);
}

/**
 * Detects whether this activation is the first install or an update of the extension.
 * Stores the last seen version in globalState, so it persists across workspaces.
 */
function detectInstallOrUpdate(context: vscode.ExtensionContext): 'install' | 'update' | 'none' {
	const STATE_KEY = 'hotmartAppSec.lastVersion';
	let currentVersion = '0.0.0';
	try {
		currentVersion = (context.extension?.packageJSON?.version as string) || currentVersion;
	} catch { /* extension property may be unavailable on older VS Code APIs */ }

	const lastVersion = context.globalState.get<string>(STATE_KEY);

	if (!lastVersion) {
		void context.globalState.update(STATE_KEY, currentVersion);
		console.log(`[Hotmart AppSec] First install detected (version=${currentVersion})`);
		return 'install';
	}

	if (lastVersion !== currentVersion) {
		void context.globalState.update(STATE_KEY, currentVersion);
		console.log(`[Hotmart AppSec] Update detected (${lastVersion} → ${currentVersion})`);
		return 'update';
	}

	return 'none';
}

/**
 * Notifies Windows users about the PowerShell execution policy requirement.
 * The extension's security hooks use PowerShell scripts (.ps1). On corporate machines
 * the default execution policy may block these scripts. This notification guides the
 * user to allow execution or provides the command to fix it.
 */
function notifyWindowsExecutionPolicy(): void {
	const STATE_KEY = 'hotmartAppSec.winPolicyNotified';

	// Only show once per machine (persisted in globalState)
	if (_extensionContext.globalState.get<boolean>(STATE_KEY)) { return; }

	void _extensionContext.globalState.update(STATE_KEY, true);

	const message =
		'[Hotmart AppSec] 🛡️ Windows detectado! Os hooks de segurança usam scripts PowerShell (.ps1). ' +
		'Se o Windows solicitar permissão para executar, por favor aprove — é a ferramenta de segurança ' +
		'corporativa protegendo seu código contra vazamento de credenciais e padrões inseguros. ' +
		'Caso os scripts sejam bloqueados, execute no PowerShell (Admin): ' +
		'Set-ExecutionPolicy RemoteSigned -Scope CurrentUser';

	vscode.window.showWarningMessage(message, 'Copiar Comando', 'Entendi').then(action => {
		if (action === 'Copiar Comando') {
			vscode.env.clipboard.writeText('Set-ExecutionPolicy RemoteSigned -Scope CurrentUser');
			vscode.window.showInformationMessage(
				'[Hotmart AppSec] Comando copiado! Cole no PowerShell como Administrador e pressione Enter. ' +
				'Isso permite a execução de scripts locais assinados e é seguro para uso corporativo.'
			);
		}
	});
}

/**
 * Migrates the legacy `.appsec-state/` folder into `.appsec/`.
 * Moves `dismissed.json` if it exists in the old location, then removes the empty folder.
 * Runs on install/update so devs who had the old layout get cleaned up automatically.
 */
function migrateLegacyAppsecState(): void {
	const folders = vscode.workspace.workspaceFolders;
	if (!folders || folders.length === 0) { return; }

	for (const folder of folders) {
		const workspaceFolder = folder.uri.fsPath;
		const legacyDir = path.join(workspaceFolder, '.appsec-state');
		const legacyFile = path.join(legacyDir, 'dismissed.json');
		const newDir = path.join(workspaceFolder, '.appsec');
		const newFile = path.join(newDir, 'dismissed.json');

		if (!fs.existsSync(legacyDir)) { continue; }

		try {
			// Move dismissed.json to the new location (merge if both exist)
			if (fs.existsSync(legacyFile)) {
				if (!fs.existsSync(newDir)) {
					fs.mkdirSync(newDir, { recursive: true });
				}

				if (fs.existsSync(newFile)) {
					// Merge: combine both arrays, dedup by id+file+line
					const oldData = JSON.parse(fs.readFileSync(legacyFile, 'utf-8')) as Array<{ id: string; file: string; line: number }>;
					const newData = JSON.parse(fs.readFileSync(newFile, 'utf-8')) as Array<{ id: string; file: string; line: number }>;
					const seen = new Set(newData.map(d => `${d.id}:${d.file}:${d.line}`));
					for (const entry of oldData) {
						if (!seen.has(`${entry.id}:${entry.file}:${entry.line}`)) {
							newData.push(entry);
						}
					}
					fs.writeFileSync(newFile, JSON.stringify(newData, null, 2), 'utf-8');
				} else {
					// Simply move the file
					fs.copyFileSync(legacyFile, newFile);
				}
				fs.unlinkSync(legacyFile);
			}

			// Remove the legacy directory if now empty
			const remaining = fs.readdirSync(legacyDir);
			if (remaining.length === 0) {
				fs.rmdirSync(legacyDir);
				console.log(`[Hotmart AppSec] Migrated .appsec-state/ → .appsec/ in ${workspaceFolder}`);
			}
		} catch (err) {
			console.warn(`[Hotmart AppSec] Migration of .appsec-state failed:`, err);
		}
	}
}

/**
 * Removes legacy workflow files from workspaces that were generated by older versions
 * of the extension. Specifically removes `ci-cd.yml` which is no longer distributed.
 * Runs on install/update.
 */
function cleanupLegacyWorkflows(): void {
	const folders = vscode.workspace.workspaceFolders;
	if (!folders || folders.length === 0) { return; }

	const LEGACY_WORKFLOWS = ['ci-cd.yml'];

	for (const folder of folders) {
		const workflowsDir = path.join(folder.uri.fsPath, '.github', 'workflows');
		if (!fs.existsSync(workflowsDir)) { continue; }

		for (const legacyFile of LEGACY_WORKFLOWS) {
			const filePath = path.join(workflowsDir, legacyFile);
			try {
				if (fs.existsSync(filePath)) {
					fs.unlinkSync(filePath);
					console.log(`[Hotmart AppSec] Removed legacy workflow: ${filePath}`);
				}
			} catch (err) {
				console.warn(`[Hotmart AppSec] Could not remove legacy workflow ${legacyFile}:`, err);
			}
		}
	}
}

/**
 * On install/update, checks all workspace folders for code files.
 * If a workspace has NO code but already has security files (steering, hooks, workflow)
 * from a previous version, removes them to keep the workspace clean.
 */
function cleanupSecurityFilesIfNoCode(): void {
	const folders = vscode.workspace.workspaceFolders;
	if (!folders || folders.length === 0) { return; }

	const currentIde = detectIDE();

	for (const folder of folders) {
		const ws = folder.uri.fsPath;

		if (hasCodeFiles(ws)) { continue; }

		console.log(`[Hotmart AppSec] No code detected in ${ws} — removing security files`);

		// Files/dirs generated by the extension that should be removed
		const filesToRemove = [
			path.join(ws, '.appsec', 'appsec-gate.sh'),
			path.join(ws, '.appsec', 'appsec-gate.ps1'),
			path.join(ws, '.appsec', 'appsec-gate-kiro.sh'),
			path.join(ws, '.appsec', 'appsec-gate-kiro.ps1'),
			path.join(ws, '.github', 'workflows', 'appsec-guard.yml'),
			path.join(ws, '.github', 'workflows', 'ci-cd.yml'),
			path.join(ws, '.claude', 'settings.json'),
			path.join(ws, '.claude', 'rules', 'appsec-rules.md'),
			path.join(ws, '.cursor', 'hooks.json'),
			path.join(ws, '.cursor', 'rules', 'appsec-rules.mdc'),
			path.join(ws, '.kiro', 'hooks', 'appsec-gate.json'),
			path.join(ws, '.kiro', 'steering', 'appsec-rules.md'),
			path.join(ws, '.github', 'copilot-instructions.md'),
		];

		for (const file of filesToRemove) {
			try {
				if (fs.existsSync(file)) {
					fs.unlinkSync(file);
					console.log(`[Hotmart AppSec] Removed: ${file}`);
				}
			} catch { /* best effort */ }
		}

		// Remove empty directories left behind (bottom-up)
		const dirsToClean = [
			path.join(ws, '.appsec'),
			path.join(ws, '.claude', 'rules'),
			path.join(ws, '.claude'),
			path.join(ws, '.cursor', 'rules'),
			path.join(ws, '.cursor'),
			path.join(ws, '.kiro', 'hooks'),
			path.join(ws, '.kiro', 'steering'),
			path.join(ws, '.kiro'),
			path.join(ws, '.github', 'workflows'),
			path.join(ws, '.github'),
		];

		for (const dir of dirsToClean) {
			try {
				if (fs.existsSync(dir)) {
					const contents = fs.readdirSync(dir);
					if (contents.length === 0) {
						fs.rmdirSync(dir);
						console.log(`[Hotmart AppSec] Removed empty dir: ${dir}`);
					}
				}
			} catch { /* best effort */ }
		}
	}
}

/**
 * Watches for creation of code files in workspace folders.
 * When a code file is created in a workspace that previously had no code,
 * applies security standards automatically.
 */
function registerCodeFileCreationWatcher(context: vscode.ExtensionContext): void {
	const CODE_PATTERN = '**/*.{ts,tsx,js,jsx,mjs,cjs,java,kt,kts,py,pyi,go,rb,php,c,h,cpp,hpp,cs,swift,rs,scala,vue,svelte,dart}';
	const watcher = vscode.workspace.createFileSystemWatcher(CODE_PATTERN, false, true, true);

	// Tracks which folders already had security applied (avoid re-applying on every file)
	const appliedFolders = new Set<string>();

	// Pre-populate with folders that already have code
	const folders = vscode.workspace.workspaceFolders;
	if (folders) {
		for (const folder of folders) {
			if (hasCodeFiles(folder.uri.fsPath)) {
				appliedFolders.add(folder.uri.fsPath);
			}
		}
	}

	watcher.onDidCreate((uri) => {
		const folder = vscode.workspace.getWorkspaceFolder(uri);
		if (!folder) { return; }
		if (appliedFolders.has(folder.uri.fsPath)) { return; }

		// First code file in this workspace — apply security standards
		console.log(`[Hotmart AppSec] First code file detected in ${folder.uri.fsPath}: ${uri.fsPath}`);
		appliedFolders.add(folder.uri.fsPath);

		applyToAllTargets(context, folder.uri.fsPath, true, true).catch(err => {
			console.error('[Hotmart AppSec] Error applying standards after code file creation:', err);
		});
	});

	context.subscriptions.push(watcher);
}

/**
 * Removes the legacy `.kiro.hook` file from the user-level hooks directory (~/.kiro/hooks/).
 * Previous versions (and MDM installs) placed this file there, but Kiro requires `.json` format.
 */
function cleanupLegacyGlobalKiroHook(): void {
	if (detectIDE() !== 'kiro') { return; }

	const homeDir = process.env.HOME || process.env.USERPROFILE || '';
	if (!homeDir) { return; }

	const legacyHook = path.join(homeDir, '.kiro', 'hooks', 'appsec-gate.kiro.hook');
	try {
		if (fs.existsSync(legacyHook)) {
			fs.unlinkSync(legacyHook);
			console.log(`[Hotmart AppSec] Removed legacy global hook: ${legacyHook}`);
		}
	} catch (err) {
		console.warn(`[Hotmart AppSec] Could not remove legacy global hook:`, err);
	}
}

/**
 * Ensures the global (user-level) Kiro steering file at ~/.kiro/steering/appsec-rules.md
 * has the required front-matter with `description`. Legacy MDM installs may have written
 * this file without the field, causing Kiro to show a "Progressive steering file missing
 * description" warning.
 *
 * Only runs when the IDE is Kiro. Overwrites only if the file exists but lacks `description`.
 */
function ensureGlobalSteeringFile(context: vscode.ExtensionContext): void {
	if (detectIDE() !== 'kiro') { return; }

	const homeDir = process.env.HOME || process.env.USERPROFILE || '';
	if (!homeDir) { return; }

	const globalSteering = path.join(homeDir, '.kiro', 'steering', 'appsec-rules.md');

	if (!fs.existsSync(globalSteering)) { return; }

	try {
		const content = fs.readFileSync(globalSteering, 'utf-8');

		// Check if it has a front-matter block with description
		const frontMatterMatch = content.match(/^---\s*\n([\s\S]*?)\n---/);
		if (!frontMatterMatch) {
			// No front-matter at all — rewrite with proper content
			writeGlobalSteering(globalSteering, context);
			return;
		}

		const frontMatter = frontMatterMatch[1];
		if (!frontMatter.includes('description:')) {
			// Has front-matter but missing description — rewrite
			writeGlobalSteering(globalSteering, context);
			return;
		}

		// description exists — check it's not empty
		const descMatch = frontMatter.match(/description:\s*["']?(.*)["']?/);
		if (descMatch && descMatch[1].trim().length === 0) {
			writeGlobalSteering(globalSteering, context);
		}
	} catch (err) {
		console.error('[Hotmart AppSec] ensureGlobalSteeringFile error:', err);
	}
}

function writeGlobalSteering(filePath: string, context: vscode.ExtensionContext): void {
	// Use the bundled source file if available, otherwise write inline
	const sourceFile = path.join(context.extensionPath, 'standards', 'kiro', 'steering', 'appsec-rules.md');

	if (fs.existsSync(sourceFile)) {
		const sourceContent = fs.readFileSync(sourceFile, 'utf-8');
		fs.mkdirSync(path.dirname(filePath), { recursive: true });
		fs.writeFileSync(filePath, sourceContent, 'utf-8');
	} else {
		// Inline fallback — minimal version that still passes integrity checks
		const content = `---
inclusion: auto
description: "Regras de segurança corporativas que proíbem práticas inseguras na geração de código por IA."
---
# SECURITY CRITICAL RULES — NON-BYPASSABLE POLICY

This assistant MUST always generate secure-by-default code.
FORBIDDEN: hardcoded credentials, SQL injection, eval() with user input,
disabled TLS, tokens in localStorage, MD5/SHA1 for passwords, stack traces to client.
Always use environment variables or a secret manager for credentials.
`;
		fs.mkdirSync(path.dirname(filePath), { recursive: true });
		fs.writeFileSync(filePath, content, 'utf-8');
	}
	console.log(`[Hotmart AppSec] Global steering file fixed: ${filePath}`);
}

function ensureSecurityHookAllWorkspaces(context: vscode.ExtensionContext, force: boolean): void {
	const folders = vscode.workspace.workspaceFolders;
	if (!folders || folders.length === 0) {
		console.log('[Hotmart AppSec] ensureSecurityHookAllWorkspaces: no workspace folders');
		return;
	}
	for (const folder of folders) {
		if (!hasCodeFiles(folder.uri.fsPath)) { continue; }
		ensureSecurityHookForWorkspace(context, folder.uri.fsPath, force);
	}
}

function ensureIdeRuleFilesAllWorkspaces(context: vscode.ExtensionContext, force: boolean): void {
	const folders = vscode.workspace.workspaceFolders;
	if (!folders || folders.length === 0) { return; }
	for (const folder of folders) {
		if (!hasCodeFiles(folder.uri.fsPath)) { continue; }
		ensureIdeRuleFilesForWorkspace(context, folder.uri.fsPath, force);
	}
}

// ─── AUTO-INSTALL SECURITY HOOK ───────────────────────────────────────────────

/**
 * Directly ensures IDE-specific rule files exist in the given workspace folder.
 * Runs on every activation as a safety net. When `force` is true, overwrites the
 * destination file even if it already exists (used on install/update).
 */
function ensureIdeRuleFilesForWorkspace(
	context: vscode.ExtensionContext,
	workspaceFolder: string,
	force: boolean
): void {
	const currentIde = detectIDE();
	console.log(`[Hotmart AppSec] ensureIdeRuleFiles: ide=${currentIde}, workspace=${workspaceFolder}, force=${force}`);

	switch (currentIde) {
		case 'vscode': {
			const targetDir = path.join(workspaceFolder, '.github');
			const destFile = path.join(targetDir, 'copilot-instructions.md');
			const sourceFile = path.join(context.extensionPath, 'standards', 'steering', 'copilot-instructions.md');

			if (!fs.existsSync(sourceFile)) {
				console.error(`[Hotmart AppSec] missing source: ${sourceFile}`);
				return;
			}
			if (fs.existsSync(destFile) && !force) { return; }

			if (!fs.existsSync(targetDir)) { fs.mkdirSync(targetDir, { recursive: true }); }
			fs.copyFileSync(sourceFile, destFile);
			console.log(`[Hotmart AppSec] Created/updated ${destFile}`);
			break;
		}
		case 'cursor': {
			const targetDir = path.join(workspaceFolder, '.cursor', 'rules');
			const destFile = path.join(targetDir, 'appsec-rules.mdc');
			const sourceFile = path.join(context.extensionPath, 'standards', 'cursor', 'rules', 'appsec-rules.mdc');

			if (!fs.existsSync(sourceFile)) {
				console.error(`[Hotmart AppSec] missing source: ${sourceFile}`);
				return;
			}
			if (fs.existsSync(destFile) && !force) { return; }

			if (!fs.existsSync(targetDir)) { fs.mkdirSync(targetDir, { recursive: true }); }
			fs.copyFileSync(sourceFile, destFile);
			console.log(`[Hotmart AppSec] Created/updated ${destFile}`);
			break;
		}
		case 'kiro': {
			const targetDir = path.join(workspaceFolder, '.kiro', 'steering');
			const destFile = path.join(targetDir, 'appsec-rules.md');
			const sourceFile = path.join(context.extensionPath, 'standards', 'kiro', 'steering', 'appsec-rules.md');

			if (!fs.existsSync(sourceFile)) { return; }
			if (fs.existsSync(destFile) && !force) { return; }

			if (!fs.existsSync(targetDir)) { fs.mkdirSync(targetDir, { recursive: true }); }
			fs.copyFileSync(sourceFile, destFile);
			console.log(`[Hotmart AppSec] Created/updated ${destFile}`);
			break;
		}
	}
}

function ensureSecurityHookForWorkspace(
	context: vscode.ExtensionContext,
	workspaceFolder: string,
	force: boolean
): void {
	const currentIde = detectIDE();

	// Always install the gate script — Claude Code, Cursor and the git pre-commit hook share it.
	installAppsecGateScript(context, workspaceFolder, force);

	// Install Kiro hook if running in Kiro
	if (currentIde === 'kiro') {
		installKiroHookOnActivate(context, workspaceFolder, force);
	}

	// Install Cursor hook if running in Cursor
	if (currentIde === 'cursor') {
		installCursorHookOnActivate(context, workspaceFolder, force);
	}

	// Always install Claude Code hook (Claude Code is used alongside any IDE)
	installClaudeHookOnActivate(context, workspaceFolder, force);

	// Install git pre-commit hook — overwrites on install/update or when the legacy blocking hook is detected
	installGitPreCommitHook(context, workspaceFolder, force);
}

/**
 * Copies the shared gate script to `.appsec/`.
 * On Windows installs appsec-gate.ps1; on macOS/Linux installs appsec-gate.sh.
 * Both versions are always installed so cross-platform repos work for all devs.
 */
function installAppsecGateScript(
	context: vscode.ExtensionContext,
	workspaceFolder: string,
	force: boolean
): void {
	const appsecDir = path.join(workspaceFolder, '.appsec');

	if (!fs.existsSync(appsecDir)) {
		fs.mkdirSync(appsecDir, { recursive: true });
	}

	// Install both .sh and .ps1 so the repo works for devs on any OS
	const scripts = [
		{ src: 'appsec-gate.sh', dest: 'appsec-gate.sh' },
		{ src: 'appsec-gate.ps1', dest: 'appsec-gate.ps1' },
	];

	for (const { src, dest } of scripts) {
		const scriptSource = path.join(context.extensionPath, 'standards', 'hooks', src);
		const scriptDest = path.join(appsecDir, dest);

		if (!fs.existsSync(scriptSource)) { continue; }
		if (fs.existsSync(scriptDest) && !force) { continue; }

		fs.copyFileSync(scriptSource, scriptDest);
		// chmod is no-op on Windows but needed for macOS/Linux
		try { fs.chmodSync(scriptDest, 0o755); } catch { /* not fatal on Windows */ }
		console.log(`[Hotmart AppSec] Gate script installed/updated at ${scriptDest}`);
	}
}

function installKiroHookOnActivate(
	context: vscode.ExtensionContext,
	workspaceFolder: string,
	force: boolean
): void {
	const hooksDir = path.join(workspaceFolder, '.kiro', 'hooks');
	const hookFile = path.join(hooksDir, 'appsec-gate.json');

	if (fs.existsSync(hookFile) && !force) {
		// Clean up legacy files from previous versions of the extension
		cleanupLegacyKiroHook(hooksDir);
		return;
	}

	if (!fs.existsSync(hooksDir)) {
		fs.mkdirSync(hooksDir, { recursive: true });
	}

	// Generate hook JSON with platform-appropriate command
	const hookContent = {
		version: 'v1',
		hooks: [
			{
				name: 'AppSec Gate \u2014 Write Operations',
				trigger: 'PreToolUse',
				matcher: 'fs_write|str_replace|fs_append',
				action: {
					type: 'command',
					command: gateCommand('.appsec/appsec-gate-kiro' + gateScriptExtension()),
				},
			},
		],
	};
	fs.writeFileSync(hookFile, JSON.stringify(hookContent, null, 2), 'utf-8');

	// Install the platform-specific gate script used by the hook
	const appsecDir = path.join(workspaceFolder, '.appsec');
	if (!fs.existsSync(appsecDir)) { fs.mkdirSync(appsecDir, { recursive: true }); }

	// Install both .sh and .ps1 so the repo works cross-platform
	const kiroScripts = [
		{ src: path.join('kiro', 'appsec-gate-kiro.sh'), dest: 'appsec-gate-kiro.sh' },
		{ src: path.join('kiro', 'appsec-gate-kiro.ps1'), dest: 'appsec-gate-kiro.ps1' },
	];

	for (const { src, dest } of kiroScripts) {
		const source = path.join(context.extensionPath, 'standards', 'hooks', src);
		const destPath = path.join(appsecDir, dest);
		if (!fs.existsSync(source)) { continue; }
		fs.copyFileSync(source, destPath);
		try { fs.chmodSync(destPath, 0o755); } catch { /* not fatal on Windows */ }
	}

	cleanupLegacyKiroHook(hooksDir);
	console.log(`[Hotmart AppSec] Kiro hook installed/updated at ${hookFile}`);
}

/**
 * Removes legacy Kiro hook files left by older versions of this extension.
 * Current format is `.json` (Kiro v2 schema). Old formats: `.kiro.hook`.
 */
function cleanupLegacyKiroHook(hooksDir: string): void {
	const legacyFiles = [
		path.join(hooksDir, 'appsec-gate.kiro.hook'),
	];
	for (const legacy of legacyFiles) {
		try {
			if (fs.existsSync(legacy)) {
				fs.unlinkSync(legacy);
				console.log(`[Hotmart AppSec] Removed legacy hook ${legacy}`);
			}
		} catch (err) {
			console.warn(`[Hotmart AppSec] Could not remove legacy hook: ${err}`);
		}
	}
}

function installClaudeHookOnActivate(
	context: vscode.ExtensionContext,
	workspaceFolder: string,
	force: boolean
): void {
	// Install .claude/settings.json with PreToolUse hook
	const claudeDir = path.join(workspaceFolder, '.claude');
	const settingsFile = path.join(claudeDir, 'settings.json');

	if (fs.existsSync(settingsFile) && !force) { return; }

	if (!fs.existsSync(claudeDir)) {
		fs.mkdirSync(claudeDir, { recursive: true });
	}

	// Generate settings with platform-appropriate command
	const settings = {
		hooks: {
			PreToolUse: [
				{
					matcher: 'Write|Edit|MultiEdit|CreateFile',
					hooks: [
						{
							type: 'command',
							command: gateCommand('.appsec/appsec-gate' + gateScriptExtension()),
						},
					],
				},
			],
		},
	};
	fs.writeFileSync(settingsFile, JSON.stringify(settings, null, 2), 'utf-8');
	console.log(`[Hotmart AppSec] Claude Code hook installed/updated at ${settingsFile}`);
}

function installCursorHookOnActivate(
	context: vscode.ExtensionContext,
	workspaceFolder: string,
	force: boolean
): void {
	// Install .cursor/hooks.json with beforeSubmitPrompt + afterFileEdit hooks
	const cursorDir = path.join(workspaceFolder, '.cursor');
	const hooksFile = path.join(cursorDir, 'hooks.json');

	if (fs.existsSync(hooksFile) && !force) { return; }

	if (!fs.existsSync(cursorDir)) {
		fs.mkdirSync(cursorDir, { recursive: true });
	}

	// Generate hooks with platform-appropriate command
	const cmd = gateCommand('.appsec/appsec-gate' + gateScriptExtension());
	const hooks = {
		hooks: {
			beforeSubmitPrompt: { command: cmd },
			afterFileEdit: { command: cmd },
		},
	};
	fs.writeFileSync(hooksFile, JSON.stringify(hooks, null, 2), 'utf-8');
	console.log(`[Hotmart AppSec] Cursor hook installed/updated at ${hooksFile}`);
}

/**
 * Returns true when the given hook file contains the legacy blocking pattern (`exit $?`)
 * generated by previous versions of this extension on Windows.
 * That pattern propagated the PowerShell exit code directly to git, causing commits to be
 * blocked whenever the regex found a match. The new hook is advisory-only (always exit 0).
 */
function isLegacyBlockingHook(hookFile: string): boolean {
	try {
		const content = fs.readFileSync(hookFile, 'utf-8');
		return content.includes('exit $?');
	} catch {
		return false;
	}
}

function installGitPreCommitHook(context: vscode.ExtensionContext, workspaceFolder: string, force: boolean): void {
	const gitHooksDir = path.join(workspaceFolder, '.git', 'hooks');
	const preCommitFile = path.join(gitHooksDir, 'pre-commit');

	// Only install if .git exists (it's a git repo)
	if (!fs.existsSync(path.join(workspaceFolder, '.git'))) {
		return;
	}

	// Skip if hook already exists, UNLESS:
	// - force is true (install/update detected), OR
	// - the existing hook contains the legacy blocking pattern (exit $?) from a prior extension version
	if (fs.existsSync(preCommitFile)) {
		if (!force && !isLegacyBlockingHook(preCommitFile)) {
			return;
		}
		console.log(`[Hotmart AppSec] Upgrading legacy blocking pre-commit hook → advisory-only at ${preCommitFile}`);
	}

	if (!fs.existsSync(gitHooksDir)) {
		fs.mkdirSync(gitHooksDir, { recursive: true });
	}

	if (isWindows()) {
		// On Windows, Git for Windows runs hooks via its bundled bash (sh.exe).
		// This hook is ADVISORY ONLY — it warns about security issues but NEVER blocks the commit.
		// Blocking is intentionally omitted: the VS Code extension handles real-time findings
		// with full context via OpenGrep rules, avoiding the false-positive risk of simple regex.
		const preCommitContent = `#!/bin/sh
# AppSec pre-commit hook (Windows) — ADVISORY ONLY
# Scans staged files for security issues and warns the developer.
# This hook NEVER blocks commits — only alerts. Real-time scanning is handled
# by the VS Code extension sidebar with full OpenGrep rule analysis.

# Only scan source code files (skip lock files, generated code, config, etc.)
STAGED=$(git -c core.quotePath=false diff --cached --name-only --diff-filter=ACMR 2>/dev/null | grep -iE '\\.(ts|tsx|js|jsx|java|py|go|rb|php|c|cpp|cs|swift|kt|rs|scala)$')
[ -z "$STAGED" ] && exit 0

# Prefer OpenGrep when available — more accurate, avoids false positives
GIT_ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
RULES_FILE=""
[ -f "$GIT_ROOT/rules/security.yml" ] && RULES_FILE="$GIT_ROOT/rules/security.yml"

if command -v opengrep >/dev/null 2>&1 && [ -n "$RULES_FILE" ]; then
  opengrep scan --quiet --config="$RULES_FILE" $STAGED 2>/dev/null || true
  exit 0
fi

# Fallback: PowerShell regex check (warning only — exit code is intentionally discarded)
if command -v powershell.exe >/dev/null 2>&1 && [ -f ".appsec/appsec-gate.ps1" ]; then
  git diff --cached --diff-filter=ACM -p 2>/dev/null | \\
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".appsec/appsec-gate.ps1" 2>&1 || true
fi

# Advisory only — NEVER block the commit
exit 0
`;
		fs.writeFileSync(preCommitFile, preCommitContent, 'utf-8');
	} else {
		// macOS/Linux: use bundled pre-commit if available, otherwise generate advisory-only fallback
		const sourceFile = path.join(context.extensionPath, 'standards', 'hooks', 'pre-commit');
		if (fs.existsSync(sourceFile)) {
			fs.copyFileSync(sourceFile, preCommitFile);
		} else {
			const preCommitContent = `#!/bin/sh
# AppSec pre-commit hook — ADVISORY ONLY
if [ -f ".appsec/appsec-gate.sh" ]; then
  git diff --cached --diff-filter=ACM -p | bash .appsec/appsec-gate.sh 2>&1 || true
fi
exit 0
`;
			fs.writeFileSync(preCommitFile, preCommitContent, 'utf-8');
		}
	}

	try { fs.chmodSync(preCommitFile, 0o755); } catch { /* Windows */ }
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
			vscode.window.showErrorMessage('[Hotmart AppSec] Ops, não conseguimos processar esse finding. Tente novamente ou entre em contato com o time de AppSec.');
			console.error('applyFixWithAI error:', err, 'arg:', findingArg);
			return;
		}
	}

	// Build the AI prompt
	const prompt = buildFixPrompt(finding);

	// Copy to clipboard
	await vscode.env.clipboard.writeText(prompt);
	vscode.window.showInformationMessage('[Hotmart AppSec] 🛡️ Prompt de correção copiado! Cole no chat da IA (Cmd+V) e deixa ela resolver pra você. 🚀');
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
	let prompt = `Corrija APENAS a vulnerabilidade ${finding.cwe} (${finding.title}) no arquivo \`${finding.file}\` linha ${finding.line}.\n\n`;
	prompt += `Código vulnerável:\n\`\`\`\n${finding.snippet}\n\`\`\`\n\n`;
	prompt += `Correção: ${finding.suggestion}\n`;

	if (finding.suggestedFix) {
		prompt += `\nExemplo de fix:\n\`\`\`\n${finding.suggestedFix}\n\`\`\`\n`;
	}

	prompt += `\nRegras:\n`;
	prompt += `- Altere SOMENTE a linha/trecho vulnerável. Não reescreva o resto do código.\n`;
	prompt += `- Mantenha a lógica e estrutura existentes intactas.\n`;
	prompt += `- Não adicione comentários, logs ou código extra desnecessário.\n`;
	prompt += `- A correção deve ser mínima e cirúrgica.`;

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

	// Sync: merge currentFindings with sidebar's findings to ensure we have the full picture.
	// The sidebar may have findings from manual scan that currentFindings doesn't have, and vice versa.
	if (currentFindings.length === 0 && sidebarProvider.findings.length > 0) {
		currentFindings = [...sidebarProvider.findings];
	} else if (sidebarProvider.findings.length > 0) {
		// Merge sidebar findings into currentFindings (deduplicate by id+file+line)
		const seen = new Set(currentFindings.map(f => `${f.id}:${f.file}:${f.line}`));
		for (const f of sidebarProvider.findings) {
			const key = `${f.id}:${f.file}:${f.line}`;
			if (!seen.has(key)) {
				currentFindings.push(f);
				seen.add(key);
			}
		}
	}

	// Remove from current findings
	currentFindings = currentFindings.filter(f =>
		!(f.id === findingInfo.id && f.file === findingInfo.file && f.line === findingInfo.line)
	);

	// Persist dismissal to disk so pre-commit hook can read it
	persistDismissal(findingInfo);

	// Update diagnostics and sidebar
	updateDiagnostics(currentFindings);
	sidebarProvider.updateFindings(currentFindings);

	vscode.window.showInformationMessage(`[Hotmart AppSec] 🛡️ Beleza, finding marcado como falso positivo. Valeu por revisar!`);
}

// ─── MARK FINDING AS FIXED ────────────────────────────────────────────────────

async function markFindingFixed(findingArg: unknown, sidebarProvider: SecuritySidebarProvider): Promise<void> {
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

	// Sync findings sources
	if (currentFindings.length === 0 && sidebarProvider.findings.length > 0) {
		currentFindings = [...sidebarProvider.findings];
	} else if (sidebarProvider.findings.length > 0) {
		const seen = new Set(currentFindings.map(f => `${f.id}:${f.file}:${f.line}`));
		for (const f of sidebarProvider.findings) {
			const key = `${f.id}:${f.file}:${f.line}`;
			if (!seen.has(key)) {
				currentFindings.push(f);
				seen.add(key);
			}
		}
	}

	// Remove from current findings
	currentFindings = currentFindings.filter(f =>
		!(f.id === findingInfo.id && f.file === findingInfo.file && f.line === findingInfo.line)
	);

	// Update diagnostics and sidebar
	updateDiagnostics(currentFindings);
	sidebarProvider.updateFindings(currentFindings);

	vscode.window.showInformationMessage(`[Hotmart AppSec] ✅ Vulnerabilidade corrigida! Mandou bem. 🎉`);
}

/**
 * Normalizes an OpenGrep rule ID by stripping the machine-specific path prefix.
 * Input:  "Users.leandro.andrade..kiro.extensions.hotmartcybersecurity.cybersecurityextension-0.8.4-universal.rules.dockerfile-run-as-root"
 * Output: "rules.dockerfile-run-as-root"
 */
function normalizeRuleId(id: string): string {
	const marker = '.rules.';
	const idx = id.indexOf(marker);
	if (idx !== -1) {
		return id.substring(idx + 1);
	}
	return id;
}

/**
 * Persists a dismissed finding to .appsec/dismissed.json
 * so the pre-commit hook can skip it.
 */
function persistDismissal(findingInfo: { id: string; file: string; line: number }): void {
	const workspaceFolder = getWorkspaceFolder();
	if (!workspaceFolder) { return; }

	const stateDir = path.join(workspaceFolder, '.appsec');
	const dismissedFile = path.join(stateDir, 'dismissed.json');

	if (!fs.existsSync(stateDir)) {
		fs.mkdirSync(stateDir, { recursive: true });
	}

	// Normalize the ID to strip machine-specific path prefix
	const normalizedId = normalizeRuleId(findingInfo.id);

	// Load existing dismissals
	let dismissed: Array<{ id: string; file: string; line: number; dismissedAt: string }> = [];
	if (fs.existsSync(dismissedFile)) {
		try {
			dismissed = JSON.parse(fs.readFileSync(dismissedFile, 'utf-8'));
		} catch {
			dismissed = [];
		}
	}

	// Add new dismissal (avoid duplicates)
	const alreadyDismissed = dismissed.some(d =>
		normalizeRuleId(d.id) === normalizedId && d.file === findingInfo.file && d.line === findingInfo.line
	);

	if (!alreadyDismissed) {
		dismissed.push({
			id: normalizedId,
			file: findingInfo.file,
			line: findingInfo.line,
			dismissedAt: new Date().toISOString(),
		});
		fs.writeFileSync(dismissedFile, JSON.stringify(dismissed, null, 2), 'utf-8');
	}
}

// ─── FILE SAVE WATCHER (auto-remove fixed findings) ──────────────────────────

function registerFileSaveWatcher(context: vscode.ExtensionContext, sidebarProvider: SecuritySidebarProvider): void {
	let rescanTimer: NodeJS.Timeout | undefined;
	const pendingFiles = new Set<string>();

	const listener = vscode.workspace.onDidSaveTextDocument((document) => {
		const filePath = vscode.workspace.asRelativePath(document.uri);

		// Skip excluded paths early
		if (isExcludedFilePath(filePath)) {
			return;
		}

		// Accumulate files saved in quick succession for batch scanning
		pendingFiles.add(filePath);

		// Debounce: wait for rapid saves to settle, then scan all pending files at once
		if (rescanTimer) {
			clearTimeout(rescanTimer);
		}

		rescanTimer = setTimeout(async () => {
			if (pendingFiles.size === 0) { return; }

			// Snapshot and clear pending files immediately to avoid race conditions
			const filesToScan = [...pendingFiles];
			pendingFiles.clear();

			try {
				const workspaceFolders = vscode.workspace.workspaceFolders;
				if (!workspaceFolders) { return; }

				const workspaceFolder = workspaceFolders[0].uri.fsPath;

				// Batch scan all saved files in one OpenGrep invocation
				const freshFindings = await runOpenGrep(filesToScan, workspaceFolder, context.extensionPath);

				// Remove old findings for scanned files and replace with fresh ones
				const scannedSet = new Set(filesToScan);
				const otherFindings = currentFindings.filter(f => !scannedSet.has(f.file));
				currentFindings = [...otherFindings, ...freshFindings];

				// Reset notification fingerprint so git watcher shows fresh results
				lastNotificationFingerprint = '';

				// Update diagnostics and sidebar
				updateDiagnostics(currentFindings);
				sidebarProvider.updateFindings(currentFindings);
			} catch (err) {
				console.error('[Hotmart AppSec] File save re-scan error:', err);
			}
		}, 800);
	});

	context.subscriptions.push(listener);
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

	// Capture the initial staged files snapshot so we can detect real staging changes
	let lastStagedSnapshot = '';
	try {
		lastStagedSnapshot = execSync('git diff --cached --name-only', { cwd: workspaceFolder, encoding: 'utf-8' });
	} catch { /* */ }

	// Capture the current index mtime at activation so we don't trigger on reload
	let lastIndexMtime = 0;
	try {
		const stat = fs.statSync(path.join(gitDir, 'index'));
		lastIndexMtime = stat.mtimeMs;
	} catch { /* */ }

	// Grace period: ignore all events in the first 2 seconds after activation
	// to avoid triggering on reload/startup
	let ready = false;
	const readyTimer = setTimeout(() => { ready = true; }, 2000);

	let debounceTimer: NodeJS.Timeout | undefined;
	let scanPending = false;
	let scanInProgress = false;

	const triggerScan = () => {
		// Prevent re-entrant scans (our own git commands can touch the index lock)
		if (scanInProgress) { return; }

		scanPending = true;
		if (debounceTimer) {
			clearTimeout(debounceTimer);
		}
		debounceTimer = setTimeout(async () => {
			if (!scanPending) { return; }
			scanPending = false;
			scanInProgress = true;

			try {
				// Check current state of the working tree (non-blocking)
				const [currentStaged, currentUnstaged] = await Promise.all([
					gitCmd(['diff', '--cached', '--name-only'], workspaceFolder),
					gitCmd(['diff', '--name-only', '--diff-filter=d'], workspaceFolder),
				]);

				// If there's absolutely nothing to scan (clean tree), skip
				if (currentStaged === '' && currentUnstaged === '') {
					lastStagedSnapshot = '';
					return;
				}

				// Skip only if the staged file list is identical AND there are no
				// unstaged changes. But if there ARE unstaged changes or the staged
				// list changed, always scan (content may have changed even for same files).
				if (currentStaged === lastStagedSnapshot && currentUnstaged === '') {
					return;
				}

				// Something changed — run the scan
				lastStagedSnapshot = currentStaged;
				await onGitOperation(sidebarProvider);
			} finally {
				// Allow future scans after a short cooldown to absorb any index
				// events triggered by our own git commands
				setTimeout(() => { scanInProgress = false; }, 1500);
			}
		}, 800);
	};

	const watcher = fs.watch(gitDir, (eventType, filename) => {
		if (!filename) { return; }
		if (!ready) { return; }

		// Trigger on:
		//   - index            → git add / git reset (staging changes)
		//   - COMMIT_EDITMSG    → git commit
		if (filename !== 'index' && filename !== 'COMMIT_EDITMSG') {
			return;
		}

		// For index changes, confirm the index was actually rewritten by comparing mtime
		if (filename === 'index') {
			try {
				const stat = fs.statSync(path.join(gitDir, 'index'));
				if (stat.mtimeMs === lastIndexMtime) {
					return;
				}
				lastIndexMtime = stat.mtimeMs;
			} catch {
				// index momentarily missing during the lock→index rename; let the scan run anyway
			}
		}

		triggerScan();
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

// Track whether we already prompted about outdated workflow in this session
async function onGitOperation(sidebarProvider: SecuritySidebarProvider): Promise<void> {
	// Show minimalist progress notification during SAST scan
	const findings = await vscode.window.withProgress(
		{
			location: vscode.ProgressLocation.Notification,
			title: '🛡️ SAST rodando',
			cancellable: false,
		},
		async (progress) => {
			progress.report({ increment: 10, message: 'analisando alterações...' });

			const result = await runSecurityScan(sidebarProvider);

			progress.report({ increment: 90, message: 'concluído!' });
			return result;
		}
	);

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

	let summary = '🛡️ ';
	const parts: string[] = [];
	if (criticalCount > 0) { parts.push(`${criticalCount} critical`); }
	if (highCount > 0) { parts.push(`${highCount} high`); }
	if (otherCount > 0) { parts.push(`${otherCount} other`); }

	summary += `${parts.join(', ')} finding(s) detectado(s).`;

	const action = await vscode.window.showWarningMessage(
		summary,
		'Ver Findings',
		'Ignorar'
	);

	if (action === 'Ver Findings') {
		await vscode.commands.executeCommand('cybersecurity.findingsView.focus');
	}
}

// ─── STEERING FILES DISTRIBUTION ─────────────────────────────────────────────

async function bootstrapProject(context: vscode.ExtensionContext): Promise<void> {
	const workspaceFolder = getWorkspaceFolder();
	if (!workspaceFolder) {
		vscode.window.showErrorMessage('[Hotmart AppSec] Nenhum workspace aberto. Abra uma pasta para aplicar os padrões de segurança corporativa.');
		return;
	}

	const currentIde = detectIDE();
	console.log(`[Hotmart AppSec] bootstrapProject: ide=${currentIde}, workspace=${workspaceFolder}`);

	if (!hasCodeFiles(workspaceFolder)) {
		vscode.window.showWarningMessage(
			'[Hotmart AppSec] Nenhum arquivo de código detectado neste workspace. Os padrões de segurança só são aplicados em projetos com código-fonte.'
		);
		return;
	}

	let applied = 0;

	// Apply IDE-specific rule files
	applied += await applyIdeSpecificFiles(context, workspaceFolder);

	// Always apply Claude rules (Claude Code can be used alongside any IDE)
	applied += await applyClaudeFiles(context, workspaceFolder);

	// Install preToolUse hooks only for the detected IDE
	applied += await applySecurityHooks(context, workspaceFolder, [currentIde]);

	// GitHub workflow (always force on bootstrap)
	applied += await applyGitHubWorkflow(context, workspaceFolder, true);

	if (applied > 0) {
		vscode.window.showInformationMessage(
			`[Hotmart AppSec] ✅ Padrões de segurança corporativa aplicados: ${applied} arquivo(s) configurado(s) para ${currentIde}. Tudo pronto! 🎯`
		);
	} else {
		vscode.window.showInformationMessage(
			`[Hotmart AppSec] ✅ Padrões de segurança corporativa já estão sincronizados para ${currentIde}. Nada pra fazer aqui. 👌`
		);
	}
}

async function updateStandards(context: vscode.ExtensionContext): Promise<void> {
	const workspaceFolder = getWorkspaceFolder();
	if (!workspaceFolder) {
		vscode.window.showErrorMessage('[Hotmart AppSec] Nenhum workspace aberto para atualizar.');
		return;
	}

	let updated = 0;

	// Update IDE-specific files (force overwrite)
	updated += await applyIdeSpecificFiles(context, workspaceFolder, true);

	// Always update Claude rules
	updated += await applyClaudeFiles(context, workspaceFolder, true);

	// Update GitHub workflow (force overwrite)
	updated += await applyGitHubWorkflow(context, workspaceFolder, true);

	if (updated > 0) {
		vscode.window.showInformationMessage(`[Hotmart AppSec] ✅ Padrões corporativos atualizados: ${updated} arquivo(s) sincronizado(s) para ${detectIDE()}. 🔄`);
	} else {
		vscode.window.showInformationMessage('[Hotmart AppSec] Tudo já está em dia! Nenhum padrão precisou de atualização. Execute "Bootstrap Project" se for a primeira vez.');
	}
}

async function showGuidelines(context: vscode.ExtensionContext): Promise<void> {
	const guidelinePath = path.join(context.extensionPath, 'standards', 'steering', 'copilot-instructions.md');
	const doc = await vscode.workspace.openTextDocument(guidelinePath);
	await vscode.window.showTextDocument(doc, { preview: true });
}

async function autoApplyIfNeeded(context: vscode.ExtensionContext, force: boolean = false): Promise<void> {
	const folders = vscode.workspace.workspaceFolders;
	if (!folders || folders.length === 0) {
		return;
	}

	const config = vscode.workspace.getConfiguration('hotmartCybersecurity');
	const autoApply = config.get<boolean>('autoApplyOnOpen', true);

	if (!autoApply && !force) {
		return;
	}

	for (const folder of folders) {
		try {
			// Only apply security files if workspace contains source code
			if (!hasCodeFiles(folder.uri.fsPath)) {
				console.log(`[Hotmart AppSec] Skipping ${folder.uri.fsPath} — no code files detected`);
				continue;
			}
			await applyToAllTargets(context, folder.uri.fsPath, true, force);
			ensureLinterIgnores(folder.uri.fsPath);
		} catch (err) {
			console.error('[Hotmart AppSec] autoApplyIfNeeded error:', err);
		}
	}
}

/**
 * Ensures that protected AppSec files are excluded from common linters/formatters
 * that may modify them (prettier, markdownlint, etc.).
 * Only modifies ignore files that already exist in the workspace.
 */
function ensureLinterIgnores(workspaceFolder: string): void {
	const APPSEC_PATHS = [
		'.kiro/steering/',
		'.kiro/specs/',
		'.claude/rules/',
		'.cursor/rules/',
		'.github/copilot-instructions.md',
		'.appsec/',
	];

	const APPSEC_MARKER = '# AppSec protected paths (do not format)';

	const ignoreFiles = ['.prettierignore', '.markdownlintignore'];

	for (const ignoreFile of ignoreFiles) {
		const filePath = path.join(workspaceFolder, ignoreFile);

		// Only modify if the ignore file already exists (don't create new ones)
		if (!fs.existsSync(filePath)) { continue; }

		try {
			const content = fs.readFileSync(filePath, 'utf-8');

			// Already has our entries
			if (content.includes(APPSEC_MARKER)) { continue; }

			// Append our protected paths
			const block = `\n${APPSEC_MARKER}\n${APPSEC_PATHS.join('\n')}\n`;
			fs.appendFileSync(filePath, block, 'utf-8');
			console.log(`[Hotmart AppSec] Added protected paths to ${ignoreFile}`);
		} catch (err) {
			console.warn(`[Hotmart AppSec] Could not update ${ignoreFile}:`, err);
		}
	}
}

async function applyToAllTargets(context: vscode.ExtensionContext, workspaceFolder: string, silent: boolean = false, force: boolean = false): Promise<void> {
	let applied = 0;
	const currentIde = detectIDE();

	console.log(`[Hotmart AppSec] applyToAllTargets: ide=${currentIde}, workspace=${workspaceFolder}, extensionPath=${context.extensionPath}, force=${force}`);

	// Apply IDE-specific rule files (copilot-instructions.md, appsec-rules.mdc, etc.)
	applied += await applyIdeSpecificFiles(context, workspaceFolder, force || silent);
	// Always apply Claude rules (Claude Code can be used alongside any IDE)
	applied += await applyClaudeFiles(context, workspaceFolder, force || silent);

	// Install security hooks only for the current IDE
	applied += await applySecurityHooks(context, workspaceFolder, [currentIde]);

	// GitHub workflow — deploy/update on install/update, cleanup legacy ci-cd.yml
	applied += await applyGitHubWorkflow(context, workspaceFolder, force);

	if (!silent && applied > 0) {
		vscode.window.showInformationMessage(`[Hotmart AppSec] ✅ Padrões de segurança corporativa aplicados: ${applied} arquivo(s) para ${currentIde}. 🎯`);
	}
}

// ─── SECURITY HOOKS INSTALLATION ──────────────────────────────────────────────

async function applySecurityHooks(
	context: vscode.ExtensionContext,
	workspaceFolder: string,
	targets: string[]
): Promise<number> {
	let count = 0;

	// Always make sure the gate script is in place; every IDE hook depends on it.
	const scriptInstalled = await installGateScriptManual(context, workspaceFolder);
	count += scriptInstalled;

	// Claude Code hooks are useful regardless of the host IDE (Claude is used alongside).
	count += await installClaudeHook(context, workspaceFolder);

	for (const target of targets) {
		switch (target) {
			case 'kiro':
				count += await installKiroHook(context, workspaceFolder);
				break;
			case 'cursor':
				count += await installCursorHook(context, workspaceFolder);
				break;
			// vscode has no native pre-prompt hook today
		}
	}

	return count;
}

async function installGateScriptManual(
	context: vscode.ExtensionContext,
	workspaceFolder: string
): Promise<number> {
	const appsecDir = path.join(workspaceFolder, '.appsec');
	let installed = 0;

	// Install both .sh and .ps1 so the repo is cross-platform
	const scripts = ['appsec-gate.sh', 'appsec-gate.ps1'];
	for (const scriptName of scripts) {
		const scriptDest = path.join(appsecDir, scriptName);
		if (fs.existsSync(scriptDest)) { continue; }

		const scriptSource = path.join(context.extensionPath, 'standards', 'hooks', scriptName);
		if (!fs.existsSync(scriptSource)) { continue; }

		if (!fs.existsSync(appsecDir)) {
			fs.mkdirSync(appsecDir, { recursive: true });
		}
		fs.copyFileSync(scriptSource, scriptDest);
		try { fs.chmodSync(scriptDest, 0o755); } catch { /* Windows */ }
		installed++;
	}

	return installed > 0 ? 1 : 0;
}

async function installCursorHook(context: vscode.ExtensionContext, workspaceFolder: string): Promise<number> {
	const cursorDir = path.join(workspaceFolder, '.cursor');
	const hooksFile = path.join(cursorDir, 'hooks.json');
	if (fs.existsSync(hooksFile)) { return 0; }

	if (!fs.existsSync(cursorDir)) {
		fs.mkdirSync(cursorDir, { recursive: true });
	}

	const cmd = gateCommand('.appsec/appsec-gate' + gateScriptExtension());
	const hooks = {
		hooks: {
			beforeSubmitPrompt: { command: cmd },
			afterFileEdit: { command: cmd },
		},
	};
	fs.writeFileSync(hooksFile, JSON.stringify(hooks, null, 2), 'utf-8');
	return 1;
}

async function installKiroHook(context: vscode.ExtensionContext, workspaceFolder: string): Promise<number> {
	const hooksDir = path.join(workspaceFolder, '.kiro', 'hooks');
	const hookFile = path.join(hooksDir, 'appsec-gate.json');

	// Don't overwrite if already exists
	if (fs.existsSync(hookFile)) {
		cleanupLegacyKiroHook(hooksDir);
		return 0;
	}

	if (!fs.existsSync(hooksDir)) {
		fs.mkdirSync(hooksDir, { recursive: true });
	}

	// Generate hook JSON with platform-appropriate command
	const hookContent = {
		version: 'v1',
		hooks: [
			{
				name: 'AppSec Gate \u2014 Write Operations',
				trigger: 'PreToolUse',
				matcher: 'fs_write|str_replace|fs_append',
				action: {
					type: 'command',
					command: gateCommand('.appsec/appsec-gate-kiro' + gateScriptExtension()),
				},
			},
		],
	};
	fs.writeFileSync(hookFile, JSON.stringify(hookContent, null, 2), 'utf-8');
	cleanupLegacyKiroHook(hooksDir);
	return 1;
}

async function installClaudeHook(context: vscode.ExtensionContext, workspaceFolder: string): Promise<number> {
	const claudeSettingsDir = path.join(workspaceFolder, '.claude');
	const settingsFile = path.join(claudeSettingsDir, 'settings.json');
	if (fs.existsSync(settingsFile)) { return 0; }

	if (!fs.existsSync(claudeSettingsDir)) {
		fs.mkdirSync(claudeSettingsDir, { recursive: true });
	}

	// Generate settings with platform-appropriate command
	const settings = {
		hooks: {
			PreToolUse: [
				{
					matcher: 'Write|Edit|MultiEdit|CreateFile',
					hooks: [
						{
							type: 'command',
							command: gateCommand('.appsec/appsec-gate' + gateScriptExtension()),
						},
					],
				},
			],
		},
	};
	fs.writeFileSync(settingsFile, JSON.stringify(settings, null, 2), 'utf-8');
	return 1;
}

// ─── GITHUB WORKFLOW ──────────────────────────────────────────────────────────

/**
 * Deploys/updates the AppSec GitHub workflow and cleans up legacy workflow files.
 * On install/update (force=true), always overwrites with the latest version.
 * Also removes ci-cd.yml if it was left behind by older versions of the extension.
 */
async function applyGitHubWorkflow(
	context: vscode.ExtensionContext,
	workspaceFolder: string,
	force: boolean = false
): Promise<number> {
	const targetDir = path.join(workspaceFolder, '.github', 'workflows');
	const sourceFile = path.join(context.extensionPath, 'standards', 'org-workflow', 'appsec-guard.yml');
	const destFile = path.join(targetDir, 'appsec-guard.yml');

	if (!fs.existsSync(sourceFile)) {
		console.error(`[Hotmart AppSec] applyGitHubWorkflow: source not found: ${sourceFile}`);
		return 0;
	}

	let count = 0;

	// Clean up legacy ci-cd.yml generated by older versions of the extension
	const legacyCiCd = path.join(targetDir, 'ci-cd.yml');
	if (fs.existsSync(legacyCiCd)) {
		try {
			fs.unlinkSync(legacyCiCd);
			console.log(`[Hotmart AppSec] Removed legacy ci-cd.yml from ${targetDir}`);
			count++;
		} catch (err) {
			console.warn(`[Hotmart AppSec] Could not remove legacy ci-cd.yml:`, err);
		}
	}

	// Deploy or update appsec-guard.yml
	if (!fs.existsSync(targetDir)) {
		fs.mkdirSync(targetDir, { recursive: true });
	}

	const sourceContent = fs.readFileSync(sourceFile, 'utf-8');

	if (fs.existsSync(destFile)) {
		const destContent = fs.readFileSync(destFile, 'utf-8');
		if (sourceContent === destContent) {
			return count; // Already up to date
		}
		if (!force) {
			return count; // Don't overwrite unless forced (install/update)
		}
	}

	fs.writeFileSync(destFile, sourceContent, 'utf-8');
	console.log(`[Hotmart AppSec] GitHub workflow installed/updated at ${destFile}`);
	return count + 1;
}

/**
 * Applies IDE-specific rule files using the SAME pattern as applyClaudeFiles.
 * For VS Code: creates .github/copilot-instructions.md
 * For Cursor: creates .cursor/rules/appsec-rules.mdc
 * For Kiro: creates .kiro/steering/appsec-rules.md
 */
async function applyIdeSpecificFiles(
	context: vscode.ExtensionContext,
	workspaceFolder: string,
	overwrite: boolean = false
): Promise<number> {
	const currentIde = detectIDE();
	let count = 0;

	switch (currentIde) {
		case 'vscode': {
			const sourceDir = path.join(context.extensionPath, 'standards', 'steering');
			const targetDir = path.join(workspaceFolder, '.github');

			if (!fs.existsSync(targetDir)) {
				fs.mkdirSync(targetDir, { recursive: true });
			}

			const source = path.join(sourceDir, 'copilot-instructions.md');
			const dest = path.join(targetDir, 'copilot-instructions.md');
			console.log(`[Hotmart AppSec] applyIdeSpecificFiles(vscode): source=${source}, exists=${fs.existsSync(source)}`);
			if (!fs.existsSync(source)) { break; }
			count += await copySingleFile(source, dest, 'copilot-instructions.md', overwrite);
			break;
		}
		case 'cursor': {
			const sourceDir = path.join(context.extensionPath, 'standards', 'cursor', 'rules');
			const targetDir = path.join(workspaceFolder, '.cursor', 'rules');

			if (!fs.existsSync(targetDir)) {
				fs.mkdirSync(targetDir, { recursive: true });
			}

			const source = path.join(sourceDir, 'appsec-rules.mdc');
			const dest = path.join(targetDir, 'appsec-rules.mdc');
			console.log(`[Hotmart AppSec] applyIdeSpecificFiles(cursor): source=${source}, exists=${fs.existsSync(source)}`);
			if (!fs.existsSync(source)) { break; }
			count += await copySingleFile(source, dest, 'appsec-rules.mdc', overwrite);
			break;
		}
		case 'kiro': {
			const sourceDir = path.join(context.extensionPath, 'standards', 'kiro', 'steering');
			const targetDir = path.join(workspaceFolder, '.kiro', 'steering');

			if (!fs.existsSync(targetDir)) {
				fs.mkdirSync(targetDir, { recursive: true });
			}

			const source = path.join(sourceDir, 'appsec-rules.md');
			const dest = path.join(targetDir, 'appsec-rules.md');
			console.log(`[Hotmart AppSec] applyIdeSpecificFiles(kiro): source=${source}, exists=${fs.existsSync(source)}`);
			if (!fs.existsSync(source)) { break; }
			count += await copySingleFile(source, dest, 'appsec-rules.md', overwrite);
			break;
		}
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
	console.log(`[Hotmart AppSec] copySingleFile: ${fileName}, source=${source}, dest=${dest}, overwrite=${overwrite}`);

	const sourceContent = fs.readFileSync(source, 'utf-8');

	if (fs.existsSync(dest)) {
		const destContent = fs.readFileSync(dest, 'utf-8');
		if (sourceContent === destContent) {
			console.log(`[Hotmart AppSec] File ${fileName} already up to date, skipping`);
			return 0;
		}

		if (!overwrite) {
			const action = await vscode.window.showWarningMessage(
				`[Hotmart AppSec] O arquivo "${fileName}" já existe e difere da versão corporativa. Deseja atualizar para a versão mais recente?`,
				'Sobrescrever',
				'Manter atual'
			);
			if (action !== 'Sobrescrever') { return 0; }
		}
	}

	fs.writeFileSync(dest, sourceContent, 'utf-8');
	console.log(`[Hotmart AppSec] File ${fileName} written successfully to ${dest}`);
	return 1;
}

function getWorkspaceFolder(): string | undefined {
	const folders = vscode.workspace.workspaceFolders;
	if (!folders || folders.length === 0) {
		return undefined;
	}
	return folders[0].uri.fsPath;
}

// ─── UPDATE CHECK ─────────────────────────────────────────────────────────────

/**
 * Queries the VS Code Marketplace for the latest published version of the extension.
 * If a newer version is available, shows a warning notification encouraging the user
 * to update, emphasizing security fixes and bug corrections.
 *
 * Runs once per activation with a short delay so it doesn't block startup.
 */
function checkForExtensionUpdate(context: vscode.ExtensionContext): void {
	const CHECK_INTERVAL_KEY = 'hotmartAppSec.lastUpdateCheck';
	const ONE_HOUR_MS = 60 * 60 * 1000;

	// Throttle: only check once per hour to avoid excessive network calls
	const lastCheck = context.globalState.get<number>(CHECK_INTERVAL_KEY, 0);
	if (Date.now() - lastCheck < ONE_HOUR_MS) {
		return;
	}

	// Delay the check so it doesn't slow down activation
	setTimeout(async () => {
		try {
			const currentVersion = (context.extension?.packageJSON?.version as string) || '0.0.0';
			const latestVersion = await fetchLatestMarketplaceVersion();

			if (!latestVersion) { return; }

			void context.globalState.update(CHECK_INTERVAL_KEY, Date.now());

			if (isNewerVersion(latestVersion, currentVersion)) {
				const action = await vscode.window.showWarningMessage(
					`[Hotmart AppSec] 🛡️ Nova versão disponível (v${latestVersion})! ` +
					`Esta atualização contém correções de bugs e melhorias de segurança importantes. ` +
					`Atualize agora para manter seu ambiente protegido contra as vulnerabilidades mais recentes.`,
					'Atualizar Agora',
					'Depois'
				);

				if (action === 'Atualizar Agora') {
					// Opens the extension page in the Extensions view so the user can update
					await vscode.commands.executeCommand(
						'workbench.extensions.action.showExtensionsWithIds',
						['HotmartCybersecurity.cybersecurityextension']
					);
				}
			}
		} catch (err) {
			console.error('[Hotmart AppSec] Update check failed:', err);
		}
	}, 5000);
}

/**
 * Fetches the latest version from the VS Code Marketplace API.
 * Uses the public query endpoint to avoid requiring authentication.
 */
async function fetchLatestMarketplaceVersion(): Promise<string | null> {
	try {
		const postData = JSON.stringify({
			filters: [{
				criteria: [
					{ filterType: 7, value: 'HotmartCybersecurity.cybersecurityextension' }
				]
			}],
			flags: 0x1 // IncludeVersions
		});

		return new Promise<string | null>((resolve) => {
			const req = https.request({
				hostname: 'marketplace.visualstudio.com',
				path: '/_apis/public/gallery/extensionquery',
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Accept': 'application/json;api-version=6.1-preview.1',
					'Content-Length': Buffer.byteLength(postData),
				},
				timeout: 10000,
			}, (res) => {
				let data = '';
				res.on('data', (chunk: string) => { data += chunk; });
				res.on('end', () => {
					try {
						const json = JSON.parse(data);
						const extensions = json?.results?.[0]?.extensions;
						if (extensions && extensions.length > 0) {
							const versions = extensions[0]?.versions;
							if (versions && versions.length > 0) {
								resolve(versions[0].version as string);
								return;
							}
						}
						resolve(null);
					} catch {
						resolve(null);
					}
				});
			});

			req.on('error', () => resolve(null));
			req.on('timeout', () => { req.destroy(); resolve(null); });
			req.write(postData);
			req.end();
		});
	} catch {
		return null;
	}
}

/**
 * Returns true if `latest` is a newer semver than `current`.
 */
function isNewerVersion(latest: string, current: string): boolean {
	const latestParts = latest.split('.').map(Number);
	const currentParts = current.split('.').map(Number);

	for (let i = 0; i < 3; i++) {
		const l = latestParts[i] || 0;
		const c = currentParts[i] || 0;
		if (l > c) { return true; }
		if (l < c) { return false; }
	}
	return false;
}

export function deactivate() {
	if (diagnosticCollection) {
		diagnosticCollection.dispose();
	}
}
