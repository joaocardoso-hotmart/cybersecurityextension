import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { execSync } from 'child_process';
import { SecuritySidebarProvider } from './sidebar';
import { scanChangedLines, SecurityFinding, Severity, setExtensionPath } from './scanner';
import { ensureOpenGrep, runOpenGrep } from './semgrep';

/**
 * Quick check for paths that should never be scanned on save.
 */
function isExcludedFilePath(filePath: string): boolean {
	return /^(\.kiro|\.cursor|\.claude|\.vscode|\.github|node_modules|out|dist|build)\//i.test(filePath)
		|| /\.(lock|min\.js|bundle\.js)$/.test(filePath);
}

const CLAUDE_FILES = {
	rules: ['appsec-rules.md'],
};

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

	// Fix global steering file if it exists but is missing description (legacy MDM installs)
	ensureGlobalSteeringFile(context);

	// Auto-apply steering files on workspace open
	autoApplyIfNeeded(context, force).catch(err => {
		console.error('[Hotmart AppSec] autoApplyIfNeeded failed:', err);
	});

	// Ensure preToolUse hook exists (runs on every activation, forces overwrite on install/update)
	ensureSecurityHookAllWorkspaces(context, force);

	// Direct IDE rule file creation (safety net, forces overwrite on install/update)
	ensureIdeRuleFilesAllWorkspaces(context, force);

	// Notify the user when the extension is freshly installed or updated
	if (installState === 'install') {
		vscode.window.showInformationMessage(
			'[Hotmart AppSec] 🛡️ Extensão instalada com sucesso! Os hooks de segurança corporativa foram configurados nos seus workspaces. Estamos aqui pra te ajudar a manter o código seguro. 💪'
		);
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
		ensureSecurityHookForWorkspace(context, folder.uri.fsPath, force);
	}
}

function ensureIdeRuleFilesAllWorkspaces(context: vscode.ExtensionContext, force: boolean): void {
	const folders = vscode.workspace.workspaceFolders;
	if (!folders || folders.length === 0) { return; }
	for (const folder of folders) {
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

	// Always install git pre-commit hook (never overwritten — user may have customized it)
	installGitPreCommitHook(context, workspaceFolder);
}

/**
 * Copies the shared `appsec-gate.sh` script to `.appsec/appsec-gate.sh`.
 * Used by Claude Code (PreToolUse), Cursor (beforeSubmitPrompt/afterFileEdit)
 * and the git pre-commit hook.
 */
function installAppsecGateScript(
	context: vscode.ExtensionContext,
	workspaceFolder: string,
	force: boolean
): void {
	const appsecDir = path.join(workspaceFolder, '.appsec');
	const scriptDest = path.join(appsecDir, 'appsec-gate.sh');
	const scriptSource = path.join(context.extensionPath, 'standards', 'hooks', 'appsec-gate.sh');

	if (!fs.existsSync(scriptSource)) { return; }
	if (fs.existsSync(scriptDest) && !force) { return; }

	if (!fs.existsSync(appsecDir)) {
		fs.mkdirSync(appsecDir, { recursive: true });
	}
	fs.copyFileSync(scriptSource, scriptDest);
	try { fs.chmodSync(scriptDest, 0o755); } catch { /* not fatal on Windows */ }
	console.log(`[Hotmart AppSec] Gate script installed/updated at ${scriptDest}`);
}

function installKiroHookOnActivate(
	context: vscode.ExtensionContext,
	workspaceFolder: string,
	force: boolean
): void {
	const hooksDir = path.join(workspaceFolder, '.kiro', 'hooks');
	const hookFile = path.join(hooksDir, 'appsec-gate.kiro.hook');

	const sourceFile = path.join(context.extensionPath, 'standards', 'hooks', 'kiro', 'appsec-gate.kiro.hook');
	if (!fs.existsSync(sourceFile)) {
		console.error(`[Hotmart AppSec] missing kiro hook source: ${sourceFile}`);
		return;
	}

	if (fs.existsSync(hookFile) && !force) {
		// Clean up legacy file from previous versions of the extension
		cleanupLegacyKiroHook(hooksDir);
		return;
	}

	if (!fs.existsSync(hooksDir)) {
		fs.mkdirSync(hooksDir, { recursive: true });
	}

	fs.copyFileSync(sourceFile, hookFile);
	cleanupLegacyKiroHook(hooksDir);
	console.log(`[Hotmart AppSec] Kiro hook installed/updated at ${hookFile}`);
}

/**
 * Removes the legacy `.json` Kiro hook left by older versions of this extension.
 * Kiro recognizes only `.kiro.hook` files, so the `.json` is dead weight.
 */
function cleanupLegacyKiroHook(hooksDir: string): void {
	const legacy = path.join(hooksDir, 'appsec-gate.json');
	try {
		if (fs.existsSync(legacy)) {
			fs.unlinkSync(legacy);
			console.log(`[Hotmart AppSec] Removed legacy hook ${legacy}`);
		}
	} catch (err) {
		console.warn(`[Hotmart AppSec] Could not remove legacy hook: ${err}`);
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

	const sourceFile = path.join(context.extensionPath, 'standards', 'hooks', 'claude', 'settings.json');
	if (!fs.existsSync(sourceFile)) { return; }
	if (fs.existsSync(settingsFile) && !force) { return; }

	if (!fs.existsSync(claudeDir)) {
		fs.mkdirSync(claudeDir, { recursive: true });
	}
	fs.copyFileSync(sourceFile, settingsFile);
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

	const sourceFile = path.join(context.extensionPath, 'standards', 'hooks', 'cursor', 'hooks.json');
	if (!fs.existsSync(sourceFile)) {
		console.error(`[Hotmart AppSec] missing cursor hook source: ${sourceFile}`);
		return;
	}
	if (fs.existsSync(hooksFile) && !force) { return; }

	if (!fs.existsSync(cursorDir)) {
		fs.mkdirSync(cursorDir, { recursive: true });
	}
	fs.copyFileSync(sourceFile, hooksFile);
	console.log(`[Hotmart AppSec] Cursor hook installed/updated at ${hooksFile}`);
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
 * Persists a dismissed finding to .appsec-state/dismissed.json
 * so the pre-commit hook can skip it.
 */
function persistDismissal(findingInfo: { id: string; file: string; line: number }): void {
	const workspaceFolder = getWorkspaceFolder();
	if (!workspaceFolder) { return; }

	const stateDir = path.join(workspaceFolder, '.appsec-state');
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

	const listener = vscode.workspace.onDidSaveTextDocument((document) => {
		const filePath = vscode.workspace.asRelativePath(document.uri);

		// Always re-scan changed files on save so NEW vulnerabilities are detected
		// even when there are no current findings (e.g. after fixing and reintroducing)
		// Only skip files that are in excluded paths
		if (isExcludedFilePath(filePath)) {
			return;
		}

		// Debounce to avoid hammering the scanner on rapid saves
		if (rescanTimer) {
			clearTimeout(rescanTimer);
		}

		rescanTimer = setTimeout(async () => {
			try {
				const workspaceFolders = vscode.workspace.workspaceFolders;
				if (!workspaceFolders) { return; }

				const workspaceFolder = workspaceFolders[0].uri.fsPath;

				// Re-scan only the saved file
				const freshFindings = await runOpenGrep([filePath], workspaceFolder, context.extensionPath);

				// Remove old findings for this file and replace with fresh ones
				const otherFindings = currentFindings.filter(f => f.file !== filePath);
				currentFindings = [...otherFindings, ...freshFindings];

				// If findings changed (fixed or new ones appeared), reset the notification
				// fingerprint so the git watcher will show a fresh notification on next stage
				lastNotificationFingerprint = '';

				// Update diagnostics and sidebar
				updateDiagnostics(currentFindings);
				sidebarProvider.updateFindings(currentFindings);
			} catch (err) {
				console.error('[Hotmart AppSec] File save re-scan error:', err);
			}
		}, 500);
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
				// Check current state of the working tree
				let currentStaged = '';
				try {
					currentStaged = execSync('git diff --cached --name-only', { cwd: workspaceFolder, encoding: 'utf-8' });
				} catch { /* */ }

				let currentUnstaged = '';
				try {
					currentUnstaged = execSync('git diff --name-only --diff-filter=d', { cwd: workspaceFolder, encoding: 'utf-8' });
				} catch { /* */ }

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

	let summary = '[Hotmart AppSec] 🛡️ Heads up! ';
	const parts: string[] = [];
	if (criticalCount > 0) { parts.push(`${criticalCount} critical`); }
	if (highCount > 0) { parts.push(`${highCount} high`); }
	if (otherCount > 0) { parts.push(`${otherCount} other`); }

	summary += `Encontramos ${parts.join(', ')} finding(s) nas suas alterações. `;
	summary += 'Vale dar uma olhada antes do push — a pipeline pode reclamar depois. 😉';

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
		vscode.window.showErrorMessage('[Hotmart AppSec] Nenhum workspace aberto. Abra uma pasta para aplicar os padrões de segurança corporativa.');
		return;
	}

	const currentIde = detectIDE();
	console.log(`[Hotmart AppSec] bootstrapProject: ide=${currentIde}, workspace=${workspaceFolder}`);

	let applied = 0;

	// Apply IDE-specific rule files
	applied += await applyIdeSpecificFiles(context, workspaceFolder);

	// Always apply Claude rules (Claude Code can be used alongside any IDE)
	applied += await applyClaudeFiles(context, workspaceFolder);

	// Install preToolUse hooks only for the detected IDE
	applied += await applySecurityHooks(context, workspaceFolder, [currentIde]);

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
		'.appsec-state/',
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

	// GitHub workflow is NOT applied automatically to avoid breaking CI/CD tools
	// (GitHub Apps like Magic Deploy lack `workflows` permission).
	// Use the manual "Bootstrap Project" command to install it.

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
	const scriptDest = path.join(appsecDir, 'appsec-gate.sh');
	if (fs.existsSync(scriptDest)) { return 0; }

	const scriptSource = path.join(context.extensionPath, 'standards', 'hooks', 'appsec-gate.sh');
	if (!fs.existsSync(scriptSource)) { return 0; }

	if (!fs.existsSync(appsecDir)) {
		fs.mkdirSync(appsecDir, { recursive: true });
	}
	fs.copyFileSync(scriptSource, scriptDest);
	try { fs.chmodSync(scriptDest, 0o755); } catch { /* not fatal on Windows */ }
	return 1;
}

async function installCursorHook(context: vscode.ExtensionContext, workspaceFolder: string): Promise<number> {
	const cursorDir = path.join(workspaceFolder, '.cursor');
	const hooksFile = path.join(cursorDir, 'hooks.json');
	if (fs.existsSync(hooksFile)) { return 0; }

	const sourceFile = path.join(context.extensionPath, 'standards', 'hooks', 'cursor', 'hooks.json');
	if (!fs.existsSync(sourceFile)) { return 0; }

	if (!fs.existsSync(cursorDir)) {
		fs.mkdirSync(cursorDir, { recursive: true });
	}
	fs.copyFileSync(sourceFile, hooksFile);
	return 1;
}

async function installKiroHook(context: vscode.ExtensionContext, workspaceFolder: string): Promise<number> {
	const hooksDir = path.join(workspaceFolder, '.kiro', 'hooks');
	const hookFile = path.join(hooksDir, 'appsec-gate.kiro.hook');

	// Don't overwrite if already exists
	if (fs.existsSync(hookFile)) {
		cleanupLegacyKiroHook(hooksDir);
		return 0;
	}

	const sourceFile = path.join(context.extensionPath, 'standards', 'hooks', 'kiro', 'appsec-gate.kiro.hook');
	if (!fs.existsSync(sourceFile)) {
		return 0;
	}

	if (!fs.existsSync(hooksDir)) {
		fs.mkdirSync(hooksDir, { recursive: true });
	}

	fs.copyFileSync(sourceFile, hookFile);
	cleanupLegacyKiroHook(hooksDir);
	return 1;
}

async function installClaudeHook(context: vscode.ExtensionContext, workspaceFolder: string): Promise<number> {
	const claudeSettingsDir = path.join(workspaceFolder, '.claude');
	const settingsFile = path.join(claudeSettingsDir, 'settings.json');
	if (fs.existsSync(settingsFile)) { return 0; }

	const sourceFile = path.join(context.extensionPath, 'standards', 'hooks', 'claude', 'settings.json');
	if (!fs.existsSync(sourceFile)) { return 0; }

	if (!fs.existsSync(claudeSettingsDir)) {
		fs.mkdirSync(claudeSettingsDir, { recursive: true });
	}
	fs.copyFileSync(sourceFile, settingsFile);
	return 1;
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

export function deactivate() {
	if (diagnosticCollection) {
		diagnosticCollection.dispose();
	}
}
