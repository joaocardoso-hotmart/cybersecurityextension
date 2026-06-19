import * as vscode from 'vscode';
import { execSync, execFileSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import { SecurityFinding, Severity, sortBySeverity } from './scanner';

/**
 * Checks if OpenGrep is installed on the system.
 */
export function isOpenGrepInstalled(): boolean {
	try {
		execSync('opengrep --version', { encoding: 'utf-8', stdio: 'pipe' });
		return true;
	} catch {
		return false;
	}
}

/**
 * Installs OpenGrep on the user's machine.
 * OpenGrep ships self-contained binaries — no Python needed.
 */
export async function installOpenGrep(): Promise<boolean> {
	const result = await vscode.window.withProgress(
		{
			location: vscode.ProgressLocation.Notification,
			title: '🛡️ Instalando OpenGrep...',
			cancellable: false,
		},
		async (progress) => {
			// macOS / Linux: use the official install script
			try {
				progress.report({ message: 'Baixando binário...' });
				execSync(
					'curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash',
					{ encoding: 'utf-8', stdio: 'pipe', timeout: 120000, shell: '/bin/bash' }
				);
				return true;
			} catch {
				// Try brew as fallback
				try {
					progress.report({ message: 'Tentando via brew...' });
					execSync('brew install opengrep/tap/opengrep', { encoding: 'utf-8', stdio: 'pipe', timeout: 120000 });
					return true;
				} catch { /* */ }
			}

			// Try pip as last resort (older method)
			try {
				progress.report({ message: 'Tentando via pip...' });
				execSync('pip3 install opengrep', { encoding: 'utf-8', stdio: 'pipe', timeout: 120000 });
				return true;
			} catch { /* */ }

			return false;
		}
	);

	if (result) {
		vscode.window.showInformationMessage('[Hotmart AppSec] ✅ OpenGrep instalado com sucesso! Scanner de segurança pronto pra uso. 🔍');
		return true;
	}

	const action = await vscode.window.showErrorMessage(
		'[Hotmart AppSec] Não conseguimos instalar o OpenGrep automaticamente. Sem ele, o scan de segurança não funciona.',
		'Ver Instruções'
	);

	if (action === 'Ver Instruções') {
		vscode.env.openExternal(vscode.Uri.parse('https://github.com/opengrep/opengrep#installation'));
	}

	return false;
}

/**
 * Ensures OpenGrep is available. Installs silently if needed.
 */
export async function ensureOpenGrep(): Promise<boolean> {
	if (isOpenGrepInstalled()) {
		return true;
	}

	// Install silently without asking
	return await installOpenGrep();
}

/**
 * Maps OpenGrep severity to our severity type.
 */
function mapSeverity(severity: string): Severity {
	switch (severity.toUpperCase()) {
		case 'ERROR': return 'critical';
		case 'WARNING': return 'high';
		case 'INFO': return 'medium';
		default: return 'low';
	}
}

/**
 * Extracts CWE from metadata.
 */
function extractCwe(metadata: Record<string, unknown>): string {
	if (metadata.cwe) {
		if (Array.isArray(metadata.cwe)) {
			return metadata.cwe[0] as string || 'CWE-000';
		}
		return metadata.cwe as string;
	}
	return 'CWE-000';
}

/**
 * Formats a check_id into a readable title.
 */
function formatTitle(checkId: string): string {
	const parts = checkId.split('.');
	const relevant = parts.slice(-2).join(' ');
	return relevant
		.replace(/-/g, ' ')
		.replace(/\b\w/g, c => c.toUpperCase())
		.substring(0, 60);
}

/**
 * Normalizes an OpenGrep check_id by stripping the machine-specific path prefix.
 * Input:  "Users.leandro.andrade..kiro.extensions.hotmartcybersecurity.cybersecurityextension-0.8.4-universal.rules.dockerfile-run-as-root"
 * Output: "rules.dockerfile-run-as-root"
 */
function normalizeCheckId(checkId: string): string {
	const marker = '.rules.';
	const idx = checkId.indexOf(marker);
	if (idx !== -1) {
		return checkId.substring(idx + 1); // includes "rules."
	}
	return checkId;
}

/**
 * Runs OpenGrep on the specified files and returns findings.
 */
export async function runOpenGrep(files: string[], workspaceFolder: string, extensionPath: string): Promise<SecurityFinding[]> {
	if (files.length === 0) {
		return [];
	}

	if (!isOpenGrepInstalled()) {
		return [];
	}

	const findings: SecurityFinding[] = [];

	try {
		// Build absolute file paths (passed as separate argv entries — no shell interpolation,
		// so filenames with parentheses, spaces or other special chars work correctly).
		// Filter out files that no longer exist on disk (e.g. deleted files from git diff).
		const filePaths = files
			.map(f => path.join(workspaceFolder, f))
			.filter(f => fs.existsSync(f));

		if (filePaths.length === 0) {
			return [];
		}

		// Use local rules bundled with the extension
		let rulesPath = path.join(extensionPath, 'rules', 'security.yml');

		// Fallback: look for rules in workspace (for development)
		if (!fs.existsSync(rulesPath)) {
			const workspaceRules = path.join(workspaceFolder, 'rules', 'security.yml');
			if (fs.existsSync(workspaceRules)) {
				rulesPath = workspaceRules;
			}
		}

		if (!fs.existsSync(rulesPath)) {
			vscode.window.showErrorMessage('[Hotmart AppSec] Arquivo de regras de segurança não encontrado. Execute "Bootstrap Project" para configurar.');
			return findings;
		}

		// Run opengrep with local rules (no internet needed).
		// Use execFileSync with argv array so paths with parentheses/spaces are passed
		// safely without going through a shell.
		const args = ['scan', '--json', '--quiet', `--config=${rulesPath}`, ...filePaths];

		let output: string;
		try {
			output = execFileSync('opengrep', args, {
				cwd: workspaceFolder,
				encoding: 'utf-8',
				maxBuffer: 50 * 1024 * 1024,
				timeout: 90000,
				stdio: ['pipe', 'pipe', 'pipe'],
			});
		} catch (execErr: unknown) {
			// OpenGrep returns exit code 1 when findings exist — parse stdout
			if (execErr && typeof execErr === 'object' && 'stdout' in execErr) {
				const stdout = (execErr as { stdout: Buffer | string }).stdout;
				output = typeof stdout === 'string' ? stdout : (stdout?.toString('utf-8') || '');
			} else {
				console.error('OpenGrep execution error:', execErr);
				return findings;
			}
		}

		if (!output || output.trim().length === 0) {
			return findings;
		}

		const result = JSON.parse(output);

		if (!result.results || !Array.isArray(result.results)) {
			return findings;
		}

		for (const item of result.results) {
			const filePath = vscode.workspace.asRelativePath(item.path);
			const line = item.start?.line || 1;
			const col = item.start?.col || 1;
			const endCol = item.end?.col || col + 20;
			const metadata = item.extra?.metadata || {};
			const message = item.extra?.message || item.check_id || 'Security issue';
			const severity = mapSeverity(item.extra?.severity || 'WARNING');
			const cwe = extractCwe(metadata);
			const snippet = item.extra?.lines || '';

			let suggestion = '';
			if (metadata.fix) {
				suggestion = metadata.fix as string;
			} else if (metadata.message) {
				suggestion = metadata.message as string;
			} else if (metadata.references && Array.isArray(metadata.references)) {
				suggestion = `Referência: ${(metadata.references as string[])[0]}`;
			} else {
				suggestion = message;
			}

			findings.push({
				id: normalizeCheckId(item.check_id || `OG_${Date.now()}`),
				severity,
				title: formatTitle(item.check_id || message),
				description: message,
				cwe,
				file: filePath,
				line,
				column: col,
				endColumn: endCol,
				snippet: snippet.trim(),
				suggestion,
				suggestedFix: item.extra?.fix || undefined,
			});
		}
	} catch (err) {
		console.error('OpenGrep parse error:', err);
	}

	// Deduplicate findings with same CWE on the same file:line
	const deduped = deduplicateFindings(findings);

	return sortBySeverity(deduped);
}

/**
 * Removes duplicate findings that share the same CWE and location (file + line).
 * Keeps the finding with highest severity (or first occurrence if equal).
 */
function deduplicateFindings(findings: SecurityFinding[]): SecurityFinding[] {
	const seen = new Map<string, SecurityFinding>();
	const severityRank: Record<Severity, number> = {
		critical: 0, high: 1, medium: 2, low: 3, info: 4,
	};

	for (const finding of findings) {
		const key = `${finding.cwe}:${finding.file}:${finding.line}`;
		const existing = seen.get(key);

		if (!existing || severityRank[finding.severity] < severityRank[existing.severity]) {
			seen.set(key, finding);
		}
	}

	return Array.from(seen.values());
}
