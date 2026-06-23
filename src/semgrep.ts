import * as vscode from 'vscode';
import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';
import * as fs from 'fs';
import { SecurityFinding, Severity, sortBySeverity } from './scanner';

const execFileAsync = promisify(execFile);

// Cache for OpenGrep availability — avoids spawning a process on every scan
let _opengrepAvailable: boolean | null = null;

/**
 * Checks if OpenGrep is installed (cached after first successful check).
 * Only re-checks if a previous install attempt was made.
 */
export function isOpenGrepInstalled(): boolean {
	if (_opengrepAvailable !== null) {
		return _opengrepAvailable;
	}
	try {
		execFileSync('opengrep', ['--version'], { encoding: 'utf-8', stdio: 'pipe', timeout: 5000 });
		_opengrepAvailable = true;
		return true;
	} catch {
		_opengrepAvailable = false;
		return false;
	}
}

/**
 * Async version of isOpenGrepInstalled (non-blocking).
 * On Windows, also searches common installation directories that winget/pip
 * may use but that are not always on VS Code's inherited PATH.
 */
async function checkOpenGrepAsync(): Promise<boolean> {
	if (_opengrepAvailable !== null) {
		return _opengrepAvailable;
	}
	try {
		await execFileAsync('opengrep', ['--version'], { encoding: 'utf-8', timeout: 5000 });
		_opengrepAvailable = true;
		return true;
	} catch {
		// On Windows, winget and pip install binaries to directories that may not
		// be on the PATH inherited by the VS Code process. Search those paths explicitly.
		if (process.platform === 'win32' && await findOpenGrepOnWindows()) {
			_opengrepAvailable = true;
			return true;
		}
		_opengrepAvailable = false;
		return false;
	}
}

/**
 * Searches common Windows installation paths for opengrep.exe.
 * Covers: winget links directory, local programs, and Python Scripts folders
 * for any installed Python version (pip places binaries there).
 */
async function findOpenGrepOnWindows(): Promise<boolean> {
	const appData = process.env.APPDATA || '';
	const localAppData = process.env.LOCALAPPDATA || '';

	// Static candidates: winget and direct program installs
	const staticCandidates = [
		path.join(localAppData, 'Microsoft', 'WinGet', 'Links', 'opengrep.exe'),
		path.join(localAppData, 'Programs', 'opengrep', 'opengrep.exe'),
	].filter(Boolean);

	for (const candidate of staticCandidates) {
		try {
			if (fs.existsSync(candidate)) {
				await execFileAsync(candidate, ['--version'], { encoding: 'utf-8', timeout: 5000 });
				return true;
			}
		} catch { /* try next */ }
	}

	// Python Scripts directories — pip installs binaries here, path is version-dependent
	// e.g. %APPDATA%\Python\Python312\Scripts\opengrep.exe
	const pythonSearchBases = [
		appData ? path.join(appData, 'Python') : '',
		localAppData ? path.join(localAppData, 'Programs', 'Python') : '',
	].filter(Boolean);

	for (const searchBase of pythonSearchBases) {
		try {
			if (!fs.existsSync(searchBase)) { continue; }
			const subdirs = fs.readdirSync(searchBase);
			for (const subdir of subdirs) {
				const candidate = path.join(searchBase, subdir, 'Scripts', 'opengrep.exe');
				if (fs.existsSync(candidate)) {
					try {
						await execFileAsync(candidate, ['--version'], { encoding: 'utf-8', timeout: 5000 });
						return true;
					} catch { /* not functional, try next */ }
				}
			}
		} catch { /* directory not accessible */ }
	}

	return false;
}

/**
 * Invalidates the OpenGrep cache (call after install attempts).
 */
function invalidateOpenGrepCache(): void {
	_opengrepAvailable = null;
}

/**
 * Installs OpenGrep on the user's machine.
 * OpenGrep ships self-contained binaries — no Python needed.
 */
export async function installOpenGrep(): Promise<boolean> {
	invalidateOpenGrepCache();

	const result = await vscode.window.withProgress(
		{
			location: vscode.ProgressLocation.Notification,
			title: '🛡️ Instalando OpenGrep...',
			cancellable: false,
		},
		async (progress) => {
			if (process.platform === 'win32') {
				// Windows installation strategies
				// 1. Try winget (available on Windows 10 1709+ and Windows 11)
				try {
					progress.report({ message: 'Tentando via winget...' });
					await execFileAsync('winget', ['install', '--id', 'OpenGrep.OpenGrep', '-e', '--accept-source-agreements', '--accept-package-agreements'], {
						encoding: 'utf-8',
						timeout: 120000,
					});
					return true;
				} catch { /* winget not available or package not found */ }

				// 2. Try scoop (popular on dev machines)
				try {
					progress.report({ message: 'Tentando via scoop...' });
					await execFileAsync('scoop', ['install', 'opengrep'], {
						encoding: 'utf-8',
						timeout: 120000,
					});
					return true;
				} catch { /* scoop not available */ }

				// 3. Try pip as fallback (Python is often available on Windows dev machines)
				try {
					progress.report({ message: 'Tentando via pip...' });
					await execFileAsync('pip', ['install', 'opengrep'], {
						encoding: 'utf-8',
						timeout: 120000,
					});
					return true;
				} catch { /* */ }

				// 4. Try pip3 as last resort
				try {
					progress.report({ message: 'Tentando via pip3...' });
					await execFileAsync('pip3', ['install', 'opengrep'], {
						encoding: 'utf-8',
						timeout: 120000,
					});
					return true;
				} catch { /* */ }

				return false;
			}

			// macOS / Linux: use the official install script
			try {
				progress.report({ message: 'Baixando binário...' });
				await execFileAsync('bash', ['-c', 'curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash'], {
					encoding: 'utf-8',
					timeout: 120000,
				});
				return true;
			} catch {
				// Try brew as fallback (macOS)
				try {
					progress.report({ message: 'Tentando via brew...' });
					await execFileAsync('brew', ['install', 'opengrep/tap/opengrep'], {
						encoding: 'utf-8',
						timeout: 120000,
					});
					return true;
				} catch { /* */ }
			}

			// Try pip as last resort (older method)
			try {
				progress.report({ message: 'Tentando via pip...' });
				await execFileAsync('pip3', ['install', 'opengrep'], {
					encoding: 'utf-8',
					timeout: 120000,
				});
				return true;
			} catch { /* */ }

			return false;
		}
	);

	if (result) {
		invalidateOpenGrepCache();
		vscode.window.showInformationMessage('[Hotmart AppSec] ✅ OpenGrep instalado com sucesso! Scanner de segurança pronto pra uso. 🔍');
		return true;
	}

	// Platform-specific failure message
	const installHint = process.platform === 'win32'
		? 'Instale manualmente via: winget install OpenGrep.OpenGrep'
		: 'Instale manualmente via: brew install opengrep/tap/opengrep';

	const action = await vscode.window.showErrorMessage(
		`[Hotmart AppSec] Não conseguimos instalar o OpenGrep automaticamente. ${installHint}`,
		'Ver Instruções',
		'Tentar novamente'
	);

	if (action === 'Ver Instruções') {
		vscode.env.openExternal(vscode.Uri.parse('https://github.com/opengrep/opengrep#installation'));
	} else if (action === 'Tentar novamente') {
		// Cache is already null from the invalidateOpenGrepCache() call at the start of this function.
		// Re-running the check picks up a manual install that happened while the error was shown.
		if (await checkOpenGrepAsync()) {
			vscode.window.showInformationMessage('[Hotmart AppSec] ✅ OpenGrep detectado! Scanner de segurança pronto. 🔍');
			return true;
		}
		vscode.window.showWarningMessage(
			'[Hotmart AppSec] OpenGrep ainda não encontrado. Verifique se está no PATH e reinicie o VS Code.'
		);
	}

	return false;
}

/**
 * Ensures OpenGrep is available. Installs silently if needed.
 * Uses async check to avoid blocking the extension host.
 */
export async function ensureOpenGrep(): Promise<boolean> {
	if (await checkOpenGrepAsync()) {
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
 * Fully async — does not block the extension host thread.
 */
export async function runOpenGrep(files: string[], workspaceFolder: string, extensionPath: string): Promise<SecurityFinding[]> {
	if (files.length === 0) {
		return [];
	}

	if (!await checkOpenGrepAsync()) {
		return [];
	}

	const findings: SecurityFinding[] = [];

	try {
		// Build absolute file paths — filter out files that no longer exist on disk.
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

		// Run opengrep asynchronously with argv array (safe for paths with special chars)
		const args = ['scan', '--json', '--quiet', `--config=${rulesPath}`, ...filePaths];

		let output: string;
		try {
			const result = await execFileAsync('opengrep', args, {
				cwd: workspaceFolder,
				encoding: 'utf-8',
				maxBuffer: 50 * 1024 * 1024,
				timeout: 90000,
			});
			output = result.stdout;
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

	// Filter out dismissed/fixed findings
	const filtered = filterDismissedFindings(deduped, workspaceFolder);

	return sortBySeverity(filtered);
}

/**
 * Reads .appsec/dismissed.json and removes findings that were dismissed or marked as fixed.
 */
function filterDismissedFindings(findings: SecurityFinding[], workspaceFolder: string): SecurityFinding[] {
	const dismissedFile = path.join(workspaceFolder, '.appsec', 'dismissed.json');
	if (!fs.existsSync(dismissedFile)) { return findings; }

	let dismissed: Array<{ id: string; file: string; line: number }> = [];
	try {
		dismissed = JSON.parse(fs.readFileSync(dismissedFile, 'utf-8'));
	} catch {
		return findings;
	}

	if (dismissed.length === 0) { return findings; }

	const dismissedKeys = new Set<string>();
	for (const d of dismissed) {
		const ruleId = normalizeCheckId(d.id);
		// Match by rule+file+line (exact) and rule+file (any line)
		dismissedKeys.add(`${ruleId}:${d.file}:${d.line}`);
		dismissedKeys.add(`${ruleId}:${d.file}:0`);
	}

	return findings.filter(f => {
		const key = `${f.id}:${f.file}:${f.line}`;
		const keyAnyLine = `${f.id}:${f.file}:0`;
		return !dismissedKeys.has(key) && !dismissedKeys.has(keyAnyLine);
	});
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
