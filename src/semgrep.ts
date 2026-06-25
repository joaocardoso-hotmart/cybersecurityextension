import * as vscode from 'vscode';
import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';
import * as fs from 'fs';
import * as https from 'https';
import { SecurityFinding, Severity, sortBySeverity } from './scanner';

const execFileAsync = promisify(execFile);

// Cache for OpenGrep availability — avoids spawning a process on every scan
let _opengrepAvailable: boolean | null = null;

// Resolved absolute path to the opengrep binary (used when not in PATH)
let _opengrepBinaryPath: string = 'opengrep';

// Extension context reference for globalState access (install cooldown)
let _extensionContext: vscode.ExtensionContext | null = null;

/** Cooldown key and duration for install attempts (24 hours) */
const INSTALL_COOLDOWN_KEY = 'hotmartAppSec.opengrepInstallCooldown';
const INSTALL_COOLDOWN_MS = 24 * 60 * 60 * 1000;

/**
 * Sets the extension context so semgrep.ts can use globalState for cooldowns.
 * Must be called once from extension.ts during activation.
 */
export function setOpenGrepContext(context: vscode.ExtensionContext): void {
	_extensionContext = context;
}

/**
 * Returns the resolved opengrep command (absolute path or bare name).
 */
function getOpenGrepCommand(): string {
	return _opengrepBinaryPath;
}

/**
 * Checks if OpenGrep is installed (cached after first successful check).
 * Only re-checks if a previous install attempt was made.
 */
export function isOpenGrepInstalled(): boolean {
	if (_opengrepAvailable !== null) {
		return _opengrepAvailable;
	}
	try {
		execFileSync(_opengrepBinaryPath, ['--version'], { encoding: 'utf-8', stdio: 'pipe', timeout: 5000 });
		_opengrepAvailable = true;
		return true;
	} catch {
		// On Windows, try finding in known paths synchronously
		if (process.platform === 'win32') {
			const found = findOpenGrepOnWindowsSync();
			if (found) {
				_opengrepBinaryPath = found;
				_opengrepAvailable = true;
				return true;
			}
		}
		_opengrepAvailable = false;
		return false;
	}
}

/**
 * Async version of isOpenGrepInstalled (non-blocking).
 * On Windows, also searches common installation directories that winget/pip/MDM
 * may use but that are not always on the IDE's inherited PATH.
 */
async function checkOpenGrepAsync(): Promise<boolean> {
	if (_opengrepAvailable !== null) {
		return _opengrepAvailable;
	}
	try {
		await execFileAsync(_opengrepBinaryPath, ['--version'], { encoding: 'utf-8', timeout: 5000 });
		_opengrepAvailable = true;
		return true;
	} catch {
		// On Windows, winget/pip/MDM install binaries to directories that may not
		// be on the PATH inherited by the IDE process. Search those paths explicitly.
		if (process.platform === 'win32') {
			const resolvedPath = await findOpenGrepOnWindows();
			if (resolvedPath) {
				_opengrepBinaryPath = resolvedPath;
				_opengrepAvailable = true;
				return true;
			}
		}
		_opengrepAvailable = false;
		return false;
	}
}

/**
 * All known Windows installation paths for opengrep.exe.
 * Covers: MDM installs (Hotmart), winget, scoop, pip, and direct program installs.
 */
function getWindowsCandidatePaths(): string[] {
	const localAppData = process.env.LOCALAPPDATA || '';
	const appData = process.env.APPDATA || '';
	const programData = process.env.ProgramData || 'C:\\ProgramData';

	const candidates: string[] = [
		// MDM install paths (Hotmart corporate deployment)
		path.join(programData, 'Hotmart', 'bin', 'opengrep.exe'),
		'C:\\Hotmart\\Instaladores\\bin\\opengrep.exe',
		// winget links directory
		path.join(localAppData, 'Microsoft', 'WinGet', 'Links', 'opengrep.exe'),
		// Direct program installs
		path.join(localAppData, 'Programs', 'opengrep', 'opengrep.exe'),
		// Scoop
		path.join(process.env.USERPROFILE || '', 'scoop', 'shims', 'opengrep.exe'),
	].filter(p => p && !p.startsWith('\\'));

	// Python Scripts directories — pip installs binaries here
	const pythonSearchBases = [
		appData ? path.join(appData, 'Python') : '',
		localAppData ? path.join(localAppData, 'Programs', 'Python') : '',
	].filter(Boolean);

	for (const searchBase of pythonSearchBases) {
		try {
			if (!fs.existsSync(searchBase)) { continue; }
			const subdirs = fs.readdirSync(searchBase);
			for (const subdir of subdirs) {
				candidates.push(path.join(searchBase, subdir, 'Scripts', 'opengrep.exe'));
			}
		} catch { /* directory not accessible */ }
	}

	return candidates;
}

/**
 * Searches common Windows installation paths for opengrep.exe (async).
 * Returns the resolved absolute path if found and functional, or null.
 */
async function findOpenGrepOnWindows(): Promise<string | null> {
	const candidates = getWindowsCandidatePaths();

	for (const candidate of candidates) {
		try {
			if (fs.existsSync(candidate)) {
				await execFileAsync(candidate, ['--version'], { encoding: 'utf-8', timeout: 5000 });
				console.log(`[Hotmart AppSec] OpenGrep found at: ${candidate}`);
				return candidate;
			}
		} catch { /* try next */ }
	}

	return null;
}

/**
 * Synchronous version of findOpenGrepOnWindows (for isOpenGrepInstalled).
 */
function findOpenGrepOnWindowsSync(): string | null {
	const candidates = getWindowsCandidatePaths();

	for (const candidate of candidates) {
		try {
			if (fs.existsSync(candidate)) {
				execFileSync(candidate, ['--version'], { encoding: 'utf-8', stdio: 'pipe', timeout: 5000 });
				console.log(`[Hotmart AppSec] OpenGrep found at: ${candidate}`);
				return candidate;
			}
		} catch { /* try next */ }
	}

	return null;
}

/**
 * Invalidates the OpenGrep cache (call after install attempts).
 */
function invalidateOpenGrepCache(): void {
	_opengrepAvailable = null;
	_opengrepBinaryPath = 'opengrep';
}

/**
 * Checks whether the install cooldown period has elapsed.
 * Returns true if we should skip the install attempt (still in cooldown).
 */
function isInstallOnCooldown(): boolean {
	if (!_extensionContext) { return false; }
	const lastAttempt = _extensionContext.globalState.get<number>(INSTALL_COOLDOWN_KEY, 0);
	return (Date.now() - lastAttempt) < INSTALL_COOLDOWN_MS;
}

/**
 * Records the current time as the last install attempt (starts cooldown).
 */
function markInstallAttempt(): void {
	if (!_extensionContext) { return; }
	void _extensionContext.globalState.update(INSTALL_COOLDOWN_KEY, Date.now());
}

/**
 * Installs OpenGrep on the user's machine.
 * OpenGrep ships self-contained binaries — no Python needed.
 * On Windows, also tries downloading the binary directly from GitHub (like MDM scripts do).
 */
export async function installOpenGrep(): Promise<boolean> {
	invalidateOpenGrepCache();
	markInstallAttempt();

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

				// 3. Download binary directly from GitHub Releases (same approach as MDM scripts)
				try {
					progress.report({ message: 'Baixando binário do GitHub...' });
					const downloaded = await downloadOpenGrepBinary();
					if (downloaded) { return true; }
				} catch { /* download failed */ }

				// 4. Try pip as fallback (Python is often available on Windows dev machines)
				try {
					progress.report({ message: 'Tentando via pip...' });
					await execFileAsync('pip', ['install', 'opengrep'], {
						encoding: 'utf-8',
						timeout: 120000,
					});
					return true;
				} catch { /* */ }

				// 5. Try pip3 as last resort
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
		// Re-check to resolve the actual binary path
		await checkOpenGrepAsync();
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
		invalidateOpenGrepCache();
		if (await checkOpenGrepAsync()) {
			vscode.window.showInformationMessage('[Hotmart AppSec] ✅ OpenGrep detectado! Scanner de segurança pronto. 🔍');
			return true;
		}
		vscode.window.showWarningMessage(
			'[Hotmart AppSec] OpenGrep ainda não encontrado. Verifique se está no PATH e reinicie a IDE.'
		);
	}

	return false;
}

/**
 * Downloads the OpenGrep binary directly from GitHub Releases.
 * Installs to C:\ProgramData\Hotmart\bin\ (same path the MDM scripts use)
 * and adds it to the system PATH if possible, otherwise user PATH.
 *
 * This is the same approach used by the corporate MDM watchdog scripts.
 */
async function downloadOpenGrepBinary(): Promise<boolean> {
	const binDir = path.join(process.env.ProgramData || 'C:\\ProgramData', 'Hotmart', 'bin');
	const binPath = path.join(binDir, 'opengrep.exe');

	try {
		// Fetch latest release info from GitHub API
		const releaseInfo = await httpGetJson('https://api.github.com/repos/opengrep/opengrep/releases/latest');
		if (!releaseInfo || !releaseInfo.assets) { return false; }

		// Find the Windows binary asset
		const asset = (releaseInfo.assets as Array<{ name: string; browser_download_url: string }>).find(
			a => /windows.*\.exe$/i.test(a.name) && !/\.(cert|sig)$/i.test(a.name)
		);

		if (!asset) {
			console.log('[Hotmart AppSec] No Windows binary found in latest OpenGrep release');
			return false;
		}

		// Ensure target directory exists
		if (!fs.existsSync(binDir)) {
			fs.mkdirSync(binDir, { recursive: true });
		}

		// Download the binary
		await httpDownloadFile(asset.browser_download_url, binPath);

		// Verify the downloaded file is functional
		try {
			await execFileAsync(binPath, ['--version'], { encoding: 'utf-8', timeout: 10000 });
		} catch {
			// Downloaded file is not functional — remove it
			try { fs.unlinkSync(binPath); } catch { /* */ }
			return false;
		}

		// Add to system PATH (best effort — may fail without admin rights)
		try {
			const sysPath = await execFileAsync('powershell', [
				'-NoProfile', '-Command',
				`[Environment]::GetEnvironmentVariable('PATH', 'Machine')`,
			], { encoding: 'utf-8', timeout: 5000 });

			if (!sysPath.stdout.includes(binDir)) {
				await execFileAsync('powershell', [
					'-NoProfile', '-Command',
					`[Environment]::SetEnvironmentVariable('PATH', [Environment]::GetEnvironmentVariable('PATH', 'Machine') + ';${binDir}', 'Machine')`,
				], { encoding: 'utf-8', timeout: 5000 });
			}
		} catch {
			// Fallback: add to user PATH if system PATH fails (no admin)
			try {
				const userPath = await execFileAsync('powershell', [
					'-NoProfile', '-Command',
					`[Environment]::GetEnvironmentVariable('PATH', 'User')`,
				], { encoding: 'utf-8', timeout: 5000 });

				if (!userPath.stdout.includes(binDir)) {
					await execFileAsync('powershell', [
						'-NoProfile', '-Command',
						`[Environment]::SetEnvironmentVariable('PATH', [Environment]::GetEnvironmentVariable('PATH', 'User') + ';${binDir}', 'User')`,
					], { encoding: 'utf-8', timeout: 5000 });
				}
			} catch {
				console.warn('[Hotmart AppSec] Could not add opengrep to PATH (no admin rights)');
			}
		}

		// Set the resolved path immediately (IDE won't see PATH until restart)
		_opengrepBinaryPath = binPath;
		console.log(`[Hotmart AppSec] OpenGrep downloaded to ${binPath}`);
		return true;
	} catch (err) {
		console.error('[Hotmart AppSec] OpenGrep download failed:', err);
		return false;
	}
}

/**
 * Simple HTTPS GET returning parsed JSON. Used for GitHub API.
 */
function httpGetJson(url: string): Promise<Record<string, unknown> | null> {
	return new Promise((resolve) => {
		const req = https.get(url, { headers: { 'User-Agent': 'HotmartAppSec-Extension' } }, (res) => {
			// Follow redirects (GitHub API may redirect)
			if (res.statusCode === 301 || res.statusCode === 302) {
				const redirectUrl = res.headers.location;
				if (redirectUrl) {
					httpGetJson(redirectUrl).then(resolve);
					return;
				}
			}
			if (res.statusCode !== 200) { resolve(null); return; }

			let data = '';
			res.on('data', chunk => { data += chunk; });
			res.on('end', () => {
				try { resolve(JSON.parse(data)); }
				catch { resolve(null); }
			});
		});
		req.on('error', () => resolve(null));
		req.setTimeout(30000, () => { req.destroy(); resolve(null); });
	});
}

/**
 * Downloads a file from a URL (follows redirects). Used for binary downloads.
 */
function httpDownloadFile(url: string, destPath: string): Promise<void> {
	return new Promise((resolve, reject) => {
		const makeRequest = (targetUrl: string, redirectsLeft: number) => {
			const parsedUrl = new URL(targetUrl);
			const options = {
				hostname: parsedUrl.hostname,
				path: parsedUrl.pathname + parsedUrl.search,
				headers: { 'User-Agent': 'HotmartAppSec-Extension' },
			};

			const req = https.get(options, (res) => {
				if ((res.statusCode === 301 || res.statusCode === 302) && redirectsLeft > 0) {
					const redirectUrl = res.headers.location;
					if (redirectUrl) {
						makeRequest(redirectUrl, redirectsLeft - 1);
						return;
					}
				}
				if (res.statusCode !== 200) {
					reject(new Error(`HTTP ${res.statusCode}`));
					return;
				}

				const file = fs.createWriteStream(destPath);
				res.pipe(file);
				file.on('finish', () => { file.close(); resolve(); });
				file.on('error', (err) => {
					try { fs.unlinkSync(destPath); } catch { /* */ }
					reject(err);
				});
			});
			req.on('error', reject);
			req.setTimeout(120000, () => { req.destroy(); reject(new Error('Timeout')); });
		};

		makeRequest(url, 5);
	});
}

/**
 * Ensures OpenGrep is available. Installs if needed.
 * Respects a 24h cooldown between install attempts to avoid spamming the user.
 */
export async function ensureOpenGrep(): Promise<boolean> {
	if (await checkOpenGrepAsync()) {
		return true;
	}

	// If we already tried installing recently and it failed, don't try again
	if (isInstallOnCooldown()) {
		console.log('[Hotmart AppSec] OpenGrep install on cooldown — skipping automatic install');
		return false;
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
			const result = await execFileAsync(getOpenGrepCommand(), args, {
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
