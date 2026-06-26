import * as vscode from 'vscode';
import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';
import * as fs from 'fs';
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
 * Known path where the corporate MDM (Workspace ONE) installs OpenGrep on Windows.
 * See: deploy/windows/mdm-install.ps1 → Install-OpenGrep function.
 */
const WINDOWS_MDM_OPENGREP = 'C:\\ProgramData\\Hotmart\\bin\\opengrep.exe';

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
 * On Windows, checks the MDM install path first — the MDM already puts the
 * binary there, so we just need to find it and use it directly.
 */
export function isOpenGrepInstalled(): boolean {
	if (_opengrepAvailable !== null) {
		return _opengrepAvailable;
	}

	// On Windows: check MDM path first (instant fs check, no process spawn)
	if (process.platform === 'win32' && fs.existsSync(WINDOWS_MDM_OPENGREP)) {
		try {
			execFileSync(WINDOWS_MDM_OPENGREP, ['--version'], { encoding: 'utf-8', stdio: 'pipe', timeout: 5000 });
			_opengrepBinaryPath = WINDOWS_MDM_OPENGREP;
			_opengrepAvailable = true;
			return true;
		} catch { /* exists but not functional */ }
	}

	// Fallback: check PATH (macOS/Linux, or Windows if in PATH)
	try {
		execFileSync('opengrep', ['--version'], { encoding: 'utf-8', stdio: 'pipe', timeout: 5000 });
		_opengrepBinaryPath = 'opengrep';
		_opengrepAvailable = true;
		return true;
	} catch {
		_opengrepAvailable = false;
		return false;
	}
}

/**
 * Async check for OpenGrep (non-blocking).
 * On Windows: MDM path → PATH → known fallback locations.
 */
async function checkOpenGrepAsync(): Promise<boolean> {
	if (_opengrepAvailable !== null) {
		return _opengrepAvailable;
	}

	// Windows: check MDM path first (the MDM already installed it here)
	if (process.platform === 'win32' && fs.existsSync(WINDOWS_MDM_OPENGREP)) {
		try {
			await execFileAsync(WINDOWS_MDM_OPENGREP, ['--version'], { encoding: 'utf-8', timeout: 5000 });
			_opengrepBinaryPath = WINDOWS_MDM_OPENGREP;
			_opengrepAvailable = true;
			addToProcessPath(path.dirname(WINDOWS_MDM_OPENGREP));
			console.log(`[Hotmart AppSec] OpenGrep found at MDM path: ${WINDOWS_MDM_OPENGREP}`);
			return true;
		} catch { /* exists but not functional */ }
	}

	// Check PATH (covers macOS/Linux and Windows when opengrep is in PATH)
	try {
		await execFileAsync('opengrep', ['--version'], { encoding: 'utf-8', timeout: 5000 });
		_opengrepBinaryPath = 'opengrep';
		_opengrepAvailable = true;
		return true;
	} catch { /* not in PATH */ }

	// Windows: check a few more known locations as fallback
	if (process.platform === 'win32') {
		const found = await findOpenGrepFallback();
		if (found) {
			_opengrepBinaryPath = found;
			_opengrepAvailable = true;
			return true;
		}
	}

	_opengrepAvailable = false;
	return false;
}

/**
 * Fallback: checks additional known Windows paths if MDM path and PATH failed.
 * Covers winget, scoop, ProgramData, and Program Files.
 */
async function findOpenGrepFallback(): Promise<string | null> {
	const localAppData = process.env.LOCALAPPDATA || '';
	const programData = process.env.ProgramData || 'C:\\ProgramData';

	const candidates = [
		// Analyst's proposed path (may be used in future MDM versions)
		'C:\\Hotmart\\Instaladores\\bin\\opengrep.exe',
		// winget
		path.join(localAppData, 'Microsoft', 'WinGet', 'Links', 'opengrep.exe'),
		path.join(localAppData, 'Programs', 'opengrep', 'opengrep.exe'),
		path.join(process.env.USERPROFILE || '', 'scoop', 'shims', 'opengrep.exe'),
		path.join(process.env['ProgramFiles'] || 'C:\\Program Files', 'opengrep', 'opengrep.exe'),
		path.join(process.env['ProgramFiles'] || 'C:\\Program Files', 'OpenGrep', 'opengrep.exe'),
	].filter(p => p && !p.startsWith('\\'));

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
 * Invalidates the OpenGrep cache (call after install attempts).
 */
function invalidateOpenGrepCache(): void {
	_opengrepAvailable = null;
	_opengrepBinaryPath = 'opengrep';
}

/**
 * Adds a directory to the current process PATH (so child processes can find it too).
 * Also attempts to add to the system PATH persistently via PowerShell (best effort).
 */
function addToProcessPath(dir: string): void {
	const currentPath = process.env.PATH || '';
	if (!currentPath.includes(dir)) {
		process.env.PATH = `${dir};${currentPath}`;
		console.log(`[Hotmart AppSec] Added ${dir} to process PATH`);
	}

	// Best effort: persist to system PATH so the user doesn't need to restart
	if (process.platform === 'win32') {
		execFileAsync('powershell', [
			'-NoProfile', '-Command',
			`$p = [Environment]::GetEnvironmentVariable('PATH','Machine');` +
			`if ($p -notlike '*${dir.replace(/\\/g, '\\\\')}*') {` +
			`[Environment]::SetEnvironmentVariable('PATH', "$p;${dir}", 'Machine') }`,
		], { encoding: 'utf-8', timeout: 5000 }).catch(() => {
			// No admin rights — try user PATH
			execFileAsync('powershell', [
				'-NoProfile', '-Command',
				`$p = [Environment]::GetEnvironmentVariable('PATH','User');` +
				`if ($p -notlike '*${dir.replace(/\\/g, '\\\\')}*') {` +
				`[Environment]::SetEnvironmentVariable('PATH', "$p;${dir}", 'User') }`,
			], { encoding: 'utf-8', timeout: 5000 }).catch(() => { /* best effort */ });
		});
	}
}

/**
 * Checks whether the install cooldown period has elapsed.
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
 * Installs OpenGrep.
 * - Windows: downloads the binary to the MDM path (C:\ProgramData\Hotmart\bin\)
 *   and adds it to PATH. Same location the MDM uses.
 * - macOS/Linux: tries official install script, then brew, then pip.
 */
export async function installOpenGrep(): Promise<boolean> {
	invalidateOpenGrepCache();
	markInstallAttempt();

	if (process.platform === 'win32') {
		// Try to install in the same path the MDM uses
		const installed = await vscode.window.withProgress(
			{
				location: vscode.ProgressLocation.Notification,
				title: '🛡️ Instalando OpenGrep...',
				cancellable: false,
			},
			async (progress) => {
				progress.report({ message: 'Baixando binário do GitHub...' });
				return await downloadOpenGrepToMdmPath();
			}
		);

		if (installed) {
			_opengrepBinaryPath = WINDOWS_MDM_OPENGREP;
			_opengrepAvailable = true;
			addToProcessPath(path.dirname(WINDOWS_MDM_OPENGREP));
			vscode.window.showInformationMessage('[Hotmart AppSec] ✅ OpenGrep instalado com sucesso! 🔍');
			return true;
		}

		// Download failed — tell user to contact IT
		const action = await vscode.window.showWarningMessage(
			'[Hotmart AppSec] Não foi possível instalar o OpenGrep automaticamente. ' +
			'Verifique sua conexão ou entre em contato com o time de AppSec.',
			'Verificar novamente',
			'Entendi'
		);

		if (action === 'Verificar novamente') {
			invalidateOpenGrepCache();
			if (await checkOpenGrepAsync()) {
				vscode.window.showInformationMessage('[Hotmart AppSec] ✅ OpenGrep detectado! 🔍');
				return true;
			}
		}

		return false;
	}

	// macOS / Linux: auto-install
	const result = await vscode.window.withProgress(
		{
			location: vscode.ProgressLocation.Notification,
			title: '🛡️ Instalando OpenGrep...',
			cancellable: false,
		},
		async (progress) => {
			// 1. Official install script
			try {
				progress.report({ message: 'Baixando binário...' });
				await execFileAsync('bash', ['-c', 'curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash'], {
					encoding: 'utf-8',
					timeout: 120000,
				});
				return true;
			} catch { /* */ }

			// 2. Homebrew (macOS)
			try {
				progress.report({ message: 'Tentando via brew...' });
				await execFileAsync('brew', ['install', 'opengrep/tap/opengrep'], {
					encoding: 'utf-8',
					timeout: 120000,
				});
				return true;
			} catch { /* */ }

			// 3. pip3 as last resort
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
	);

	if (result) {
		invalidateOpenGrepCache();
		await checkOpenGrepAsync();
		vscode.window.showInformationMessage('[Hotmart AppSec] ✅ OpenGrep instalado com sucesso! 🔍');
		return true;
	}

	const action = await vscode.window.showErrorMessage(
		'[Hotmart AppSec] Não conseguimos instalar o OpenGrep. Instale manualmente via: brew install opengrep/tap/opengrep',
		'Ver Instruções'
	);

	if (action === 'Ver Instruções') {
		vscode.env.openExternal(vscode.Uri.parse('https://github.com/opengrep/opengrep#installation'));
	}

	return false;
}

/**
 * Downloads OpenGrep binary from GitHub Releases to the MDM path.
 * Same approach the deploy/windows/mdm-install.ps1 uses.
 */
async function downloadOpenGrepToMdmPath(): Promise<boolean> {
	const binDir = path.dirname(WINDOWS_MDM_OPENGREP);

	try {
		// Fetch latest release from GitHub API
		const releaseData = await httpGetJson('https://api.github.com/repos/opengrep/opengrep/releases/latest');
		if (!releaseData || !releaseData.assets) { return false; }

		// Find Windows binary (same logic as mdm-install.ps1: "opengrep_windows_x86.exe")
		const assets = releaseData.assets as Array<{ name: string; browser_download_url: string }>;
		const asset = assets.find(a =>
			a.name === 'opengrep_windows_x86.exe' ||
			(/windows.*\.exe$/i.test(a.name) && !/\.(cert|sig)$/i.test(a.name))
		);

		if (!asset) {
			console.log('[Hotmart AppSec] No Windows binary found in latest OpenGrep release');
			return false;
		}

		// Ensure directory exists
		if (!fs.existsSync(binDir)) {
			fs.mkdirSync(binDir, { recursive: true });
		}

		// Download
		await httpDownloadFile(asset.browser_download_url, WINDOWS_MDM_OPENGREP);

		// Verify it works
		try {
			await execFileAsync(WINDOWS_MDM_OPENGREP, ['--version'], { encoding: 'utf-8', timeout: 10000 });
		} catch {
			try { fs.unlinkSync(WINDOWS_MDM_OPENGREP); } catch { /* */ }
			return false;
		}

		console.log(`[Hotmart AppSec] OpenGrep downloaded to ${WINDOWS_MDM_OPENGREP}`);
		return true;
	} catch (err) {
		console.error('[Hotmart AppSec] OpenGrep download failed:', err);
		return false;
	}
}

/**
 * Simple HTTPS GET returning parsed JSON (for GitHub API).
 */
function httpGetJson(url: string): Promise<Record<string, unknown> | null> {
	const https = require('https');
	return new Promise((resolve) => {
		const req = https.get(url, { headers: { 'User-Agent': 'HotmartAppSec-Extension' } }, (res: { statusCode?: number; headers: Record<string, string>; on: Function }) => {
			if (res.statusCode === 301 || res.statusCode === 302) {
				const redirect = res.headers.location;
				if (redirect) { httpGetJson(redirect).then(resolve); return; }
			}
			if (res.statusCode !== 200) { resolve(null); return; }
			let data = '';
			res.on('data', (chunk: string) => { data += chunk; });
			res.on('end', () => { try { resolve(JSON.parse(data)); } catch { resolve(null); } });
		});
		req.on('error', () => resolve(null));
		req.setTimeout(30000, () => { req.destroy(); resolve(null); });
	});
}

/**
 * Downloads a file from URL (follows redirects).
 */
function httpDownloadFile(url: string, destPath: string): Promise<void> {
	const https = require('https');
	return new Promise((resolve, reject) => {
		const makeReq = (targetUrl: string, redirects: number) => {
			const parsed = new URL(targetUrl);
			https.get({ hostname: parsed.hostname, path: parsed.pathname + parsed.search, headers: { 'User-Agent': 'HotmartAppSec-Extension' } }, (res: { statusCode?: number; headers: Record<string, string>; pipe: Function }) => {
				if ((res.statusCode === 301 || res.statusCode === 302) && redirects > 0) {
					const r = res.headers.location;
					if (r) { makeReq(r, redirects - 1); return; }
				}
				if (res.statusCode !== 200) { reject(new Error(`HTTP ${res.statusCode}`)); return; }
				const file = fs.createWriteStream(destPath);
				res.pipe(file);
				file.on('finish', () => { file.close(); resolve(); });
				file.on('error', (e: Error) => { try { fs.unlinkSync(destPath); } catch { /* */ } reject(e); });
			}).on('error', reject);
		};
		makeReq(url, 5);
	});
}

/**
 * Ensures OpenGrep is available. On Windows, checks MDM path then installs if needed.
 * On macOS/Linux, installs if needed. Respects cooldown.
 */
export async function ensureOpenGrep(): Promise<boolean> {
	if (await checkOpenGrepAsync()) {
		return true;
	}

	// If we already tried recently and failed, don't spam the user
	if (isInstallOnCooldown()) {
		console.log('[Hotmart AppSec] OpenGrep install on cooldown — skipping');
		return false;
	}

	return await installOpenGrep();
}

// ─── OPENGREP SCAN LOGIC ─────────────────────────────────────────────────────

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
 */
function normalizeCheckId(checkId: string): string {
	const marker = '.rules.';
	const idx = checkId.indexOf(marker);
	if (idx !== -1) {
		return checkId.substring(idx + 1);
	}
	return checkId;
}

/**
 * Runs OpenGrep on the specified files and returns findings.
 * Uses the resolved binary path (MDM path on Windows, PATH on macOS/Linux).
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

	const deduped = deduplicateFindings(findings);
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
