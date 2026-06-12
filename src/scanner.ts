import * as vscode from 'vscode';
import { execSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import { runOpenGrep } from './semgrep';

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

// Extension path — set during activation
let _extensionPath = '';

export function setExtensionPath(p: string): void {
	_extensionPath = p;
}

/**
 * Files that should never be scanned.
 */
const EXCLUDED_PATHS = [
	/^\.kiro\//,
	/^\.cursor\//,
	/^\.claude\//,
	/^\.vscode\//,
	/^\.github\//,
	/^node_modules\//,
	/^out\//,
	/^dist\//,
	/^build\//,
	/^vendor\//,
	/^target\//,
	/^\.terraform\//,
	/\.min\.js$/,
	/\.bundle\.js$/,
	/\.lock$/,
	/package-lock\.json$/,
	/yarn\.lock$/,
	/pnpm-lock\.yaml$/,
	/Cargo\.lock$/,
	/Gemfile\.lock$/,
	/composer\.lock$/,
	/poetry\.lock$/,
	/^tsconfig.*\.json$/,
	/^\.eslintrc.*\.json$/,
	/^\.prettierrc.*$/,
	/^CLAUDE\.md$/,
	/^README/i,
	/^CHANGELOG/i,
	/^LICENSE/i,
	/\.mdc$/,
];

function isExcludedFile(filePath: string): boolean {
	return EXCLUDED_PATHS.some(pattern => pattern.test(filePath));
}

/**
 * Decodes a git-quoted filename back to its real UTF-8 name.
 * Git wraps filenames containing non-ASCII chars in double quotes and uses
 * octal escape sequences (e.g. "TesteExtens\303\243o.js" → TesteExtensão.js).
 */
function decodeGitFilename(raw: string): string {
	// If the entry is surrounded by double quotes, it's git-quoted
	if (raw.startsWith('"') && raw.endsWith('"')) {
		const inner = raw.slice(1, -1);
		// Replace octal sequences (\NNN) with their byte values
		const bytes: number[] = [];
		for (let i = 0; i < inner.length; i++) {
			if (inner[i] === '\\' && i + 3 < inner.length) {
				const octal = inner.substring(i + 1, i + 4);
				if (/^[0-3][0-7]{2}$/.test(octal)) {
					bytes.push(parseInt(octal, 8));
					i += 3;
					continue;
				}
				// Handle other escape sequences
				switch (inner[i + 1]) {
					case 'n': bytes.push(0x0A); i += 1; continue;
					case 't': bytes.push(0x09); i += 1; continue;
					case '\\': bytes.push(0x5C); i += 1; continue;
					case '"': bytes.push(0x22); i += 1; continue;
				}
			}
			// Regular ASCII character
			const code = inner.charCodeAt(i);
			if (code < 128) {
				bytes.push(code);
			} else {
				// Non-ASCII char not escaped (shouldn't normally happen)
				const encoded = new TextEncoder().encode(inner[i]);
				for (const b of encoded) { bytes.push(b); }
			}
		}
		return new TextDecoder('utf-8').decode(new Uint8Array(bytes));
	}
	return raw;
}

/**
 * Gets the list of changed/new files from git.
 */
function getChangedFiles(workspaceFolder: string): string[] {
	const files = new Set<string>();

	try {
		// Unstaged modified files (exclude deletions with --diff-filter=d)
		try {
			const out = execSync('git -c core.quotePath=false diff --name-only --diff-filter=d', { cwd: workspaceFolder, encoding: 'utf-8', stdio: 'pipe' });
			if (out.trim()) {
				for (const f of out.trim().split('\n')) { files.add(decodeGitFilename(f)); }
			}
		} catch { /* */ }

		// Staged files (exclude deletions with --diff-filter=d)
		try {
			const out = execSync('git -c core.quotePath=false diff --cached --name-only --diff-filter=d', { cwd: workspaceFolder, encoding: 'utf-8', stdio: 'pipe' });
			if (out.trim()) {
				for (const f of out.trim().split('\n')) { files.add(decodeGitFilename(f)); }
			}
		} catch { /* */ }

		// Untracked files
		try {
			const out = execSync('git -c core.quotePath=false ls-files --others --exclude-standard', { cwd: workspaceFolder, encoding: 'utf-8', stdio: 'pipe' });
			if (out.trim()) {
				for (const f of out.trim().split('\n')) { files.add(decodeGitFilename(f)); }
			}
		} catch { /* */ }
	} catch { /* not a git repo */ }

	// Filter out excluded files and non-code files
	return Array.from(files).filter(f => {
		if (isExcludedFile(f)) { return false; }
		// Source code: ts, tsx, js, jsx, java, kotlin, python, go, ruby, php, c/cpp, c#,
		// swift, rust, scala. Plus IaC/config: terraform, yaml, json, dockerfile.
		return /\.(ts|tsx|js|jsx|mjs|cjs|java|kt|kts|py|pyi|go|rb|erb|rake|php|phtml|c|h|cpp|cc|cxx|hpp|cs|swift|rs|scala|sc|tf|tfvars|hcl|ya?ml|json)$/i.test(f)
			|| /(^|\/)Dockerfile(\..+)?$/i.test(f)
			|| /(^|\/)Gemfile$/i.test(f)
			|| /(^|\/)Rakefile$/i.test(f);
	});
}

/**
 * Scans changed files using OpenGrep.
 */
export async function scanChangedLines(): Promise<SecurityFinding[]> {
	const workspaceFolders = vscode.workspace.workspaceFolders;
	if (!workspaceFolders) {
		return [];
	}

	const workspaceFolder = workspaceFolders[0].uri.fsPath;
	const changedFiles = getChangedFiles(workspaceFolder);

	if (changedFiles.length === 0) {
		return [];
	}

	return await runOpenGrep(changedFiles, workspaceFolder, _extensionPath);
}

/**
 * Scans the currently active editor file regardless of git status.
 * Used by the "Scan Manual" button.
 */
export async function scanActiveFile(): Promise<SecurityFinding[]> {
	const editor = vscode.window.activeTextEditor;
	if (!editor) {
		return [];
	}

	const workspaceFolders = vscode.workspace.workspaceFolders;
	if (!workspaceFolders) {
		return [];
	}

	const workspaceFolder = workspaceFolders[0].uri.fsPath;
	const filePath = vscode.workspace.asRelativePath(editor.document.uri);

	if (isExcludedFile(filePath)) {
		return [];
	}

	return await runOpenGrep([filePath], workspaceFolder, _extensionPath);
}

/**
 * Scans ALL code files in the workspace (both tracked and untracked).
 * Used by "Scan Manual" when no specific file is active.
 */
export async function scanAllWorkspaceFiles(): Promise<SecurityFinding[]> {
	const workspaceFolders = vscode.workspace.workspaceFolders;
	if (!workspaceFolders) {
		return [];
	}

	const workspaceFolder = workspaceFolders[0].uri.fsPath;

	// Get all tracked + changed + untracked files
	const changedFiles = getChangedFiles(workspaceFolder);

	// Also get all tracked files from git
	let allTracked: string[] = [];
	try {
		const out = execSync('git ls-files', { cwd: workspaceFolder, encoding: 'utf-8', stdio: 'pipe' });
		if (out.trim()) {
			allTracked = out.trim().split('\n').map(f => decodeGitFilename(f));
		}
	} catch { /* not a git repo */ }

	// Merge and deduplicate
	const allFiles = [...new Set([...changedFiles, ...allTracked])].filter(f => {
		if (isExcludedFile(f)) { return false; }
		return /\.(ts|tsx|js|jsx|mjs|cjs|java|kt|kts|py|pyi|go|rb|erb|rake|php|phtml|c|h|cpp|cc|cxx|hpp|cs|swift|rs|scala|sc)$/i.test(f);
	});

	if (allFiles.length === 0) {
		return [];
	}

	return await runOpenGrep(allFiles, workspaceFolder, _extensionPath);
}

