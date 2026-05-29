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
 * Gets the list of changed/new files from git.
 */
function getChangedFiles(workspaceFolder: string): string[] {
	const files = new Set<string>();

	try {
		// Unstaged modified files
		try {
			const out = execSync('git diff --name-only', { cwd: workspaceFolder, encoding: 'utf-8', stdio: 'pipe' });
			if (out.trim()) {
				for (const f of out.trim().split('\n')) { files.add(f); }
			}
		} catch { /* */ }

		// Staged files
		try {
			const out = execSync('git diff --cached --name-only', { cwd: workspaceFolder, encoding: 'utf-8', stdio: 'pipe' });
			if (out.trim()) {
				for (const f of out.trim().split('\n')) { files.add(f); }
			}
		} catch { /* */ }

		// Untracked files
		try {
			const out = execSync('git ls-files --others --exclude-standard', { cwd: workspaceFolder, encoding: 'utf-8', stdio: 'pipe' });
			if (out.trim()) {
				for (const f of out.trim().split('\n')) { files.add(f); }
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
