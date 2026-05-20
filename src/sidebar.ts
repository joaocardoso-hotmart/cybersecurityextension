import * as vscode from 'vscode';
import { SecurityFinding, Severity, scanChangedLines } from './scanner';

export class SecuritySidebarProvider implements vscode.WebviewViewProvider {
	public static readonly viewType = 'cybersecurity.findingsView';

	private _view?: vscode.WebviewView;
	private _findings: SecurityFinding[] = [];

	constructor(private readonly _extensionUri: vscode.Uri) {}

	public resolveWebviewView(
		webviewView: vscode.WebviewView,
		_context: vscode.WebviewViewResolveContext,
		_token: vscode.CancellationToken
	): void {
		this._view = webviewView;

		webviewView.webview.options = {
			enableScripts: true,
			localResourceRoots: [this._extensionUri],
		};

		webviewView.webview.html = this._getEmptyHtml();

		webviewView.webview.onDidReceiveMessage(async (message) => {
			switch (message.command) {
				case 'openFile':
					await this._openFinding(message.file, message.line, message.column);
					break;
				case 'refresh':
					await this.refresh();
					break;
			}
		});
	}

	public async refresh(): Promise<void> {
		if (this._view) {
			this._view.webview.html = this._getLoadingHtml();
			this._findings = await scanChangedLines();
			this._view.webview.html = this._getHtmlForWebview();
		}
	}

	public updateFindings(findings: SecurityFinding[]): void {
		this._findings = findings;
		if (this._view) {
			this._view.webview.html = this._getHtmlForWebview();
		}
	}

	public get findings(): SecurityFinding[] {
		return this._findings;
	}

	private async _openFinding(file: string, line: number, column: number): Promise<void> {
		const workspaceFolders = vscode.workspace.workspaceFolders;
		if (!workspaceFolders) {
			return;
		}

		const fileUri = vscode.Uri.joinPath(workspaceFolders[0].uri, file);
		const document = await vscode.workspace.openTextDocument(fileUri);
		const editor = await vscode.window.showTextDocument(document);

		const position = new vscode.Position(line - 1, column - 1);
		editor.selection = new vscode.Selection(position, position);
		editor.revealRange(
			new vscode.Range(position, position),
			vscode.TextEditorRevealType.InCenter
		);
	}

	private _getEmptyHtml(): string {
		return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<style>
		body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 12px; }
		.empty { text-align: center; padding: 40px 0; opacity: 0.7; }
		.refresh-btn { background: var(--vscode-button-background); color: var(--vscode-button-foreground); border: none; padding: 6px 12px; border-radius: 3px; cursor: pointer; margin-top: 12px; }
	</style>
</head>
<body>
	<div class="empty">
		<p>🛡️ Nenhum scan executado ainda.</p>
		<p style="font-size: 11px; opacity: 0.7;">O scan roda automaticamente ao fazer <code>git add</code> ou <code>git commit</code>.</p>
		<button class="refresh-btn" onclick="refresh()">Executar Scan Agora</button>
	</div>
	<script>
		const vscode = acquireVsCodeApi();
		function refresh() { vscode.postMessage({ command: 'refresh' }); }
	</script>
</body>
</html>`;
	}

	private _getLoadingHtml(): string {
		return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<style>
		body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 12px; }
		.loading { text-align: center; padding: 40px 0; }
		.spinner { display: inline-block; width: 24px; height: 24px; border: 3px solid var(--vscode-foreground); border-top-color: transparent; border-radius: 50%; animation: spin 0.8s linear infinite; }
		@keyframes spin { to { transform: rotate(360deg); } }
	</style>
</head>
<body>
	<div class="loading">
		<div class="spinner"></div>
		<p>Escaneando vulnerabilidades...</p>
	</div>
</body>
</html>`;
	}

	private _getHtmlForWebview(): string {
		const findings = this._findings;
		const counts = this._getCounts(findings);

		const findingsHtml = findings.length > 0
			? findings.map(f => this._renderFinding(f)).join('')
			: '<p class="empty">✅ Nenhuma vulnerabilidade encontrada.</p>';

		return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<style>
		* { box-sizing: border-box; margin: 0; padding: 0; }
		body {
			font-family: var(--vscode-font-family);
			font-size: var(--vscode-font-size);
			color: var(--vscode-foreground);
			background: var(--vscode-sideBar-background);
			padding: 8px;
		}
		.header {
			display: flex;
			align-items: center;
			justify-content: space-between;
			margin-bottom: 12px;
			padding-bottom: 8px;
			border-bottom: 1px solid var(--vscode-panel-border);
		}
		.header h2 {
			font-size: 13px;
			font-weight: 600;
			text-transform: uppercase;
			letter-spacing: 0.5px;
		}
		.refresh-btn {
			background: none;
			border: 1px solid var(--vscode-button-border, var(--vscode-foreground));
			color: var(--vscode-foreground);
			cursor: pointer;
			padding: 4px 8px;
			border-radius: 3px;
			font-size: 11px;
		}
		.refresh-btn:hover {
			background: var(--vscode-button-hoverBackground, rgba(255,255,255,0.1));
		}
		.summary {
			display: flex;
			gap: 6px;
			flex-wrap: wrap;
			margin-bottom: 12px;
		}
		.badge {
			padding: 2px 8px;
			border-radius: 10px;
			font-size: 11px;
			font-weight: 600;
		}
		.badge-critical { background: #d32f2f; color: #fff; }
		.badge-high { background: #f57c00; color: #fff; }
		.badge-medium { background: #fbc02d; color: #000; }
		.badge-low { background: #388e3c; color: #fff; }
		.badge-info { background: #1976d2; color: #fff; }
		.finding {
			background: var(--vscode-editor-background);
			border: 1px solid var(--vscode-panel-border);
			border-radius: 4px;
			margin-bottom: 8px;
			overflow: hidden;
		}
		.finding-header {
			display: flex;
			align-items: center;
			gap: 8px;
			padding: 8px 10px;
			cursor: pointer;
		}
		.finding-header:hover {
			background: var(--vscode-list-hoverBackground);
		}
		.severity-dot {
			width: 10px;
			height: 10px;
			border-radius: 50%;
			flex-shrink: 0;
		}
		.dot-critical { background: #d32f2f; }
		.dot-high { background: #f57c00; }
		.dot-medium { background: #fbc02d; }
		.dot-low { background: #388e3c; }
		.dot-info { background: #1976d2; }
		.finding-title {
			font-size: 12px;
			font-weight: 600;
			flex: 1;
		}
		.finding-cwe {
			font-size: 10px;
			opacity: 0.7;
			font-family: monospace;
		}
		.finding-body {
			padding: 0 10px 10px;
			font-size: 11px;
			border-top: 1px solid var(--vscode-panel-border);
		}
		.finding-location {
			display: flex;
			align-items: center;
			gap: 4px;
			margin: 8px 0;
			cursor: pointer;
			color: var(--vscode-textLink-foreground);
			text-decoration: underline;
			font-family: monospace;
			font-size: 11px;
		}
		.finding-location:hover {
			color: var(--vscode-textLink-activeForeground);
		}
		.finding-snippet {
			background: var(--vscode-textBlockQuote-background);
			padding: 6px 8px;
			border-radius: 3px;
			font-family: monospace;
			font-size: 11px;
			overflow-x: auto;
			white-space: pre;
			margin: 6px 0;
		}
		.finding-description {
			margin: 6px 0;
			opacity: 0.85;
			line-height: 1.4;
		}
		.finding-suggestion {
			background: var(--vscode-inputValidation-infoBackground, rgba(0,120,212,0.1));
			border-left: 3px solid var(--vscode-inputValidation-infoBorder, #1976d2);
			padding: 6px 8px;
			border-radius: 0 3px 3px 0;
			margin-top: 6px;
			line-height: 1.4;
		}
		.suggestion-label {
			font-weight: 600;
			margin-bottom: 2px;
		}
		.empty {
			text-align: center;
			padding: 40px 0;
			opacity: 0.7;
		}
		details > summary {
			list-style: none;
		}
		details > summary::-webkit-details-marker {
			display: none;
		}
	</style>
</head>
<body>
	<div class="header">
		<h2>🛡️ Security Findings</h2>
		<button class="refresh-btn" onclick="refresh()" aria-label="Atualizar scan">⟳ Scan</button>
	</div>

	<div class="summary">
		${counts.critical > 0 ? `<span class="badge badge-critical">Critical: ${counts.critical}</span>` : ''}
		${counts.high > 0 ? `<span class="badge badge-high">High: ${counts.high}</span>` : ''}
		${counts.medium > 0 ? `<span class="badge badge-medium">Medium: ${counts.medium}</span>` : ''}
		${counts.low > 0 ? `<span class="badge badge-low">Low: ${counts.low}</span>` : ''}
		${counts.info > 0 ? `<span class="badge badge-info">Info: ${counts.info}</span>` : ''}
		${findings.length === 0 ? '<span class="badge badge-low">0 findings</span>' : ''}
	</div>

	<div class="findings">
		${findingsHtml}
	</div>

	<script>
		const vscode = acquireVsCodeApi();

		function openFile(file, line, column) {
			vscode.postMessage({ command: 'openFile', file, line, column });
		}

		function refresh() {
			vscode.postMessage({ command: 'refresh' });
		}
	</script>
</body>
</html>`;
	}

	private _renderFinding(finding: SecurityFinding): string {
		const escapedSnippet = this._escapeHtml(finding.snippet);
		const escapedSuggestion = this._escapeHtml(finding.suggestion);
		const escapedDescription = this._escapeHtml(finding.description);

		return `
<div class="finding">
	<details>
		<summary class="finding-header">
			<span class="severity-dot dot-${finding.severity}"></span>
			<span class="finding-title">${this._escapeHtml(finding.title)}</span>
			<span class="finding-cwe">${finding.cwe}</span>
		</summary>
		<div class="finding-body">
			<div class="finding-location" onclick="openFile('${this._escapeJs(finding.file)}', ${finding.line}, ${finding.column})">
				📄 ${this._escapeHtml(finding.file)}:${finding.line}
			</div>
			<div class="finding-snippet">${escapedSnippet}</div>
			<div class="finding-description">${escapedDescription}</div>
			<div class="finding-suggestion">
				<div class="suggestion-label">💡 Correção sugerida:</div>
				${escapedSuggestion}
			</div>
		</div>
	</details>
</div>`;
	}

	private _getCounts(findings: SecurityFinding[]): Record<Severity, number> {
		const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
		for (const f of findings) {
			counts[f.severity]++;
		}
		return counts;
	}

	private _escapeHtml(text: string): string {
		return text
			.replace(/&/g, '&amp;')
			.replace(/</g, '&lt;')
			.replace(/>/g, '&gt;')
			.replace(/"/g, '&quot;')
			.replace(/'/g, '&#039;');
	}

	private _escapeJs(text: string): string {
		return text.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
	}
}
