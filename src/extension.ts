import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';

const STEERING_FILES = ['appsec-rules.md', 'executive.md'];

const IDE_TARGETS: Record<string, string> = {
	kiro: '.kiro/steering',
	cursor: '.cursor/rules',
	vscode: '.vscode/steering',
};

export function activate(context: vscode.ExtensionContext) {
	console.log('Hotmart Cybersecurity Extension activated');

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

	// Auto-apply on workspace open if not already present
	autoApplyIfNeeded(context);
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
		const targetDir = path.join(workspaceFolder, IDE_TARGETS[target.id]);
		applied += await applySteeringFiles(context, targetDir);
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
	for (const [, targetPath] of Object.entries(IDE_TARGETS)) {
		const targetDir = path.join(workspaceFolder, targetPath);
		if (fs.existsSync(targetDir)) {
			updated += await applySteeringFiles(context, targetDir, true);
		}
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

	// Check if any steering files are already present
	const kiroDir = path.join(workspaceFolder, IDE_TARGETS.kiro);
	const hasKiroSteering = STEERING_FILES.some(f => fs.existsSync(path.join(kiroDir, f)));

	if (!hasKiroSteering) {
		const action = await vscode.window.showInformationMessage(
			'🛡️ Padrões de segurança Hotmart não detectados neste projeto. Deseja aplicar?',
			'Aplicar',
			'Ignorar',
			'Não perguntar novamente'
		);

		if (action === 'Aplicar') {
			await applyToAllTargets(context, workspaceFolder);
		} else if (action === 'Não perguntar novamente') {
			await config.update('autoApplyOnOpen', false, vscode.ConfigurationTarget.Workspace);
		}
	}
}

async function applyToAllTargets(context: vscode.ExtensionContext, workspaceFolder: string): Promise<void> {
	let applied = 0;
	for (const [, targetPath] of Object.entries(IDE_TARGETS)) {
		const targetDir = path.join(workspaceFolder, targetPath);
		applied += await applySteeringFiles(context, targetDir);
	}

	vscode.window.showInformationMessage(
		`✅ Padrões de segurança aplicados: ${applied} arquivo(s).`
	);
}

async function applySteeringFiles(
	context: vscode.ExtensionContext,
	targetDir: string,
	overwrite: boolean = false
): Promise<number> {
	const standardsDir = path.join(context.extensionPath, 'standards', 'steering');
	let count = 0;

	if (!fs.existsSync(targetDir)) {
		fs.mkdirSync(targetDir, { recursive: true });
	}

	for (const file of STEERING_FILES) {
		const source = path.join(standardsDir, file);
		const dest = path.join(targetDir, file);

		if (!fs.existsSync(source)) {
			continue;
		}

		if (!overwrite && fs.existsSync(dest)) {
			// Check if content is different
			const sourceContent = fs.readFileSync(source, 'utf-8');
			const destContent = fs.readFileSync(dest, 'utf-8');
			if (sourceContent === destContent) {
				continue;
			}

			const action = await vscode.window.showWarningMessage(
				`O arquivo "${file}" já existe e é diferente da versão corporativa. Sobrescrever?`,
				'Sobrescrever',
				'Manter atual'
			);

			if (action !== 'Sobrescrever') {
				continue;
			}
		}

		const content = fs.readFileSync(source, 'utf-8');
		fs.writeFileSync(dest, content, 'utf-8');
		count++;
	}

	return count;
}

function getWorkspaceFolder(): string | undefined {
	const folders = vscode.workspace.workspaceFolders;
	if (!folders || folders.length === 0) {
		return undefined;
	}
	return folders[0].uri.fsPath;
}

export function deactivate() {}
