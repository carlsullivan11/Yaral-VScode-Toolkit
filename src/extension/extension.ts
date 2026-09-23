import { randomUUID } from 'crypto';
import * as path from 'path';
import * as vscode from 'vscode';
import { buildMitreCoverage, CONFIG_FILENAME, conventionsReport, MitreFramework, mitreCoverageReport, navigatorLayer, suggestedConfig } from '../core';
import { isYaral } from './convert';
import { DiagnosticsManager } from './diagnostics';
import { registerProviders } from './providers';
import { WorkspaceIndex, YARAL_GLOB } from './workspaceIndex';

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  const index = new WorkspaceIndex();
  const diagnostics = new DiagnosticsManager(index);
  context.subscriptions.push(index, diagnostics);

  registerProviders(context, index);
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider({ language: 'yaral' }, diagnostics, {
      providedCodeActionKinds: DiagnosticsManager.providedCodeActionKinds,
    }),
  );

  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  status.command = 'yaral.showConventions';
  context.subscriptions.push(status);
  const updateStatus = () => {
    const editor = vscode.window.activeTextEditor;
    if (editor && isYaral(editor.document)) {
      status.text = `$(shield) YARA-L · ${index.ruleCount()} rules`;
      status.tooltip = 'Show conventions learned from workspace YARA-L rules';
      status.show();
    } else status.hide();
  };

  // Re-lint open documents when the workspace index (conventions) changes.
  let relintTimer: NodeJS.Timeout | undefined;
  context.subscriptions.push(
    index.onDidChange(() => {
      clearTimeout(relintTimer);
      relintTimer = setTimeout(() => diagnostics.lintAllOpen(), 300);
      updateStatus();
    }),
    vscode.workspace.onDidOpenTextDocument((d) => {
      if (!isYaral(d)) return;
      index.indexDocument(d);
      diagnostics.lint(d);
    }),
    vscode.workspace.onDidChangeTextDocument((e) => {
      if (!isYaral(e.document)) return;
      index.indexDocument(e.document);
      diagnostics.schedule(e.document);
    }),
    vscode.workspace.onDidCloseTextDocument((d) => {
      if (isYaral(d) && d.uri.scheme !== 'file') diagnostics.clear(d.uri);
    }),
    vscode.window.onDidChangeActiveTextEditor(updateStatus),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('yaral.showConventions', async () => {
      await index.initialize();
      const conventions = index.getConventions();
      if (!conventions) {
        vscode.window.showInformationMessage('YARA-L convention learning is disabled (yaral.conventions.enable).');
        return;
      }
      const doc = await vscode.workspace.openTextDocument({ content: conventionsReport(conventions), language: 'markdown' });
      await vscode.commands.executeCommand('markdown.showPreview', doc.uri);
    }),
    vscode.commands.registerCommand('yaral.showMitreCoverage', async () => {
      await index.initialize();
      const coverage = buildMitreCoverage(index.allSummaries(), index.getConfig(undefined).config.mitre);
      const doc = await vscode.workspace.openTextDocument({ content: mitreCoverageReport(coverage), language: 'markdown' });
      await vscode.commands.executeCommand('markdown.showPreview', doc.uri);
    }),
    vscode.commands.registerCommand('yaral.exportNavigatorLayer', async () => {
      await index.initialize();
      const config = index.getConfig(undefined).config;
      const choices = config.mitre.frameworks.filter((f) => f !== 'atlas');
      const framework = (await vscode.window.showQuickPick(choices, { placeHolder: 'ATT&CK domain for the Navigator layer' })) as MitreFramework | undefined;
      if (!framework) return;
      const folder = vscode.workspace.workspaceFolders?.[0]?.uri;
      const target = await vscode.window.showSaveDialog({
        defaultUri: folder ? vscode.Uri.joinPath(folder, `yaral-${framework}-layer.json`) : undefined,
        filters: { JSON: ['json'] },
      });
      if (!target) return;
      const layer = navigatorLayer(buildMitreCoverage(index.allSummaries(), config.mitre), framework);
      await vscode.workspace.fs.writeFile(target, Buffer.from(JSON.stringify(layer, null, 2) + '\n'));
      vscode.window.showInformationMessage(`Wrote ATT&CK Navigator layer. Open it at https://mitre-attack.github.io/attack-navigator/`);
    }),
    vscode.commands.registerCommand('yaral.refreshConventions', async () => {
      await index.rebuild();
      vscode.window.showInformationMessage(`YARA-L: indexed ${index.ruleCount()} rules.`);
    }),
    vscode.commands.registerCommand('yaral.lintWorkspace', async () => {
      await index.initialize();
      const uris = await vscode.workspace.findFiles(YARAL_GLOB, '**/node_modules/**');
      const n = await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: 'Linting YARA-L rules' }, () =>
        diagnostics.lintWorkspace(uris),
      );
      vscode.window.showInformationMessage(`YARA-L: linted ${n} files. See the Problems panel.`);
      await vscode.commands.executeCommand('workbench.actions.view.problems');
    }),
    vscode.commands.registerCommand('yaral.insertRuleId', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      await editor.edit((b) => b.insert(editor.selection.active, `mr_${randomUUID()}`));
    }),
    vscode.commands.registerCommand('yaral.createConfig', async () => {
      const folder = vscode.workspace.workspaceFolders?.[0];
      if (!folder) {
        vscode.window.showErrorMessage('Open a folder first.');
        return;
      }
      await index.initialize();
      const conventions = index.getConventions();
      const target = vscode.Uri.file(path.join(folder.uri.fsPath, CONFIG_FILENAME));
      try {
        await vscode.workspace.fs.stat(target);
        const choice = await vscode.window.showWarningMessage(`${CONFIG_FILENAME} already exists. Overwrite it?`, { modal: true }, 'Overwrite');
        if (choice !== 'Overwrite') return;
      } catch {
        // does not exist
      }
      const content = conventions ? suggestedConfig(conventions) : {};
      await vscode.workspace.fs.writeFile(target, Buffer.from(JSON.stringify(content, null, 2) + '\n'));
      await vscode.window.showTextDocument(target);
    }),
  );

  await index.initialize();
  diagnostics.lintAllOpen();
  updateStatus();
}

export function deactivate(): void {
  // Disposables are cleaned up via context.subscriptions.
}
