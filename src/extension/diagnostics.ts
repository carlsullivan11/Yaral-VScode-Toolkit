import * as vscode from 'vscode';
import { Fix, lintDocument, RULES_BY_ID } from '../core';
import { isYaral, toRange, toSeverity } from './convert';
import { WorkspaceIndex } from './workspaceIndex';

const DOCS_BASE = 'https://github.com/carlsullivan11/Yaral-VScode-Toolkit/blob/main/docs/lint-rules.md';

/** Runs the linter on open documents and keeps quick fixes for code actions. */
export class DiagnosticsManager implements vscode.Disposable, vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];
  private readonly collection = vscode.languages.createDiagnosticCollection('yaral');
  private readonly fixes = new Map<string, Map<vscode.Diagnostic, Fix>>();
  private readonly timers = new Map<string, NodeJS.Timeout>();

  constructor(private readonly index: WorkspaceIndex) {}

  schedule(document: vscode.TextDocument, delay = 250): void {
    if (!isYaral(document)) return;
    const key = document.uri.toString();
    clearTimeout(this.timers.get(key));
    this.timers.set(
      key,
      setTimeout(() => {
        this.timers.delete(key);
        this.lint(document);
      }, delay),
    );
  }

  lint(document: vscode.TextDocument): void {
    if (!isYaral(document) || document.isClosed) return;
    if (!vscode.workspace.getConfiguration('yaral', document.uri).get<boolean>('lint.enable', true)) {
      this.collection.delete(document.uri);
      return;
    }
    const { config, functions } = this.index.getConfig(document.uri);
    const parsed = this.index.parse(document);
    const results = lintDocument(parsed, {
      filePath: document.uri.scheme === 'file' ? document.uri.fsPath : undefined,
      config,
      functions,
      conventions: config.conventions.enabled ? this.index.getConventions() : undefined,
    });
    const fixMap = new Map<vscode.Diagnostic, Fix>();
    const diagnostics = results.map((r) => {
      const d = new vscode.Diagnostic(toRange(r.range), r.message, toSeverity(r.severity));
      d.source = 'yaral';
      d.code = { value: `${r.ruleId}/${r.ruleName}`, target: vscode.Uri.parse(`${DOCS_BASE}#${r.ruleId.toLowerCase()}`) };
      if (r.ruleId === 'YL205' || r.ruleId === 'YL202') d.tags = [vscode.DiagnosticTag.Unnecessary];
      if (r.fix) fixMap.set(d, r.fix);
      return d;
    });
    this.fixes.set(document.uri.toString(), fixMap);
    this.collection.set(document.uri, diagnostics);
  }

  lintAllOpen(): void {
    for (const d of vscode.workspace.textDocuments) this.lint(d);
  }

  /** Lints every rule file in the workspace (Problems panel). */
  async lintWorkspace(uris: vscode.Uri[]): Promise<number> {
    let count = 0;
    for (const uri of uris) {
      const doc = await vscode.workspace.openTextDocument(uri);
      this.lint(doc);
      count++;
    }
    return count;
  }

  clear(uri: vscode.Uri): void {
    this.collection.delete(uri);
    this.fixes.delete(uri.toString());
  }

  provideCodeActions(document: vscode.TextDocument, _range: vscode.Range, context: vscode.CodeActionContext): vscode.CodeAction[] {
    const fixMap = this.fixes.get(document.uri.toString());
    const actions: vscode.CodeAction[] = [];
    for (const diag of context.diagnostics) {
      if (diag.source !== 'yaral') continue;
      const fix = fixMap?.get(diag);
      if (fix) {
        const action = new vscode.CodeAction(fix.title, vscode.CodeActionKind.QuickFix);
        action.edit = new vscode.WorkspaceEdit();
        for (const e of fix.edits) action.edit.replace(document.uri, toRange(e.range), e.newText);
        action.diagnostics = [diag];
        action.isPreferred = true;
        actions.push(action);
      }
      const code = typeof diag.code === 'object' ? String(diag.code.value) : String(diag.code ?? '');
      const ruleId = code.split('/')[0];
      if (RULES_BY_ID.has(ruleId) && ruleId !== 'YL001') {
        const line = diag.range.start.line;
        const indent = document.lineAt(line).text.match(/^\s*/)![0];
        const suppress = new vscode.CodeAction(`Suppress ${ruleId} for this line`, vscode.CodeActionKind.QuickFix);
        suppress.edit = new vscode.WorkspaceEdit();
        suppress.edit.insert(document.uri, new vscode.Position(line, 0), `${indent}// yaral-lint-disable-next-line ${ruleId}\n`);
        suppress.diagnostics = [diag];
        actions.push(suppress);
      }
    }
    return actions;
  }

  dispose(): void {
    this.collection.dispose();
    this.timers.forEach((t) => clearTimeout(t));
  }
}
