import * as path from 'path';
import * as vscode from 'vscode';
import {
  buildConventions,
  buildFunctionIndex,
  Conventions,
  DEFAULT_CONFIG,
  FunctionIndex,
  LintConfig,
  findConfigFile,
  readConfigFile,
  matchesAnyGlob,
  mergeConfig,
  parse,
  ParsedDocument,
  RuleSummary,
  Severity,
  summarizeRule,
} from '../core';

export const YARAL_GLOB = '**/*.{yaral,yara-l,yl2}';

/**
 * Indexes every YARA-L rule in the workspace. The index feeds convention
 * learning (standard meta keys / outcomes), duplicate detection, completion
 * of reference lists, and is kept current with file-system and editor events.
 */
export class WorkspaceIndex implements vscode.Disposable {
  private readonly summaries = new Map<string, RuleSummary[]>();
  private readonly listRefs = new Map<string, Set<string>>();
  private conventions: Conventions | undefined;
  private readonly configs = new Map<string, { config: LintConfig; file?: string }>();
  private readonly disposables: vscode.Disposable[] = [];
  private readonly changeEmitter = new vscode.EventEmitter<void>();
  readonly onDidChange = this.changeEmitter.event;
  private parsedCache = new WeakMap<vscode.TextDocument, { version: number; doc: ParsedDocument }>();
  private ready: Promise<void> | undefined;

  constructor() {
    const watcher = vscode.workspace.createFileSystemWatcher(YARAL_GLOB);
    watcher.onDidCreate((uri) => this.indexUri(uri).then(() => this.changed()));
    watcher.onDidChange((uri) => {
      // Open documents are indexed from the editor buffer instead.
      if (!vscode.workspace.textDocuments.some((d) => d.uri.toString() === uri.toString())) {
        this.indexUri(uri).then(() => this.changed());
      }
    });
    watcher.onDidDelete((uri) => {
      this.summaries.delete(uri.fsPath);
      this.listRefs.delete(uri.fsPath);
      this.changed();
    });
    const configWatcher = vscode.workspace.createFileSystemWatcher('**/.yaral-lint.json');
    const resetConfig = () => {
      this.configs.clear();
      this.changed();
    };
    configWatcher.onDidCreate(resetConfig);
    configWatcher.onDidChange(resetConfig);
    configWatcher.onDidDelete(resetConfig);
    this.disposables.push(
      watcher,
      configWatcher,
      this.changeEmitter,
      vscode.workspace.onDidChangeConfiguration((e) => {
        if (e.affectsConfiguration('yaral')) resetConfig();
      }),
    );
  }

  /** Parses a document, caching by version. */
  parse(document: vscode.TextDocument): ParsedDocument {
    const cached = this.parsedCache.get(document);
    if (cached && cached.version === document.version) return cached.doc;
    const doc = parse(document.getText());
    this.parsedCache.set(document, { version: document.version, doc });
    return doc;
  }

  async initialize(): Promise<void> {
    if (!this.ready) this.ready = this.rebuild();
    return this.ready;
  }

  async rebuild(): Promise<void> {
    this.summaries.clear();
    this.listRefs.clear();
    const uris = await vscode.workspace.findFiles(YARAL_GLOB, '**/node_modules/**', 20000);
    await Promise.all(uris.map((u) => this.indexUri(u)));
    for (const d of vscode.workspace.textDocuments) if (d.languageId === 'yaral') this.indexDocument(d);
    this.changed();
  }

  private async indexUri(uri: vscode.Uri): Promise<void> {
    try {
      const bytes = await vscode.workspace.fs.readFile(uri);
      this.indexText(uri.fsPath, Buffer.from(bytes).toString('utf8'));
    } catch {
      this.summaries.delete(uri.fsPath);
    }
  }

  /** Re-index an open (possibly unsaved) document. */
  indexDocument(document: vscode.TextDocument): void {
    if (document.uri.scheme !== 'file' && document.uri.scheme !== 'untitled') return;
    const doc = this.parse(document);
    this.store(document.uri.fsPath, doc);
    this.conventions = undefined;
  }

  private indexText(file: string, text: string): void {
    this.store(file, parse(text));
  }

  private store(file: string, doc: ParsedDocument): void {
    this.summaries.set(file, doc.rules.map((r) => summarizeRule(r, file, doc)));
    const lists = new Set<string>();
    for (const r of doc.rules) for (const v of r.varRefs) if (v.sigil === '%') lists.add(v.name);
    this.listRefs.set(file, lists);
  }

  private changed(): void {
    this.conventions = undefined;
    this.changeEmitter.fire();
  }

  getConventions(): Conventions | undefined {
    const settings = vscode.workspace.getConfiguration('yaral');
    if (!settings.get<boolean>('conventions.enable', true)) return undefined;
    if (!this.conventions) {
      const cfg = this.getConfig(undefined).config;
      const exclude = [...cfg.conventions.exclude, ...settings.get<string[]>('conventions.exclude', [])];
      const all: RuleSummary[] = [];
      for (const [file, s] of this.summaries) {
        if (!matchesAnyGlob(file, exclude)) all.push(...s);
      }
      this.conventions = buildConventions(all, cfg.conventions.threshold, cfg.conventions.minRules);
    }
    return this.conventions;
  }

  /** Reference list names (`%name`) used anywhere in the workspace. */
  referenceLists(): Map<string, number> {
    const counts = new Map<string, number>();
    for (const set of this.listRefs.values()) for (const l of set) counts.set(l, (counts.get(l) ?? 0) + 1);
    return counts;
  }

  /** Effective config: defaults ← VS Code settings ← nearest .yaral-lint.json. */
  getConfig(uri: vscode.Uri | undefined): { config: LintConfig; file?: string; functions: FunctionIndex } {
    const folder = uri ? vscode.workspace.getWorkspaceFolder(uri) : vscode.workspace.workspaceFolders?.[0];
    const startDir = uri && uri.scheme === 'file' ? path.dirname(uri.fsPath) : folder?.uri.fsPath ?? process.cwd();
    let entry = this.configs.get(startDir);
    if (!entry) {
      const settings = vscode.workspace.getConfiguration('yaral', uri);
      const fromSettings = mergeConfig(DEFAULT_CONFIG, {
        rules: settings.get<Record<string, Severity>>('lint.rules', {}),
        conventions: {
          threshold: settings.get<number>('conventions.threshold', DEFAULT_CONFIG.conventions.threshold),
          minRules: settings.get<number>('conventions.minRules', DEFAULT_CONFIG.conventions.minRules),
        },
      });
      try {
        const file = findConfigFile(startDir);
        entry = file ? { config: mergeConfig(fromSettings, readConfigFile(file)), file } : { config: fromSettings };
      } catch (e) {
        vscode.window.showWarningMessage(`YARA-L: ${(e as Error).message}`);
        entry = { config: fromSettings };
      }
      this.configs.set(startDir, entry);
    }
    return { ...entry, functions: buildFunctionIndex(entry.config.functions) };
  }

  ruleCount(): number {
    let n = 0;
    for (const s of this.summaries.values()) n += s.length;
    return n;
  }

  dispose(): void {
    this.disposables.forEach((d) => d.dispose());
  }
}
