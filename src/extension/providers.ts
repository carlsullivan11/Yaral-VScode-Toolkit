import * as vscode from 'vscode';
import {
  allUdmFields,
  callContextAt,
  commentAt,
  dottedNameAt,
  format,
  FunctionDef,
  functionMarkdown,
  KEYWORD_DOCS,
  ParsedDocument,
  Rule,
  ruleAt,
  SECTION_DOCS,
  SECTION_ORDER,
  sectionAt,
  signature,
  tokenAt,
  UDM_ACTIONS,
  UDM_ENTITY_TYPES,
  UDM_EVENT_TYPES,
  UDM_SOURCE_TYPES,
  variableTables,
} from '../core';
import { toRange } from './convert';
import { WorkspaceIndex } from './workspaceIndex';

const SELECTOR: vscode.DocumentSelector = { language: 'yaral' };

export function registerProviders(context: vscode.ExtensionContext, index: WorkspaceIndex): void {
  context.subscriptions.push(
    vscode.languages.registerHoverProvider(SELECTOR, new HoverProvider(index)),
    vscode.languages.registerCompletionItemProvider(SELECTOR, new CompletionProvider(index), '.', '$', '%', '#', '"'),
    vscode.languages.registerSignatureHelpProvider(SELECTOR, new SignatureProvider(index), '(', ','),
    vscode.languages.registerDocumentSymbolProvider(SELECTOR, new SymbolProvider(index)),
    vscode.languages.registerDefinitionProvider(SELECTOR, new VariableProvider(index)),
    vscode.languages.registerReferenceProvider(SELECTOR, new VariableProvider(index)),
    vscode.languages.registerRenameProvider(SELECTOR, new VariableProvider(index)),
    vscode.languages.registerDocumentHighlightProvider(SELECTOR, new VariableProvider(index)),
    vscode.languages.registerFoldingRangeProvider(SELECTOR, new FoldingProvider(index)),
    vscode.languages.registerDocumentFormattingEditProvider(SELECTOR, new FormattingProvider()),
  );
}

// ------------------------------------------------------------------ hover

class HoverProvider implements vscode.HoverProvider {
  constructor(private readonly index: WorkspaceIndex) {}

  provideHover(document: vscode.TextDocument, position: vscode.Position): vscode.Hover | undefined {
    const doc = this.index.parse(document);
    const offset = document.offsetAt(position);
    if (commentAt(doc, offset)) return undefined;
    const tok = tokenAt(doc, offset);
    if (!tok) return undefined;
    const range = toRange(tok.range);
    const rule = ruleAt(doc, offset);
    const md = (s: string) => new vscode.Hover(new vscode.MarkdownString(s), range);

    // Section headers
    const tIdx = doc.tokens.indexOf(tok);
    if (tok.kind === 'ident' && doc.tokens[tIdx + 1]?.text === ':' && SECTION_DOCS[tok.text]) {
      const s = SECTION_DOCS[tok.text];
      return md(`**${s.name}:** section\n\n${s.description}\n\n\`\`\`yaral\n${s.example}\n\`\`\`\n\n[Documentation](${s.docUrl})`);
    }

    // Functions
    const dotted = dottedNameAt(doc, offset);
    const { functions, config } = this.index.getConfig(document.uri);
    if (dotted && !dotted.text.startsWith('$')) {
      const f = functions.get(dotted.text);
      if (f) return new vscode.Hover(new vscode.MarkdownString(functionMarkdown(f)), new vscode.Range(document.positionAt(dotted.start), document.positionAt(dotted.end)));
    }

    // Meta keys: show workspace conventions
    if (rule && tok.kind === 'ident' && sectionAt(rule, offset)?.kind === 'meta' && doc.tokens[tIdx + 1]?.text === '=') {
      const conv = this.index.getConventions();
      const stat = conv?.metaKeys.find((m) => m.key === tok.text);
      const lines = [`**meta** \`${tok.text}\``];
      if (config.requiredMeta.includes(tok.text)) lines.push('', 'Required by `.yaral-lint.json`.');
      if (conv && stat) {
        lines.push('', `Used in **${stat.count}/${conv.ruleCount}** workspace rules (${Math.round(stat.ratio * 100)}%)${conv.standardMeta.includes(tok.text) ? ' — *standard*' : ''}.`);
        if (stat.values.length) lines.push('', 'Common values: ' + stat.values.slice(0, 8).map((v) => `\`${v.value}\` (${v.count})`).join(', '));
      } else if (conv) {
        lines.push('', 'Not used by any other rule in the workspace.');
      }
      const allowed = config.metaValues[tok.text];
      if (allowed) lines.push('', `Allowed values: ${allowed.map((v) => '`' + v + '`').join(', ')}`);
      return md(lines.join('\n'));
    }

    // Variables
    if (rule && (tok.kind === 'eventVar' || tok.kind === 'countVar')) {
      return md(variableHover(doc, rule, tok.text, this.index));
    }
    if (tok.kind === 'listRef') {
      const uses = this.index.referenceLists().get(tok.text.slice(1)) ?? 0;
      return md(`**reference list / data table** \`${tok.text}\`\n\nReferenced by ${uses} file${uses === 1 ? '' : 's'} in the workspace. Use \`in %list\`, \`in regex %list\` or \`in cidr %list\`; data table columns are \`%table.column\`.`);
    }

    // UDM field inside `$e.path`
    if (dotted && dotted.text.startsWith('$') && tok.kind === 'ident') {
      const fieldPath = dotted.text.replace(/^\$\w+\./, '');
      return md(`**UDM field** \`${fieldPath}\`\n\n[UDM field list](https://cloud.google.com/chronicle/docs/reference/udm-field-list)`);
    }

    if (tok.kind === 'duration') {
      return md(`**duration** \`${tok.text}\``);
    }
    const kw = KEYWORD_DOCS[tok.text.toLowerCase()];
    if (kw && tok.kind === 'ident') {
      return md(`**${kw.name}**\n\n${kw.description}${kw.example ? `\n\n\`\`\`yaral\n${kw.example}\n\`\`\`` : ''}`);
    }
    return undefined;
  }
}

function variableHover(doc: ParsedDocument, rule: Rule, text: string, index: WorkspaceIndex): string {
  const name = text.slice(1);
  const t = variableTables(rule);
  const lines: string[] = [];
  const snippet = (tok: { range: { start: { line: number } } }) => doc.index.lineText(tok.range.start.line).trim();
  if (text.startsWith('#')) {
    lines.push(`**count** \`${text}\` — number of ${t.eventVars.has(name) ? `events matched by \`$${name}\`` : `distinct values of \`$${name}\``} in the match window.`);
    return lines.join('\n');
  }
  const outcome = rule.outcomes.find((o) => o.name === name);
  if (t.eventVars.has(name)) {
    const refs = rule.varRefs.filter((r) => r.name === name && r.section === 'events').length;
    lines.push(`**event variable** \`${text}\``, '', `Defined by ${refs} predicate${refs === 1 ? '' : 's'} in \`events:\`.`);
  } else if (t.placeholders.has(name)) {
    lines.push(`**placeholder variable** \`${text}\`${t.matchVars.has(name) ? ' — *match variable*' : ''}`, '', '```yaral', snippet(t.placeholders.get(name)!.token), '```');
  } else if (outcome) {
    const conv = index.getConventions();
    const stat = conv?.outcomes.find((o) => o.name === name);
    lines.push(`**outcome variable** \`${text}\``, '', '```yaral', snippet(outcome.token), '```');
    if (conv && stat) lines.push('', `Used in ${stat.count}/${conv.ruleCount} workspace rules (${Math.round(stat.ratio * 100)}%).`);
  } else {
    lines.push(`**variable** \`${text}\` — not defined in this rule.`);
  }
  return lines.join('\n');
}

// ------------------------------------------------------------------ completion

class CompletionProvider implements vscode.CompletionItemProvider {
  constructor(private readonly index: WorkspaceIndex) {}

  provideCompletionItems(document: vscode.TextDocument, position: vscode.Position): vscode.CompletionItem[] | undefined {
    const doc = this.index.parse(document);
    const offset = document.offsetAt(position);
    const linePrefix = document.lineAt(position).text.slice(0, position.character);
    if (commentAt(doc, offset) && !/^\s*$/.test(linePrefix)) return undefined;
    const rule = ruleAt(doc, offset);
    const sec = rule ? sectionAt(rule, offset) : undefined;
    const { functions, config } = this.index.getConfig(document.uri);
    const conventions = this.index.getConventions();

    // Enum values inside strings
    const enumMatch = /([\w.]+)\s*!?=\s*"([^"]*)$/.exec(linePrefix);
    if (enumMatch) {
      const key = enumMatch[1];
      let values: { value: string; detail?: string }[] = [];
      if (sec?.kind === 'meta') {
        const stat = conventions?.metaKeys.find((m) => m.key === key);
        values = (config.metaValues[key] ?? []).map((v) => ({ value: v, detail: 'allowed value' }));
        for (const v of stat?.values ?? []) if (!values.some((x) => x.value === v.value)) values.push({ value: v.value, detail: `used in ${v.count} rules` });
      } else if (/metadata\.event_type$/.test(key)) values = UDM_EVENT_TYPES.map((value) => ({ value }));
      else if (/metadata\.entity_type$/.test(key)) values = UDM_ENTITY_TYPES.map((value) => ({ value }));
      else if (/metadata\.source_type$/.test(key)) values = UDM_SOURCE_TYPES.map((value) => ({ value }));
      else if (/security_result\.action$/.test(key)) values = UDM_ACTIONS.map((value) => ({ value }));
      const partial = enumMatch[2];
      const range = new vscode.Range(position.translate(0, -partial.length), position);
      return values.map((v, i) => {
        const item = new vscode.CompletionItem(v.value, vscode.CompletionItemKind.EnumMember);
        item.detail = v.detail;
        item.range = range;
        item.sortText = String(i).padStart(4, '0');
        return item;
      });
    }
    if (/"[^"]*$/.test(linePrefix.replace(/"[^"]*"/g, ''))) return undefined; // inside another string

    // UDM field paths after `$var.`
    const fieldMatch = /\$[A-Za-z_]\w*((?:\.\w+|\["[^"]*"\])*)\.(\w*)$/.exec(linePrefix);
    if (fieldMatch) {
      const parent = fieldMatch[1].replace(/^\./, '');
      return udmChildren(parent, new vscode.Range(position.translate(0, -fieldMatch[2].length), position));
    }

    // Namespaced functions: `strings.`
    const nsMatch = /(?:^|[^\w.$#%])([a-z_]+)\.(\w*)$/.exec(linePrefix);
    if (nsMatch && functions.namespaces().includes(nsMatch[1])) {
      const range = new vscode.Range(position.translate(0, -nsMatch[2].length), position);
      return functions
        .all()
        .filter((f) => f.name.startsWith(nsMatch[1] + '.'))
        .map((f) => functionItem(f, f.name.slice(nsMatch[1].length + 1), range));
    }

    // Reference lists
    const listMatch = /%(\w*)$/.exec(linePrefix);
    if (listMatch) {
      const range = new vscode.Range(position.translate(0, -listMatch[1].length), position);
      return [...this.index.referenceLists().entries()].map(([name, count]) => {
        const item = new vscode.CompletionItem(name, vscode.CompletionItemKind.Reference);
        item.detail = `reference list · used in ${count} file${count === 1 ? '' : 's'}`;
        item.range = range;
        return item;
      });
    }

    // Variables
    const varMatch = /([$#])(\w*)$/.exec(linePrefix);
    if (varMatch && rule) {
      const range = new vscode.Range(position.translate(0, -varMatch[2].length), position);
      const t = variableTables(rule);
      const items: vscode.CompletionItem[] = [];
      const add = (name: string, kind: vscode.CompletionItemKind, detail: string, sort: string) => {
        const item = new vscode.CompletionItem(name, kind);
        item.detail = detail;
        item.range = range;
        item.sortText = sort + name;
        items.push(item);
      };
      for (const n of t.eventVars.keys()) add(n, vscode.CompletionItemKind.Variable, 'event variable', '0');
      if (varMatch[1] === '$') {
        for (const n of t.placeholders.keys()) add(n, vscode.CompletionItemKind.Variable, t.matchVars.has(n) ? 'match variable' : 'placeholder', '1');
        for (const n of t.outcomeVars) add(n, vscode.CompletionItemKind.Field, 'outcome variable', '2');
        // In outcome:, offer the workspace's standard outcome variables with their typical expression.
        if (sec?.kind === 'outcome' && /^\s*\$\w*$/.test(linePrefix) && conventions) {
          const firstEvent = [...t.eventVars.keys()][0] ?? 'e';
          for (const o of conventions.outcomes.slice(0, 80)) {
            if (t.outcomeVars.has(o.name)) continue;
            const item = new vscode.CompletionItem(o.name, vscode.CompletionItemKind.Snippet);
            const expr = (o.examples[0]?.expr ?? '').replace(/\$e(?=\.)/g, `$${firstEvent}`);
            item.detail = `workspace outcome · ${o.count}/${conventions.ruleCount} rules`;
            item.documentation = new vscode.MarkdownString('```yaral\n$' + o.name + ' = ' + expr + '\n```');
            item.insertText = new vscode.SnippetString(`${o.name} = \${1:${expr.replace(/[$}\\]/g, '\\$&')}}`);
            item.range = range;
            item.sortText = `3${String(100000 - o.count).padStart(6, '0')}`;
            items.push(item);
          }
        }
      }
      return items;
    }

    const wordRange = document.getWordRangeAtPosition(position, /[\w]+/);
    const items: vscode.CompletionItem[] = [];

    // Meta keys at line start in meta:
    if (sec?.kind === 'meta' && /^\s*\w*$/.test(linePrefix)) {
      const existing = new Set(rule!.meta.map((m) => m.key));
      const keys = new Map<string, string>();
      for (const k of config.requiredMeta) keys.set(k, 'required');
      for (const m of conventions?.metaKeys ?? []) if (!keys.has(m.key)) keys.set(m.key, `used in ${m.count}/${conventions!.ruleCount} rules`);
      let i = 0;
      for (const [key, detail] of keys) {
        if (existing.has(key)) continue;
        const item = new vscode.CompletionItem(key, vscode.CompletionItemKind.Property);
        item.detail = `meta · ${detail}`;
        item.insertText = new vscode.SnippetString(`${key} = "$1"`);
        item.range = wordRange;
        item.sortText = String(i++).padStart(4, '0');
        items.push(item);
      }
    }

    // Section headers when at shallow indentation
    if (rule && /^\s{0,4}\w*$/.test(linePrefix)) {
      const present = new Set(rule.sections.map((s) => s.kind));
      for (const s of SECTION_ORDER) {
        if (present.has(s)) continue;
        const item = new vscode.CompletionItem(`${s}:`, vscode.CompletionItemKind.Module);
        item.documentation = new vscode.MarkdownString(SECTION_DOCS[s].description);
        item.insertText = `${s}:`;
        item.range = wordRange;
        item.sortText = 'z' + SECTION_ORDER.indexOf(s);
        items.push(item);
      }
    }

    if (sec && sec.kind !== 'meta') {
      for (const f of functions.all()) {
        if (f.name.includes('.')) continue;
        if (f.sections && !f.sections.includes(sec.kind)) continue;
        items.push(functionItem(f, f.name, wordRange));
      }
      for (const ns of functions.namespaces()) {
        const item = new vscode.CompletionItem(ns, vscode.CompletionItemKind.Module);
        item.detail = 'function namespace';
        item.command = { command: 'editor.action.triggerSuggest', title: '' };
        item.insertText = ns + '.';
        item.range = wordRange;
        items.push(item);
      }
      for (const kw of ['and', 'or', 'not', 'in', 'nocase', 'regex', 'cidr', 'any', 'all', 'over', 'before', 'after', 'true', 'false']) {
        const item = new vscode.CompletionItem(kw, vscode.CompletionItemKind.Keyword);
        item.range = wordRange;
        items.push(item);
      }
      if (sec.kind === 'options') {
        const item = new vscode.CompletionItem('allow_zero_values', vscode.CompletionItemKind.Property);
        item.insertText = 'allow_zero_values = true';
        items.push(item);
      }
    }
    return items;
  }
}

function functionItem(f: FunctionDef, label: string, range: vscode.Range | undefined): vscode.CompletionItem {
  const item = new vscode.CompletionItem(label, f.aggregate ? vscode.CompletionItemKind.Method : vscode.CompletionItemKind.Function);
  item.detail = signature(f);
  item.documentation = new vscode.MarkdownString(functionMarkdown(f));
  item.insertText = new vscode.SnippetString(f.params.length ? `${label}($0)` : `${label}()`);
  item.command = f.params.length ? { command: 'editor.action.triggerParameterHints', title: '' } : undefined;
  item.range = range;
  return item;
}

function udmChildren(parent: string, range: vscode.Range): vscode.CompletionItem[] {
  const prefix = parent ? parent + '.' : '';
  const children = new Map<string, boolean>();
  for (const f of allUdmFields()) {
    if (!f.startsWith(prefix)) continue;
    const rest = f.slice(prefix.length);
    if (!rest) continue;
    const seg = rest.split('.')[0];
    const hasChildren = rest.includes('.');
    children.set(seg, (children.get(seg) ?? false) || hasChildren);
  }
  return [...children.entries()].map(([seg, hasChildren]) => {
    const item = new vscode.CompletionItem(seg, hasChildren ? vscode.CompletionItemKind.Module : vscode.CompletionItemKind.Field);
    item.detail = `UDM ${prefix}${seg}`;
    item.range = range;
    if (hasChildren) item.command = { command: 'editor.action.triggerSuggest', title: '' };
    return item;
  });
}

// ------------------------------------------------------------------ signature help

class SignatureProvider implements vscode.SignatureHelpProvider {
  constructor(private readonly index: WorkspaceIndex) {}

  provideSignatureHelp(document: vscode.TextDocument, position: vscode.Position): vscode.SignatureHelp | undefined {
    const doc = this.index.parse(document);
    const ctx = callContextAt(doc, document.offsetAt(position));
    if (!ctx) return undefined;
    const f = this.index.getConfig(document.uri).functions.get(ctx.name);
    if (!f) return undefined;
    const sig = new vscode.SignatureInformation(signature(f), new vscode.MarkdownString(f.description));
    sig.parameters = f.params.map((p) => new vscode.ParameterInformation(`${p.name}${p.optional ? '?' : ''}: ${p.type}${p.repeated ? ', ...' : ''}`, p.description));
    const help = new vscode.SignatureHelp();
    help.signatures = [sig];
    help.activeSignature = 0;
    const repeatedIdx = f.params.findIndex((p) => p.repeated);
    help.activeParameter = repeatedIdx !== -1 && ctx.argIndex >= repeatedIdx ? repeatedIdx : Math.min(ctx.argIndex, f.params.length - 1);
    return help;
  }
}

// ------------------------------------------------------------------ symbols

class SymbolProvider implements vscode.DocumentSymbolProvider {
  constructor(private readonly index: WorkspaceIndex) {}

  provideDocumentSymbols(document: vscode.TextDocument): vscode.DocumentSymbol[] {
    const doc = this.index.parse(document);
    return doc.rules.map((rule) => {
      const ruleSym = new vscode.DocumentSymbol(rule.name || '(unnamed rule)', 'rule', vscode.SymbolKind.Class, toRange(rule.range), toRange((rule.nameToken ?? rule.ruleKeyword).range));
      const t = variableTables(rule);
      for (const s of rule.sections) {
        const secSym = new vscode.DocumentSymbol(s.kind, '', vscode.SymbolKind.Namespace, toRange({ start: s.header.range.start, end: s.range.end }), toRange(s.header.range));
        if (s.kind === 'meta') {
          for (const m of rule.meta) {
            secSym.children.push(new vscode.DocumentSymbol(m.key, m.value, vscode.SymbolKind.Property, toRange({ start: m.keyToken.range.start, end: (m.valueToken ?? m.keyToken).range.end }), toRange(m.keyToken.range)));
          }
        } else if (s.kind === 'events') {
          for (const [name, ref] of t.eventVars) secSym.children.push(new vscode.DocumentSymbol('$' + name, 'event', vscode.SymbolKind.Variable, toRange(ref.token.range), toRange(ref.token.range)));
          for (const [name, ref] of t.placeholders) secSym.children.push(new vscode.DocumentSymbol('$' + name, t.matchVars.has(name) ? 'match' : 'placeholder', vscode.SymbolKind.Variable, toRange(ref.token.range), toRange(ref.token.range)));
        } else if (s.kind === 'outcome') {
          for (const o of rule.outcomes) secSym.children.push(new vscode.DocumentSymbol('$' + o.name, 'outcome', vscode.SymbolKind.Field, toRange(o.range), toRange(o.token.range)));
        }
        ruleSym.children.push(secSym);
      }
      return ruleSym;
    });
  }
}

// ------------------------------------------------------------------ variables: definition / references / rename / highlight

class VariableProvider implements vscode.DefinitionProvider, vscode.ReferenceProvider, vscode.RenameProvider, vscode.DocumentHighlightProvider {
  constructor(private readonly index: WorkspaceIndex) {}

  private target(document: vscode.TextDocument, position: vscode.Position) {
    const doc = this.index.parse(document);
    const offset = document.offsetAt(position);
    const tok = tokenAt(doc, offset);
    if (!tok || (tok.kind !== 'eventVar' && tok.kind !== 'countVar')) return undefined;
    const rule = ruleAt(doc, offset);
    if (!rule) return undefined;
    const name = tok.text.slice(1);
    const refs = rule.varRefs.filter((r) => r.sigil !== '%' && r.name === name);
    return { doc, rule, tok, name, refs };
  }

  provideDefinition(document: vscode.TextDocument, position: vscode.Position): vscode.Location | undefined {
    const t = this.target(document, position);
    if (!t) return undefined;
    const tables = variableTables(t.rule);
    const def =
      tables.eventVars.get(t.name)?.token ??
      tables.placeholders.get(t.name)?.token ??
      t.rule.outcomes.find((o) => o.name === t.name)?.token;
    return def ? new vscode.Location(document.uri, toRange(def.range)) : undefined;
  }

  provideReferences(document: vscode.TextDocument, position: vscode.Position): vscode.Location[] {
    const t = this.target(document, position);
    return t ? t.refs.map((r) => new vscode.Location(document.uri, toRange(r.token.range))) : [];
  }

  provideDocumentHighlights(document: vscode.TextDocument, position: vscode.Position): vscode.DocumentHighlight[] {
    const t = this.target(document, position);
    return t
      ? t.refs.map((r) => new vscode.DocumentHighlight(toRange(r.token.range), r.isOutcomeDefinition ? vscode.DocumentHighlightKind.Write : vscode.DocumentHighlightKind.Read))
      : [];
  }

  prepareRename(document: vscode.TextDocument, position: vscode.Position): vscode.Range {
    const t = this.target(document, position);
    if (!t) throw new Error('Only YARA-L variables can be renamed');
    return toRange({ start: { line: t.tok.range.start.line, character: t.tok.range.start.character + 1 }, end: t.tok.range.end });
  }

  provideRenameEdits(document: vscode.TextDocument, position: vscode.Position, newName: string): vscode.WorkspaceEdit | undefined {
    const t = this.target(document, position);
    if (!t) return undefined;
    const clean = newName.replace(/^[$#]/, '');
    if (!/^[A-Za-z_]\w*$/.test(clean)) throw new Error(`'${newName}' is not a valid variable name`);
    const edit = new vscode.WorkspaceEdit();
    for (const r of t.refs) {
      edit.replace(document.uri, toRange({ start: { line: r.token.range.start.line, character: r.token.range.start.character + 1 }, end: r.token.range.end }), clean);
    }
    return edit;
  }
}

// ------------------------------------------------------------------ folding & formatting

class FoldingProvider implements vscode.FoldingRangeProvider {
  constructor(private readonly index: WorkspaceIndex) {}

  provideFoldingRanges(document: vscode.TextDocument): vscode.FoldingRange[] {
    const doc = this.index.parse(document);
    const ranges: vscode.FoldingRange[] = [];
    for (const rule of doc.rules) {
      if (rule.range.end.line > rule.range.start.line) ranges.push(new vscode.FoldingRange(rule.range.start.line, rule.range.end.line - 1));
      for (const s of rule.sections) {
        if (s.range.end.line > s.header.range.start.line) ranges.push(new vscode.FoldingRange(s.header.range.start.line, s.range.end.line));
      }
    }
    for (const c of doc.comments) {
      if (c.range.end.line > c.range.start.line) ranges.push(new vscode.FoldingRange(c.range.start.line, c.range.end.line, vscode.FoldingRangeKind.Comment));
    }
    return ranges;
  }
}

class FormattingProvider implements vscode.DocumentFormattingEditProvider {
  provideDocumentFormattingEdits(document: vscode.TextDocument, options: vscode.FormattingOptions): vscode.TextEdit[] {
    if (!vscode.workspace.getConfiguration('yaral', document.uri).get<boolean>('format.enable', true)) return [];
    const text = document.getText();
    // Rules are always indented with spaces (tabs are flagged by YL701).
    const formatted = format(text, { indent: ' '.repeat(options.insertSpaces ? Math.max(2, Math.min(options.tabSize, 4)) : 2) });
    if (formatted === text) return [];
    return [vscode.TextEdit.replace(new vscode.Range(document.positionAt(0), document.positionAt(text.length)), formatted)];
  }
}
