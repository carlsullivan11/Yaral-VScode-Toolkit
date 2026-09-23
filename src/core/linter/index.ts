import * as path from 'path';
import { arity, buildFunctionIndex, FunctionIndex } from '../catalog/functions';
import { KNOWN_OPTIONS, SEVERITY_RISK_SCORES } from '../catalog/keywords';
import { DEFAULT_CONFIG, LintConfig } from '../config';
import { Conventions } from '../conventions';
import { ALTERNATE_MITRE_KEYS, findByName, frameworkOfId, isTacticId, isTechniqueId, lookupMitre, MitreFramework, splitMitreValue } from '../mitre';
import { LineIndex, Range, Token } from '../lexer';
import { durationSeconds, parse, ParsedDocument, Rule, section, SECTION_ORDER, Section, VarRef } from '../parser';
import { resolveSeverity, RULES_BY_ID, Severity } from './rules';

export interface TextEdit {
  range: Range;
  newText: string;
}

export interface Fix {
  title: string;
  edits: TextEdit[];
}

export interface LintDiagnostic {
  ruleId: string;
  ruleName: string;
  severity: Exclude<Severity, 'off'>;
  message: string;
  range: Range;
  fix?: Fix;
}

export interface LintOptions {
  filePath?: string;
  config?: LintConfig;
  conventions?: Conventions;
  functions?: FunctionIndex;
}

const GENERIC_EVENT_NAME = /^(e|e\d+|event|event\d+|evt|evt\d+)$/;
const SNAKE = /^[a-z][a-z0-9_]*$/;

export function lint(text: string, options: LintOptions = {}): LintDiagnostic[] {
  const doc = parse(text);
  return lintDocument(doc, options);
}

export function lintDocument(doc: ParsedDocument, options: LintOptions = {}): LintDiagnostic[] {
  const config = options.config ?? DEFAULT_CONFIG;
  const functions = options.functions ?? buildFunctionIndex(config.functions);
  const out: LintDiagnostic[] = [];

  const report = (ruleId: string, message: string, range: Range, fix?: Fix) => {
    const severity = resolveSeverity(ruleId, config.rules);
    if (severity === 'off') return;
    out.push({ ruleId, ruleName: RULES_BY_ID.get(ruleId)?.name ?? ruleId, severity, message, range, fix });
  };

  for (const e of doc.errors) report('YL001', e.message, e.range);

  if (doc.rules.length > 1) {
    for (const r of doc.rules.slice(1)) report('YL107', 'File contains more than one rule', r.ruleKeyword.range);
  }

  for (const rule of doc.rules) {
    const ctx: RuleCtx = { doc, rule, config, functions, conventions: options.conventions, filePath: options.filePath, report };
    checkStructure(ctx);
    checkVariables(ctx);
    checkFunctions(ctx);
    checkMeta(ctx);
    checkMitre(ctx);
    checkOutcomes(ctx);
    checkMatch(ctx);
    checkOptions(ctx);
  }

  checkWhitespace(doc, report);

  return applySuppressions(doc, out).sort((a, b) => a.range.start.line - b.range.start.line || a.range.start.character - b.range.start.character);
}

interface RuleCtx {
  doc: ParsedDocument;
  rule: Rule;
  config: LintConfig;
  functions: FunctionIndex;
  conventions?: Conventions;
  filePath?: string;
  report: (ruleId: string, message: string, range: Range, fix?: Fix) => void;
}

function ruleAnchor(rule: Rule): Range {
  return (rule.nameToken ?? rule.ruleKeyword).range;
}

// ------------------------------------------------------------------ structure

function checkStructure({ rule, config, filePath, report }: RuleCtx): void {
  for (const required of ['events', 'condition'] as const) {
    if (!section(rule, required)) report('YL101', `Rule is missing the required '${required}:' section`, ruleAnchor(rule));
  }

  const seen = new Set<string>();
  let lastOrder = -1;
  for (const s of rule.sections) {
    if (seen.has(s.kind)) {
      report('YL103', `Duplicate '${s.kind}:' section`, s.header.range);
      continue;
    }
    seen.add(s.kind);
    const order = SECTION_ORDER.indexOf(s.kind);
    if (order < lastOrder) {
      report('YL102', `'${s.kind}:' must come before '${SECTION_ORDER[lastOrder]}:' (order: ${SECTION_ORDER.join(', ')})`, s.header.range);
    }
    lastOrder = Math.max(lastOrder, order);
    if (s.tokens.length === 0) report('YL104', `'${s.kind}:' section is empty`, s.header.range);
  }

  if (rule.nameToken) {
    if (!SNAKE.test(rule.name)) {
      report('YL106', `Rule name '${rule.name}' should be lower snake_case`, rule.nameToken.range);
    }
    if (filePath && config.filenameMatchesRuleName) {
      const base = path.basename(filePath).replace(/\.[^.]+$/, '');
      if (base !== rule.name && !base.startsWith('Untitled')) {
        report('YL105', `Rule name '${rule.name}' does not match file name '${base}'`, rule.nameToken.range, {
          title: `Rename rule to '${base}'`,
          edits: [{ range: rule.nameToken.range, newText: base }],
        });
      }
    }
  }
}

// ------------------------------------------------------------------ variables

interface VarTables {
  eventVars: Map<string, VarRef>;
  placeholders: Map<string, VarRef>;
  outcomeVars: Set<string>;
  matchVars: Set<string>;
}

export function variableTables(rule: Rule): VarTables {
  const eventVars = new Map<string, VarRef>();
  const placeholders = new Map<string, VarRef>();
  for (const ref of rule.varRefs) {
    if (ref.section !== 'events' || ref.sigil !== '$') continue;
    if (ref.isFieldAccess) {
      if (!eventVars.has(ref.name)) eventVars.set(ref.name, ref);
    }
  }
  for (const ref of rule.varRefs) {
    if (ref.section !== 'events' || ref.sigil !== '$' || ref.isFieldAccess) continue;
    if (!eventVars.has(ref.name) && !placeholders.has(ref.name)) placeholders.set(ref.name, ref);
  }
  return {
    eventVars,
    placeholders,
    outcomeVars: new Set(rule.outcomes.map((o) => o.name)),
    matchVars: new Set((rule.match?.vars ?? []).map((t) => t.text.slice(1))),
  };
}

function checkVariables(ctx: RuleCtx): void {
  const { rule, report } = ctx;
  const t = variableTables(rule);
  const hasEvents = !!section(rule, 'events');

  // YL201 undefined references
  if (hasEvents) {
    for (const ref of rule.varRefs) {
      if (ref.sigil === '%' || ref.section === 'events' || ref.section === 'match' || ref.isOutcomeDefinition) continue;
      const name = ref.name;
      let ok: boolean;
      if (ref.sigil === '#') ok = t.eventVars.has(name) || t.placeholders.has(name);
      else if (ref.isFieldAccess) ok = t.eventVars.has(name);
      else ok = t.eventVars.has(name) || t.placeholders.has(name) || t.outcomeVars.has(name);
      if (!ok) {
        const kind = ref.isFieldAccess || ref.sigil === '#' ? 'event variable' : 'variable';
        report('YL201', `Undefined ${kind} '${ref.token.text}'${ref.sigil === '$' && !ref.isFieldAccess ? ' (not defined in events: or outcome:)' : ''}`, ref.token.range);
      }
    }
  }

  // YL202 event variables not used in condition
  const condition = section(rule, 'condition');
  if (condition) {
    const used = new Set(rule.varRefs.filter((r) => r.section === 'condition' && r.sigil !== '%').map((r) => r.name));
    // Referencing a placeholder derived from an event (e.g. `#country` where
    // `$country = $e.principal.location.country_or_region`) also uses the event.
    const derived = placeholderSources(rule);
    for (const [name, ref] of t.eventVars) {
      const viaPlaceholder = [...used].some((u) => derived.get(u)?.has(name));
      if (!used.has(name) && !viaPlaceholder) report('YL202', `Event variable '$${name}' is not referenced in condition:`, ref.token.range);
    }
  }

  // YL203 match variables
  for (const tok of rule.match?.vars ?? []) {
    const name = tok.text.slice(1);
    if (t.eventVars.has(name)) {
      report('YL203', `Match variable '${tok.text}' is an event variable; match on a placeholder such as '$user = ${tok.text}.principal.user.userid'`, tok.range);
    } else if (!t.placeholders.has(name)) {
      report('YL203', `Match variable '${tok.text}' is not assigned in events:`, tok.range);
    }
  }

  // YL205 unused placeholders
  const counts = new Map<string, number>();
  for (const ref of rule.varRefs) if (ref.sigil !== '%') counts.set(ref.name, (counts.get(ref.name) ?? 0) + 1);
  for (const [name, ref] of t.placeholders) {
    if ((counts.get(name) ?? 0) <= 1) {
      report('YL205', `Placeholder '$${name}' is assigned but never used (not joined, matched, output or referenced in condition)`, ref.token.range);
    }
  }

  // YL207 case collisions
  const byLower = new Map<string, string>();
  const reported = new Set<string>();
  for (const ref of rule.varRefs) {
    if (ref.sigil === '%') continue;
    const lower = ref.name.toLowerCase();
    const prior = byLower.get(lower);
    if (prior === undefined) byLower.set(lower, ref.name);
    else if (prior !== ref.name && !reported.has(ref.name)) {
      reported.add(ref.name);
      report('YL207', `'$${ref.name}' differs from '$${prior}' only by case`, ref.token.range);
    }
  }

  // YL208 generic event variable names
  for (const [name, ref] of t.eventVars) {
    if (GENERIC_EVENT_NAME.test(name)) {
      report('YL208', `Consider a descriptive event variable name instead of '$${name}' (e.g. $login, $process, $dns)`, ref.token.range);
    }
  }

  // YL306 / YL307 performance filters (Google SecOps community style guide)
  const events = section(rule, 'events');
  if (events) {
    const paths = new Map<string, Set<string>>();
    for (let i = 0; i < events.tokens.length; i++) {
      const { text, next } = fieldPathAt(events.tokens, i);
      if (text && text.includes('.')) {
        const [v, ...rest] = text.split('.');
        const set = paths.get(v.slice(1)) ?? new Set<string>();
        set.add(rest.join('.').replace(/\[.*$/, ''));
        paths.set(v.slice(1), set);
      }
      i = Math.max(i, next - 1);
    }
    for (const [name, ref] of t.eventVars) {
      const p = [...(paths.get(name) ?? [])];
      if (p.some((x) => x.startsWith('graph.'))) {
        const missing = ['graph.metadata.entity_type', 'graph.metadata.source_type'].filter((f) => !p.includes(f));
        if (missing.length) report('YL307', `Entity variable '$${name}' should filter on ${missing.join(' and ')}`, ref.token.range);
      } else if (!p.some((x) => /^metadata\.(event_type|log_type|product_name|vendor_name|product_event_type|base_labels)/.test(x))) {
        report('YL306', `Event variable '$${name}' has no metadata filter (e.g. $${name}.metadata.event_type = "...")`, ref.token.range);
      }
    }
  }

  // YL206 outcome aggregation in multi-event rules
  if (rule.match) {
    const aggregates = rule.calls.filter((c) => c.section === 'outcome' && ctx.functions.get(c.name)?.aggregate && c.closeParen);
    const inAggregate = (tok: Token) => aggregates.some((c) => tok.start > c.openParen.start && tok.end <= c.closeParen!.end);
    for (const o of rule.outcomes) {
      for (let i = 0; i < o.expr.length; i++) {
        const tok = o.expr[i];
        if (tok.kind !== 'eventVar') continue;
        const name = tok.text.slice(1);
        const isField = o.expr[i + 1]?.text === '.' && o.expr[i + 1].start === tok.end;
        const needsAgg = isField || (t.placeholders.has(name) && !t.matchVars.has(name));
        if (needsAgg && !inAggregate(tok)) {
          report('YL206', `'${tok.text}${isField ? '.…' : ''}' must be aggregated (e.g. array_distinct(), max()) because the rule has a match: section`, tok.range);
          break;
        }
      }
    }
  }
}

/** Maps each placeholder to the event variables it is assigned from in events:. */
function placeholderSources(rule: Rule): Map<string, Set<string>> {
  const map = new Map<string, Set<string>>();
  const events = section(rule, 'events');
  if (!events) return map;
  // Group tokens by line: `$p = $e.field` / `$e.field = $p` / `$p = func($e.field)` statements.
  const byLine = new Map<number, Token[]>();
  for (const tok of events.tokens) {
    const arr = byLine.get(tok.range.start.line) ?? [];
    arr.push(tok);
    byLine.set(tok.range.start.line, arr);
  }
  for (const toks of byLine.values()) {
    const bare: string[] = [];
    const fields: string[] = [];
    toks.forEach((tok, i) => {
      if (tok.kind !== 'eventVar') return;
      const isField = toks[i + 1]?.text === '.' && toks[i + 1].start === tok.end;
      (isField ? fields : bare).push(tok.text.slice(1));
    });
    for (const p of bare) {
      const set = map.get(p) ?? new Set<string>();
      fields.forEach((f) => set.add(f));
      map.set(p, set);
    }
  }
  return map;
}

// ------------------------------------------------------------------ functions

function unquote(text: string): string {
  if (text.startsWith('`')) return text.slice(1, -1);
  // "..." strings: YARA-L unescapes \\ -> \ before the regex engine sees them.
  return text.slice(1, -1).replace(/\\\\/g, '\\').replace(/\\"/g, '"');
}

function checkFunctions(ctx: RuleCtx): void {
  const { rule, functions, report } = ctx;
  for (const call of rule.calls) {
    const def = functions.get(call.name);
    const range = { start: call.nameTokens[0].range.start, end: call.nameTokens[call.nameTokens.length - 1].range.end };
    if (!def) {
      const suggestion = closest(call.name, functions.all().map((f) => f.name), 3);
      report('YL301', `Unknown function '${call.name}'${suggestion ? ` — did you mean '${suggestion}'?` : ''}`, range,
        suggestion ? { title: `Change to '${suggestion}'`, edits: [{ range, newText: suggestion }] } : undefined);
      continue;
    }
    const { min, max } = arity(def);
    const n = call.args.length;
    if (n < min || n > max) {
      const expected = min === max ? `${min}` : max === Infinity ? `at least ${min}` : `${min}-${max}`;
      report('YL302', `'${def.name}' expects ${expected} argument${expected === '1' ? '' : 's'} but got ${n}`, call.range);
    }
    if (def.sections && !def.sections.includes(call.section)) {
      report('YL303', `'${def.name}' can only be used in ${def.sections.map((s) => s + ':').join(', ')} (found in ${call.section}:)`, range);
    }
    if (/^re\.(regex|capture|replace)$/.test(def.name)) {
      const pat = call.args[1];
      if (pat && pat.length === 1 && pat[0].kind === 'string') {
        checkRegex(unquote(pat[0].text), pat[0].range, def.name === 're.regex', report);
      }
    }
  }

  for (const s of rule.sections) {
    for (const tok of s.tokens) {
      if (tok.kind === 'regex' && tok.text.length >= 2 && tok.text.endsWith('/')) {
        checkRegex(tok.text.slice(1, -1), tok.range, true, report);
      }
    }
  }
}

const RE2_UNSUPPORTED: [RegExp, string][] = [
  [/\(\?<?[=!]/, 'lookaround assertions'],
  [/(^|[^\\])\\[1-9]/, 'backreferences'],
  [/\(\?>/, 'atomic groups'],
  [/[*+?}][+]/, 'possessive quantifiers'],
];

function checkRegex(pattern: string, range: Range, substringMatch: boolean, report: RuleCtx['report']): void {
  for (const [re, what] of RE2_UNSUPPORTED) {
    if (re.test(pattern)) {
      report('YL304', `RE2 does not support ${what}`, range);
      return;
    }
  }
  // Translate RE2-only syntax to something JavaScript can compile.
  const js = pattern
    .replace(/^\(\?[imsU]+\)/, '')
    .replace(/\(\?[imsU]+:/g, '(?:')
    .replace(/\(\?P</g, '(?<')
    .replace(/\\[Az]/g, '')
    .replace(/\[\[:\w+:\]\]/g, 'x')
    .replace(/\[:\w+:\]/g, 'x')
    .replace(/\\p\{?\w+\}?/g, 'x')
    .replace(/\\Q.*?\\E/g, 'x');
  try {
    new RegExp(js);
  } catch (e) {
    report('YL304', `Invalid regular expression: ${(e as Error).message.replace(/^Invalid regular expression: /, '')}`, range);
    return;
  }
  if (substringMatch) {
    const body = pattern.replace(/^\(\?[imsU]+\)/, '');
    if (/^\.\*/.test(body) || (/\.\*$/.test(body) && !/\\\.\*$/.test(body))) {
      report('YL305', 'Leading/trailing `.*` is redundant: YARA-L regexes already match substrings', range);
    }
  }
}

// ------------------------------------------------------------------ meta

function metaInsertEdit(ctx: RuleCtx, line: string): TextEdit | undefined {
  const { rule, doc } = ctx;
  const meta = section(rule, 'meta');
  if (!meta) {
    if (!rule.openBrace) return undefined;
    const pos = rule.openBrace.range.end;
    return { range: { start: pos, end: pos }, newText: `\n\n  meta:\n    ${line}` };
  }
  const last = meta.tokens[meta.tokens.length - 1];
  const anchor = last ?? meta.header;
  const indent = last ? doc.index.lineText(rule.meta[0]?.keyToken.range.start.line ?? anchor.range.start.line).match(/^\s*/)![0] : '    ';
  const pos = { line: anchor.range.end.line, character: doc.index.lineText(anchor.range.end.line).length };
  return { range: { start: pos, end: pos }, newText: `\n${indent}${line}` };
}

function checkMeta(ctx: RuleCtx): void {
  const { rule, config, conventions, filePath, report } = ctx;
  const keys = new Map<string, number>();
  for (const m of rule.meta) keys.set(m.key, (keys.get(m.key) ?? 0) + 1);
  const anchor = section(rule, 'meta')?.header.range ?? ruleAnchor(rule);

  for (const key of config.requiredMeta) {
    if (!keys.has(key)) {
      const edit = metaInsertEdit(ctx, `${key} = ""`);
      report('YL401', `Missing required meta key '${key}'`, anchor, edit && { title: `Add meta '${key}'`, edits: [edit] });
    }
  }

  if (conventions) {
    for (const key of conventions.standardMeta) {
      if (keys.has(key) || config.requiredMeta.includes(key)) continue;
      const stat = conventions.metaKeys.find((m) => m.key === key);
      const pct = stat ? Math.round(stat.ratio * 100) : 0;
      const value = stat?.enumLike && stat.values[0] ? stat.values[0].value : '';
      const edit = metaInsertEdit(ctx, `${key} = "${value}"`);
      report('YL402', `Meta key '${key}' is used by ${pct}% of workspace rules but is missing here`, anchor, edit && { title: `Add meta '${key}'`, edits: [edit] });
    }
  }

  const seen = new Set<string>();
  for (const m of rule.meta) {
    if (seen.has(m.key)) report('YL405', `Duplicate meta key '${m.key}'`, m.keyToken.range);
    seen.add(m.key);

    const allowed = config.metaValues[m.key];
    if (allowed && m.valueToken && !allowed.includes(m.value)) {
      const ci = allowed.find((a) => a.toLowerCase() === m.value.toLowerCase());
      const suggestion = ci ?? closest(m.value, allowed, 3);
      report(
        'YL403',
        `Invalid value "${m.value}" for meta '${m.key}'. Allowed: ${allowed.join(', ')}`,
        m.valueToken.range,
        suggestion ? { title: `Change to "${suggestion}"`, edits: [{ range: m.valueToken.range, newText: `"${suggestion}"` }] } : undefined,
      );
    }

    const pattern = config.metaPatterns[m.key];
    if (pattern && m.valueToken) {
      let re: RegExp | undefined;
      try {
        re = new RegExp(pattern);
      } catch {
        re = undefined;
      }
      if (re && !re.test(m.value)) report('YL404', `Meta '${m.key}' value "${m.value}" does not match ${pattern}`, m.valueToken.range);
    }

    if (conventions && conventions.ruleCount >= conventions.minRules) {
      const stat = conventions.metaKeys.find((s) => s.key === m.key);
      if (!stat || stat.count <= 1) {
        const common = conventions.metaKeys.filter((s) => s.ratio >= 0.2 && s.key !== m.key).map((s) => s.key);
        const suggestion = closest(m.key, [...new Set([...common, ...config.requiredMeta])], 2);
        if (suggestion && !keys.has(suggestion)) {
          report('YL406', `Meta key '${m.key}' is not used by other rules — did you mean '${suggestion}'?`, m.keyToken.range, {
            title: `Rename to '${suggestion}'`,
            edits: [{ range: m.keyToken.range, newText: suggestion }],
          });
        }
      }
    }
  }

  if (conventions && filePath) {
    const norm = (p: string) => path.resolve(p);
    for (const d of conventions.duplicates) {
      if (!d.files.some((f) => norm(f) === norm(filePath))) continue;
      const others = d.files.filter((f) => norm(f) !== norm(filePath));
      const where = others.length ? others.map((f) => path.basename(f)).join(', ') : 'this file';
      if (d.kind === 'rule name' && d.value === rule.name && rule.nameToken) {
        report('YL407', `Rule name '${rule.name}' is also used in ${where}`, rule.nameToken.range);
      }
      if (d.kind === 'rule_id') {
        const m = rule.meta.find((x) => x.key === 'rule_id' && x.value === d.value);
        if (m) report('YL407', `rule_id '${d.value}' is also used in ${where}`, (m.valueToken ?? m.keyToken).range);
      }
    }
  }
}

// ------------------------------------------------------------------ MITRE

function checkMitre(ctx: RuleCtx): void {
  const { rule, config, report } = ctx;
  const { tacticKey, techniqueKey, frameworks, defaultFramework } = config.mitre;
  const keys = new Set(rule.meta.map((m) => m.key));

  // YL412 alternative key names
  for (const m of rule.meta) {
    const canonical = ALTERNATE_MITRE_KEYS[m.key];
    if (!canonical) continue;
    const target = canonical === 'tactic' ? tacticKey : techniqueKey;
    if (target === m.key) continue;
    const idsOnly = splitMitreValue(m.value).every((x) => lookupMitre(x.text));
    report(
      'YL412',
      `Use '${target}' for MITRE ${canonical}s instead of '${m.key}'`,
      m.keyToken.range,
      !keys.has(target) && idsOnly ? { title: `Rename to '${target}'`, edits: [{ range: m.keyToken.range, newText: target }] } : undefined,
    );
  }

  const tacticMeta = rule.meta.filter((m) => m.key === tacticKey);
  const techniqueMeta = rule.meta.filter((m) => m.key === techniqueKey);
  if (!tacticMeta.length && !techniqueMeta.length) return;

  // Framework(s) the rule already uses, to resolve ambiguous names.
  const used = new Set<MitreFramework>();
  for (const m of [...tacticMeta, ...techniqueMeta]) {
    for (const item of splitMitreValue(m.value)) {
      const f = frameworkOfId(item.text);
      if (f) used.add(f);
    }
  }
  const preferred: MitreFramework = used.size === 1 ? [...used][0] : defaultFramework;

  const listedTactics = new Set<string>();
  const check = (kind: 'tactic' | 'technique', m: (typeof rule.meta)[number]) => {
    if (!m.valueToken || m.valueToken.kind !== 'string') return;
    const base = m.valueToken.range.start;
    const spanRange = (s: { start: number; end: number }) => ({
      start: { line: base.line, character: base.character + 1 + s.start },
      end: { line: base.line, character: base.character + 1 + s.end },
    });
    const validShape = kind === 'tactic' ? isTacticId : isTechniqueId;
    for (const item of splitMitreValue(m.value)) {
      const range = spanRange(item);
      const entry = lookupMitre(item.text);
      if (!validShape(item.text)) {
        if (entry) {
          report('YL408', `${item.text} is a MITRE ${entry.kind} ID, but '${m.key}' expects ${kind} IDs`, range);
          continue;
        }
        const matches = findByName(item.text, kind, frameworks);
        if (matches.length) {
          const pick = matches.find((x) => x.framework === preferred) ?? matches[0];
          const alternatives = matches.filter((x) => x !== pick).map((x) => `${x.id} (${x.framework})`);
          report(
            'YL410',
            `Use the ${kind} ID instead of the name: '${item.text}' is ${pick.id} (${pick.framework})${alternatives.length ? `; also ${alternatives.join(', ')}` : ''}`,
            range,
            { title: `Replace with ${pick.id}`, edits: [{ range, newText: pick.id }] },
          );
          if (kind === 'tactic') listedTactics.add(pick.id);
        } else {
          report('YL408', `'${item.text}' is not a MITRE ${kind} ID (expected e.g. ${kind === 'tactic' ? 'TA0006, TA0108 (ICS), AML.TA0005 (ATLAS)' : 'T1110, T1021.002, T0843 (ICS), AML.T0051 (ATLAS)'})`, range);
        }
        continue;
      }
      if (!entry) {
        report('YL408', `Unknown MITRE ${kind} ID '${item.text}'`, range);
        continue;
      }
      if (!frameworks.includes(entry.framework)) {
        report('YL408', `${item.text} belongs to MITRE ${entry.framework}, which is not enabled in mitre.frameworks`, range);
        continue;
      }
      if (entry.kind === 'tactic') listedTactics.add(entry.id);
      if (entry.kind === 'technique') {
        if (entry.revokedBy) {
          const replacement = typeof entry.revokedBy === 'string' ? entry.revokedBy : undefined;
          report('YL409', `${entry.id} (${entry.name}) has been revoked${replacement ? ` and replaced by ${replacement} (${lookupMitre(replacement)?.name ?? ''})` : ''}`, range,
            replacement ? { title: `Replace with ${replacement}`, edits: [{ range, newText: replacement }] } : undefined);
        } else if (entry.deprecated) {
          report('YL409', `${entry.id} (${entry.name}) is deprecated`, range);
        }
      }
    }
  };
  for (const m of tacticMeta) check('tactic', m);
  for (const m of techniqueMeta) check('technique', m);

  // YL411 technique/tactic consistency
  if (listedTactics.size) {
    for (const m of techniqueMeta) {
      if (!m.valueToken) continue;
      for (const item of splitMitreValue(m.value)) {
        const e = lookupMitre(item.text);
        if (!e || e.kind !== 'technique' || e.revokedBy || e.tactics.length === 0) continue;
        if (!e.tactics.some((t) => listedTactics.has(t))) {
          const base = m.valueToken.range.start;
          report('YL411', `${e.id} (${e.name}) belongs to ${e.tactics.join(', ')}, none of which is in '${tacticKey}'`, {
            start: { line: base.line, character: base.character + 1 + item.start },
            end: { line: base.line, character: base.character + 1 + item.end },
          });
        }
      }
    }
  }
}

// ------------------------------------------------------------------ outcomes

function outcomeInsertEdit(ctx: RuleCtx, line: string): TextEdit | undefined {
  const { rule, doc } = ctx;
  const outcome = section(rule, 'outcome');
  if (outcome) {
    const last = outcome.tokens[outcome.tokens.length - 1] ?? outcome.header;
    const firstLine = rule.outcomes[0]?.token.range.start.line;
    const indent = firstLine !== undefined ? doc.index.lineText(firstLine).match(/^\s*/)![0] : '    ';
    const pos = { line: last.range.end.line, character: doc.index.lineText(last.range.end.line).length };
    return { range: { start: pos, end: pos }, newText: `\n${indent}${line}` };
  }
  const condition = section(rule, 'condition');
  if (!condition) return undefined;
  const hdrLine = condition.header.range.start.line;
  const indent = doc.index.lineText(hdrLine).match(/^\s*/)![0];
  const pos = { line: hdrLine, character: 0 };
  return { range: { start: pos, end: pos }, newText: `${indent}outcome:\n${indent}  ${line}\n\n` };
}

function checkOutcomes(ctx: RuleCtx): void {
  const { rule, config, conventions, report } = ctx;
  const names = new Set<string>();
  for (const o of rule.outcomes) {
    if (names.has(o.name)) report('YL204', `Outcome variable '$${o.name}' is assigned more than once`, o.token.range);
    names.add(o.name);
    if (!SNAKE.test(o.name)) report('YL505', `Outcome variable '$${o.name}' should be lower snake_case`, o.token.range);
  }

  const anchor = section(rule, 'outcome')?.header.range ?? ruleAnchor(rule);
  const firstEventVar = [...variableTables(rule).eventVars.keys()][0] ?? 'e';

  for (const name of config.requiredOutcomes) {
    if (!names.has(name)) {
      const edit = outcomeInsertEdit(ctx, `$${name} = `);
      report('YL501', `Missing required outcome variable '$${name}'`, anchor, edit && { title: `Add outcome '$${name}'`, edits: [edit] });
    }
  }
  if (conventions) {
    for (const name of conventions.standardOutcomes) {
      if (names.has(name) || config.requiredOutcomes.includes(name)) continue;
      const stat = conventions.outcomes.find((o) => o.name === name);
      const pct = stat ? Math.round(stat.ratio * 100) : 0;
      const expr = (stat?.examples[0]?.expr ?? '').replace(/\$e(?=\.)/g, `$${firstEventVar}`);
      const edit = outcomeInsertEdit(ctx, `$${name} = ${expr}`);
      report('YL502', `Outcome '$${name}' is used by ${pct}% of workspace rules but is missing here`, anchor, edit && { title: `Add outcome '$${name}'`, edits: [edit] });
    }
  }

  if (rule.outcomes.length > config.maxOutcomes) {
    report('YL503', `Rule defines ${rule.outcomes.length} outcome variables; the maximum is ${config.maxOutcomes}`, anchor);
  }

  // YL504 risk_score vs severity
  const severity = rule.meta.find((m) => m.key === 'severity')?.value;
  const risk = rule.outcomes.find((o) => o.name === 'risk_score');
  if (severity && risk) {
    const key = Object.keys(SEVERITY_RISK_SCORES).find((k) => k.toLowerCase() === severity.toLowerCase() || (k === 'Info' && /^informational$/i.test(severity)));
    const value = constantValue(risk.expr);
    if (key && value !== undefined && value !== SEVERITY_RISK_SCORES[key]) {
      report('YL504', `severity "${severity}" conventionally maps to $risk_score ${SEVERITY_RISK_SCORES[key]} (found ${value})`, risk.token.range);
    }
  }

  // YL506 hard-coded thresholds in condition
  const condition = section(rule, 'condition');
  if (condition) {
    const constants = new Set(rule.outcomes.map((o) => constantValue(o.expr)).filter((v) => v !== undefined));
    const toks = condition.tokens;
    for (let i = 0; i + 2 < toks.length; i++) {
      if (toks[i].kind === 'countVar' && toks[i + 1].kind === 'op' && /^[<>]=?$/.test(toks[i + 1].text) && toks[i + 2].kind === 'number') {
        const n = Number(toks[i + 2].text);
        if (n > 1 && !constants.has(n)) {
          report('YL506', `Consider exposing the threshold ${n} as an outcome variable (e.g. $${toks[i].text.slice(1)}_threshold = ${n})`, toks[i + 2].range);
        }
      }
    }
  }
}

function constantValue(expr: Token[]): number | undefined {
  if (expr.length === 1 && expr[0].kind === 'number') return Number(expr[0].text);
  if (expr.length === 4 && expr[0].kind === 'ident' && expr[1].text === '(' && expr[2].kind === 'number' && expr[3].text === ')') {
    return Number(expr[2].text);
  }
  return undefined;
}

// ------------------------------------------------------------------ match

function checkMatch(ctx: RuleCtx): void {
  const { rule, config, report } = ctx;
  const match = section(rule, 'match');
  if (!match || !rule.match) return;
  if (!rule.match.overToken || !rule.match.window) {
    report('YL601', "match: requires a time window, e.g. '$user over 10m'", (rule.match.overToken ?? match.header).range);
  } else {
    const secs = durationSeconds(rule.match.window.text);
    const max = durationSeconds(config.maxMatchWindow) ?? 172800;
    if (secs !== undefined && secs > max) {
      report('YL602', `Match window ${rule.match.window.text} exceeds the maximum of ${config.maxMatchWindow}`, rule.match.window.range);
    }
  }

  // YL603 redundant zero checks on match variables
  const allowZero = section(rule, 'options')?.tokens.some((t) => t.text === 'allow_zero_values');
  const events = section(rule, 'events');
  if (allowZero || !events) return;
  const matchVars = new Set(rule.match.vars.map((t) => t.text));
  const fieldToVar = placeholderFieldMap(events);
  const toks = events.tokens;
  for (let i = 0; i < toks.length; i++) {
    const { text: lhs, next } = fieldPathAt(toks, i);
    if (!lhs) continue;
    const op = toks[next];
    const rhs = toks[next + 1];
    if (op?.text === '!=' && rhs && (rhs.text === '""' || rhs.text === '0')) {
      const isMatch = matchVars.has(lhs) || (fieldToVar.has(lhs) && matchVars.has(fieldToVar.get(lhs)!));
      if (isMatch) {
        report('YL603', `'${lhs} != ${rhs.text}' is redundant: match variables already exclude zero values`, { start: toks[i].range.start, end: rhs.range.end }, {
          title: 'Remove redundant check',
          edits: [{ range: { start: { line: toks[i].range.start.line, character: 0 }, end: { line: rhs.range.end.line + 1, character: 0 } }, newText: '' }],
        });
      }
    }
    i = next - 1;
  }
}

/** Reads `$e.a.b["k"]` (or `$x`) starting at token i. */
function fieldPathAt(toks: Token[], i: number): { text?: string; next: number } {
  const t = toks[i];
  if (!t || t.kind !== 'eventVar') return { next: i + 1 };
  let text = t.text;
  let j = i + 1;
  for (;;) {
    if (toks[j]?.text === '.' && toks[j + 1]?.kind === 'ident') {
      text += '.' + toks[j + 1].text;
      j += 2;
    } else if (toks[j]?.text === '[' && toks[j + 2]?.text === ']') {
      text += `[${toks[j + 1].text}]`;
      j += 3;
    } else break;
  }
  return { text, next: j };
}

function placeholderFieldMap(events: Section): Map<string, string> {
  const map = new Map<string, string>();
  const toks = events.tokens;
  for (let i = 0; i < toks.length; i++) {
    const a = fieldPathAt(toks, i);
    if (!a.text || toks[a.next]?.text !== '=') continue;
    const b = fieldPathAt(toks, a.next + 1);
    if (!b.text) continue;
    const aIsVar = !a.text.includes('.');
    const bIsVar = !b.text.includes('.');
    if (aIsVar && !bIsVar) map.set(b.text, a.text);
    if (bIsVar && !aIsVar) map.set(a.text, b.text);
  }
  return map;
}

// ------------------------------------------------------------------ options

function checkOptions({ rule, report }: RuleCtx): void {
  const options = section(rule, 'options');
  if (!options) return;
  const toks = options.tokens;
  for (let i = 0; i < toks.length; i++) {
    if (toks[i].kind === 'ident' && toks[i + 1]?.text === '=' && !KNOWN_OPTIONS.includes(toks[i].text)) {
      report('YL801', `Unknown option '${toks[i].text}'`, toks[i].range);
    }
  }
}

// ------------------------------------------------------------------ whitespace

function checkWhitespace(doc: ParsedDocument, report: RuleCtx['report']): void {
  for (let line = 0; line < doc.index.lineCount; line++) {
    const text = doc.index.lineText(line);
    const tab = text.indexOf('\t');
    if (tab !== -1) {
      const leading = text.match(/^[ \t]*/)![0];
      report('YL701', 'Tab character', { start: { line, character: tab }, end: { line, character: tab + 1 } },
        leading.includes('\t')
          ? { title: 'Replace leading tabs with spaces', edits: [{ range: { start: { line, character: 0 }, end: { line, character: leading.length } }, newText: leading.replace(/\t/g, '  ') }] }
          : undefined);
    }
    const trailing = text.match(/[ \t]+$/);
    if (trailing && trailing.index !== undefined && trailing.index > 0) {
      const range = { start: { line, character: trailing.index }, end: { line, character: text.length } };
      report('YL702', 'Trailing whitespace', range, { title: 'Remove trailing whitespace', edits: [{ range, newText: '' }] });
    }
  }
}

// ------------------------------------------------------------------ suppressions

const SUPPRESS = /yaral-lint-disable(-next-line|-line)?\b([^\n*]*)/;

/**
 * Honors inline suppression comments:
 *   // yaral-lint-disable-next-line YL205, unused-placeholder
 *   // yaral-lint-disable-line YL506
 *   // yaral-lint-disable YL208          (whole file)
 * Without rule ids, every rule is suppressed for that scope.
 */
function applySuppressions(doc: ParsedDocument, diagnostics: LintDiagnostic[]): LintDiagnostic[] {
  type Scope = { line?: number; rules?: Set<string> };
  const scopes: Scope[] = [];
  for (const c of doc.comments) {
    const m = SUPPRESS.exec(c.text);
    if (!m) continue;
    const ids = m[2].split(/[\s,]+/).filter((x) => /^[A-Za-z][\w-]*$/.test(x) && x !== '--');
    const rules = ids.length ? new Set(ids) : undefined;
    if (m[1] === '-next-line') scopes.push({ line: c.range.end.line + 1, rules });
    else if (m[1] === '-line') scopes.push({ line: c.range.start.line, rules });
    else scopes.push({ rules });
  }
  if (!scopes.length) return diagnostics;
  return diagnostics.filter(
    (d) =>
      !scopes.some(
        (s) => (s.line === undefined || s.line === d.range.start.line) && (!s.rules || s.rules.has(d.ruleId) || s.rules.has(d.ruleName)),
      ),
  );
}

// ------------------------------------------------------------------ helpers

export function levenshtein(a: string, b: string): number {
  const dp = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let prev = dp[0];
    dp[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = dp[j];
      dp[j] = Math.min(dp[j] + 1, dp[j - 1] + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = tmp;
    }
  }
  return dp[b.length];
}

export function closest(word: string, candidates: string[], maxDistance: number): string | undefined {
  let best: string | undefined;
  let bestD = Infinity;
  for (const c of candidates) {
    if (c === word) continue;
    const d = levenshtein(word.toLowerCase(), c.toLowerCase());
    if (d < bestD && d <= maxDistance) {
      best = c;
      bestD = d;
    }
  }
  return best;
}

/** Applies non-overlapping fixes to text (used by `yaral-lint --fix`). */
export function applyFixes(text: string, diagnostics: LintDiagnostic[], onlyRules?: Set<string>): { text: string; applied: number } {
  const index = new LineIndex(text);
  const edits: { start: number; end: number; newText: string }[] = [];
  for (const d of diagnostics) {
    if (!d.fix || (onlyRules && !onlyRules.has(d.ruleId))) continue;
    const e = d.fix.edits.map((x) => ({ start: index.offsetAt(x.range.start), end: index.offsetAt(x.range.end), newText: x.newText }));
    // Skip fixes that overlap an already-accepted edit.
    if (e.some((x) => edits.some((y) => (x.start < y.end && y.start < x.end) || x.start === y.start))) continue;
    edits.push(...e);
  }
  edits.sort((a, b) => b.start - a.start);
  let out = text;
  for (const e of edits) out = out.slice(0, e.start) + e.newText + out.slice(e.end);
  return { text: out, applied: edits.length };
}
