/**
 * Structural parser for YARA-L 2.0 rules.
 *
 * This is deliberately a tolerant, section-oriented parser rather than a full
 * expression grammar: it recovers from errors, and extracts what the editor
 * and linter need (sections, meta entries, variables, function calls,
 * outcome assignments and the match clause). Google SecOps remains the
 * authoritative compiler; use the SecOps `verifyRuleText` API for that.
 */

import { LexError, LineIndex, Range, Token, tokenize } from './lexer';

export const SECTION_ORDER = ['meta', 'events', 'match', 'outcome', 'condition', 'options'] as const;
export type SectionKind = (typeof SECTION_ORDER)[number];
const SECTION_SET = new Set<string>(SECTION_ORDER);

/** Words that may precede `(` without being a function call. */
const NON_FUNCTION_WORDS = new Set(['and', 'or', 'not', 'in', 'over', 'nocase', 'any', 'all', 'regex', 'cidr', 'by', 'before', 'after', 'every']);

export interface Section {
  kind: SectionKind;
  header: Token;
  /** Tokens inside the section, excluding the header and colon. */
  tokens: Token[];
  range: Range;
  start: number;
  end: number;
}

export interface MetaEntry {
  key: string;
  keyToken: Token;
  /** Value with surrounding quotes removed. */
  value: string;
  valueToken?: Token;
}

export type VarSigil = '$' | '#' | '%';

export interface VarRef {
  /** Name without sigil. */
  name: string;
  sigil: VarSigil;
  token: Token;
  section: SectionKind;
  /** `$e.field` style reference: `$e` is an event/entity variable. */
  isFieldAccess: boolean;
  /** Left-hand side of an outcome assignment (`$risk_score = ...`). */
  isOutcomeDefinition: boolean;
}

export interface FunctionCall {
  name: string;
  nameTokens: Token[];
  range: Range;
  /** Tokens for each argument, split on top-level commas. */
  args: Token[][];
  section: SectionKind;
  openParen: Token;
  closeParen?: Token;
}

export interface OutcomeAssignment {
  name: string;
  token: Token;
  expr: Token[];
  range: Range;
}

export interface MatchClause {
  vars: Token[];
  overToken?: Token;
  window?: Token;
}

export interface Rule {
  name: string;
  ruleKeyword: Token;
  nameToken?: Token;
  openBrace?: Token;
  closeBrace?: Token;
  range: Range;
  start: number;
  end: number;
  sections: Section[];
  meta: MetaEntry[];
  varRefs: VarRef[];
  calls: FunctionCall[];
  outcomes: OutcomeAssignment[];
  match?: MatchClause;
}

export interface ParseError {
  message: string;
  range: Range;
}

export interface ParsedDocument {
  text: string;
  index: LineIndex;
  tokens: Token[];
  comments: Token[];
  rules: Rule[];
  errors: ParseError[];
}

export function section(rule: Rule, kind: SectionKind): Section | undefined {
  return rule.sections.find((s) => s.kind === kind);
}

export function parse(text: string): ParsedDocument {
  const index = new LineIndex(text);
  const lex = tokenize(text, index);
  const errors: ParseError[] = lex.errors.map((e: LexError) => ({ ...e }));
  const tokens = lex.tokens;

  checkBrackets(tokens, errors);

  const rules: Rule[] = [];
  let i = 0;
  while (i < tokens.length) {
    const t = tokens[i];
    if (t.kind === 'ident' && t.text === 'rule') {
      const { rule, next } = parseRule(tokens, i, index, errors);
      rules.push(rule);
      i = next;
      continue;
    }
    errors.push({ message: `Unexpected '${t.text}' outside of a rule`, range: t.range });
    // Skip to the next `rule` keyword to avoid cascading errors.
    i++;
    while (i < tokens.length && !(tokens[i].kind === 'ident' && tokens[i].text === 'rule')) i++;
  }

  return { text, index, tokens, comments: lex.comments, rules, errors };
}

function checkBrackets(tokens: Token[], errors: ParseError[]): void {
  const pairs: Record<string, string> = { ')': '(', ']': '[', '}': '{' };
  const stack: Token[] = [];
  for (const t of tokens) {
    if (t.kind !== 'punct') continue;
    if (t.text === '(' || t.text === '[' || t.text === '{') {
      stack.push(t);
    } else if (t.text in pairs) {
      const top = stack[stack.length - 1];
      if (top && top.text === pairs[t.text]) {
        stack.pop();
      } else {
        errors.push({ message: `Unmatched '${t.text}'`, range: t.range });
      }
    }
  }
  for (const t of stack) {
    errors.push({ message: `Unclosed '${t.text}'`, range: t.range });
  }
}

function parseRule(tokens: Token[], start: number, index: LineIndex, errors: ParseError[]): { rule: Rule; next: number } {
  const ruleKeyword = tokens[start];
  let i = start + 1;
  let nameToken: Token | undefined;
  if (tokens[i]?.kind === 'ident') {
    nameToken = tokens[i];
    i++;
  } else {
    errors.push({ message: 'Expected a rule name after `rule`', range: ruleKeyword.range });
  }

  let openBrace: Token | undefined;
  if (tokens[i]?.text === '{') {
    openBrace = tokens[i];
    i++;
  } else {
    errors.push({ message: "Expected '{' after rule name", range: (nameToken ?? ruleKeyword).range });
  }

  // Find the matching close brace.
  const bodyStart = i;
  let depth = 1;
  let closeBrace: Token | undefined;
  while (i < tokens.length) {
    const t = tokens[i];
    if (t.kind === 'punct') {
      if (t.text === '{') depth++;
      else if (t.text === '}') {
        depth--;
        if (depth === 0) {
          closeBrace = t;
          break;
        }
      }
    }
    // A new top-level `rule` keyword means this rule was never closed.
    if (t.kind === 'ident' && t.text === 'rule' && tokens[i + 1]?.kind === 'ident' && tokens[i + 2]?.text === '{' && depth === 1) {
      break;
    }
    i++;
  }
  const bodyEnd = i;
  const body = tokens.slice(bodyStart, bodyEnd);
  if (!closeBrace && openBrace) {
    errors.push({ message: `Rule '${nameToken?.text ?? ''}' is missing its closing '}'`, range: openBrace.range });
  }

  const last = closeBrace ?? body[body.length - 1] ?? nameToken ?? ruleKeyword;
  const rule: Rule = {
    name: nameToken?.text ?? '',
    ruleKeyword,
    nameToken,
    openBrace,
    closeBrace,
    range: index.range(ruleKeyword.start, last.end),
    start: ruleKeyword.start,
    end: last.end,
    sections: splitSections(body, index, errors),
    meta: [],
    varRefs: [],
    calls: [],
    outcomes: [],
  };

  for (const s of rule.sections) {
    if (s.kind === 'meta') rule.meta.push(...parseMeta(s, errors));
    rule.varRefs.push(...collectVarRefs(s));
    rule.calls.push(...collectCalls(s, index));
    if (s.kind === 'outcome') rule.outcomes.push(...parseOutcomes(s, index));
    if (s.kind === 'match') rule.match = parseMatch(s);
  }

  return { rule, next: closeBrace ? bodyEnd + 1 : bodyEnd };
}

function splitSections(body: Token[], index: LineIndex, errors: ParseError[]): Section[] {
  const sections: Section[] = [];
  let depth = 0;
  let current: Section | undefined;
  for (let i = 0; i < body.length; i++) {
    const t = body[i];
    const next = body[i + 1];
    if (depth === 0 && t.kind === 'ident' && SECTION_SET.has(t.text) && next?.text === ':') {
      if (current) finishSection(current, index);
      current = { kind: t.text as SectionKind, header: t, tokens: [], range: t.range, start: t.start, end: next.end };
      sections.push(current);
      i++; // skip ':'
      continue;
    }
    if (t.kind === 'punct') {
      if (t.text === '(' || t.text === '[' || t.text === '{') depth++;
      else if (t.text === ')' || t.text === ']' || t.text === '}') depth = Math.max(0, depth - 1);
    }
    if (!current) {
      errors.push({ message: `Unexpected '${t.text}' before the first section (expected meta:, events:, ...)`, range: t.range });
      continue;
    }
    current.tokens.push(t);
  }
  if (current) finishSection(current, index);
  return sections;
}

function finishSection(s: Section, index: LineIndex): void {
  const last = s.tokens[s.tokens.length - 1];
  s.end = last ? last.end : s.header.end + 1;
  s.range = index.range(s.start, s.end);
}

function unquote(text: string): string {
  if (text.length >= 2 && (text[0] === '"' || text[0] === '`')) {
    return text.slice(1, text[text.length - 1] === text[0] ? -1 : undefined).replace(/\\(.)/g, '$1');
  }
  return text;
}

function parseMeta(s: Section, errors: ParseError[]): MetaEntry[] {
  const entries: MetaEntry[] = [];
  const toks = s.tokens;
  let i = 0;
  while (i < toks.length) {
    const key = toks[i];
    if (key.kind !== 'ident') {
      errors.push({ message: `Expected a meta key, found '${key.text}'`, range: key.range });
      i++;
      continue;
    }
    if (toks[i + 1]?.text !== '=') {
      errors.push({ message: `Expected '=' after meta key '${key.text}'`, range: key.range });
      i++;
      continue;
    }
    const value = toks[i + 2];
    if (!value || value.range.start.line !== key.range.start.line) {
      errors.push({ message: `Missing value for meta key '${key.text}'`, range: key.range });
      entries.push({ key: key.text, keyToken: key, value: '' });
      i += 2;
      continue;
    }
    entries.push({ key: key.text, keyToken: key, value: unquote(value.text), valueToken: value });
    i += 3;
  }
  return entries;
}

function collectVarRefs(s: Section): VarRef[] {
  const refs: VarRef[] = [];
  const toks = s.tokens;
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t.kind !== 'eventVar' && t.kind !== 'countVar' && t.kind !== 'listRef') continue;
    const sigil = t.text[0] as VarSigil;
    const next = toks[i + 1];
    const prev = toks[i - 1];
    const isFieldAccess = sigil === '$' && next?.text === '.' && next.start === t.end;
    const startsStatement = !prev || prev.range.end.line < t.range.start.line;
    const isOutcomeDefinition = s.kind === 'outcome' && sigil === '$' && startsStatement && next?.text === '=';
    refs.push({ name: t.text.slice(1), sigil, token: t, section: s.kind, isFieldAccess, isOutcomeDefinition });
  }
  return refs;
}

function collectCalls(s: Section, index: LineIndex): FunctionCall[] {
  const calls: FunctionCall[] = [];
  const toks = s.tokens;
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t.text !== '(' || t.kind !== 'punct') continue;
    const prev = toks[i - 1];
    if (!prev || prev.kind !== 'ident') continue;
    // `not (`, `and (` ... are grouping, but `re.regex(` is a call.
    if (NON_FUNCTION_WORDS.has(prev.text.toLowerCase()) && toks[i - 2]?.text !== '.') continue;

    // Walk back over `ident . ident . ident`.
    const nameTokens: Token[] = [prev];
    let j = i - 2;
    while (j >= 1 && toks[j].text === '.' && toks[j - 1].kind === 'ident' && toks[j].start === toks[j - 1].end) {
      nameTokens.unshift(toks[j - 1]);
      j -= 2;
    }
    // `$e.foo(` is not a function call we can reason about.
    if (j >= 0 && toks[j].text === '.' && toks[j - 1]?.kind === 'eventVar') continue;

    const args: Token[][] = [];
    let current: Token[] = [];
    let depth = 0;
    let k = i + 1;
    let closeParen: Token | undefined;
    for (; k < toks.length; k++) {
      const a = toks[k];
      if (a.kind === 'punct' && (a.text === '(' || a.text === '[')) depth++;
      if (a.kind === 'punct' && (a.text === ')' || a.text === ']')) {
        if (depth === 0) {
          closeParen = a;
          break;
        }
        depth--;
      }
      if (depth === 0 && a.text === ',' && a.kind === 'punct') {
        args.push(current);
        current = [];
        continue;
      }
      current.push(a);
    }
    if (current.length > 0 || args.length > 0) args.push(current);

    calls.push({
      name: nameTokens.map((n) => n.text).join('.'),
      nameTokens,
      range: index.range(nameTokens[0].start, (closeParen ?? t).end),
      args,
      section: s.kind,
      openParen: t,
      closeParen,
    });
  }
  return calls;
}

function parseOutcomes(s: Section, index: LineIndex): OutcomeAssignment[] {
  const out: OutcomeAssignment[] = [];
  const toks = s.tokens;
  let current: OutcomeAssignment | undefined;
  let depth = 0;
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    const prev = toks[i - 1];
    const startsStatement = !prev || (prev.range.end.line < t.range.start.line && depth === 0);
    if (startsStatement && t.kind === 'eventVar' && toks[i + 1]?.text === '=') {
      current = { name: t.text.slice(1), token: t, expr: [], range: t.range };
      out.push(current);
      i++; // skip '='
      continue;
    }
    if (t.kind === 'punct') {
      if (t.text === '(' || t.text === '[') depth++;
      else if (t.text === ')' || t.text === ']') depth = Math.max(0, depth - 1);
    }
    if (current) {
      current.expr.push(t);
      current.range = index.range(current.token.start, t.end);
    }
  }
  return out;
}

function parseMatch(s: Section): MatchClause {
  const vars: Token[] = [];
  let overToken: Token | undefined;
  let window: Token | undefined;
  for (let i = 0; i < s.tokens.length; i++) {
    const t = s.tokens[i];
    if (t.kind === 'ident' && t.text === 'over') {
      overToken = t;
      window = s.tokens.slice(i + 1).find((x) => x.kind === 'duration');
      break;
    }
    if (t.kind === 'eventVar') vars.push(t);
  }
  return { vars, overToken, window };
}

/** Converts a duration token such as `10m` to seconds. */
export function durationSeconds(text: string): number | undefined {
  const m = /^(\d+)([smhd])$/.exec(text);
  if (!m) return undefined;
  const mult = { s: 1, m: 60, h: 3600, d: 86400 }[m[2] as 's' | 'm' | 'h' | 'd'];
  return Number(m[1]) * mult;
}
