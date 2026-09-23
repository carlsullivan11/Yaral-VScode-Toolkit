/**
 * Whitespace-only formatter for YARA-L rules.
 *
 * - `rule name {` and `}` at column 0, section headers indented one level,
 *   section bodies two levels, plus one level per open bracket.
 * - Trailing whitespace removed, leading tabs converted, blank lines collapsed.
 * - Lines inside multi-line strings or block comments are left untouched.
 * - Text outside rules (license headers, etc.) is only trimmed.
 *
 * The formatter never changes non-whitespace characters.
 */

import { tokenize, LineIndex, Token } from './lexer';

export interface FormatOptions {
  indent?: string;
}

const SECTION_HEADER = /^(meta|events|match|outcome|condition|options)\s*:/;

export function format(text: string, options: FormatOptions = {}): string {
  const unit = options.indent ?? '  ';
  const eol = text.includes('\r\n') ? '\r\n' : '\n';
  const index = new LineIndex(text);
  const { tokens, comments } = tokenize(text, index);

  // Lines whose start lies inside a multi-line token must not be touched.
  const frozen = new Set<number>();
  for (const t of [...tokens, ...comments]) {
    if (t.range.end.line > t.range.start.line) {
      for (let l = t.range.start.line + 1; l <= t.range.end.line; l++) frozen.add(l);
    }
  }

  // Bracket depth (and rule-brace depth) at the start of every line.
  const lineTokens = new Map<number, Token[]>();
  for (const t of tokens) {
    const arr = lineTokens.get(t.range.start.line) ?? [];
    arr.push(t);
    lineTokens.set(t.range.start.line, arr);
  }

  const out: string[] = [];
  let braceDepth = 0; // rule braces
  let parenDepth = 0; // ( and [ inside a rule
  let inSection = false;
  let blankRun = 0;

  for (let line = 0; line < index.lineCount; line++) {
    const raw = index.lineText(line);
    const toks = lineTokens.get(line) ?? [];

    if (frozen.has(line)) {
      out.push(raw);
      blankRun = 0;
      updateDepths(toks);
      continue;
    }

    const trimmed = raw.trim();
    if (trimmed === '') {
      blankRun++;
      if (blankRun <= 1) out.push('');
      continue;
    }
    blankRun = 0;

    let level: number;
    if (braceDepth === 0) {
      level = 0;
      inSection = false;
    } else if (SECTION_HEADER.test(trimmed) && parenDepth === 0) {
      level = braceDepth;
      inSection = true;
    } else if (trimmed.startsWith('}') && parenDepth === 0) {
      level = braceDepth - 1;
    } else {
      const closesFirst = /^[)\]]/.test(trimmed) ? 1 : 0;
      level = braceDepth + (inSection ? 1 : 0) + Math.max(0, parenDepth - closesFirst);
    }

    const content = raw.replace(/^[ \t]+/, '').replace(/[ \t]+$/, '');
    out.push(braceDepth === 0 && !trimmed.startsWith('rule') ? raw.replace(/[ \t]+$/, '') : unit.repeat(Math.max(0, level)) + content);
    updateDepths(toks);
  }

  function updateDepths(toks: Token[]) {
    for (const t of toks) {
      if (t.kind !== 'punct') continue;
      if (t.text === '{') {
        if (parenDepth === 0) braceDepth++;
        else parenDepth++;
      } else if (t.text === '}') {
        if (parenDepth === 0) {
          braceDepth = Math.max(0, braceDepth - 1);
          if (braceDepth === 0) inSection = false;
        } else parenDepth--;
      } else if (t.text === '(' || t.text === '[') parenDepth++;
      else if (t.text === ')' || t.text === ']') parenDepth = Math.max(0, parenDepth - 1);
    }
  }

  // Trim leading/trailing blank lines and ensure a single final newline.
  while (out.length && out[out.length - 1] === '') out.pop();
  while (out.length && out[0] === '') out.shift();
  return out.join(eol) + eol;
}
