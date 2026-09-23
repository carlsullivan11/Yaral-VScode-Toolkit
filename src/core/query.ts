/** Position-based queries used by editor features (hover, completion, rename...). */

import { Position, Token } from './lexer';
import { ParsedDocument, Rule, Section } from './parser';

export function ruleAt(doc: ParsedDocument, offset: number): Rule | undefined {
  return doc.rules.find((r) => offset >= r.start && offset <= (r.closeBrace ? r.closeBrace.end : doc.text.length));
}

export function sectionAt(rule: Rule, offset: number): Section | undefined {
  let found: Section | undefined;
  for (const s of rule.sections) if (s.header.start <= offset) found = s;
  return found;
}

export function tokenAt(doc: ParsedDocument, offset: number): Token | undefined {
  // Prefer the token that contains the offset; fall back to the one ending at it.
  let before: Token | undefined;
  for (const t of doc.tokens) {
    if (t.start <= offset && offset < t.end) return t;
    if (t.end === offset) before = t;
    if (t.start > offset) break;
  }
  return before;
}

export function commentAt(doc: ParsedDocument, offset: number): Token | undefined {
  return doc.comments.find((c) => c.start <= offset && offset <= c.end);
}

/** Returns the dotted name (`strings.to_lower`, `$e.principal.ip`) the token belongs to. */
export function dottedNameAt(doc: ParsedDocument, offset: number): { text: string; start: number; end: number; tokenIndex: number } | undefined {
  const idx = doc.tokens.findIndex((t) => t.start <= offset && offset <= t.end && (t.kind === 'ident' || t.kind === 'eventVar'));
  if (idx === -1) return undefined;
  const toks = doc.tokens;
  let s = idx;
  while (s >= 2 && toks[s - 1].text === '.' && toks[s - 1].start === toks[s - 2].end && (toks[s - 2].kind === 'ident' || toks[s - 2].kind === 'eventVar')) s -= 2;
  let e = idx;
  while (e + 2 < toks.length && toks[e + 1].text === '.' && toks[e + 1].start === toks[e].end && toks[e + 2].kind === 'ident' && toks[e + 2].start === toks[e + 1].end) e += 2;
  return { text: doc.text.slice(toks[s].start, toks[e].end), start: toks[s].start, end: toks[e].end, tokenIndex: idx };
}

/** Innermost unclosed call around the offset, for signature help. */
export function callContextAt(doc: ParsedDocument, offset: number): { name: string; argIndex: number } | undefined {
  const stack: { name?: string; commas: number }[] = [];
  const toks = doc.tokens;
  for (let i = 0; i < toks.length && toks[i].start < offset; i++) {
    const t = toks[i];
    if (t.kind !== 'punct') continue;
    if (t.text === '(') {
      let name: string | undefined;
      if (toks[i - 1]?.kind === 'ident') {
        const parts = [toks[i - 1].text];
        let j = i - 2;
        while (j >= 1 && toks[j].text === '.' && toks[j - 1].kind === 'ident') {
          parts.unshift(toks[j - 1].text);
          j -= 2;
        }
        name = parts.join('.');
      }
      stack.push({ name, commas: 0 });
    } else if (t.text === '[') stack.push({ commas: 0 });
    else if (t.text === ')' || t.text === ']') stack.pop();
    else if (t.text === ',' && stack.length) stack[stack.length - 1].commas++;
    else if (t.text === '}' || t.text === '{') stack.length = 0;
  }
  const top = stack[stack.length - 1];
  return top?.name ? { name: top.name, argIndex: top.commas } : undefined;
}

export function positionLess(a: Position, b: Position): boolean {
  return a.line < b.line || (a.line === b.line && a.character < b.character);
}
