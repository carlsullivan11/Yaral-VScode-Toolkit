/**
 * Tokenizer for YARA-L 2.0.
 *
 * The lexer never throws: malformed input (unterminated strings, comments or
 * regexes, stray characters) produces tokens plus entries in `errors`, so the
 * editor can keep offering features on half-written rules.
 */

export type TokenKind =
  | 'ident'
  | 'eventVar' // $name
  | 'countVar' // #name
  | 'listRef' // %name
  | 'string' // "..." or `...`
  | 'regex' // /.../
  | 'number'
  | 'duration' // 5m, 1h, 30s, 2d
  | 'punct'
  | 'op'
  | 'comment';

export interface Position {
  line: number; // 0-based
  character: number; // 0-based
}

export interface Range {
  start: Position;
  end: Position;
}

export interface Token {
  kind: TokenKind;
  text: string;
  /** Offset of first character. */
  start: number;
  /** Offset one past the last character. */
  end: number;
  range: Range;
}

export interface LexError {
  message: string;
  range: Range;
}

export interface LexResult {
  tokens: Token[]; // excludes comments
  comments: Token[];
  errors: LexError[];
}

const OPERATORS = ['!=', '<=', '>=', '=', '<', '>', '+', '-', '*', '/', '!'];
const PUNCT = new Set(['{', '}', '(', ')', '[', ']', ',', ':', '.']);
const REGEX_PRECEDERS_OPS = new Set(['=', '!=', '(', ',', '[']);
const REGEX_PRECEDERS_KW = new Set(['and', 'or', 'not', 'regex', 'in']);

/** Maps between offsets and line/character positions. */
export class LineIndex {
  private readonly lineStarts: number[] = [0];

  constructor(readonly text: string) {
    for (let i = 0; i < text.length; i++) {
      if (text.charCodeAt(i) === 10) this.lineStarts.push(i + 1);
    }
  }

  positionAt(offset: number): Position {
    let lo = 0;
    let hi = this.lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (this.lineStarts[mid] <= offset) lo = mid;
      else hi = mid - 1;
    }
    return { line: lo, character: offset - this.lineStarts[lo] };
  }

  offsetAt(pos: Position): number {
    const start = this.lineStarts[Math.min(pos.line, this.lineStarts.length - 1)] ?? 0;
    return Math.min(start + pos.character, this.text.length);
  }

  range(start: number, end: number): Range {
    return { start: this.positionAt(start), end: this.positionAt(end) };
  }

  get lineCount(): number {
    return this.lineStarts.length;
  }

  lineText(line: number): string {
    const start = this.lineStarts[line];
    const next = this.lineStarts[line + 1];
    const end = next === undefined ? this.text.length : next - 1;
    return this.text.slice(start, end).replace(/\r$/, '');
  }
}

function isIdentStart(c: string): boolean {
  return /[A-Za-z_]/.test(c);
}

function isIdentPart(c: string): boolean {
  return /[A-Za-z0-9_]/.test(c);
}

export function tokenize(text: string, index = new LineIndex(text)): LexResult {
  const tokens: Token[] = [];
  const comments: Token[] = [];
  const errors: LexError[] = [];
  let i = 0;
  const n = text.length;

  const push = (kind: TokenKind, start: number, end: number, into = tokens) => {
    into.push({ kind, text: text.slice(start, end), start, end, range: index.range(start, end) });
  };

  const regexAllowed = (): boolean => {
    const prev = tokens[tokens.length - 1];
    if (!prev) return false;
    if ((prev.kind === 'op' || prev.kind === 'punct') && REGEX_PRECEDERS_OPS.has(prev.text)) return true;
    if (prev.kind === 'ident' && REGEX_PRECEDERS_KW.has(prev.text.toLowerCase())) return true;
    return false;
  };

  while (i < n) {
    const c = text[i];

    if (c === ' ' || c === '\t' || c === '\r' || c === '\n') {
      i++;
      continue;
    }

    // Comments
    if (c === '/' && text[i + 1] === '/') {
      const start = i;
      while (i < n && text[i] !== '\n') i++;
      push('comment', start, i, comments);
      continue;
    }
    if (c === '/' && text[i + 1] === '*') {
      const start = i;
      const close = text.indexOf('*/', i + 2);
      if (close === -1) {
        i = n;
        errors.push({ message: 'Unterminated block comment', range: index.range(start, start + 2) });
      } else {
        i = close + 2;
      }
      push('comment', start, i, comments);
      continue;
    }

    // Strings
    if (c === '"' || c === '`') {
      const start = i;
      const quote = c;
      i++;
      let closed = false;
      while (i < n) {
        const ch = text[i];
        if (quote === '"' && ch === '\\') {
          i += 2;
          continue;
        }
        if (ch === quote) {
          i++;
          closed = true;
          break;
        }
        if (ch === '\n' && quote === '"') break;
        i++;
      }
      if (!closed) {
        errors.push({ message: 'Unterminated string literal', range: index.range(start, i) });
      }
      push('string', start, i);
      continue;
    }

    // Regex literal
    if (c === '/' && regexAllowed()) {
      const start = i;
      i++;
      let closed = false;
      while (i < n) {
        const ch = text[i];
        if (ch === '\\') {
          i += 2;
          continue;
        }
        if (ch === '/') {
          i++;
          closed = true;
          break;
        }
        if (ch === '\n') break;
        i++;
      }
      if (!closed) {
        errors.push({ message: 'Unterminated regular expression', range: index.range(start, i) });
      }
      push('regex', start, i);
      continue;
    }

    // Variables
    if ((c === '$' || c === '#' || c === '%') && i + 1 < n && isIdentStart(text[i + 1])) {
      const start = i;
      i++;
      while (i < n && isIdentPart(text[i])) i++;
      push(c === '$' ? 'eventVar' : c === '#' ? 'countVar' : 'listRef', start, i);
      continue;
    }

    // Numbers & durations
    if (/[0-9]/.test(c)) {
      const start = i;
      while (i < n && /[0-9]/.test(text[i])) i++;
      if (text[i] === '.' && /[0-9]/.test(text[i + 1] ?? '')) {
        i++;
        while (i < n && /[0-9]/.test(text[i])) i++;
      }
      if (/[smhd]/.test(text[i] ?? '') && !isIdentPart(text[i + 1] ?? '')) {
        i++;
        push('duration', start, i);
      } else {
        push('number', start, i);
      }
      continue;
    }

    if (isIdentStart(c)) {
      const start = i;
      while (i < n && isIdentPart(text[i])) i++;
      push('ident', start, i);
      continue;
    }

    const op = OPERATORS.find((o) => text.startsWith(o, i));
    if (op) {
      push('op', i, i + op.length);
      i += op.length;
      continue;
    }

    if (PUNCT.has(c)) {
      push('punct', i, i + 1);
      i++;
      continue;
    }

    errors.push({ message: `Unexpected character '${c}'`, range: index.range(i, i + 1) });
    i++;
  }

  return { tokens, comments, errors };
}
