import { strict as assert } from 'assert';
import { test } from 'node:test';
import { tokenize } from '../src/core/lexer';

const kinds = (text: string) => tokenize(text).tokens.map((t) => `${t.kind}:${t.text}`);

test('tokenizes variables, lists, counts and field paths', () => {
  assert.deepEqual(kinds('$e.principal.ip in %list and #e > 5'), [
    'eventVar:$e', 'punct:.', 'ident:principal', 'punct:.', 'ident:ip', 'ident:in', 'listRef:%list', 'ident:and', 'countVar:#e', 'op:>', 'number:5',
  ]);
});

test('distinguishes regex literals from division', () => {
  assert.deepEqual(kinds('$e.x = /a\\/b/ nocase'), ['eventVar:$e', 'punct:.', 'ident:x', 'op:=', 'regex:/a\\/b/', 'ident:nocase']);
  assert.deepEqual(kinds('max($a / 2)'), ['ident:max', 'punct:(', 'eventVar:$a', 'op:/', 'number:2', 'punct:)']);
  assert.ok(kinds('NOT /x/').includes('regex:/x/'), 'uppercase keywords precede regexes');
});

test('recognizes durations, strings, raw strings and comments', () => {
  const r = tokenize('over 10m // c\n "a\\"b" `raw\\s` /* block */');
  assert.deepEqual(r.tokens.map((t) => t.kind), ['ident', 'duration', 'string', 'string']);
  assert.equal(r.comments.length, 2);
  assert.equal(r.errors.length, 0);
});

test('reports unterminated constructs without throwing', () => {
  assert.equal(tokenize('"abc').errors[0].message, 'Unterminated string literal');
  assert.equal(tokenize('/* abc').errors[0].message, 'Unterminated block comment');
  assert.equal(tokenize('$e.x = /abc').errors[0].message, 'Unterminated regular expression');
});

test('computes line/character ranges', () => {
  const t = tokenize('rule x {\n  events:\n').tokens.find((x) => x.text === 'events')!;
  assert.deepEqual(t.range.start, { line: 1, character: 2 });
});
