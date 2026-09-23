import { strict as assert } from 'assert';
import { test } from 'node:test';
import { parse } from '../src/core/parser';
import { callContextAt, dottedNameAt, ruleAt, sectionAt } from '../src/core/query';
import { arity, BUILTIN_FUNCTIONS, buildFunctionIndex } from '../src/core/catalog/functions';

const text = 'rule r {\n  events:\n    strings.concat($e.principal.ip, re.capture($e.x, "a"), \n  condition:\n    $e\n}';

test('call context for signature help', () => {
  const doc = parse(text);
  const at = (needle: string, delta = 0) => text.indexOf(needle) + delta;
  assert.deepEqual(callContextAt(doc, at('$e.principal')), { name: 'strings.concat', argIndex: 0 });
  assert.deepEqual(callContextAt(doc, at('"a"')), { name: 're.capture', argIndex: 1 });
  assert.deepEqual(callContextAt(doc, at('"a"', 5)), { name: 'strings.concat', argIndex: 2 });
});

test('dotted names and section lookup', () => {
  const doc = parse(text);
  const off = text.indexOf('principal');
  assert.equal(dottedNameAt(doc, off)?.text, '$e.principal.ip');
  assert.equal(dottedNameAt(doc, text.indexOf('concat'))?.text, 'strings.concat');
  const rule = ruleAt(doc, off)!;
  assert.equal(sectionAt(rule, off)?.kind, 'events');
});

test('function catalog is well formed', () => {
  const names = new Set<string>();
  for (const f of BUILTIN_FUNCTIONS) {
    assert.ok(!names.has(f.name), `duplicate ${f.name}`);
    names.add(f.name);
    assert.ok(f.description.length > 10, f.name);
    const { min, max } = arity(f);
    assert.ok(min <= max, f.name);
  }
  const idx = buildFunctionIndex([{ name: 'custom.fn', params: [], returns: 'int', description: 'Custom function.' }]);
  assert.ok(idx.get('custom.fn'));
  assert.ok(idx.namespaces().includes('strings'));
});

test('every lint rule is documented', () => {
  const { LINT_RULES } = require('../src/core/linter/rules') as typeof import('../src/core/linter/rules');
  const docs = require('fs').readFileSync(require('path').join(__dirname, '..', '..', 'docs', 'lint-rules.md'), 'utf8') as string;
  for (const r of LINT_RULES) assert.ok(docs.includes(`| \`${r.name}\` |`), `${r.id} missing from docs/lint-rules.md`);
});
