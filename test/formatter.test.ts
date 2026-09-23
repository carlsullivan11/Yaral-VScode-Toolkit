import { strict as assert } from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { test } from 'node:test';
import { format } from '../src/core/formatter';
import { EXAMPLES } from './helpers';

test('formats indentation, whitespace and blank lines', () => {
  const input = 'rule  x {\n meta:\n author = "a"   \n\n\n\tevents:\n $e.x = 1 and (\n$e.y = 2 or\n  $e.z = 3\n)\ncondition:\n$e\n  }';
  const expected = 'rule  x {\n  meta:\n    author = "a"\n\n  events:\n    $e.x = 1 and (\n      $e.y = 2 or\n      $e.z = 3\n    )\n  condition:\n    $e\n}\n';
  assert.equal(format(input), expected);
});

test('is idempotent and only changes whitespace', () => {
  for (const f of fs.readdirSync(EXAMPLES)) {
    const text = fs.readFileSync(path.join(EXAMPLES, f), 'utf8');
    const once = format(text);
    assert.equal(once, text, `${f} should already be formatted`);
    assert.equal(format(once), once);
  }
  const messy = 'rule a {\nevents:\n        $e.x = `multi\n   line   \n raw`\n  /* keep\n      this */\ncondition:\n $e }';
  const out = format(messy);
  assert.equal(out.replace(/\s+/g, ''), messy.replace(/\s+/g, ''));
  assert.ok(out.includes('   line   \n raw`'), 'multi-line string content preserved');
  assert.equal(format(out), out);
});

test('leaves license headers alone', () => {
  const header = '/*\n * Copyright\n */\n\n';
  assert.ok(format(header + 'rule a {\n  events:\n    $e.x = 1\n  condition:\n    $e\n}\n').startsWith(header));
});
