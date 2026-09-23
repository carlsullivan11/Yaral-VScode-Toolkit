import { strict as assert } from 'assert';
import { test } from 'node:test';
import { parse, section } from '../src/core/parser';
import { MINIMAL } from './helpers';

test('parses sections, meta and outcomes', () => {
  const doc = parse(`rule r {
  meta:
    author = "a"
    severity = "High"
  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.target.user.userid = $user
  match:
    $user over 1h
  outcome:
    $risk_score = max(if($e.principal.ip = "1.1.1.1", 10, 0))
    $ips = array_distinct($e.principal.ip)
  condition:
    $e
}`);
  assert.equal(doc.errors.length, 0);
  const rule = doc.rules[0];
  assert.equal(rule.name, 'r');
  assert.deepEqual(rule.sections.map((s) => s.kind), ['meta', 'events', 'match', 'outcome', 'condition']);
  assert.deepEqual(rule.meta.map((m) => [m.key, m.value]), [['author', 'a'], ['severity', 'High']]);
  assert.deepEqual(rule.outcomes.map((o) => o.name), ['risk_score', 'ips']);
  assert.equal(rule.match?.window?.text, '1h');
  assert.deepEqual(rule.match?.vars.map((v) => v.text), ['$user']);
  assert.deepEqual(rule.calls.map((c) => [c.name, c.args.length]), [['max', 1], ['if', 3], ['array_distinct', 1]]);
  assert.ok(section(rule, 'events'));
});

test('classifies variable references', () => {
  const rule = parse(MINIMAL).rules[0];
  const ref = rule.varRefs.find((r) => r.section === 'events')!;
  assert.equal(ref.name, 'login');
  assert.equal(ref.isFieldAccess, true);
});

test('does not treat keywords followed by ( as function calls', () => {
  const doc = parse('rule r { events: NOT ($e.x = 1) and not ($e.y = 2) condition: $e }');
  assert.deepEqual(doc.rules[0].calls, []);
});

test('recovers from unbalanced brackets', () => {
  const doc = parse('rule r {\n events:\n  strings.concat($e.x\n condition:\n  $e\n}');
  assert.ok(doc.errors.some((e) => e.message.includes("Unclosed '('")));
  assert.equal(doc.rules.length, 1);
});

test('parses multiple rules and reports stray tokens', () => {
  const doc = parse('foo\nrule a { events: $e.x = 1 condition: $e }\nrule b { events: $e.x = 1 condition: $e }');
  assert.equal(doc.rules.length, 2);
  assert.ok(doc.errors[0].message.includes('outside of a rule'));
});
