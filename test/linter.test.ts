import { strict as assert } from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { test } from 'node:test';
import { applyFixes, lint, LintDiagnostic } from '../src/core/linter';
import { DEFAULT_CONFIG, mergeConfig } from '../src/core/config';
import { buildConventions, summarizeText } from '../src/core/conventions';
import { EXAMPLES, FIXTURES, MINIMAL, rule } from './helpers';

const ids = (d: LintDiagnostic[]) => [...new Set(d.map((x) => x.ruleId))].sort();

test('minimal valid rule has no diagnostics', () => {
  assert.deepEqual(lint(MINIMAL), []);
});

test('example rules are clean', () => {
  for (const f of fs.readdirSync(EXAMPLES)) {
    const file = path.join(EXAMPLES, f);
    const d = lint(fs.readFileSync(file, 'utf8'), { filePath: file });
    assert.deepEqual(d.map((x) => `${x.ruleId} ${x.message}`), [], f);
  }
});

test('bad fixture triggers the expected rules', () => {
  const file = path.join(FIXTURES, 'bad_rule.yaral');
  const d = lint(fs.readFileSync(file, 'utf8'), { filePath: file });
  const expected = ['YL102', 'YL105', 'YL106', 'YL201', 'YL204', 'YL205', 'YL206', 'YL208', 'YL301', 'YL302', 'YL304', 'YL403', 'YL505', 'YL506', 'YL602', 'YL603'];
  for (const id of expected) assert.ok(ids(d).includes(id), `expected ${id}; got ${ids(d).join(', ')}`);
  const unknown = d.find((x) => x.ruleId === 'YL301')!;
  assert.match(unknown.message, /did you mean 'strings\.to_lower'/);
});

test('missing sections and match window', () => {
  assert.deepEqual(ids(lint(rule('  meta:\n    author = "a"'))).filter((x) => x === 'YL101'), ['YL101']);
  const d = lint(rule('  events:\n    $e.x = $u\n  match:\n    $u\n  condition:\n    $e'));
  assert.ok(ids(d).includes('YL601'));
});

test('event variable used only through a derived placeholder counts as used', () => {
  const d = lint(rule(`  events:
    $e.metadata.event_type = "USER_LOGIN"
    $country = $e.principal.location.country_or_region
    $user = $e.target.user.userid
  match:
    $user over 1h
  condition:
    #country > 1`));
  assert.ok(!ids(d).includes('YL202'), JSON.stringify(d));
});

test('unused event variable is reported', () => {
  const d = lint(rule('  events:\n    $a.x = $h\n    $b.y = $h\n  match:\n    $h over 1h\n  condition:\n    $a'));
  assert.deepEqual(d.filter((x) => x.ruleId === 'YL202').map((x) => x.message), ["Event variable '$b' is not referenced in condition:"]);
});

test('non-aggregated outcomes only flagged when match exists', () => {
  const single = lint(rule('  events:\n    $e.x = 1\n  outcome:\n    $h = $e.principal.hostname\n  condition:\n    $e'));
  assert.ok(!ids(single).includes('YL206'));
  const multi = lint(rule('  events:\n    $e.x = $u\n  match:\n    $u over 1h\n  outcome:\n    $h = $e.principal.hostname\n    $ok = array_distinct($e.principal.ip)\n    $m = $u\n  condition:\n    $e'));
  assert.equal(multi.filter((x) => x.ruleId === 'YL206').length, 1);
});

test('config: required meta, allowed values, patterns and severity overrides', () => {
  const config = mergeConfig(DEFAULT_CONFIG, {
    requiredMeta: ['author', 'rule_id'],
    metaPatterns: { rule_id: '^mr_' },
    requiredOutcomes: ['risk_score'],
    rules: { YL506: 'off', 'unused-placeholder': 'error' },
  });
  const text = rule('  meta:\n    author = "a"\n    severity = "Hi"\n  events:\n    $e.x = $p\n  condition:\n    $e');
  const d = lint(text, { config });
  assert.ok(d.some((x) => x.ruleId === 'YL401' && x.message.includes('rule_id')));
  assert.ok(d.some((x) => x.ruleId === 'YL403' && x.fix?.edits[0].newText === '"High"'));
  assert.ok(d.some((x) => x.ruleId === 'YL501'));
  assert.equal(d.find((x) => x.ruleId === 'YL205')?.severity, 'error');
  const withId = lint(rule('  meta:\n    rule_id = "abc"\n  events:\n    $e.x = 1\n  condition:\n    $e'), { config });
  assert.ok(withId.some((x) => x.ruleId === 'YL404'));
});

test('regex checks', () => {
  const d = lint(rule('  events:\n    $e.a = /.*foo/\n    $e.b = /(?i)ba[r/\n    re.regex($e.c, `x(?!y)`)\n  condition:\n    $e'));
  const msgs = d.filter((x) => x.ruleId === 'YL304' || x.ruleId === 'YL305').map((x) => x.ruleId);
  assert.deepEqual(msgs.sort(), ['YL304', 'YL304', 'YL305']);
});

test('RE2-only syntax is accepted', () => {
  const d = lint(rule('  events:\n    re.regex($e.a, `(?i)^\\A(?P<x>\\pL+)[[:alpha:]]\\z`)\n  condition:\n    $e'));
  assert.ok(!ids(d).includes('YL304'), JSON.stringify(d));
});

test('risk score vs severity and hard-coded thresholds', () => {
  const d = lint(rule('  meta:\n    severity = "High"\n  events:\n    $e.x = $u\n  match:\n    $u over 1h\n  outcome:\n    $risk_score = max(10)\n  condition:\n    #e > 20'));
  assert.ok(d.some((x) => x.ruleId === 'YL504' && x.message.includes('85')));
  assert.ok(d.some((x) => x.ruleId === 'YL506'));
});

test('suppression comments', () => {
  const text = rule(`  events:
    // yaral-lint-disable-next-line YL205
    $e.x = $unused
    $e.y = $unused2 // yaral-lint-disable-line unused-placeholder
    $e.z = $unused3
  condition:
    $e`);
  const d = lint(text).filter((x) => x.ruleId === 'YL205');
  assert.deepEqual(d.map((x) => x.message.match(/\$\w+/)![0]), ['$unused3']);
  assert.deepEqual(lint('// yaral-lint-disable\n' + text), []);
});

test('whitespace diagnostics and fixes', () => {
  const text = rule('  events:\n\t$e.x = 1   \n  condition:\n    $e');
  const ws = (d: LintDiagnostic[]) => ids(d).filter((x) => x.startsWith('YL7'));
  const d = lint(text);
  assert.deepEqual(ws(d), ['YL701', 'YL702']);
  const fixed = applyFixes(text, d.filter((x) => x.ruleId.startsWith('YL7'))).text;
  assert.deepEqual(ws(lint(fixed)), []);
});

test('workspace conventions: standard meta/outcomes, typos and duplicates', () => {
  const mk = (name: string, extra = '') =>
    rule(`  meta:\n    author = "a"\n    description = "d"\n    severity = "Low"\n    tactic = "TA0001"${extra}\n  events:\n    $e.x = 1\n  outcome:\n    $risk_score = max(35)\n    $event_count = count_distinct($e.metadata.id)\n  condition:\n    $e`, name);
  const files = ['r1', 'r2', 'r3', 'r4', 'r5'].map((n) => ({ file: `/w/${n}.yaral`, text: mk(n) }));
  files.push({ file: '/w/dup.yaral', text: mk('r1') });
  const conv = buildConventions(files.flatMap((f) => summarizeText(f.text, f.file)), 0.8, 5);
  assert.ok(conv.standardMeta.includes('tactic'));
  assert.ok(conv.standardOutcomes.includes('event_count'));
  assert.deepEqual(conv.metaKeys.find((m) => m.key === 'severity')?.values, [{ value: 'Low', count: 6 }]);

  const target = rule('  meta:\n    author = "a"\n    description = "d"\n    severity = "Low"\n    tacitc = "TA0001"\n  events:\n    $e.x = 1\n  outcome:\n    $risk_score = max(35)\n  condition:\n    $e', 'new_rule');
  const d = lint(target, { conventions: conv, filePath: '/w/new_rule.yaral' });
  assert.ok(d.some((x) => x.ruleId === 'YL402' && x.message.includes("'tactic'")));
  assert.ok(d.some((x) => x.ruleId === 'YL406' && x.message.includes("did you mean 'tactic'")));
  const missingOutcome = d.find((x) => x.ruleId === 'YL502')!;
  assert.match(missingOutcome.fix!.edits[0].newText, /\$event_count = count_distinct\(\$e\.metadata\.id\)/);

  const dup = lint(mk('r1'), { conventions: conv, filePath: '/w/r1.yaral' });
  assert.ok(dup.some((x) => x.ruleId === 'YL407' && x.message.includes('dup.yaral')));
});

test('quick fix inserts missing outcome section before condition', () => {
  const config = mergeConfig(DEFAULT_CONFIG, { requiredOutcomes: ['risk_score'], requiredMeta: [] });
  const text = rule('  events:\n    $e.x = 1\n\n  condition:\n    $e');
  const fixed = applyFixes(text, lint(text, { config })).text;
  assert.match(fixed, /  outcome:\n    \$risk_score = \n\n  condition:/);
});
