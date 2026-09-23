import { strict as assert } from 'assert';
import { test } from 'node:test';
import { applyFixes, lint } from '../src/core/linter';
import { DEFAULT_CONFIG, mergeConfig } from '../src/core/config';
import { summarizeText } from '../src/core/conventions';
import { findByName, lookupMitre, splitMitreValue } from '../src/core/mitre';
import { buildMitreCoverage, navigatorLayer } from '../src/core/mitreCoverage';
import { rule } from './helpers';

const withMeta = (meta: string) =>
  rule(`  meta:\n    author = "a"\n    description = "d"\n    severity = "Low"\n${meta}\n  events:\n    $login.metadata.event_type = "USER_LOGIN"\n  condition:\n    $login`);
const mitreDiags = (text: string, config = DEFAULT_CONFIG) => lint(text, { config }).filter((d) => /^YL4(0[89]|1\d)$/.test(d.ruleId));

test('looks up IDs across ATT&CK Enterprise, ICS, Mobile and ATLAS', () => {
  assert.equal(lookupMitre('T1110')?.framework, 'enterprise');
  assert.equal(lookupMitre('TA0006')?.name, 'Credential Access');
  assert.equal(lookupMitre('T0886')?.framework, 'ics');
  assert.equal(lookupMitre('TA0108')?.name, 'Initial Access');
  assert.equal(lookupMitre('TA0027')?.framework, 'mobile');
  assert.equal(lookupMitre('AML.T0051')?.name, 'LLM Prompt Injection');
  assert.equal(lookupMitre('AML.TA0005')?.framework, 'atlas');
  assert.equal(lookupMitre('T9999'), undefined);
  // Names are ambiguous across frameworks
  assert.deepEqual(findByName('initial access', 'tactic').map((e) => e.framework).sort(), ['atlas', 'enterprise', 'ics', 'mobile']);
});

test('splits comma-separated and "ID - Name" values', () => {
  assert.deepEqual(splitMitreValue('T1110, T1078.004 - Cloud Accounts;AML.T0051').map((x) => x.text), ['T1110', 'T1078.004', 'AML.T0051']);
  const spans = splitMitreValue('TA0006,  TA0001');
  assert.deepEqual(spans[1], { text: 'TA0001', start: 9, end: 15 });
});

test('valid IDs from every framework are accepted', () => {
  assert.deepEqual(mitreDiags(withMeta('    tactic = "TA0006, TA0108, AML.TA0005"\n    technique = "T1110, T0886, AML.T0051"')), []);
});

test('YL408 unknown IDs, wrong kind, disabled framework', () => {
  const d = mitreDiags(withMeta('    tactic = "TA9999, T1110"\n    technique = "T1110.999, Foo"'));
  assert.deepEqual(d.map((x) => x.ruleId), ['YL408', 'YL408', 'YL408', 'YL408']);
  assert.match(d[1].message, /technique ID, but 'tactic' expects tactic IDs/);
  const noAtlas = mergeConfig(DEFAULT_CONFIG, { mitre: { frameworks: ['enterprise'] } });
  const d2 = mitreDiags(withMeta('    tactic = "AML.TA0005"'), noAtlas);
  assert.match(d2[0].message, /belongs to MITRE atlas, which is not enabled/);
});

test('YL409 revoked techniques offer their replacement', () => {
  const text = withMeta('    tactic = "TA0112"\n    technique = "T1562.001"');
  const d = mitreDiags(text);
  const revoked = d.find((x) => x.ruleId === 'YL409')!;
  assert.match(revoked.message, /revoked and replaced by T1685/);
  const fixed = applyFixes(text, [revoked]).text;
  assert.match(fixed, /technique = "T1685"/);
});

test('YL410 names are replaced with IDs, preferring the framework the rule already uses', () => {
  const text = withMeta('    tactic = "Initial Access"\n    technique = "T0886"');
  const d = mitreDiags(text).find((x) => x.ruleId === 'YL410')!;
  assert.match(d.message, /TA0108 \(ics\)/);
  assert.match(applyFixes(text, [d]).text, /tactic = "TA0108"/);
  const enterprise = mitreDiags(withMeta('    tactic = "Credential Access"')).find((x) => x.ruleId === 'YL410')!;
  assert.equal(enterprise.fix!.edits[0].newText, 'TA0006');
});

test('YL411 technique not under any listed tactic', () => {
  const d = mitreDiags(withMeta('    tactic = "TA0002"\n    technique = "T1110"'));
  assert.deepEqual(d.map((x) => x.ruleId), ['YL411']);
  assert.match(d[0].message, /TA0006/);
});

test('YL412 alternative MITRE keys, with rename fix only when values are IDs', () => {
  const ids = mitreDiags(withMeta('    mitre_attack_tactic = "TA0006"'));
  assert.equal(ids[0].ruleId, 'YL412');
  assert.equal(ids[0].fix?.edits[0].newText, 'tactic');
  const names = mitreDiags(withMeta('    mitre_attack_tactic = "Credential Access"'));
  assert.equal(names[0].fix, undefined);
  const custom = mergeConfig(DEFAULT_CONFIG, { mitre: { tacticKey: 'mitre_attack_tactic' } });
  assert.deepEqual(mitreDiags(withMeta('    mitre_attack_tactic = "TA0006"'), custom), []);
});

test('coverage and ATT&CK Navigator layers', () => {
  const summaries = [
    ...summarizeText(withMeta('    tactic = "TA0006"\n    technique = "T1110"').replace('test_rule', 'r1'), '/r1.yaral'),
    ...summarizeText(withMeta('    technique = "T1110.003, T0886, AML.T0051"').replace('test_rule', 'r2'), '/r2.yaral'),
    ...summarizeText(withMeta('').replace('test_rule', 'r3'), '/r3.yaral'),
  ];
  const cov = buildMitreCoverage(summaries, DEFAULT_CONFIG.mitre);
  const ent = cov.frameworks.find((f) => f.framework === 'enterprise')!;
  assert.deepEqual(ent.techniques.get('T1110'), ['r1']);
  assert.deepEqual(ent.tactics.get('TA0006'), ['r1', 'r2']);
  assert.deepEqual(cov.frameworks.find((f) => f.framework === 'ics')!.techniques.get('T0886'), ['r2']);
  assert.deepEqual(cov.frameworks.find((f) => f.framework === 'atlas')!.techniques.get('AML.T0051'), ['r2']);
  assert.deepEqual(cov.unmappedRules, ['r3']);
  const layer = navigatorLayer(cov, 'ics') as { domain: string; techniques: { techniqueID: string }[] };
  assert.equal(layer.domain, 'ics-attack');
  assert.deepEqual(layer.techniques.map((t) => t.techniqueID), ['T0886']);
  assert.throws(() => navigatorLayer(cov, 'atlas'));
});
