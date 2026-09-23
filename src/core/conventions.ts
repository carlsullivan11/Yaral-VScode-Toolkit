/**
 * Learns team conventions from existing rules: which meta keys and outcome
 * variables are "standard", the values used for enum-like meta keys, and the
 * typical expression for each outcome variable. Also detects duplicate rule
 * names / rule_ids across the rule set.
 */

import { parse, ParsedDocument, Rule } from './parser';
import { Token } from './lexer';

export interface RuleSummary {
  file: string;
  ruleName: string;
  nameRange?: Token['range'];
  meta: Record<string, string>;
  metaKeys: string[];
  outcomes: { name: string; expr: string }[];
  hasMatch: boolean;
}

export interface MetaKeyStat {
  key: string;
  count: number;
  ratio: number;
  /** Value frequencies, only kept for enum-like keys. */
  values: { value: string; count: number }[];
  enumLike: boolean;
}

export interface OutcomeStat {
  name: string;
  count: number;
  ratio: number;
  /** Most common expressions (event variable normalized to `$e`). */
  examples: { expr: string; count: number }[];
}

export interface Conventions {
  ruleCount: number;
  threshold: number;
  minRules: number;
  metaKeys: MetaKeyStat[];
  outcomes: OutcomeStat[];
  /** Meta keys present in at least `threshold` of rules (when enough rules). */
  standardMeta: string[];
  /** Outcome variables present in at least `threshold` of rules. */
  standardOutcomes: string[];
  /** Rules that share a name or rule_id. */
  duplicates: { kind: 'rule name' | 'rule_id'; value: string; files: string[] }[];
}

const MAX_ENUM_VALUES = 12;

export function summarizeRule(rule: Rule, file: string, doc: ParsedDocument): RuleSummary {
  const meta: Record<string, string> = {};
  for (const m of rule.meta) if (!(m.key in meta)) meta[m.key] = m.value;
  return {
    file,
    ruleName: rule.name,
    nameRange: rule.nameToken?.range,
    meta,
    metaKeys: [...new Set(rule.meta.map((m) => m.key))],
    outcomes: rule.outcomes.map((o) => ({ name: o.name, expr: normalizeExpr(o.expr, doc) })),
    hasMatch: rule.sections.some((s) => s.kind === 'match'),
  };
}

export function summarizeText(text: string, file: string): RuleSummary[] {
  const doc = parse(text);
  return doc.rules.map((r) => summarizeRule(r, file, doc));
}

function normalizeExpr(expr: Token[], doc: ParsedDocument): string {
  if (expr.length === 0) return '';
  const raw = doc.text.slice(expr[0].start, expr[expr.length - 1].end);
  // `$login.principal.ip` -> `$e.principal.ip` so examples group across rules.
  return raw.replace(/\$[A-Za-z_][A-Za-z0-9_]*(?=\.)/g, '$e').replace(/\s+/g, ' ');
}

export function buildConventions(summaries: RuleSummary[], threshold = 0.8, minRules = 5): Conventions {
  const ruleCount = summaries.length;
  const metaCounts = new Map<string, { count: number; values: Map<string, number> }>();
  const outcomeCounts = new Map<string, { count: number; exprs: Map<string, number> }>();

  for (const s of summaries) {
    for (const key of s.metaKeys) {
      const entry = metaCounts.get(key) ?? { count: 0, values: new Map() };
      entry.count++;
      const v = s.meta[key];
      if (v !== undefined) entry.values.set(v, (entry.values.get(v) ?? 0) + 1);
      metaCounts.set(key, entry);
    }
    for (const name of new Set(s.outcomes.map((o) => o.name))) {
      const entry = outcomeCounts.get(name) ?? { count: 0, exprs: new Map() };
      entry.count++;
      const expr = s.outcomes.find((o) => o.name === name)?.expr ?? '';
      entry.exprs.set(expr, (entry.exprs.get(expr) ?? 0) + 1);
      outcomeCounts.set(name, entry);
    }
  }

  const metaKeys: MetaKeyStat[] = [...metaCounts.entries()]
    .map(([key, e]) => {
      const values = [...e.values.entries()].map(([value, count]) => ({ value, count })).sort((a, b) => b.count - a.count);
      // Enum-like: a handful of distinct short values reused across rules.
      const enumLike = values.length <= MAX_ENUM_VALUES && e.count >= 3 && values.length < e.count && values.every((v) => v.value.length <= 40);
      return { key, count: e.count, ratio: ruleCount ? e.count / ruleCount : 0, values: enumLike ? values : [], enumLike };
    })
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));

  const outcomes: OutcomeStat[] = [...outcomeCounts.entries()]
    .map(([name, e]) => ({
      name,
      count: e.count,
      ratio: ruleCount ? e.count / ruleCount : 0,
      examples: [...e.exprs.entries()]
        .map(([expr, count]) => ({ expr, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 3),
    }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));

  const enough = ruleCount >= minRules;
  return {
    ruleCount,
    threshold,
    minRules,
    metaKeys,
    outcomes,
    standardMeta: enough ? metaKeys.filter((m) => m.ratio >= threshold).map((m) => m.key) : [],
    standardOutcomes: enough ? outcomes.filter((o) => o.ratio >= threshold).map((o) => o.name) : [],
    duplicates: findDuplicates(summaries),
  };
}

function findDuplicates(summaries: RuleSummary[]): Conventions['duplicates'] {
  const out: Conventions['duplicates'] = [];
  const group = (kind: 'rule name' | 'rule_id', keyOf: (s: RuleSummary) => string | undefined) => {
    const map = new Map<string, Set<string>>();
    for (const s of summaries) {
      const k = keyOf(s);
      if (!k) continue;
      const set = map.get(k) ?? new Set();
      set.add(s.file);
      map.set(k, set);
    }
    for (const [value, files] of map) {
      // Same file listed twice means a genuine duplicate within one file.
      const count = summaries.filter((s) => keyOf(s) === value).length;
      if (count > 1) out.push({ kind, value, files: [...files] });
    }
  };
  group('rule name', (s) => s.ruleName || undefined);
  group('rule_id', (s) => s.meta['rule_id'] || undefined);
  return out;
}

/** Markdown report describing the learned conventions. */
export function conventionsReport(c: Conventions): string {
  const pct = (x: number) => `${Math.round(x * 100)}%`;
  const lines: string[] = [
    '# YARA-L Workspace Conventions',
    '',
    `Indexed **${c.ruleCount}** rules. Items present in at least **${pct(c.threshold)}** of rules are treated as standard` +
      (c.ruleCount < c.minRules ? ` (not enforced until ${c.minRules} rules are indexed).` : '.'),
    '',
    '## Meta keys',
    '',
    '| Key | Rules | Coverage | Standard | Common values |',
    '|---|---:|---:|:---:|---|',
    ...c.metaKeys.map(
      (m) =>
        `| \`${m.key}\` | ${m.count} | ${pct(m.ratio)} | ${c.standardMeta.includes(m.key) ? '✅' : ''} | ${m.values
          .slice(0, 6)
          .map((v) => `\`${v.value}\` (${v.count})`)
          .join(', ')} |`,
    ),
    '',
    '## Outcome variables',
    '',
    '| Variable | Rules | Coverage | Standard | Most common expression |',
    '|---|---:|---:|:---:|---|',
    ...c.outcomes
      .slice(0, 60)
      .map(
        (o) =>
          `| \`$${o.name}\` | ${o.count} | ${pct(o.ratio)} | ${c.standardOutcomes.includes(o.name) ? '✅' : ''} | \`${(o.examples[0]?.expr ?? '').replace(/\|/g, '\\|').slice(0, 80)}\` |`,
      ),
  ];
  if (c.duplicates.length) {
    lines.push('', '## Duplicates', '');
    for (const d of c.duplicates) lines.push(`- ${d.kind} \`${d.value}\`: ${d.files.join(', ')}`);
  }
  return lines.join('\n') + '\n';
}

/** Suggested `.yaral-lint.json` content derived from the learned conventions. */
export function suggestedConfig(c: Conventions): Record<string, unknown> {
  const metaValues: Record<string, string[]> = {};
  for (const m of c.metaKeys) {
    if (m.enumLike && c.standardMeta.includes(m.key)) metaValues[m.key] = m.values.map((v) => v.value).sort();
  }
  return {
    requiredMeta: c.standardMeta,
    requiredOutcomes: c.standardOutcomes,
    metaValues,
    conventions: { enabled: true, threshold: c.threshold, minRules: c.minRules },
  };
}
