/** MITRE coverage across a rule set, plus ATT&CK Navigator layer export. */

import { RuleSummary } from './conventions';
import { allMitre, frameworkInfo, lookupMitre, MitreConfig, MitreFramework, MitreTechnique, splitMitreValue } from './mitre';

export interface FrameworkCoverage {
  framework: MitreFramework;
  name: string;
  version: string;
  /** Technique ID -> rule names mapped to it. */
  techniques: Map<string, string[]>;
  /** Tactic ID -> rule names (explicit tactic meta or implied by techniques). */
  tactics: Map<string, string[]>;
  totalTechniques: number;
  totalTactics: number;
}

export interface MitreCoverage {
  frameworks: FrameworkCoverage[];
  unmappedRules: string[];
}

export function buildMitreCoverage(summaries: RuleSummary[], config: MitreConfig): MitreCoverage {
  const byFw = new Map<MitreFramework, FrameworkCoverage>();
  for (const f of config.frameworks) {
    const info = frameworkInfo(f);
    byFw.set(f, {
      framework: f,
      name: info.name,
      version: info.version,
      techniques: new Map(),
      tactics: new Map(),
      totalTechniques: allMitre('technique', [f]).filter((t) => !(t as MitreTechnique).deprecated && !t.id.includes('.')).length,
      totalTactics: allMitre('tactic', [f]).length,
    });
  }
  const add = (map: Map<string, string[]>, id: string, rule: string) => {
    const list = map.get(id) ?? [];
    if (!list.includes(rule)) list.push(rule);
    map.set(id, list);
  };
  const unmapped: string[] = [];
  for (const s of summaries) {
    let mapped = false;
    for (const key of [config.tacticKey, config.techniqueKey]) {
      const value = s.meta[key];
      if (!value) continue;
      for (const item of splitMitreValue(value)) {
        const e = lookupMitre(item.text, config.frameworks);
        if (!e) continue;
        const cov = byFw.get(e.framework)!;
        mapped = true;
        if (e.kind === 'tactic') add(cov.tactics, e.id, s.ruleName);
        else {
          const id = typeof e.revokedBy === 'string' ? e.revokedBy : e.id;
          add(cov.techniques, id, s.ruleName);
          for (const t of e.tactics) add(cov.tactics, t, s.ruleName);
        }
      }
    }
    if (!mapped) unmapped.push(s.ruleName);
  }
  return { frameworks: [...byFw.values()], unmappedRules: unmapped };
}

export function mitreCoverageReport(c: MitreCoverage): string {
  const lines = ['# MITRE Coverage', ''];
  for (const f of c.frameworks) {
    const parents = new Set([...f.techniques.keys()].map((id) => id.split('.').slice(0, id.startsWith('AML.') ? 2 : 1).join('.')));
    lines.push(
      `## ${f.name} (v${f.version})`,
      '',
      `${f.tactics.size}/${f.totalTactics} tactics · ${parents.size}/${f.totalTechniques} techniques covered (${f.techniques.size} technique/sub-technique IDs)`,
      '',
    );
    if (f.tactics.size === 0) continue;
    lines.push('| Tactic | Rules | Techniques |', '|---|---:|---|');
    for (const t of allMitre('tactic', [f.framework])) {
      const rules = f.tactics.get(t.id) ?? [];
      const techs = [...f.techniques.keys()].filter((id) => (lookupMitre(id) as MitreTechnique | undefined)?.tactics.includes(t.id));
      lines.push(`| ${t.id} ${t.name} | ${rules.length || '—'} | ${techs.map((id) => `\`${id}\``).join(' ') || ''} |`);
    }
    lines.push('');
  }
  if (c.unmappedRules.length) {
    lines.push(`## Rules without MITRE mapping (${c.unmappedRules.length})`, '', ...c.unmappedRules.slice(0, 200).map((r) => `- ${r}`), '');
  }
  return lines.join('\n');
}

/** ATT&CK Navigator layer (format 4.5) for an ATT&CK domain. */
export function navigatorLayer(c: MitreCoverage, framework: MitreFramework, name = 'YARA-L rule coverage'): Record<string, unknown> {
  if (framework === 'atlas') throw new Error('Navigator layers are generated for ATT&CK domains (enterprise, ics, mobile) only');
  const f = c.frameworks.find((x) => x.framework === framework);
  if (!f) throw new Error(`Framework '${framework}' is not enabled in mitre.frameworks`);
  const info = frameworkInfo(framework);
  const max = Math.max(1, ...[...f.techniques.values()].map((r) => r.length));
  return {
    name,
    versions: { attack: info.version.split('.')[0], navigator: '5.1.0', layer: '4.5' },
    domain: info.domain,
    description: `Techniques referenced by YARA-L rule meta. Score = number of rules.`,
    techniques: [...f.techniques.entries()].map(([techniqueID, rules]) => ({
      techniqueID,
      score: rules.length,
      comment: rules.join(', '),
      enabled: true,
      showSubtechniques: true,
    })),
    gradient: { colors: ['#e6f2ff', '#1f6feb'], minValue: 0, maxValue: max },
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: false,
    hideDisabled: false,
    legendItems: [],
  };
}
