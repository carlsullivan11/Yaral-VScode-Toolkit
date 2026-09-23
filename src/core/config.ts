/**
 * `.yaral-lint.json` configuration shared by the VS Code extension and the
 * `yaral-lint` CLI, so developers and CI enforce the same standards.
 */

import * as fs from 'fs';
import * as path from 'path';
import { FunctionDef } from './catalog/functions';
import { Severity } from './linter/rules';
import { DEFAULT_MITRE_CONFIG, MitreConfig } from './mitre';

export const CONFIG_FILENAME = '.yaral-lint.json';

export interface ConventionsConfig {
  /** Learn standard meta keys / outcome variables from other rules. */
  enabled: boolean;
  /** Fraction of rules that must contain an item for it to be "standard". */
  threshold: number;
  /** Minimum rules indexed before learned conventions are enforced. */
  minRules: number;
  /** Glob patterns excluded from convention learning. */
  exclude: string[];
}

export interface LintConfig {
  /** Per-rule severity overrides keyed by rule id (YL101) or name (missing-section). */
  rules: Record<string, Severity>;
  /** Meta keys every rule must define. */
  requiredMeta: string[];
  /** Allowed values for meta keys (case-sensitive). */
  metaValues: Record<string, string[]>;
  /** Regular expressions meta values must match. */
  metaPatterns: Record<string, string>;
  /** Outcome variables every rule must define (without `$`). */
  requiredOutcomes: string[];
  /** Largest allowed match window. */
  maxMatchWindow: string;
  /** Largest number of outcome variables. */
  maxOutcomes: number;
  /** Require the file name (without extension) to equal the rule name. */
  filenameMatchesRuleName: boolean;
  /** Additional / overriding function definitions. */
  functions: FunctionDef[];
  /** Glob patterns the CLI skips. */
  ignore: string[];
  conventions: ConventionsConfig;
  /** MITRE ATT&CK (Enterprise, ICS, Mobile) and ATLAS validation of tactic/technique meta. */
  mitre: MitreConfig;
}

export const DEFAULT_CONFIG: LintConfig = {
  rules: {},
  requiredMeta: ['author', 'description', 'severity'],
  metaValues: {
    severity: ['Info', 'Informational', 'Low', 'Medium', 'High', 'Critical'],
    priority: ['Info', 'Informational', 'Low', 'Medium', 'High', 'Critical'],
  },
  metaPatterns: {},
  requiredOutcomes: [],
  maxMatchWindow: '48h',
  maxOutcomes: 20,
  filenameMatchesRuleName: true,
  functions: [],
  ignore: ['**/node_modules/**'],
  conventions: {
    enabled: true,
    threshold: 0.8,
    minRules: 5,
    exclude: ['**/node_modules/**', '**/_deprecated/**'],
  },
  mitre: DEFAULT_MITRE_CONFIG,
};

export type PartialConfig = Partial<Omit<LintConfig, 'conventions' | 'mitre'>> & {
  conventions?: Partial<ConventionsConfig>;
  mitre?: Partial<MitreConfig>;
};

export function mergeConfig(base: LintConfig, override: PartialConfig | undefined): LintConfig {
  if (!override) return base;
  return {
    ...base,
    ...override,
    rules: { ...base.rules, ...(override.rules ?? {}) },
    metaValues: { ...base.metaValues, ...(override.metaValues ?? {}) },
    metaPatterns: { ...base.metaPatterns, ...(override.metaPatterns ?? {}) },
    functions: [...base.functions, ...(override.functions ?? [])],
    conventions: { ...base.conventions, ...(override.conventions ?? {}) },
    mitre: { ...base.mitre, ...(override.mitre ?? {}) },
  };
}

/** Walks up from `startDir` to find the nearest config file. */
export function findConfigFile(startDir: string): string | undefined {
  let dir = path.resolve(startDir);
  for (;;) {
    const candidate = path.join(dir, CONFIG_FILENAME);
    if (fs.existsSync(candidate)) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
}

export function readConfigFile(file: string): PartialConfig {
  const raw = fs.readFileSync(file, 'utf8');
  try {
    return JSON.parse(raw) as PartialConfig;
  } catch (e) {
    throw new Error(`Invalid JSON in ${file}: ${(e as Error).message}`);
  }
}

export function loadConfig(startDir: string, explicitFile?: string): { config: LintConfig; file?: string } {
  const file = explicitFile ?? findConfigFile(startDir);
  if (!file) return { config: DEFAULT_CONFIG };
  return { config: mergeConfig(DEFAULT_CONFIG, readConfigFile(file)), file };
}

/** Minimal glob matcher supporting `**`, `*` and `?` on forward-slash paths. */
export function globToRegExp(glob: string): RegExp {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        const slash = glob[i + 2] === '/';
        re += slash ? '(?:.*/)?' : '.*';
        i += slash ? 2 : 1;
      } else {
        re += '[^/]*';
      }
    } else if (c === '?') {
      re += '[^/]';
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  return new RegExp(`^${re}$`);
}

export function matchesAnyGlob(filePath: string, globs: string[]): boolean {
  const normalized = filePath.split(path.sep).join('/');
  return globs.some((g) => {
    const re = globToRegExp(g);
    return re.test(normalized) || re.test(normalized.replace(/^\.?\//, ''));
  });
}
