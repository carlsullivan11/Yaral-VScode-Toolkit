/** Registry of lint rules. IDs are stable; names are human-friendly aliases. */

export type Severity = 'error' | 'warning' | 'info' | 'hint' | 'off';

export interface LintRuleMeta {
  id: string;
  name: string;
  severity: Severity;
  description: string;
}

const r = (id: string, name: string, severity: Severity, description: string): LintRuleMeta => ({ id, name, severity, description });

export const LINT_RULES: LintRuleMeta[] = [
  r('YL001', 'syntax-error', 'error', 'Lexical or structural syntax error (unbalanced brackets, unterminated strings, malformed rule header).'),

  r('YL101', 'missing-section', 'error', 'A rule must have `events:` and `condition:` sections.'),
  r('YL102', 'section-order', 'error', 'Sections must appear in the order meta, events, match, outcome, condition, options.'),
  r('YL103', 'duplicate-section', 'error', 'A section is declared more than once.'),
  r('YL104', 'empty-section', 'warning', 'A section header has no content.'),
  r('YL105', 'filename-rule-name', 'warning', 'The file name should equal the rule name so rules can be found and deployed by name.'),
  r('YL106', 'rule-name-format', 'warning', 'Rule names should be lower snake_case identifiers.'),
  r('YL107', 'multiple-rules', 'warning', 'Keep exactly one rule per file; the SecOps API manages rules individually.'),

  r('YL201', 'undefined-variable', 'error', 'A variable is used but never defined in `events:` or `outcome:`.'),
  r('YL202', 'unused-event-variable', 'warning', 'Every event variable declared in `events:` should be referenced in `condition:`.'),
  r('YL203', 'undefined-match-variable', 'error', 'Match variables must be placeholders assigned in `events:`.'),
  r('YL204', 'duplicate-outcome', 'error', 'An outcome variable is assigned more than once.'),
  r('YL205', 'unused-placeholder', 'warning', 'A placeholder variable is assigned but never used for a join, match, outcome or condition.'),
  r('YL206', 'non-aggregated-outcome', 'warning', 'In rules with `match:`, event fields in outcomes must be wrapped in an aggregate function (max, array_distinct, ...).'),
  r('YL207', 'variable-case-collision', 'info', 'Two variables differ only by capitalization (e.g. $Host and $host).'),
  r('YL208', 'generic-event-variable', 'hint', 'Prefer descriptive event variable names ($login, $process) over $e / $e1 / $event.'),

  r('YL301', 'unknown-function', 'warning', 'Function is not in the YARA-L function catalog (add custom ones under `functions` in .yaral-lint.json).'),
  r('YL302', 'argument-count', 'error', 'Function is called with the wrong number of arguments.'),
  r('YL303', 'function-section', 'warning', 'Function is used in a section where it is not allowed (e.g. aggregates outside `outcome:`).'),
  r('YL304', 'invalid-regex', 'warning', 'Regular expression is invalid or uses features RE2 does not support (lookaround, backreferences).'),
  r('YL305', 'regex-wildcard-edges', 'info', 'Leading or trailing `.*` in a regex is redundant (YARA-L regexes match substrings) and slows evaluation.'),
  r('YL306', 'missing-event-filter', 'info', 'Event variable has no metadata filter (event_type, log_type, product_name ...), so the rule must evaluate every event.'),
  r('YL307', 'entity-graph-filter', 'info', 'Entity graph variables should filter on graph.metadata.entity_type and graph.metadata.source_type.'),

  r('YL401', 'missing-required-meta', 'warning', 'A meta key required by .yaral-lint.json is missing.'),
  r('YL402', 'missing-conventional-meta', 'info', 'A meta key used by most rules in the workspace is missing.'),
  r('YL403', 'invalid-meta-value', 'warning', 'A meta value is not one of the allowed values.'),
  r('YL404', 'meta-pattern', 'warning', 'A meta value does not match the pattern configured in .yaral-lint.json.'),
  r('YL405', 'duplicate-meta', 'warning', 'A meta key is defined more than once.'),
  r('YL406', 'meta-key-typo', 'info', 'A meta key is not used elsewhere in the workspace but is close to a common key (possible typo).'),
  r('YL407', 'duplicate-rule-identity', 'error', 'rule name or meta rule_id duplicates another rule in the workspace.'),
  r('YL408', 'mitre-unknown-id', 'warning', 'tactic/technique value is not a valid ID in the enabled MITRE frameworks (ATT&CK Enterprise, ICS, Mobile, ATLAS).'),
  r('YL409', 'mitre-deprecated', 'warning', 'MITRE technique is revoked or deprecated; revoked techniques link to their replacement.'),
  r('YL410', 'mitre-name-instead-of-id', 'warning', 'Use MITRE IDs (TA0006, T1110, AML.T0051) rather than names in tactic/technique meta.'),
  r('YL411', 'mitre-tactic-mismatch', 'info', 'None of the technique\'s tactics are listed in the rule\'s tactic meta.'),
  r('YL412', 'mitre-meta-key', 'info', 'Use the configured MITRE meta keys (tactic/technique by default) instead of alternatives such as mitre_attack_tactic.'),

  r('YL501', 'missing-required-outcome', 'warning', 'An outcome variable required by .yaral-lint.json is missing.'),
  r('YL502', 'missing-conventional-outcome', 'info', 'An outcome variable used by most rules in the workspace is missing.'),
  r('YL503', 'too-many-outcomes', 'error', 'A rule can define at most 20 outcome variables.'),
  r('YL504', 'risk-score-severity', 'info', 'Constant $risk_score does not match the risk score conventionally used for the rule severity.'),
  r('YL505', 'outcome-name-style', 'info', 'Outcome variable names should be lower snake_case.'),
  r('YL506', 'hardcoded-threshold', 'info', 'Expose hard-coded condition thresholds as outcome variables (e.g. $failed_login_threshold = 10) so analysts see them.'),

  r('YL601', 'match-window-missing', 'error', '`match:` requires a window: `$var over <duration>`.'),
  r('YL602', 'match-window-too-large', 'error', 'Match window exceeds the maximum (48h by default).'),
  r('YL603', 'redundant-zero-check', 'info', 'Match variables already exclude zero values unless `allow_zero_values` is set; this check is redundant.'),

  r('YL701', 'no-tabs', 'info', 'Use spaces rather than tabs.'),
  r('YL702', 'trailing-whitespace', 'info', 'Remove trailing whitespace.'),

  r('YL801', 'unknown-option', 'hint', 'Option is not a known YARA-L option.'),
];

export const RULES_BY_ID = new Map(LINT_RULES.map((x) => [x.id, x]));
export const RULES_BY_NAME = new Map(LINT_RULES.map((x) => [x.name, x]));

export function resolveSeverity(id: string, overrides: Record<string, Severity>): Severity {
  const meta = RULES_BY_ID.get(id);
  if (!meta) return 'warning';
  return overrides[id] ?? overrides[meta.name] ?? meta.severity;
}
