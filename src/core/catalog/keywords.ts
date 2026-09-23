/** Documentation for YARA-L keywords, sections and enum values. */

const SYNTAX = 'https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax';

export interface KeywordDoc {
  name: string;
  description: string;
  example?: string;
  docUrl?: string;
}

export const SECTION_DOCS: Record<string, KeywordDoc> = {
  meta: {
    name: 'meta',
    description: 'Descriptive key/value metadata about the rule, such as author, description, severity and MITRE ATT&CK mapping. Values are strings, numbers or booleans. Meta values are carried into detections.',
    example: 'meta:\n  author = "Detection Engineering"\n  description = "Detects ..."\n  severity = "Medium"',
    docUrl: `${SYNTAX}#meta_section_syntax`,
  },
  events: {
    name: 'events',
    description: 'Required. Declares the event (and entity) variables and the predicates they must satisfy. Placeholder variables assigned here (`$user = $e.principal.user.userid`) join events together and can be used in match/outcome.',
    example: 'events:\n  $e.metadata.event_type = "USER_LOGIN"\n  $e.security_result.action = "BLOCK"\n  $user = $e.target.user.userid',
    docUrl: `${SYNTAX}#events_section_syntax`,
  },
  match: {
    name: 'match',
    description: 'Optional. Groups events by placeholder variables over a time window (maximum 48h), which turns the rule into a multi-event rule. Match variables automatically exclude zero values unless `allow_zero_values` is set.',
    example: 'match:\n  $user, $host over 10m',
    docUrl: `${SYNTAX}#match_section_syntax`,
  },
  outcome: {
    name: 'outcome',
    description: 'Optional. Defines up to 20 outcome variables that are attached to detections. `$risk_score` is used for risk-based alerting. In rules with a match section, event fields must be wrapped in an aggregate function.',
    example: 'outcome:\n  $risk_score = max(65)\n  $event_count = count_distinct($e.metadata.id)',
    docUrl: `${SYNTAX}#outcome_section_syntax`,
  },
  condition: {
    name: 'condition',
    description: 'Required. Boolean expression over event variables (`$e`), event counts (`#e`) and outcome variables that decides when a detection fires. Every event variable must be referenced.',
    example: 'condition:\n  #e > 5 and $risk_score > 50',
    docUrl: `${SYNTAX}#condition_section_syntax`,
  },
  options: {
    name: 'options',
    description: 'Optional. Rule execution options, for example `allow_zero_values = true` so match variables may have zero values.',
    example: 'options:\n  allow_zero_values = true',
    docUrl: `${SYNTAX}#options_section_syntax`,
  },
};

export const KEYWORD_DOCS: Record<string, KeywordDoc> = {
  rule: { name: 'rule', description: 'Declares a YARA-L rule: `rule <name> { ... }`. Rule names must be unique in the SecOps instance.' },
  and: { name: 'and', description: 'Logical AND.' },
  or: { name: 'or', description: 'Logical OR.' },
  not: { name: 'not', description: 'Logical negation. `not $e.field in %list` excludes values found in a reference list.' },
  in: { name: 'in', description: 'Membership test against a reference list (`%list`), data table column (`%table.column`) or literal array.', example: '$e.principal.ip in %trusted_ips' },
  nocase: { name: 'nocase', description: 'Modifier that makes a string or regex comparison case-insensitive.', example: '$e.target.process.file.full_path = /\\\\powershell\\.exe$/ nocase' },
  regex: { name: 'regex', description: 'Used with reference lists to treat each list entry as a regular expression: `$e.field in regex %list`.' },
  cidr: { name: 'cidr', description: 'Used with reference lists to treat each list entry as a CIDR range: `$e.principal.ip in cidr %subnets`.' },
  over: { name: 'over', description: 'Specifies the match window duration, e.g. `$user over 1h`. Units: s, m, h, d. Maximum 48h.' },
  before: { name: 'before', description: 'Sliding window qualifier: `over 1h before $e2` anchors the window before a pivot event.' },
  after: { name: 'after', description: 'Sliding window qualifier: `over 1h after $e1` anchors the window after a pivot event.' },
  every: { name: 'every', description: 'Hop window qualifier: `over every 10m`.' },
  any: { name: 'any', description: 'Array quantifier: true if the predicate holds for any element of a repeated field.', example: 'any $e.principal.ip = "10.0.0.1"' },
  all: { name: 'all', description: 'Array quantifier: true if the predicate holds for every element of a repeated field.', example: 'all $e.principal.ip != "10.0.0.1"' },
  true: { name: 'true', description: 'Boolean literal.' },
  false: { name: 'false', description: 'Boolean literal.' },
  allow_zero_values: { name: 'allow_zero_values', description: 'Option: allow match variables to take zero values ("" or 0). By default events with zero-valued match variables are dropped.', docUrl: `${SYNTAX}#options_section_syntax` },
};

export const KNOWN_OPTIONS = ['allow_zero_values', 'suppression_window'];

/** UDM `metadata.event_type` values. */
export const UDM_EVENT_TYPES = [
  'EMAIL_TRANSACTION', 'EMAIL_UNCATEGORIZED', 'FILE_COPY', 'FILE_CREATION', 'FILE_DELETION', 'FILE_MODIFICATION',
  'FILE_MOVE', 'FILE_OPEN', 'FILE_READ', 'GENERIC_EVENT', 'GROUP_CREATION', 'GROUP_DELETION', 'GROUP_MODIFICATION',
  'NETWORK_CONNECTION', 'NETWORK_DHCP', 'NETWORK_DNS', 'NETWORK_FTP', 'NETWORK_HTTP', 'NETWORK_SMTP',
  'PROCESS_INJECTION', 'PROCESS_LAUNCH', 'PROCESS_MODULE_LOAD', 'PROCESS_OPEN', 'PROCESS_TERMINATION',
  'PROCESS_UNCATEGORIZED', 'REGISTRY_CREATION', 'REGISTRY_DELETION', 'REGISTRY_MODIFICATION', 'RESOURCE_CREATION',
  'RESOURCE_DELETION', 'RESOURCE_PERMISSIONS_CHANGE', 'RESOURCE_READ', 'RESOURCE_WRITTEN', 'SCAN_FILE', 'SCAN_HOST',
  'SCAN_NETWORK', 'SCHEDULED_TASK_CREATION', 'SERVICE_CREATION', 'SERVICE_DELETION', 'SERVICE_MODIFICATION',
  'SERVICE_START', 'SERVICE_STOP', 'SERVICE_UNSPECIFIED', 'SETTING_CREATION', 'SETTING_DELETION',
  'SETTING_MODIFICATION', 'STATUS_HEARTBEAT', 'STATUS_UPDATE', 'SYSCALL', 'SYSTEM_AUDIT_LOG_WIPE',
  'USER_CHANGE_PASSWORD', 'USER_CHANGE_PERMISSIONS', 'USER_CREATION', 'USER_DELETION', 'USER_LOGIN', 'USER_LOGOUT',
  'USER_RESOURCE_ACCESS', 'USER_RESOURCE_CREATION', 'USER_RESOURCE_DELETION', 'USER_RESOURCE_UPDATE_CONTENT',
  'USER_RESOURCE_UPDATE_PERMISSIONS', 'USER_UNCATEGORIZED',
];

/** Entity graph `metadata.entity_type` values. */
export const UDM_ENTITY_TYPES = ['ASSET', 'DOMAIN_NAME', 'FILE', 'GROUP', 'IP_ADDRESS', 'RESOURCE', 'URL', 'USER'];

/** Entity graph `metadata.source_type` values. */
export const UDM_SOURCE_TYPES = ['ENTITY_CONTEXT', 'DERIVED_CONTEXT', 'GLOBAL_CONTEXT'];

/** Common `security_result.action` values. */
export const UDM_ACTIONS = ['ALLOW', 'BLOCK', 'ALLOW_WITH_MODIFICATION', 'QUARANTINE', 'FAIL', 'CHALLENGE', 'UNKNOWN_ACTION'];

/** Severity values and the matching risk_score from the Google SecOps community style guide. */
export const SEVERITY_RISK_SCORES: Record<string, number> = {
  Info: 10,
  Low: 35,
  Medium: 65,
  High: 85,
  Critical: 95,
};
