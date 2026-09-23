# Research & Roadmap

This document records the research behind the toolkit's feature set and ranks what to build next.

## Research inputs

1. **Google's public rule corpus**: [chronicle/detection-rules](https://github.com/chronicle/detection-rules), 922 `.yaral` files (379 community, the rest deprecated/legacy), plus its `STYLE_GUIDE.md` and the `content_manager` CI tool.
2. **YARA-L 2.0 language reference**: syntax (sections, match windows, outcomes, options) and the function reference.
3. **Detection-as-code practice**: how rule repos are reviewed, tested and deployed through the SecOps API.

### What the corpus says about real-world YARA-L

Measured across the corpus with this toolkit's parser:

| Signal | Finding | How the toolkit uses it |
|---|---|---|
| Meta keys | `author` and `description` in 100% of rules. `reference` 70%, `severity` 42%, `rule_id`/`rule_name`/`priority`/`type` 37%. Several parallel MITRE schemes (`tactic`/`technique`, `mitre_attack_tactic`/`mitre_attack_technique`, `mitre`). | Standard keys are learned per repository rather than hard-coded. Typo detection (`YL406`) and allowed-value checks (`YL403`). |
| Outcome variables | `$risk_score` (369 rules), `$event_count` (243), then `$principal_ip`, `$principal_user_userid`, `$principal_process_*` … | Learned standard outcomes (`YL502`) plus completions that insert the team's usual expression. |
| Functions | `re.regex` (2,459 calls), `strings.contains`, `strings.to_lower`, `strings.concat`, `re.capture`, `net.ip_in_range_cidr`…; aggregates `array_distinct` (3,180), `count_distinct`, `max`, `if`. | Catalog with docs, arity and section checks. `re.*` patterns are validated for RE2 compatibility. |
| Style guide | `rule_id` = `mr_<uuidv4>`; severity/priority ∈ Info…Critical; a severity→`risk_score` table (35/65/85/95); ≤20 outcomes; descriptive event variables (not `$e1`); expose thresholds as outcomes; no redundant `!= ""` on match variables; filter on `metadata.event_type`, plus `entity_type`/`source_type` for entity rules. | Encoded as `YL404` (via `metaPatterns`), `YL403`, `YL504`, `YL503`, `YL208`, `YL506`, `YL603`, `YL306`, `YL307`. |
| Syntax edge cases | Uppercase `NOT (`/`AND`, raw backtick strings, `/regex/ nocase`, `%list` and `%table.column`, `#placeholder` counts in `condition:`, event variables referenced only through derived placeholders. | The parser handles all of these. Each one produced false positives during development and now has a regression test. |
| Deprecated rules | 13 errors in one legacy rule (a real multi-line string bug). The rest parse cleanly. | Confirms the tolerant parser on production content. |

### Pain points for YARA-L developers

- **The feedback loop runs through the SecOps UI.** Compiler errors, test runs and retrohunts all need the web console, so feedback before a commit is slow.
- **Standards live in people's heads.** Meta keys, risk scores and outcome fields drift between authors. Downstream SOAR playbooks and dashboards then break on missing outcome fields.
- **UDM is large and nested.** Field names are easy to misspell, and nothing warns until the rule matches nothing.
- **Multi-event semantics are subtle:** match windows, aggregation requirements in outcomes, zero-value behavior of match variables, and every event variable appearing in the condition.
- **Regexes are RE2.** Lookarounds and backreferences copied from Sigma or PCRE sources don't compile.
- **Reference lists and data tables are external.** A typo in `%allowlist_name` fails only at deploy time.
- **Testing is manual.** Nothing checks locally that a rule matches known-bad samples and skips known-good ones.

## Delivered in v0.1

- Syntax highlighting, language configuration, snippets
- Tolerant parser + 42-rule linter with quick fixes and inline suppressions
- Workspace convention learning (standard meta/outcomes, value enums, typos, duplicate rule names / IDs)
- Hover docs, signature help, completion for functions, UDM paths, enums, variables, reference lists, meta keys/values
- Outline, go to definition, references, rename, highlights, folding, formatter
- `yaral-lint` CLI (text/json/sarif/github, `--fix`, `format --check`, `conventions --init`) and a GitHub Action

## Roadmap

Ordered by value to a detection engineer relative to effort.

### P1: Close the loop with Google SecOps

| Feature | Notes |
|---|---|
| **Verify rule** command + CI step | Call `verifyRuleText` and map compiler errors to diagnostics. Auth via `gcloud` Application Default Credentials locally and Workload Identity Federation in CI. Region-aware base URL (`{region}-chronicle.googleapis.com`). |
| **Test rule / retrohunt from the editor** | Run the current rule over a time range. Show detections, matched events and outcome values in a webview, and diff the results against the deployed version. |
| **Pull / deploy / diff** | Compare local rules with deployed versions and state (enabled, alerting, run frequency), compatible with `content_manager`'s `rule_config.yaml`, then deploy on merge. |
| **Reference lists & data tables** | Validate `%name` / `%table.column` against local `reference_lists/` and `data_tables/` folders (content_manager layout) or the tenant. Hover shows entries, and data-table columns get completions. |

### P2: Deeper static analysis

| Feature | Notes |
|---|---|
| **Full UDM schema** | Generate field catalogs from Google's UDM definitions to flag unknown fields (`$e.principal.hostnmae`) and to show each field's type and repeated/enum status on hover. |
| **Type checking** | Types for function arguments and comparisons: string vs int, timestamps, repeated fields that need `any`/`all`, enum values (`metadata.event_type = "USER_LOGON"` would be flagged). |
| **Condition analysis** | Report conditions that can never fire (`#e > 0 and !$e`), missing `match:` when the condition counts events, and outcome variables in the condition that need a match window. |
| **Cost / performance hints** | Unanchored regexes on high-volume fields, missing `log_type` filters, very large match windows, entity-graph joins without `source_type`. |
| **Search & dashboard queries** | Support UDM search / statistical search syntax (YARA-L query fragments without a `rule {}` wrapper, as in the corpus's `dashboards/` folder). |

### P3: Testing & content quality

| Feature | Notes |
|---|---|
| **Rule unit tests** | `*.test.yaml` next to each rule with sample UDM events and expected match / no-match, plus a local evaluator for single-event rules (and simple multi-event ones). Run in CI without SecOps. |
| **MITRE ATT&CK tooling** | Validate tactic/technique IDs against ATT&CK STIX data, show names on hover, complete IDs, and export an ATT&CK Navigator coverage layer from the repo. |
| **Rule versioning checks** | In CI, flag rules whose logic changed without a `version` meta bump (git-diff aware). Generate a changelog. |
| **Coverage dashboard** | Webview of rules by severity, tactic, log type and data source, with gaps against the log types actually ingested. |
| **Sigma import** | Convert Sigma to YARA-L through pySigma's SecOps backend, then run this linter on the output (for example, RE2 incompatibilities). |

### P4: Platform

| Feature | Notes |
|---|---|
| **Language Server (LSP)** | `src/core` is already editor-agnostic, so wrapping it in an LSP server would support Neovim, JetBrains, Zed and Emacs. |
| **npm-published CLI & pre-commit hook** | `npx yaral-lint` and a first-class `.pre-commit-hooks.yaml`. |
| **Semantic highlighting** | Distinguish event vs. placeholder vs. outcome variables by role rather than by pattern. |
| **VS Code Marketplace / Open VSX release** | Automated publishing from tagged releases. |

## Open questions for the team

- Which meta schema is canonical: `tactic`/`technique` or `mitre_attack_*`? The linter can enforce either once chosen (`requiredMeta`, `metaPatterns`).
- Should `YL504` (severity↔risk score) be a warning for your team, or stay informational?
- Which SecOps region(s) and auth method should the API integration support first?
