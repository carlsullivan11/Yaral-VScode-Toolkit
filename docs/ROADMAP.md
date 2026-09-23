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

## Decisions

| Topic | Decision |
|---|---|
| License | MIT |
| MITRE meta schema | `tactic` / `technique` with IDs (comma-separated for several). `mitre_attack_*` and similar keys are flagged by `YL412`, with a rename quick fix. |
| MITRE frameworks | ATT&CK Enterprise, ATT&CK for ICS, ATT&CK Mobile and ATLAS, all enabled by default (`mitre.frameworks`). |

## Delivered

### v0.1

- Syntax highlighting, language configuration, snippets
- Tolerant parser + linter with quick fixes and inline suppressions
- Workspace convention learning (standard meta/outcomes, value enums, typos, duplicate rule names / IDs)
- Hover docs, signature help, completion for functions, UDM paths, enums, variables, reference lists, meta keys/values
- Outline, go to definition, references, rename, highlights, folding, formatter
- `yaral-lint` CLI (text/json/sarif/github, `--fix`, `format --check`, `conventions --init`) and a GitHub Action

### v0.2: MITRE frameworks (pulled forward from Stage 4)

- Bundled catalog generated from MITRE's official data: ATT&CK v19.2 (Enterprise 858, ICS 106, Mobile 176 techniques) and ATLAS 2026.09 (208 techniques), including revocations and their replacements. It is refreshed with `npm run update-mitre` and a monthly workflow that opens a PR.
- Lint rules `YL408`–`YL412`:
  - unknown or wrong-kind IDs, and IDs from frameworks that aren't enabled
  - revoked/deprecated techniques, with a fix to the replacement (for example, v19 revoked T1562 → T1685)
  - names instead of IDs, fixed to the ID using the framework the rule already uses (e.g. "Initial Access" → TA0108 in an ICS rule)
  - techniques not under any listed tactic
  - alternative meta keys
- Hover on IDs (name, framework, tactics, link) and ID completion that matches by ID or name, ranking techniques under the rule's tactics first.
- `yaral-lint mitre` coverage report for all four frameworks, and ATT&CK Navigator layer export (`--layer`, Enterprise/ICS/Mobile). Both are also available as VS Code commands.
- `mitre`, `mitre-ics` and `mitre-atlas` snippets. The ICS and ATLAS example rules use them.

## Staged plan

```
Stage 0 ──► Stage 1 (SecOps API) ──────────────────────┐
       └──► Stage 2 (expression parser, UDM, types) ──► Stage 3 (rule tests) ──► Stage 4 (quality & insight)
                                                           Stage 5 (LSP, queries) after Stage 2
```

Stages 1 and 2 are independent and can run in parallel. The recommended order is Stage 0, then Stage 1 steps 1–2 (setup and verify rule), then the Stage 2 parser.

### Stage 0: Make it trustworthy (about 1–2 weeks)

| Work | Why |
|---|---|
| Automated tests inside real VS Code (`@vscode/test-electron`) in CI | So far the extension has only been exercised through a mocked `vscode` API. |
| Verify the function catalog against Google's function reference | It was written without access to the docs. Add a check that fails when the catalog and docs disagree. |
| CI and the GitHub Action green on GitHub | Neither has run on GitHub yet. |
| Publish: VS Code Marketplace, Open VSX, npm (`npx yaral-lint`) | MIT license is in place. |
| Pre-commit hook (`.pre-commit-hooks.yaml`) | Linting before each commit. |
| Performance test on about 5,000 rules | Keep indexing and re-linting fast as repos grow. |

**Done when:** the extension is published, CI is green, and the catalog is verified.

### Stage 1: Connect to Google SecOps

1. **Setup:** a `secops` block in `.yaral-lint.json` (project, region, instance). Auth uses `gcloud` Application Default Credentials locally and Workload Identity Federation in CI.
2. **Verify rule:** `verifyRuleText` errors shown as diagnostics, on demand or on save, and as `yaral-lint verify` in CI. Results are cached by rule-text hash, and 429 responses are retried.
3. **Test rule / retrohunt:** run the rule over a time range and show detections, matched events and outcomes in a panel, with a diff against the deployed version.
4. **Pull / diff / deploy:** compatible with `content_manager`'s `rule_config.yaml` layout.
5. **Reference lists and data tables:** validate `%names` locally or against the tenant, and show contents on hover.

**Risk:** the SecOps API is `v1alpha`, so all calls sit behind one client module.

### Stage 2: Expression parser and deeper static analysis

1. **Expression parser:** a real syntax tree for `events:`, `condition:` and `outcome:`. Existing checks migrate onto it, and the 917-rule Google corpus becomes a regression test.
2. **Full UDM schema:** field existence, types, enum values (`USER_LOGON` would be flagged), and repeated fields that need `any`/`all`.
3. **Type checking:** function argument types, string vs. number comparisons, timestamps.
4. **Condition analysis:** conditions that can never fire, counts without `match:`, outcome variables in the condition without a window.

### Stage 3: Rule unit tests (needs Stage 2)

- `<rule>.test.yaml` next to each rule, with sample UDM events and expected match / no-match.
- A local evaluator: single-event rules first, then match windows and joins.
- `yaral-lint test` in CI, plus VS Code Testing panel integration.
- Import real events from SecOps (Stage 1) as test fixtures.

**Done when:** breaking a known-bad sample fails CI without SecOps credentials.

### Stage 4: Content quality and insight

| Feature | Notes |
|---|---|
| **MITRE: data-source-aware coverage** | Cross-reference techniques with the log types a rule uses. Show which covered techniques depend on log sources you don't ingest. |
| **MITRE: detection gaps** | Highlight high-prevalence techniques with no rule, per framework. For ICS, filter by the asset types in scope. |
| **MITRE: ATLAS Navigator layers** | Add layer export once the ATLAS Navigator's domain/version format is confirmed. ATT&CK layers already ship. |
| **MITRE: other frameworks** | Candidates: MITRE D3FEND (defensive mapping), the CAPEC → ATT&CK bridge, and cloud-specific views (ATT&CK Enterprise's IaaS/SaaS/Identity Provider platforms as filters). The data pipeline already handles multiple frameworks, so adding one means another converter in `scripts/update-mitre.mjs`. |
| **Version checks in CI** | Flag logic changes without a `version` meta bump, and generate a changelog. |
| **CodeLens above each rule** | Severity, risk score, deployed state, detections in the last 7 days (Stage 1). |
| **Coverage dashboard** | Webview by tactic, log type and severity, with gaps against ingested log types. |
| **Sigma import** | Via pySigma's SecOps backend, then linted (e.g. RE2 incompatibilities). |

### Stage 5: Platform

- **Language server** wrapping the editor-agnostic `src/core` (Neovim, JetBrains, Zed, Emacs).
- **UDM search / dashboard queries** without a `rule {}` wrapper.
- **Semantic highlighting** by variable role.

## Open questions

- Which SecOps region(s) and auth method should Stage 1 support first? Is a test tenant available?
- Should `YL504` (severity↔risk score) and `YL411` (technique/tactic mismatch) be warnings for your team, or stay informational?
- Do you use Google's `content_manager` layout? If so, Stage 1 should read and write its files.
