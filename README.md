# YARA-L Toolkit for VS Code

Language support and a CI/CD linter for **YARA-L 2.0**, the detection language of Google Security Operations (SecOps / Chronicle).

It's built for detection-as-code teams. The same engine runs in the editor and in your pipeline (`yaral-lint`), so rules are checked the same way before they reach SecOps. It also learns your team's conventions from the rules already in the repository, such as the standard `meta` keys and the usual `outcome` variables. New rules are then held to the same standard.

## Features

| Area | What you get |
|---|---|
| **Highlighting** | TextMate grammar: sections, meta keys, event/placeholder/count variables, UDM field paths, `%reference_lists`, regex literals (vs. division), raw strings, durations, functions, case-insensitive `AND`/`OR`/`NOT`. |
| **Linting** | 47 rules ([docs/lint-rules.md](docs/lint-rules.md)): syntax, section order, undefined or unused variables, match windows, non-aggregated outcomes, unknown functions and argument counts, RE2 regex validity, required/allowed meta values, severity↔`$risk_score`, performance hints, whitespace. |
| **Workspace conventions** | Indexes every `.yaral` file to find standard meta keys and outcome variables (default: present in ≥80% of rules). Flags missing ones and offers them as completions with the team's usual expression. Also catches meta-key typos (`sevirity`) and duplicate rule names / `rule_id`s across the repo. |
| **MITRE ATT&CK & ATLAS** | Validates `tactic` / `technique` meta against ATT&CK **Enterprise**, **ICS** and **Mobile** (v19.2) and **ATLAS** (AI systems, 2026.09). Catches unknown IDs, revoked techniques (fixed to their replacement), names used instead of IDs, and techniques outside the listed tactics. Hover shows names and links; completion matches by ID or name. Coverage report and ATT&CK Navigator layer export. |
| **Function docs** | Hover docs, signature help and completion for every built-in function (`strings.*`, `re.*`, `net.*`, `math.*`, `timestamp.*`, `arrays.*`, `cast.*`, `window.*`, outcome aggregates…). Custom entries can be added in config. |
| **Completion** | UDM field paths after `$event.` (from ~900 real rules), `metadata.event_type` / `entity_type` / `source_type` / `security_result.action` enums, rule variables, reference lists used elsewhere in the repo, meta keys and values, section headers. |
| **Navigation** | Outline (rule → sections → meta / variables / outcomes), go to definition, find references, highlight, **rename variable**, folding. |
| **Quick fixes** | Add missing meta / outcome (pre-filled from conventions), fix meta value case, fix function-name typos, remove redundant zero checks, rename rule to file name, remove trailing whitespace, suppress a rule for one line. |
| **Formatting** | Whitespace-only formatter (indentation, trailing space, blank lines). It never changes tokens; this was verified on all 917 public Google rules. |
| **Snippets** | `rule`, `rule-multi`, `rule-sequence` (with auto-generated `mr_<uuid>` `rule_id`), `entity-join`, `risk`, `risk-if`, `mitre`, `license`, … |
| **CI/CD** | `yaral-lint` CLI with `text`, `json`, `sarif` (GitHub code scanning) and `github` (PR annotations) output, `--fix`, `format --check`, and a reusable GitHub Action. |

## Getting started

```bash
npm ci
npm run build          # dist/extension.js + dist/cli.js
npm test
npm run package        # builds yaral-toolkit-<version>.vsix
code --install-extension yaral-toolkit-0.2.0.vsix
```

To develop the extension, open this folder in VS Code and press **F5**. That launches an Extension Development Host on `examples/`.

Rule files are recognized by extension: `.yaral`, `.yara-l`, `.yl2`.

### Commands

- **YARA-L: Show Workspace Conventions Report**: meta-key / outcome coverage, common values and duplicates (also opened from the status-bar item).
- **YARA-L: Show MITRE ATT&CK / ATLAS Coverage**: tactic/technique coverage per framework, plus rules with no mapping.
- **YARA-L: Export ATT&CK Navigator Layer**: a layer file (Enterprise, ICS or Mobile) to open in the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
- **YARA-L: Create .yaral-lint.json From Workspace Conventions**: turns the learned standards into an enforced config.
- **YARA-L: Lint All Rules in Workspace**: fills the Problems panel for every rule, not just open files.
- **YARA-L: Insert New rule_id (mr_&lt;uuid&gt;)**
- **YARA-L: Re-index Workspace Rules**

## Configuration: `.yaral-lint.json`

Put this file at the root of your rules repository. The extension and the CLI both use the nearest one, so developers and CI enforce the same standards. VS Code settings (`yaral.*`) provide the defaults, and the file overrides them.

```jsonc
{
  // Meta keys every rule must have
  "requiredMeta": ["author", "description", "rule_id", "severity", "priority"],
  // Allowed values (quick fix corrects case, e.g. "high" -> "High")
  "metaValues": {
    "severity": ["Info", "Low", "Medium", "High", "Critical"],
    "type": ["alert", "hunt"]
  },
  // Regexes meta values must match
  "metaPatterns": { "rule_id": "^mr_[0-9a-f-]{36}$", "technique": "^T\\d{4}(\\.\\d{3})?$" },
  // Outcome variables every rule must define
  "requiredOutcomes": ["risk_score"],
  // Severity overrides by id or name: error | warning | info | hint | off
  "rules": { "YL208": "off", "hardcoded-threshold": "warning" },
  "maxMatchWindow": "48h",
  "maxOutcomes": 20,
  "filenameMatchesRuleName": true,
  "ignore": ["**/node_modules/**"],
  // Convention learning from the other rules in the repo
  "conventions": { "enabled": true, "threshold": 0.8, "minRules": 5, "exclude": ["**/_deprecated/**"] },
  // MITRE validation of tactic/technique meta (IDs, comma-separated)
  "mitre": {
    "frameworks": ["enterprise", "ics", "mobile", "atlas"],
    "defaultFramework": "enterprise",   // resolves ambiguous names like "Initial Access"
    "tacticKey": "tactic",
    "techniqueKey": "technique"
  },
  // Teach the linter about functions Google adds before the catalog is updated
  "functions": [
    { "name": "strings.new_function", "params": [{ "name": "text", "type": "string" }], "returns": "string", "description": "…" }
  ]
}
```

`yaral-lint conventions --init` (or the matching VS Code command) writes a starting config from the rules you already have.

Suppress a finding inline with `// yaral-lint-disable-next-line YL205`, `// yaral-lint-disable-line unused-placeholder`, or file-wide with `// yaral-lint-disable YL208`.

## CLI: `yaral-lint`

```text
yaral-lint [lint] [paths...]      Lint .yaral files (default: .)
  --format text|json|sarif|github  --output <file>  --max-warnings <n>
  --quiet  --fix  --no-conventions  --config <file>
yaral-lint format [paths...] [--check]
yaral-lint conventions [paths...] [--json] [--init]
yaral-lint mitre [paths...] [--json] [--layer layer.json --framework enterprise|ics|mobile]
yaral-lint rules
```

Exit codes: `0` clean, `1` errors / too many warnings / unformatted files, `2` usage error.

### GitHub Actions

```yaml
- uses: carlsullivan11/Yaral-VScode-Toolkit@main
  with:
    paths: rules
    max-warnings: "25"
    format-check: "true"
    sarif-file: yaral.sarif   # optional, for github/codeql-action/upload-sarif
```

See [examples/github-workflow.yml](examples/github-workflow.yml) and [docs/ci-cd.md](docs/ci-cd.md) for the full detection-as-code pipeline. That includes GitLab CI, pre-commit hooks, and deploying through Google's `content_manager` with the authoritative `verifyRuleText` check.

## MITRE frameworks

Rules map to MITRE with IDs in `tactic` and `technique` meta. A key can hold several comma-separated IDs, and frameworks can be mixed:

```yaral
tactic = "TA0108, TA0109"          // ATT&CK for ICS
technique = "T0886"
tactic = "AML.TA0005"              // ATLAS
technique = "AML.T0051.000"
```

The bundled data comes straight from MITRE's official releases ([attack-stix-data](https://github.com/mitre-attack/attack-stix-data) and [atlas-data](https://github.com/mitre-atlas/atlas-data)). Refresh it with `npm run update-mitre`; a monthly workflow does this automatically and opens a PR. Rules that use `mitre_attack_tactic`-style keys get a quick fix to rename them.

## Scope and accuracy

- The parser is tolerant and section-oriented, not Google's compiler. It parses all 917 rules in [chronicle/detection-rules](https://github.com/chronicle/detection-rules) and reports a syntax error only in one deprecated rule that really is broken. Use SecOps' `verifyRuleText` API in CI as the final authority (see [docs/ci-cd.md](docs/ci-cd.md)).
- The function catalog (`src/core/catalog/functions.ts`) follows Google's YARA-L 2.0 function reference, but Google adds functions often. Unknown functions are warnings, not errors, and can be declared under `functions` in config.
- UDM completion covers a curated subset of UDM, taken from the fields real rules use. It is not the full schema; see the [roadmap](docs/ROADMAP.md).

## Project layout

```
src/core/        editor-agnostic engine (lexer, parser, linter, conventions, formatter, catalogs)
src/extension/   VS Code providers (diagnostics, hover, completion, symbols, rename, ...)
src/cli/         yaral-lint CLI
syntaxes/        TextMate grammar
snippets/        rule templates
test/            node:test suites + fixtures
docs/            lint rule reference, CI/CD guide, research & roadmap
```

## License

[MIT](LICENSE). MITRE ATT&CK® and ATLAS™ data is © The MITRE Corporation and is reproduced under MITRE's [terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) for the research behind the feature set and what's planned next: SecOps API integration (verify, test and deploy rules), full UDM schema and type checking, reference-list / data-table validation, rule unit tests, deeper MITRE coverage analysis, and a language server for other editors.
