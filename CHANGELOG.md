# Changelog

## 0.2.0

- MIT license
- MITRE ATT&CK Enterprise, ICS and Mobile (v19.2) and ATLAS (2026.09) support for `tactic` / `technique` meta:
  - lint rules YL408–YL412 (unknown IDs, revoked/deprecated techniques with replacement fixes, names instead of IDs, technique/tactic mismatch, alternative MITRE meta keys)
  - hover with names and links; ID completion that matches by ID or name
  - `yaral-lint mitre` coverage report and ATT&CK Navigator layer export (also as VS Code commands)
  - `npm run update-mitre` and a monthly workflow to refresh the data
- ICS and ATLAS example rules; `mitre-ics` / `mitre-atlas` snippets

## 0.1.0

Initial release.

- YARA-L 2.0 syntax highlighting, language configuration and snippets
- Tolerant parser and 42-rule linter with quick fixes and inline suppressions
- Workspace convention learning: standard meta keys / outcome variables, meta value enums, typo and duplicate detection
- Hover documentation, signature help and completion for functions, UDM fields, enums, variables, reference lists, meta keys and values
- Outline, go to definition, find references, rename, highlights, folding and a whitespace-only formatter
- `yaral-lint` CLI (text / JSON / SARIF / GitHub annotations, `--fix`, `format --check`, `conventions --init`) and a GitHub Action
