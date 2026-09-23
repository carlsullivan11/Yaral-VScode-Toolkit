# YARA-L in CI/CD

A typical detection-as-code pipeline has three gates. Each one is cheaper and faster than the next:

| Gate | Tool | Needs credentials | Catches |
|---|---|---|---|
| 1. Editor | YARA-L Toolkit extension | no | Everything below, as you type |
| 2. Pull request | `yaral-lint` / GitHub Action | no | Syntax, structure, variable errors, team standards, formatting |
| 3. Pre-merge / deploy | SecOps `verifyRuleText` API (e.g. Google's `content_manager`) | yes | Anything only Google's compiler knows (UDM field validity, type errors) |

`yaral-lint` covers gates 1 and 2 without credentials, so every contributor and every fork gets the same feedback. Gate 3 is authoritative and belongs on trusted branches with Workload Identity Federation.

## GitHub Actions

Use the composite action in this repository:

```yaml
- uses: actions/checkout@v4
- uses: carlsullivan11/Yaral-VScode-Toolkit@main
  with:
    paths: rules             # space-separated files/dirs
    max-warnings: "0"        # optional
    format-check: "true"     # optional
    sarif-file: yaral.sarif  # optional
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: yaral.sarif
    category: yaral-lint
```

The action:

- adds inline annotations to the PR diff (`--format github`),
- writes a readable report to the job summary,
- fails the job on lint errors (plus warnings above `max-warnings`, and unformatted files when `format-check` is on),
- optionally writes SARIF so findings appear in **Security → Code scanning**.

A complete workflow is in [`examples/github-workflow.yml`](../examples/github-workflow.yml).

### Pinning

Pin the action to a tag or commit SHA (`@v0.1.0` or `@<sha>`) rather than `@main` so rule-repo CI doesn't change underneath you.

## GitLab CI

```yaml
yaral-lint:
  image: node:22
  script:
    - git clone --depth 1 https://github.com/carlsullivan11/Yaral-VScode-Toolkit.git /tmp/yaral
    - (cd /tmp/yaral && npm ci --ignore-scripts && npm run build)
    - node /tmp/yaral/dist/cli.js rules --format json --output yaral-report.json || true
    - node /tmp/yaral/dist/cli.js rules --max-warnings 25
    - node /tmp/yaral/dist/cli.js format --check rules
  artifacts:
    when: always
    paths: [yaral-report.json]
```

## Pre-commit hook

Using a local hook (no extra install beyond a built checkout of this repo):

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: yaral-lint
        name: yaral-lint
        entry: node /path/to/Yaral-VScode-Toolkit/dist/cli.js --quiet
        language: system
        files: \.(yaral|yara-l|yl2)$
```

## Authoritative verification with Google SecOps

Google's [`content_manager`](https://github.com/chronicle/detection-rules/tree/main/tools/content_manager) calls the SecOps `verifyRuleText` endpoint (`POST {instance}:verifyRuleText` with `{"rule_text": ...}`) and can also pull, update, enable and archive rules, reference lists, data tables and rule exclusions. A suggested flow:

1. **PR opened**: run `yaral-lint` (fast, no secrets).
2. **PR approved / merge queue**: authenticate with Workload Identity Federation and run `content_manager` rule verification on the changed rules.
3. **Merge to main**: `content_manager` updates rules in SecOps from the local files and `rule_config.yaml` (enabled, alerting, run frequency).

Keep `yaral-lint` required on every PR even when gate 3 exists. It runs in seconds, needs no secrets, and enforces your team's conventions, which the SecOps compiler doesn't know about.

## Recommended rollout

1. Run `yaral-lint conventions rules` to see what your rules already agree on.
2. `yaral-lint conventions rules --init` to write `.yaral-lint.json`, then review it.
3. Start CI with `--max-warnings` set to today's count, then lower it over time.
4. Run `yaral-lint --fix rules && yaral-lint format rules` once to clear mechanical issues in a single commit.
