/**
 * yaral-lint — command-line YARA-L linter/formatter for CI/CD pipelines.
 *
 *   yaral-lint [lint] <paths...>   Lint rules (default command)
 *   yaral-lint format <paths...>   Format rules (--check for CI)
 *   yaral-lint conventions <paths> Report learned workspace conventions
 *   yaral-lint rules               List lint rules
 */

import * as fs from 'fs';
import * as path from 'path';
import {
  applyFixes,
  buildConventions,
  buildMitreCoverage,
  mitreCoverageReport,
  MitreFramework,
  navigatorLayer,
  buildFunctionIndex,
  CONFIG_FILENAME,
  Conventions,
  conventionsReport,
  findRuleFiles,
  format,
  LINT_RULES,
  lint,
  LintConfig,
  LintDiagnostic,
  loadConfig,
  matchesAnyGlob,
  RuleSummary,
  suggestedConfig,
  summarizeText,
} from '../core';
import { version } from '../../package.json';

const VERSION: string = version;

interface Args {
  command: string;
  paths: string[];
  flags: Record<string, string | boolean>;
}

function parseArgs(argv: string[]): Args {
  const commands = new Set(['lint', 'format', 'conventions', 'mitre', 'rules', 'help']);
  const flags: Record<string, string | boolean> = {};
  const paths: string[] = [];
  let command = 'lint';
  const valued = new Set(['config', 'format', 'max-warnings', 'output', 'rule', 'threshold', 'layer', 'framework']);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const [k, v] = a.slice(2).split('=', 2);
      if (v !== undefined) flags[k] = v;
      else if (valued.has(k)) flags[k] = argv[++i] ?? '';
      else flags[k] = true;
    } else if (a === '-h') flags.help = true;
    else if (a === '-v') flags.version = true;
    else if (paths.length === 0 && command === 'lint' && commands.has(a) && !fs.existsSync(a)) command = a;
    else paths.push(a);
  }
  return { command, paths, flags };
}

const HELP = `yaral-lint ${VERSION} — YARA-L 2.0 linter for Google SecOps detection-as-code

Usage:
  yaral-lint [lint] [paths...] [options]    Lint .yaral files (default: current directory)
  yaral-lint format [paths...] [--check]    Format files in place, or verify formatting
  yaral-lint conventions [paths...]         Show meta/outcome conventions learned from rules
  yaral-lint mitre [paths...]               MITRE ATT&CK / ATLAS coverage of the rules
  yaral-lint rules                          List all lint rules

Lint options:
  --config <file>        Path to ${CONFIG_FILENAME} (default: nearest to cwd)
  --format <fmt>         text (default) | json | sarif | github
  --output <file>        Write the report to a file instead of stdout
  --max-warnings <n>     Exit non-zero if more than n warnings (default: unlimited)
  --quiet                Report errors only
  --fix                  Apply safe automatic fixes
  --no-conventions       Do not learn conventions from other rules

Conventions options:
  --json                 Output JSON statistics
  --init                 Write a ${CONFIG_FILENAME} derived from the conventions
  --threshold <0-1>      Coverage required for a key to be "standard"

MITRE options:
  --json                 Output JSON coverage
  --layer <file>         Write an ATT&CK Navigator layer (with --framework enterprise|ics|mobile)

Exit codes: 0 ok, 1 lint errors / too many warnings / unformatted files, 2 usage error.
`;

function main(): number {
  const args = parseArgs(process.argv.slice(2));
  if (args.flags.version) {
    console.log(VERSION);
    return 0;
  }
  if (args.flags.help || args.command === 'help') {
    console.log(HELP);
    return 0;
  }
  const inputs = args.paths.length ? args.paths : ['.'];
  let config: LintConfig;
  let configFile: string | undefined;
  try {
    ({ config, file: configFile } = loadConfig(process.cwd(), typeof args.flags.config === 'string' ? args.flags.config : undefined));
  } catch (e) {
    console.error((e as Error).message);
    return 2;
  }
  if (typeof args.flags.threshold === 'string') config.conventions.threshold = Number(args.flags.threshold);

  switch (args.command) {
    case 'rules':
      for (const r of LINT_RULES) console.log(`${r.id}  ${r.name.padEnd(30)} ${r.severity.padEnd(8)} ${r.description}`);
      return 0;
    case 'format':
      return runFormat(inputs, config, !!args.flags.check);
    case 'conventions':
      return runConventions(inputs, config, args);
    case 'mitre':
      return runMitre(inputs, config, args);
    default:
      return runLint(inputs, config, configFile, args);
  }
}

function collectConventions(files: string[], config: LintConfig, texts: Map<string, string>): Conventions {
  const summaries: RuleSummary[] = [];
  for (const f of files) {
    if (matchesAnyGlob(f, config.conventions.exclude)) continue;
    summaries.push(...summarizeText(texts.get(f) ?? fs.readFileSync(f, 'utf8'), f));
  }
  return buildConventions(summaries, config.conventions.threshold, config.conventions.minRules);
}

function runLint(inputs: string[], config: LintConfig, configFile: string | undefined, args: Args): number {
  const files = findRuleFiles(inputs, config.ignore);
  if (files.length === 0) {
    console.error(`No YARA-L files found in ${inputs.join(', ')}`);
    return 2;
  }
  const texts = new Map(files.map((f) => [f, fs.readFileSync(f, 'utf8')]));
  const conventions = config.conventions.enabled && !args.flags['no-conventions'] ? collectConventions(files, config, texts) : undefined;
  const functions = buildFunctionIndex(config.functions);

  const results: { file: string; diagnostics: LintDiagnostic[] }[] = [];
  let fixed = 0;
  for (const file of files) {
    let text = texts.get(file)!;
    let diagnostics = lint(text, { filePath: file, config, conventions, functions });
    if (args.flags.fix) {
      // Only fixes that don't need human input (no empty placeholders).
      const safe = new Set(['YL603', 'YL701', 'YL702', 'YL403']);
      const res = applyFixes(text, diagnostics, safe);
      if (res.applied > 0) {
        text = format(res.text);
        fs.writeFileSync(file, text);
        fixed += res.applied;
        diagnostics = lint(text, { filePath: file, config, conventions, functions });
      }
    }
    if (args.flags.quiet) diagnostics = diagnostics.filter((d) => d.severity === 'error');
    results.push({ file, diagnostics });
  }

  const all = results.flatMap((r) => r.diagnostics);
  const errors = all.filter((d) => d.severity === 'error').length;
  const warnings = all.filter((d) => d.severity === 'warning').length;

  const fmt = typeof args.flags.format === 'string' ? args.flags.format : 'text';
  let report: string;
  if (fmt === 'json') report = JSON.stringify(results.map((r) => ({ file: path.relative(process.cwd(), r.file), diagnostics: r.diagnostics })), null, 2);
  else if (fmt === 'sarif') report = JSON.stringify(toSarif(results), null, 2);
  else if (fmt === 'github') report = toGithub(results);
  else report = toText(results, files.length, configFile, conventions, fixed);

  if (typeof args.flags.output === 'string') fs.writeFileSync(args.flags.output, report + '\n');
  else if (report) console.log(report);
  if (fmt === 'github') console.error(summaryLine(files.length, errors, warnings, all.length - errors - warnings));

  const maxWarnings = typeof args.flags['max-warnings'] === 'string' ? Number(args.flags['max-warnings']) : Infinity;
  return errors > 0 || warnings > maxWarnings ? 1 : 0;
}

function summaryLine(files: number, errors: number, warnings: number, infos: number): string {
  return `${files} file${files === 1 ? '' : 's'} checked: ${errors} error${errors === 1 ? '' : 's'}, ${warnings} warning${warnings === 1 ? '' : 's'}, ${infos} info`;
}

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const color = (code: string, s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const SEV_COLOR: Record<string, string> = { error: '31', warning: '33', info: '36', hint: '90' };

function toText(results: { file: string; diagnostics: LintDiagnostic[] }[], fileCount: number, configFile?: string, conventions?: Conventions, fixed = 0): string {
  const lines: string[] = [];
  for (const r of results) {
    if (r.diagnostics.length === 0) continue;
    lines.push(color('4', path.relative(process.cwd(), r.file)));
    for (const d of r.diagnostics) {
      const pos = `${d.range.start.line + 1}:${d.range.start.character + 1}`.padEnd(8);
      lines.push(`  ${pos} ${color(SEV_COLOR[d.severity], d.severity.padEnd(7))} ${d.message}  ${color('90', `${d.ruleId}/${d.ruleName}`)}`);
    }
    lines.push('');
  }
  const all = results.flatMap((r) => r.diagnostics);
  const errors = all.filter((d) => d.severity === 'error').length;
  const warnings = all.filter((d) => d.severity === 'warning').length;
  lines.push(summaryLine(fileCount, errors, warnings, all.length - errors - warnings));
  if (fixed) lines.push(`Applied ${fixed} fix${fixed === 1 ? '' : 'es'}.`);
  const notes = [configFile ? `config: ${path.relative(process.cwd(), configFile)}` : 'config: defaults'];
  if (conventions) notes.push(`conventions learned from ${conventions.ruleCount} rules`);
  lines.push(color('90', notes.join(' · ')));
  return lines.join('\n');
}

function toGithub(results: { file: string; diagnostics: LintDiagnostic[] }[]): string {
  const level: Record<string, string> = { error: 'error', warning: 'warning', info: 'notice', hint: 'notice' };
  const esc = (s: string) => s.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
  return results
    .flatMap((r) =>
      r.diagnostics.map(
        (d) =>
          `::${level[d.severity]} file=${path.relative(process.cwd(), r.file)},line=${d.range.start.line + 1},col=${d.range.start.character + 1},endLine=${d.range.end.line + 1},endColumn=${d.range.end.character + 1},title=${d.ruleId} ${d.ruleName}::${esc(d.message)}`,
      ),
    )
    .join('\n');
}

function toSarif(results: { file: string; diagnostics: LintDiagnostic[] }[]) {
  const level: Record<string, string> = { error: 'error', warning: 'warning', info: 'note', hint: 'note' };
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'yaral-lint',
            version: VERSION,
            informationUri: 'https://github.com/carlsullivan11/Yaral-VScode-Toolkit',
            rules: LINT_RULES.map((r) => ({
              id: r.id,
              name: r.name,
              shortDescription: { text: r.description },
              defaultConfiguration: { level: level[r.severity] ?? 'none' },
            })),
          },
        },
        results: results.flatMap((r) =>
          r.diagnostics.map((d) => ({
            ruleId: d.ruleId,
            level: level[d.severity],
            message: { text: d.message },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: path.relative(process.cwd(), r.file).split(path.sep).join('/') },
                  region: {
                    startLine: d.range.start.line + 1,
                    startColumn: d.range.start.character + 1,
                    endLine: d.range.end.line + 1,
                    endColumn: d.range.end.character + 1,
                  },
                },
              },
            ],
          })),
        ),
      },
    ],
  };
}

function runFormat(inputs: string[], config: LintConfig, check: boolean): number {
  const files = findRuleFiles(inputs, config.ignore);
  let changed = 0;
  for (const f of files) {
    const text = fs.readFileSync(f, 'utf8');
    const formatted = format(text);
    if (formatted === text) continue;
    changed++;
    if (check) console.log(`Needs formatting: ${path.relative(process.cwd(), f)}`);
    else {
      fs.writeFileSync(f, formatted);
      console.log(`Formatted ${path.relative(process.cwd(), f)}`);
    }
  }
  console.error(`${files.length} files checked, ${changed} ${check ? 'need formatting' : 'formatted'}`);
  return check && changed > 0 ? 1 : 0;
}

function runConventions(inputs: string[], config: LintConfig, args: Args): number {
  const files = findRuleFiles(inputs, config.ignore);
  const conventions = collectConventions(files, config, new Map());
  if (args.flags.init) {
    const target = path.join(process.cwd(), CONFIG_FILENAME);
    if (fs.existsSync(target) && !args.flags.force) {
      console.error(`${CONFIG_FILENAME} already exists (use --force to overwrite)`);
      return 2;
    }
    fs.writeFileSync(target, JSON.stringify(suggestedConfig(conventions), null, 2) + '\n');
    console.log(`Wrote ${target}`);
    return 0;
  }
  console.log(args.flags.json ? JSON.stringify(conventions, null, 2) : conventionsReport(conventions));
  return 0;
}

function runMitre(inputs: string[], config: LintConfig, args: Args): number {
  const files = findRuleFiles(inputs, config.ignore);
  const summaries = files.flatMap((f) => summarizeText(fs.readFileSync(f, 'utf8'), f));
  const coverage = buildMitreCoverage(summaries, config.mitre);
  if (typeof args.flags.layer === 'string') {
    const framework = (typeof args.flags.framework === 'string' ? args.flags.framework : 'enterprise') as MitreFramework;
    try {
      fs.writeFileSync(args.flags.layer, JSON.stringify(navigatorLayer(coverage, framework), null, 2) + '\n');
    } catch (e) {
      console.error((e as Error).message);
      return 2;
    }
    console.log(`Wrote ${framework} Navigator layer to ${args.flags.layer}`);
    return 0;
  }
  if (args.flags.json) {
    const plain = {
      frameworks: coverage.frameworks.map((f) => ({ ...f, techniques: Object.fromEntries(f.techniques), tactics: Object.fromEntries(f.tactics) })),
      unmappedRules: coverage.unmappedRules,
    };
    console.log(JSON.stringify(plain, null, 2));
  } else console.log(mitreCoverageReport(coverage));
  return 0;
}

process.exitCode = main();
