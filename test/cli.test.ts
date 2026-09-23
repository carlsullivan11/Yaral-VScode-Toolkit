import { strict as assert } from 'assert';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { test } from 'node:test';
import { EXAMPLES, FIXTURES } from './helpers';

const CLI = path.join(__dirname, '..', '..', 'dist', 'cli.js');
const run = (args: string[], cwd = process.cwd()) => spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8' });

test('CLI passes clean rules and fails bad ones', { skip: !fs.existsSync(CLI) && 'run npm run build first' }, () => {
  assert.equal(run([EXAMPLES]).status, 0);
  const bad = run([path.join(FIXTURES, 'bad_rule.yaral'), '--format', 'json']);
  assert.equal(bad.status, 1);
  const report = JSON.parse(bad.stdout);
  assert.ok(report[0].diagnostics.length > 5);
});

test('CLI emits SARIF and GitHub annotations', { skip: !fs.existsSync(CLI) && 'run npm run build first' }, () => {
  const sarif = JSON.parse(run([path.join(FIXTURES, 'bad_rule.yaral'), '--format', 'sarif']).stdout);
  assert.equal(sarif.version, '2.1.0');
  assert.ok(sarif.runs[0].results.length > 0);
  const gh = run([path.join(FIXTURES, 'bad_rule.yaral'), '--format', 'github']).stdout;
  assert.match(gh, /^::error file=.*bad_rule\.yaral,line=\d+/m);
});

test('CLI format --check and --fix', { skip: !fs.existsSync(CLI) && 'run npm run build first' }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'yaral-'));
  const file = path.join(dir, 'x.yaral');
  fs.writeFileSync(file, 'rule x {\nevents:\n\t$e.x = 1   \ncondition:\n$e\n}\n');
  assert.equal(run(['format', '--check', dir], dir).status, 1);
  assert.equal(run(['--fix', dir], dir).status, 0);
  assert.equal(run(['format', '--check', dir], dir).status, 0);
  assert.match(run([dir], dir).stdout, /0 errors/);
  assert.doesNotMatch(run([dir], dir).stdout, /YL70[12]/);
});
