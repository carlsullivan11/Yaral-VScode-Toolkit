import * as fs from 'fs';
import * as path from 'path';
import { matchesAnyGlob } from './config';

export const YARAL_EXTENSIONS = ['.yaral', '.yara-l', '.yl2'];

export function isYaralFile(file: string): boolean {
  return YARAL_EXTENSIONS.some((ext) => file.toLowerCase().endsWith(ext));
}

/** Recursively collects YARA-L files under the given files/directories. */
export function findRuleFiles(inputs: string[], ignore: string[] = []): string[] {
  const out = new Set<string>();
  const walk = (p: string) => {
    if (matchesAnyGlob(path.resolve(p), ignore)) return;
    let stat: fs.Stats;
    try {
      stat = fs.statSync(p);
    } catch {
      return;
    }
    if (stat.isDirectory()) {
      const base = path.basename(p);
      if (base === 'node_modules' || (base.startsWith('.') && base.length > 1 && p !== inputs[0])) return;
      for (const entry of fs.readdirSync(p).sort()) walk(path.join(p, entry));
    } else if (isYaralFile(p)) {
      out.add(path.resolve(p));
    }
  };
  for (const input of inputs) {
    // Files named explicitly are always linted, even if they don't use a known extension.
    if (fs.existsSync(input) && fs.statSync(input).isFile()) out.add(path.resolve(input));
    else walk(input);
  }
  return [...out];
}
