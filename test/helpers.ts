import * as path from 'path';

export const FIXTURES = path.join(__dirname, '..', '..', 'test', 'fixtures');
export const EXAMPLES = path.join(__dirname, '..', '..', 'examples', 'rules');

/** Wraps rule sections into a minimal valid rule. */
export function rule(body: string, name = 'test_rule'): string {
  return `rule ${name} {\n${body}\n}\n`;
}

export const MINIMAL = rule(`  meta:
    author = "a"
    description = "d"
    severity = "Low"

  events:
    $login.metadata.event_type = "USER_LOGIN"

  condition:
    $login`);
