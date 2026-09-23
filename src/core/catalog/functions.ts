/**
 * YARA-L 2.0 function catalog.
 *
 * Powers hover documentation, completion, signature help and the
 * unknown-function / argument-count lint checks. Google adds functions to
 * YARA-L regularly; teams can add or override entries without a new
 * extension release through `functions` in `.yaral-lint.json`.
 *
 * Reference: https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-functions
 */

export interface FunctionParam {
  name: string;
  type: string;
  description?: string;
  optional?: boolean;
  /** Parameter may be repeated (variadic). */
  repeated?: boolean;
}

export interface FunctionDef {
  name: string;
  params: FunctionParam[];
  returns: string;
  description: string;
  example?: string;
  /** Outcome-section aggregation function. */
  aggregate?: boolean;
  /** Sections where the function may be used. Omitted means anywhere. */
  sections?: string[];
  docUrl?: string;
}

const DOCS = 'https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-functions';
const OUTCOME_DOCS = 'https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax#outcome_section_syntax';

const p = (name: string, type: string, description?: string, extra: Partial<FunctionParam> = {}): FunctionParam => ({
  name,
  type,
  description,
  ...extra,
});

const agg = (name: string, description: string, returns: string, example: string): FunctionDef => ({
  name,
  params: [p('expression', 'any', 'Expression evaluated for every event in the match window.')],
  returns,
  description,
  example,
  aggregate: true,
  sections: ['outcome'],
  docUrl: OUTCOME_DOCS,
});

export const BUILTIN_FUNCTIONS: FunctionDef[] = [
  // ---------------------------------------------------------------- arrays
  {
    name: 'arrays.concat',
    params: [p('array', 'array', 'Arrays to concatenate.', { repeated: true })],
    returns: 'array',
    description: 'Returns a new array that contains the elements of all of the input arrays, in order.',
    example: 'arrays.concat($e.principal.ip, $e.target.ip)',
  },
  {
    name: 'arrays.index_to_bool',
    params: [p('array', 'array<bool>'), p('index', 'int', 'Zero-based index; negative values count from the end.')],
    returns: 'bool',
    description: 'Returns the element at the given index of a boolean array, or false if the index is out of range.',
  },
  {
    name: 'arrays.index_to_float',
    params: [p('array', 'array<number>'), p('index', 'int', 'Zero-based index; negative values count from the end.')],
    returns: 'float',
    description: 'Returns the element at the given index as a float, or 0 if the index is out of range.',
  },
  {
    name: 'arrays.index_to_int',
    params: [p('array', 'array<number>'), p('index', 'int', 'Zero-based index; negative values count from the end.')],
    returns: 'int',
    description: 'Returns the element at the given index as an int, or 0 if the index is out of range.',
  },
  {
    name: 'arrays.index_to_str',
    params: [p('array', 'array<string>'), p('index', 'int', 'Zero-based index; negative values count from the end.')],
    returns: 'string',
    description: 'Returns the element at the given index as a string, or an empty string if the index is out of range.',
    example: 'arrays.index_to_str(strings.split($e.target.url, "/"), 2)',
  },
  {
    name: 'arrays.join_string',
    params: [p('array', 'array<string>'), p('delimiter', 'string', 'Separator placed between elements.', { optional: true })],
    returns: 'string',
    description: 'Joins the elements of a string array into a single string.',
    example: 'arrays.join_string($e.principal.ip, ",")',
  },
  {
    name: 'arrays.length',
    params: [p('array', 'array')],
    returns: 'int',
    description: 'Returns the number of elements in an array.',
    example: 'arrays.length($e.principal.ip) > 1',
  },
  {
    name: 'arrays.max',
    params: [p('array', 'array<number>')],
    returns: 'float',
    description: 'Returns the largest element of a numeric array, or 0 if the array is empty.',
  },
  {
    name: 'arrays.min',
    params: [p('array', 'array<number>'), p('ignore_zeros', 'bool', 'Ignore zero values.', { optional: true })],
    returns: 'float',
    description: 'Returns the smallest element of a numeric array, or 0 if the array is empty.',
  },
  {
    name: 'arrays.size',
    params: [p('array', 'array')],
    returns: 'int',
    description: 'Returns the number of elements in an array. Alias of arrays.length.',
  },

  // ---------------------------------------------------------------- bytes / cast
  {
    name: 'bytes.to_base64',
    params: [p('bytes', 'bytes'), p('default', 'string', 'Value to return on failure.', { optional: true })],
    returns: 'string',
    description: 'Encodes a bytes value as a base64 string.',
  },
  {
    name: 'cast.as_bool',
    params: [p('value', 'int | string')],
    returns: 'bool',
    description: 'Converts an int or string to a bool. Strings "true"/"false" (case-insensitive) and 1/0 are accepted.',
  },
  {
    name: 'cast.as_float',
    params: [p('value', 'int | string')],
    returns: 'float',
    description: 'Converts an int or numeric string to a float. Non-numeric strings return 0.',
    example: 'cast.as_float($e.additional.fields["score"]) > 0.5',
  },
  {
    name: 'cast.as_int',
    params: [p('value', 'float | string')],
    returns: 'int',
    description: 'Converts a float or numeric string to an int. Non-numeric strings return 0.',
  },
  {
    name: 'cast.as_string',
    params: [p('value', 'int | float | bool | bytes'), p('default', 'string', 'Value returned when the conversion fails.', { optional: true })],
    returns: 'string',
    description: 'Converts a value to its string representation.',
  },

  // ---------------------------------------------------------------- fingerprint / hash / group
  {
    name: 'hash.fingerprint2011',
    params: [p('value', 'string')],
    returns: 'int',
    description: 'Returns the fingerprint2011 hash of a string, a stable int64 useful for sampling or bucketing.',
  },
  {
    name: 'group',
    params: [p('field', 'any', 'Fields whose values are merged into one placeholder.', { repeated: true })],
    returns: 'any',
    description: 'Groups the values of several fields into a single placeholder variable so any of them can join.',
    example: '$ip = group($e.principal.ip, $e.target.ip)',
    sections: ['events'],
  },

  // ---------------------------------------------------------------- math
  { name: 'math.abs', params: [p('value', 'int | float')], returns: 'int | float', description: 'Returns the absolute value of a number.', example: 'math.abs($e1.metadata.event_timestamp.seconds - $e2.metadata.event_timestamp.seconds) < 300' },
  { name: 'math.ceil', params: [p('value', 'float')], returns: 'int', description: 'Returns the smallest integer that is greater than or equal to the value.' },
  { name: 'math.floor', params: [p('value', 'float')], returns: 'int', description: 'Returns the largest integer that is less than or equal to the value.' },
  {
    name: 'math.geo_distance',
    params: [p('longitude1', 'float'), p('latitude1', 'float'), p('longitude2', 'float'), p('latitude2', 'float')],
    returns: 'float',
    description: 'Returns the distance in meters between two geographic coordinates. Useful for impossible-travel detections.',
    example: 'math.geo_distance($e1.principal.location.region_coordinates.longitude, $e1.principal.location.region_coordinates.latitude, $e2.principal.location.region_coordinates.longitude, $e2.principal.location.region_coordinates.latitude)',
  },
  { name: 'math.is_increasing', params: [p('num1', 'number'), p('num2', 'number'), p('num3', 'number')], returns: 'bool', description: 'Returns true if the three values are strictly increasing.' },
  { name: 'math.log', params: [p('value', 'number')], returns: 'float', description: 'Returns the natural logarithm of a number.' },
  { name: 'math.pow', params: [p('base', 'number'), p('exponent', 'number')], returns: 'float', description: 'Returns base raised to the power of exponent.' },
  { name: 'math.random', params: [], returns: 'float', description: 'Returns a pseudo-random float in [0, 1). Useful for sampling.' },
  { name: 'math.round', params: [p('value', 'number'), p('places', 'int', 'Number of decimal places.', { optional: true })], returns: 'float', description: 'Rounds a number to the nearest integer or to the given number of decimal places.' },
  { name: 'math.sqrt', params: [p('value', 'number')], returns: 'float', description: 'Returns the square root of a number.' },

  // ---------------------------------------------------------------- net
  {
    name: 'net.ip_in_range_cidr',
    params: [p('ip', 'string', 'IPv4 or IPv6 address.'), p('cidr', 'string', 'Range in CIDR notation, for example "10.0.0.0/8".')],
    returns: 'bool',
    description: 'Returns true if the IP address is within the given CIDR range.',
    example: 'not net.ip_in_range_cidr($e.principal.ip, "10.0.0.0/8")',
  },

  // ---------------------------------------------------------------- re
  {
    name: 're.regex',
    params: [p('text', 'string', 'Field or value to test.'), p('pattern', 'regex', 'RE2 pattern as a string or /regex/ literal. Append `nocase` for case-insensitive matching.')],
    returns: 'bool',
    description: 'Returns true if the text contains a match for the RE2 regular expression. Equivalent to `field = /pattern/`.',
    example: 're.regex($e.target.process.command_line, `(?i)-enc(odedcommand)?\\s`)',
  },
  {
    name: 're.capture',
    params: [p('text', 'string'), p('pattern', 'regex', 'RE2 pattern with at most one capture group.')],
    returns: 'string',
    description: 'Returns the first capture group (or the whole match if there is no group) of the pattern in the text.',
    example: '$domain = re.capture($e.target.url, `https?://([^/]+)`)',
  },
  {
    name: 're.replace',
    params: [p('text', 'string'), p('pattern', 'regex'), p('replacement', 'string', 'Replacement text; \\1 references capture groups.')],
    returns: 'string',
    description: 'Replaces every match of the pattern in the text with the replacement.',
    example: 're.replace($e.principal.hostname, `\\..*$`, "")',
  },

  // ---------------------------------------------------------------- sampling
  {
    name: 'optimization.sample_rate',
    params: [p('byte_or_string', 'string', 'Value to hash for sampling.'), p('rate', 'float', 'Fraction of values to keep, 0-1.')],
    returns: 'bool',
    description: 'Returns true for a deterministic sample of values at the given rate. Useful for high-volume hunting rules.',
  },

  // ---------------------------------------------------------------- strings
  { name: 'strings.base64_decode', params: [p('encoded', 'string')], returns: 'string', description: 'Decodes a base64-encoded string. Returns an empty string on invalid input.', example: 'strings.base64_decode($encoded_cmd)' },
  {
    name: 'strings.coalesce',
    params: [p('value', 'string', 'Values checked left to right.', { repeated: true })],
    returns: 'string',
    description: 'Returns the first non-empty string argument.',
    example: '$user = strings.coalesce($e.principal.user.userid, $e.principal.user.email_addresses)',
  },
  {
    name: 'strings.concat',
    params: [p('value', 'string | int | float', 'Values to concatenate.', { repeated: true })],
    returns: 'string',
    description: 'Concatenates any number of strings, ints or floats.',
    example: 'strings.concat($e.principal.hostname, ":", $e.principal.port)',
  },
  { name: 'strings.contains', params: [p('text', 'string'), p('substring', 'string')], returns: 'bool', description: 'Returns true if the text contains the substring (case-sensitive).', example: 'strings.contains(strings.to_lower($e.target.process.command_line), "invoke-webrequest")' },
  { name: 'strings.count_substrings', params: [p('text', 'string'), p('substring', 'string')], returns: 'int', description: 'Returns the number of non-overlapping occurrences of the substring in the text.' },
  { name: 'strings.ends_with', params: [p('text', 'string'), p('suffix', 'string')], returns: 'bool', description: 'Returns true if the text ends with the suffix.' },
  { name: 'strings.extract_domain', params: [p('url_or_hostname', 'string')], returns: 'string', description: 'Extracts the registered domain (eTLD+1) from a URL or hostname.', example: 'strings.extract_domain($e.target.url)' },
  { name: 'strings.extract_hostname', params: [p('url', 'string')], returns: 'string', description: 'Extracts the hostname from a URL.' },
  { name: 'strings.from_base64', params: [p('encoded', 'string')], returns: 'bytes', description: 'Decodes a base64 string into bytes.' },
  { name: 'strings.from_hex', params: [p('hex', 'string')], returns: 'bytes', description: 'Decodes a hex string into bytes.' },
  { name: 'strings.ltrim', params: [p('text', 'string'), p('cutset', 'string', 'Characters to remove.', { optional: true })], returns: 'string', description: 'Removes leading whitespace (or the given characters).' },
  { name: 'strings.reverse', params: [p('text', 'string')], returns: 'string', description: 'Returns the string with its characters reversed.' },
  { name: 'strings.rtrim', params: [p('text', 'string'), p('cutset', 'string', 'Characters to remove.', { optional: true })], returns: 'string', description: 'Removes trailing whitespace (or the given characters).' },
  {
    name: 'strings.split',
    params: [p('text', 'string'), p('delimiter', 'string', 'Defaults to ",".', { optional: true })],
    returns: 'array<string>',
    description: 'Splits a string on a delimiter and returns an array of strings.',
    example: 'arrays.index_to_str(strings.split($e.principal.user.email_addresses, "@"), 1)',
  },
  { name: 'strings.starts_with', params: [p('text', 'string'), p('prefix', 'string')], returns: 'bool', description: 'Returns true if the text starts with the prefix.' },
  { name: 'strings.to_lower', params: [p('text', 'string')], returns: 'string', description: 'Converts a string to lowercase.', example: 'strings.to_lower($e.target.process.file.full_path)' },
  { name: 'strings.to_upper', params: [p('text', 'string')], returns: 'string', description: 'Converts a string to uppercase.' },
  { name: 'strings.trim', params: [p('text', 'string'), p('cutset', 'string', 'Characters to remove.', { optional: true })], returns: 'string', description: 'Removes leading and trailing whitespace (or the given characters).' },
  { name: 'strings.url_decode', params: [p('url', 'string')], returns: 'string', description: 'Decodes a URL-encoded (percent-encoded) string.' },

  // ---------------------------------------------------------------- timestamp
  { name: 'timestamp.as_unix_seconds', params: [p('timestamp', 'string'), p('time_zone', 'string', 'IANA or UTC-offset time zone.', { optional: true })], returns: 'int', description: 'Parses a timestamp string ("yyyy-mm-dd hh:mm:ss") and returns Unix seconds.' },
  { name: 'timestamp.current_seconds', params: [], returns: 'int', description: 'Returns the current time in Unix seconds. In retrohunts this is the time the retrohunt runs.', example: 'timestamp.current_seconds() - $e.metadata.event_timestamp.seconds < 86400' },
  { name: 'timestamp.diff', params: [p('timestamp1', 'int', 'Unix seconds.'), p('timestamp2', 'int', 'Unix seconds.'), p('unit', 'string', '"SECOND", "MINUTE", "HOUR" or "DAY".')], returns: 'int', description: 'Returns timestamp1 - timestamp2 in the given unit.' },
  { name: 'timestamp.get_date', params: [p('unix_seconds', 'int'), p('time_zone', 'string', 'Defaults to "UTC".', { optional: true })], returns: 'string', description: 'Returns the date ("yyyy-mm-dd") for a Unix timestamp.' },
  { name: 'timestamp.get_day_of_week', params: [p('unix_seconds', 'int'), p('time_zone', 'string', 'Defaults to "UTC".', { optional: true })], returns: 'int', description: 'Returns the day of week, 1 (Sunday) to 7 (Saturday).', example: 'timestamp.get_day_of_week($e.metadata.event_timestamp.seconds, "America/New_York") in [1, 7]' },
  { name: 'timestamp.get_hour', params: [p('unix_seconds', 'int'), p('time_zone', 'string', 'Defaults to "UTC".', { optional: true })], returns: 'int', description: 'Returns the hour of day, 0-23.' },
  { name: 'timestamp.get_minute', params: [p('unix_seconds', 'int'), p('time_zone', 'string', 'Defaults to "UTC".', { optional: true })], returns: 'int', description: 'Returns the minute of the hour, 0-59.' },
  { name: 'timestamp.get_timestamp', params: [p('unix_seconds', 'int'), p('format', 'string', 'strftime-style format.', { optional: true }), p('time_zone', 'string', 'Defaults to "UTC".', { optional: true })], returns: 'string', description: 'Formats a Unix timestamp as a string.' },
  { name: 'timestamp.get_week', params: [p('unix_seconds', 'int'), p('time_zone', 'string', 'Defaults to "UTC".', { optional: true })], returns: 'int', description: 'Returns the week of the year, 0-53. Weeks start on Sunday.' },
  { name: 'timestamp.now', params: [], returns: 'int', description: 'Returns the current time in Unix seconds.' },

  // ---------------------------------------------------------------- window (outcome)
  ...(['avg', 'first', 'last', 'median', 'mode', 'stddev', 'variance'] as const).map(
    (fn): FunctionDef => ({
      name: `window.${fn}`,
      params: [p('value', 'number'), p('ignore_zeros', 'bool', 'Ignore zero values.', { optional: true })],
      returns: fn === 'mode' ? 'any' : 'float',
      description: `Returns the ${fn === 'stddev' ? 'standard deviation' : fn} of the values in the match window.`,
      sections: ['outcome'],
      aggregate: true,
    }),
  ),

  // ---------------------------------------------------------------- conditional
  {
    name: 'if',
    params: [p('condition', 'bool'), p('then', 'any'), p('else', 'any', 'Defaults to the zero value.', { optional: true })],
    returns: 'any',
    description: 'Evaluates to `then` when the condition is true, otherwise `else`. Commonly wrapped in an aggregate to build risk scores.',
    example: '$risk_score = max(if($e.principal.user.userid = "root", 50, 10))',
    sections: ['outcome'],
    docUrl: OUTCOME_DOCS,
  },

  // ---------------------------------------------------------------- outcome aggregates
  agg('array', 'Returns an array of all values, including duplicates (up to 25 elements).', 'array', '$ips = array($e.principal.ip)'),
  agg('array_distinct', 'Returns an array of distinct values (up to 25 elements).', 'array', '$hosts = array_distinct($e.principal.hostname)'),
  agg('avg', 'Returns the average of numeric values.', 'float', '$avg_bytes = avg($e.network.sent_bytes)'),
  agg('count', 'Returns the number of values.', 'int', '$event_count = count($e.metadata.id)'),
  agg('count_distinct', 'Returns the number of distinct values.', 'int', '$event_count = count_distinct($e.metadata.id)'),
  agg('earliest', 'Returns the earliest timestamp (microseconds) of the values.', 'int', '$first_seen = earliest($e.metadata.event_timestamp)'),
  agg('latest', 'Returns the latest timestamp (microseconds) of the values.', 'int', '$last_seen = latest($e.metadata.event_timestamp)'),
  agg('max', 'Returns the maximum value.', 'number', '$risk_score = max(65)'),
  agg('min', 'Returns the minimum value.', 'number', '$min_port = min($e.target.port)'),
  agg('stddev', 'Returns the standard deviation of numeric values.', 'float', '$bytes_stddev = stddev($e.network.sent_bytes)'),
  agg('sum', 'Returns the sum of numeric values.', 'number', '$total_bytes = sum($e.network.sent_bytes)'),
].map((f) => ({ docUrl: DOCS, ...f }));

export interface FunctionIndex {
  get(name: string): FunctionDef | undefined;
  all(): FunctionDef[];
  namespaces(): string[];
}

export function buildFunctionIndex(extra: FunctionDef[] = []): FunctionIndex {
  const map = new Map<string, FunctionDef>();
  for (const f of BUILTIN_FUNCTIONS) map.set(f.name, f);
  for (const f of extra) map.set(f.name, f);
  return {
    get: (name) => map.get(name),
    all: () => [...map.values()],
    namespaces: () => [...new Set([...map.keys()].filter((k) => k.includes('.')).map((k) => k.split('.')[0]))].sort(),
  };
}

export function arity(f: FunctionDef): { min: number; max: number } {
  const min = f.params.filter((x) => !x.optional && !x.repeated).length + (f.params.some((x) => x.repeated) ? 1 : 0);
  const max = f.params.some((x) => x.repeated) ? Infinity : f.params.length;
  return { min, max };
}

export function signature(f: FunctionDef): string {
  const params = f.params.map((x) => `${x.name}${x.optional ? '?' : ''}: ${x.type}${x.repeated ? ', ...' : ''}`);
  return `${f.name}(${params.join(', ')}) → ${f.returns}`;
}

/** Markdown documentation for hovers and completion items. */
export function functionMarkdown(f: FunctionDef): string {
  const lines = ['```yaral', signature(f), '```', '', f.description];
  if (f.params.length) {
    lines.push('');
    for (const x of f.params) {
      lines.push(`- \`${x.name}\`${x.optional ? ' *(optional)*' : ''}${x.repeated ? ' *(repeatable)*' : ''}: ${x.type}${x.description ? ' — ' + x.description : ''}`);
    }
  }
  if (f.sections) lines.push('', `*Allowed in:* ${f.sections.map((s) => '`' + s + ':`').join(', ')}`);
  if (f.example) lines.push('', '**Example**', '```yaral', f.example, '```');
  if (f.docUrl) lines.push('', `[Documentation](${f.docUrl})`);
  return lines.join('\n');
}
