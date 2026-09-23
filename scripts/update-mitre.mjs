// Regenerates src/core/catalog/mitre-data.json from MITRE's official data.
//
//   npm run update-mitre                 # download the latest releases
//   npm run update-mitre -- --dir <dir>  # use local copies (enterprise.json, ics.json, mobile.json, atlas.yaml)
//
// Sources:
//   ATT&CK (Enterprise, ICS, Mobile): https://github.com/mitre-attack/attack-stix-data (STIX 2.1)
//   ATLAS:                            https://github.com/mitre-atlas/atlas-data (dist/v6)

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'js-yaml';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'src', 'core', 'catalog', 'mitre-data.json');
const dirArg = process.argv.indexOf('--dir');
const localDir = dirArg !== -1 ? process.argv[dirArg + 1] : undefined;

const ATTACK = {
  enterprise: { name: 'MITRE ATT&CK Enterprise', domain: 'enterprise-attack', url: 'https://attack.mitre.org' },
  ics: { name: 'MITRE ATT&CK ICS', domain: 'ics-attack', url: 'https://attack.mitre.org/matrices/ics/' },
  mobile: { name: 'MITRE ATT&CK Mobile', domain: 'mobile-attack', url: 'https://attack.mitre.org/matrices/mobile/' },
};
const ATTACK_RAW = (d) => `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/${d}/${d}.json`;
const ATLAS_RAW = 'https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/';

async function fetchText(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.text();
}

async function load(localName, url) {
  if (localDir) return fs.readFileSync(path.join(localDir, localName), 'utf8');
  return fetchText(url);
}

const externalId = (o, source) => o.external_references?.find((r) => r.source_name === source)?.external_id;

/** Converts an ATT&CK STIX bundle into { version, tactics, techniques }. */
function convertAttack(bundle) {
  const objects = bundle.objects;
  const collection = objects.find((o) => o.type === 'x-mitre-collection');
  const byStixId = new Map(objects.map((o) => [o.id, o]));

  const tactics = {};
  const shortnameToId = {};
  for (const o of objects.filter((x) => x.type === 'x-mitre-tactic' && !x.revoked && !x.x_mitre_deprecated)) {
    const id = externalId(o, 'mitre-attack');
    tactics[id] = o.name;
    shortnameToId[o.x_mitre_shortname] = id;
  }

  const revokedBy = new Map();
  for (const r of objects.filter((x) => x.type === 'relationship' && x.relationship_type === 'revoked-by')) {
    revokedBy.set(r.source_ref, r.target_ref);
  }

  const techniques = {};
  for (const o of objects.filter((x) => x.type === 'attack-pattern')) {
    const id = externalId(o, 'mitre-attack');
    if (!id) continue;
    const entry = { n: o.name, t: [...new Set((o.kill_chain_phases ?? []).map((k) => shortnameToId[k.phase_name]).filter(Boolean))] };
    if (o.revoked) {
      const target = byStixId.get(revokedBy.get(o.id));
      entry.r = target ? externalId(target, 'mitre-attack') ?? true : true;
    } else if (o.x_mitre_deprecated) {
      entry.d = 1;
    }
    // Revoked/deprecated duplicates never overwrite a live technique with the same ID.
    if (!techniques[id] || (!entry.r && !entry.d)) techniques[id] = entry;
  }
  return { version: collection?.x_mitre_version ?? 'unknown', tactics, techniques };
}

/** Converts ATLAS v6 YAML into the same shape. */
function convertAtlas(doc) {
  const tactics = Object.fromEntries(Object.entries(doc.tactics).map(([id, t]) => [id, t.name]));
  const techniques = {};
  for (const [id, t] of Object.entries(doc.techniques)) techniques[id] = { n: t.name, t: [] };
  for (const [source, rels] of Object.entries(doc.relationships)) {
    for (const r of rels.achieves ?? []) techniques[source]?.t.push(r.target);
  }
  // Sub-techniques inherit parent tactics when not listed explicitly.
  for (const [id, t] of Object.entries(techniques)) {
    if (t.t.length === 0 && id.split('.').length > 2) t.t = [...(techniques[id.split('.').slice(0, 2).join('.')]?.t ?? [])];
  }
  return { version: doc.collection.version, tactics, techniques };
}

const frameworks = {};
for (const [key, meta] of Object.entries(ATTACK)) {
  const bundle = JSON.parse(await load(`${key}.json`, ATTACK_RAW(meta.domain)));
  frameworks[key] = { ...meta, ...convertAttack(bundle) };
}
let atlasText;
if (localDir) atlasText = fs.readFileSync(path.join(localDir, 'atlas.yaml'), 'utf8');
else {
  // dist/v6/ATLAS-latest.yaml is a symlink whose raw content is the target file name.
  const latest = (await fetchText(ATLAS_RAW + 'ATLAS-latest.yaml')).trim();
  atlasText = latest.endsWith('.yaml') && !latest.includes('\n') ? await fetchText(ATLAS_RAW + latest) : latest;
}
frameworks.atlas = {
  name: 'MITRE ATLAS',
  domain: 'atlas',
  url: 'https://atlas.mitre.org',
  ...convertAtlas(yaml.load(atlasText)),
};

const sortKeys = (obj) => Object.fromEntries(Object.entries(obj).sort(([a], [b]) => a.localeCompare(b, 'en', { numeric: true })));
for (const f of Object.values(frameworks)) {
  f.tactics = sortKeys(f.tactics);
  f.techniques = sortKeys(f.techniques);
}

fs.writeFileSync(OUT, JSON.stringify({ generated: new Date().toISOString().slice(0, 10), frameworks }) + '\n');
for (const [k, f] of Object.entries(frameworks)) {
  console.log(`${k.padEnd(10)} v${f.version}: ${Object.keys(f.tactics).length} tactics, ${Object.keys(f.techniques).length} techniques`);
}
console.log(`Wrote ${path.relative(ROOT, OUT)} (${(fs.statSync(OUT).size / 1024).toFixed(0)} KB)`);
