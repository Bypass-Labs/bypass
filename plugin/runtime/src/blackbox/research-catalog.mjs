// Keep the catalog as a small runtime reference for Muse, never a vulnerability allowlist.
import fs from 'node:fs';

const catalogPath = new URL('../../docs/muse_spark_bug_bounty_tier_1_tier_2.md', import.meta.url);
let rows = null;

function readRows() {
  if (rows) return rows;
  let source = '';
  try {source = fs.readFileSync(catalogPath, 'utf8');} catch {return rows = [];}
  rows = source.split('\n').flatMap(line => {
    const cells = line.split('|').map(value => value.trim());
    if (!/^\d+$/.test(cells[1] ?? '') || !cells[2] || !cells[4]) return [];
    return [{name: cells[2], tier: Number(cells[1]) <= 20 ? 1 : 2,
      verification: cells[4]}];
  });
  return rows;
}

export function researchCatalogIndex() {
  // The web planner receives this once, on its first page. Include the short
  // verification criterion so Muse can use the reference instead of only
  // seeing class names; the full document never enters a model prompt.
  return readRows().map(({name, tier, verification}) => ({name, tier, verification}));
}

export function researchCatalogHint(family) {
  const normalize = value => String(value ?? '').toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ').trim();
  const normalized = normalize(family);
  if (!normalized) return null;
  const catalog = readRows();
  const exact = catalog.find(item => normalize(item.name) === normalized);
  if (exact) return {...exact};

  // Internal probe names are often shorter and reversed relative to catalog
  // titles (for example sql-boolean or xss-reflected). Match their meaningful
  // words without making the catalog a list of permitted hypothesis names.
  const generic = new Set(['model', 'body', 'hosts', 'output', 'operator',
    'probe', 'experiment', 'strategy', 'test', 'route']);
  const words = [...new Set(normalized.split(' ').filter(word =>
    word.length >= 3 && !generic.has(word)))];
  if (!words.length) return null;
  const catalogWords = catalog.map(item => new Set(normalize(item.name).split(' ')));
  const frequency = new Map();
  for (const row of catalogWords)
    for (const word of row) frequency.set(word, (frequency.get(word) ?? 0) + 1);
  const matches = catalog.flatMap((item, index) => {
    const overlap = words.filter(word => catalogWords[index].has(word));
    if (!overlap.length) return [];
    const unique = overlap.some(word => frequency.get(word) === 1);
    if (!unique && (overlap.length < 2 || overlap.length !== words.length)) return [];
    return [{item, overlap: overlap.length, missing: words.length - overlap.length,
      unique}];
  }).sort((a, b) => b.overlap - a.overlap || a.missing - b.missing);
  if (!matches.length || matches.length > 1 &&
      matches[0].overlap === matches[1].overlap &&
      matches[0].missing === matches[1].missing) return null;
  return {...matches[0].item};
}
