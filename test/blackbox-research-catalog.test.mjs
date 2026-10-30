import test from 'node:test';
import assert from 'node:assert/strict';
import {researchCatalogIndex, researchCatalogHint} from '../src/blackbox/research-catalog.mjs';

test('Muse receives verification criteria with the compact catalog reference', () => {
  const rows = researchCatalogIndex();
  assert.equal(rows.length, 35);
  assert.ok(rows.every(row => row.name && [1, 2].includes(row.tier) &&
    typeof row.verification === 'string' && row.verification.length > 20));
  assert.match(rows.find(row => row.name.includes('Boolean-Based')).verification,
    /true and false conditions/);
});

test('catalog hints resolve internal probe names without restricting new families', () => {
  assert.match(researchCatalogHint('sql-boolean')?.name ?? '', /Boolean-Based/);
  assert.match(researchCatalogHint('sql-error')?.name ?? '', /Error-Based/);
  assert.equal(researchCatalogHint('xss-reflected')?.name, 'Reflected XSS');
  assert.equal(researchCatalogHint('xxe-body-hosts')?.name, 'XML External Entity (XXE)');
  assert.equal(researchCatalogHint('jwt-bypass')?.name, 'JWT Verification Bypass');
  assert.equal(researchCatalogHint('nosql-operator-bypass')?.name, 'NoSQL Injection');
  assert.equal(researchCatalogHint('unknown-expression-evaluation'), null);
  assert.equal(researchCatalogHint('xss'), null);
});
