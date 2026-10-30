import test from 'node:test';
import assert from 'node:assert/strict';
import {unresolvedWebModelCuts} from '../src/blackbox/index.mjs';

const page = (overrides = {}) => ({origin: 'http://127.0.0.1:3000',
  discoveredVia: 'derived-session', candidatesAvailable: 24, candidatesSent: 0,
  preludeRoutesAvailable: 9, preludeRoutesSent: 0,
  httpSequenceAvailable: 33, httpSequenceSent: 20, ...overrides});

test('a later complete derived review resolves an earlier deferred page', () => {
  const cuts = unresolvedWebModelCuts([page(), page({candidatesSent: 24,
    preludeRoutesSent: 9, httpSequenceSent: 33})]);
  assert.deepEqual(cuts, {candidates: [], prelude: [], sequences: []});
});

test('a later partial page keeps real candidate, prelude and sequence cuts visible', () => {
  const cuts = unresolvedWebModelCuts([page(), page({candidatesSent: 20,
    preludeRoutesSent: 8, httpSequenceSent: 30})]);
  assert.equal(cuts.candidates.length, 2);
  assert.equal(cuts.prelude.length, 2);
  assert.equal(cuts.sequences.length, 2);
});

test('another origin, surface, or larger inventory does not clear a cut by count alone', () => {
  const cuts = unresolvedWebModelCuts([page(),
    page({origin: 'http://127.0.0.1:3001', candidatesSent: 24, preludeRoutesSent: 9,
      httpSequenceSent: 33}),
    page({discoveredVia: 'credential-origin', candidatesSent: 24, preludeRoutesSent: 9,
      httpSequenceSent: 33}),
    page({candidatesAvailable: 25, candidatesSent: 25,
      preludeRoutesAvailable: 10, preludeRoutesSent: 10,
      httpSequenceAvailable: 34, httpSequenceSent: 34})]);
  assert.equal(cuts.candidates.length, 1);
  assert.equal(cuts.prelude.length, 1);
  assert.equal(cuts.sequences.length, 1);
  assert.equal(cuts.candidates[0].candidatesSent, 0);
  assert.equal(cuts.prelude[0].preludeRoutesSent, 0);
});
