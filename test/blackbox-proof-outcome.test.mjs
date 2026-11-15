import test from 'node:test';
import assert from 'node:assert/strict';
import {blackboxProofOutcome} from '../src/engine.mjs';

test('replaying an observation never promotes it to a confirmed exploit',()=>{
  assert.deepEqual(blackboxProofOutcome({verdict:'observed'}),
    {status:'observed',exitCode:3});
  assert.deepEqual(blackboxProofOutcome({verdict:'observed'},{retest:true}),
    {status:'observed',exitCode:3});
  assert.deepEqual(blackboxProofOutcome({verdict:'confirmed'}),
    {status:'confirmed',exitCode:1});
  assert.deepEqual(blackboxProofOutcome({verdict:'not_reproduced'},{retest:true}),
    {status:'fixed_verified',exitCode:0});
});
