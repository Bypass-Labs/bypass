import test from 'node:test';
import assert from 'node:assert/strict';
import {modelDisplay} from '../src/model-display.mjs';

test('model display names the active model instead of repeating profile and provider',()=>{
  assert.equal(modelDisplay({name:'meta',provider:'meta',modelId:'muse-spark-1.3',connection:'connected'}),
    'muse-spark-1.3 · Meta Model API · connected');
});
