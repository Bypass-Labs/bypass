// Child process for an interrupted Muse route-page continuation regression.
import fs from 'node:fs';
import path from 'node:path';
import {runAudit} from '../../src/blackbox/index.mjs';

const [root, origin, resumeFrom = ''] = process.argv.slice(2);
const blank = schema => schema?.type === 'object' ?
  Object.fromEntries((schema.required ?? []).map(key =>
    [key, blank(schema.properties?.[key])])) :
  schema?.type === 'array' ? [] :
  schema?.type === 'integer' || schema?.type === 'number' ? 0 :
  schema?.type === 'boolean' ? false : schema?.enum?.[0] ?? '';
let pages = 0;
const infer = async (_model, messages, options = {}) => {
  const system = messages[0]?.content ?? '';
  if (system.startsWith('Allocate the next black-box investigation effort'))
    return {priorities: ['sequence', 'web', 'access', 'session', 'stored', 'json']
      .map(name => ({name, weight: name === 'sequence' ? 100 : 1,
        why: 'Observed query routes'}))};
  if (system.startsWith('You are planning bounded, authorized HTTP research.')) {
    const context = JSON.parse(messages[1].content);
    pages++;
    fs.appendFileSync(path.join(root, 'sequence-pages.jsonl'), JSON.stringify({
      resumed: Boolean(resumeFrom), routes: context.routes.map(item => item.path),
      priorSequenceResults: context.priorSequenceResults}) + '\n');
    if (process.env.BX_SLOW_PAGE2 === '1' && pages > 1)
      await new Promise(resolve => setTimeout(resolve, 30000));
    const route = context.routes.find(item => item.kind === 'read' &&
      item.fields.includes('q'));
    return {flows: route ? [{family: 'query-response',
      why: 'Compare the observed query response', priority: 8,
      as: 'anonymous', oracle: 'observation', prelude: [],
      subject: {method: 'GET', path: route.path, placement: 'query', key: 'q',
        fixedFields: [], bodyTemplate: '', headers: []},
      observe: [], binding: null, controlValue: 'plain',
      firstValue: 'one', secondValue: 'two', marker: '', secondMarker: '',
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}}] : []};
  }
  return blank(options.schema);
};

try {
  const result = await runAudit({url: origin, root,
    scopeFile: path.join(root, 'blackbox.scope.json'),
    overrides: {acceptLocal: true}, infer,
    noDiscovery: true, offline: true,
    ...(resumeFrom ? {resumeFrom} : {})});
  fs.writeFileSync(path.join(root, resumeFrom ? 'resumed-result.json' :
    'initial-result.json'), JSON.stringify({run: result.run, runDir: result.runDir}));
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
