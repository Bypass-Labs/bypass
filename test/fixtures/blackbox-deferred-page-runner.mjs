import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {loadScope} from '../../src/blackbox/scope.mjs';
import {runWebProbes} from '../../src/blackbox/web-probes.mjs';

const [root, origin, mode] = process.argv.slice(2);
const checkpointFile = path.join(root, 'deferred-page.json');
const scope = loadScope({file: path.join(root, 'scope.json'), origin,
  overrides: {acceptLocal: true}}).scope;
const routes = Array.from({length: 28}, (_, index) => `/api/r${index}`);
const surface = {patterns: routes.map(pattern => ({pattern, methods: ['GET'],
  params: {q: ['plain']}, responseFacts: {status: 200,
    type: 'application/json', shape: {result: 'string'}}})),
jsonBodyOperations: [{path: '/api/transform', method: 'POST',
  contentType: 'application/json', fields: ['value'], requiredFields: ['value'],
  fieldExamples: {value: ['plain']}}]};
let evidence = 0;
const requester = async ({url, method = 'GET', body, headers = {}}) => {
  const response = await fetch(new URL(url, origin), {method, body, headers,
    redirect: 'manual'});
  const text = await response.text();
  let parsed;
  try {parsed = JSON.parse(text);} catch {parsed = null;}
  return {status: response.status, body: text, bytes: Buffer.byteLength(text),
    type: response.headers.get('content-type') ?? '',
    headers: Object.fromEntries(response.headers),
    hash: createHash('sha256').update(text).digest('hex'),
    shape: parsed && !Array.isArray(parsed) ?
      Object.fromEntries(Object.entries(parsed).map(([key, value]) =>
        [key, typeof value])) : null,
    ids: [], evidenceId: `ev-${String(++evidence).padStart(4, '0')}`};
};
const blank = schema => schema?.type === 'object' ?
  Object.fromEntries((schema.required ?? []).map(key =>
    [key, blank(schema.properties?.[key])])) :
  schema?.type === 'array' ? [] : schema?.type === 'integer' ||
  schema?.type === 'number' ? 0 : schema?.type === 'boolean' ? false :
  schema?.enum?.[0] ?? '';
const infer = async (_model, messages, {schema} = {}) => {
  const system = messages[0].content;
  const context = JSON.parse(messages[1].content);
  if (system.startsWith('Allocate the next black-box investigation effort'))
    return {priorities: ['json', 'sequence', 'web', 'stored', 'access']
      .map((name, index) => ({name, weight: 100 - index * 10,
        why: 'Observed JSON and GET contracts'}))};
  if (system.startsWith('Select distinct harmless response-transformation experiments'))
    return {experiments: mode === 'resume' ? [] : [{family: 'Response transform',
      path: '/api/transform', field: 'value', as: 'anonymous',
      oracle: 'observation', controlValue: 'plain', firstValue: 'one',
      secondValue: 'two', marker: context.marker, secondMarker: context.secondMarker,
      fixedFields: [], prelude: [], observePath: '', observeAs: 'anonymous',
      why: 'Observed response transform', priority: 8}]};
  if (system.startsWith('You are planning bounded, authorized HTTP research.')) {
    const route = context.routes.find(item => item.kind === 'read' &&
      item.fields.includes('q'));
    return {flows: route ? [{family: 'Query observation',
      why: 'Compare an observed query input', priority: 8,
      as: 'anonymous', oracle: 'observation', prelude: [], observe: [],
      binding: null, protectedPath: '',
      subject: {method: 'GET', path: route.path, placement: 'query',
        key: 'q', fixedFields: [], bodyTemplate: '', headers: []},
      controlValue: 'plain', firstValue: 'one', secondValue: 'two',
      marker: context.marker, secondMarker: context.secondMarker,
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}}] : []};
  }
  return blank(schema);
};
let resumeResearch = null;
if (mode === 'resume') resumeResearch = JSON.parse(fs.readFileSync(checkpointFile, 'utf8'));
const result = await runWebProbes(surface, scope, {requester, infer,
  model: {model: 'fixture'}, budget: 100, maxModelPages: 35,
  remainingModelCalls: () => 35, researchDeadline: Date.now() + 25000,
  flowPagePass: 'primary', resumeResearch,
  onFlowPageCheckpoint: state => {
    const saved = {kind: 'http-sequence-page', pass: 'primary', origin, ...state};
    const tmp = `${checkpointFile}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(saved));
    fs.renameSync(tmp, checkpointFile);
  }});
fs.writeFileSync(path.join(root, 'deferred-result.json'), JSON.stringify({
  results: result.results.filter(item => item.kind.startsWith('model-http'))
    .map(item => ({proposalId: item.proposalId, verdict: item.verdict,
      path: item.lead?.path}))}));
