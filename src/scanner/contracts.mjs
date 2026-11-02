import fs from 'node:fs';
import { validateJSON } from '../schema.mjs';
import { need } from '../util.mjs';

// Keep authored definitions shared; expand local references for existing
// validators and self-contained MCP tool schemas. No external references load.
export function resolveManifest(document) {
  function expand(value, stack=[], depth=0) {
    need(depth<64,'Scanner contract exceeds nesting limit.',3);
    if(Array.isArray(value))return value.map(item=>expand(item,stack,depth+1));
    if(value===null||typeof value!=='object')return value;
    if(Object.hasOwn(value,'$ref')){
      const reference=value.$ref;
      need(Object.keys(value).length===1&&typeof reference==='string'&&reference.startsWith('#/'),'Scanner contract supports only local references without siblings.',3);
      need(!stack.includes(reference),'Cyclic scanner contract reference.',3);
      let target=document;
      for(const token of reference.slice(2).split('/')){
        const key=token.replaceAll('~1','/').replaceAll('~0','~');
        need(target&&typeof target==='object'&&!Array.isArray(target)&&Object.hasOwn(target,key),'Missing scanner contract reference.',3);
        target=target[key];
      }
      need(target&&typeof target==='object'&&!Array.isArray(target),'Scanner contract reference must target an object.',3);
      return expand(target,[...stack,reference],depth+1);
    }
    return Object.fromEntries(Object.entries(value).map(([key,item])=>[key,expand(item,stack,depth+1)]));
  }
  return expand(document);
}

// The Python package and Node adapters load this same wire contract.
export const manifest = resolveManifest(JSON.parse(fs.readFileSync(new URL('../../scanner/protocol/v4.json', import.meta.url), 'utf8')));
export const protocolVersion = manifest.protocolVersion;

export function validateOperation(operation, arguments_ = {}) {
  const definition = manifest.operations[operation];
  need(Object.hasOwn(manifest.operations, operation), 'Unknown scanner operation.', 2);
  validateJSON(definition.inputSchema, arguments_, 'scanner arguments');
  return arguments_;
}

export function scannerCapabilities(codeqlReady = false) {
  return {
    protocolVersion, status: 'ready', analysisImplemented: true,
    independentModelRequests: 0,
    implementedOperations: ['capabilities','rules','policies','start','status','resume','cancel','report','signals','artifact','build_failed','next_task','evidence','submit','evaluate'],
    operations: Object.keys(manifest.operations), stages: ['discovery', 'evaluation', 'reporting'],
    features: {codeqlDiscovery:true,aiDiscovery:true,evaluation:true,codeqlReady},
    languages: ['cpp','csharp','go','java','javascript','python','ruby','rust','actions']
  };
}

export function unavailable(operation) {
  const result = {
    protocolVersion, status: 'not_implemented', code: 'not_implemented', operation,
    message: 'The requested scanner operation is unavailable.',
    modelCalls: 0
  };
  validateJSON(manifest.schemas.error, result, 'scanner error');
  return result;
}
