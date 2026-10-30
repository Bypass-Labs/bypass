import fs from 'node:fs';
import { validateJSON } from '../schema.mjs';
import { need } from '../util.mjs';

// The Python package and Node adapters load this same wire contract.
export const manifest = JSON.parse(fs.readFileSync(new URL('../../scanner/protocol/v2.json', import.meta.url), 'utf8'));
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
    implementedOperations: ['capabilities','rules','start','status','resume','cancel','report','signals','artifact','build_failed'],
    operations: Object.keys(manifest.operations), stages: ['discovery', 'evaluation', 'reporting'],
    features: {codeqlDiscovery:true,aiDiscovery:false,evaluation:false,codeqlReady},
    languages: ['cpp','csharp','go','java','javascript','python','ruby','rust','actions']
  };
}

export function unavailable(operation) {
  const result = {
    protocolVersion, status: 'not_implemented', code: 'not_implemented', operation,
    message: 'AI discovery/evaluation is not implemented. CodeQL discovery makes zero model calls.',
    modelCalls: 0
  };
  validateJSON(manifest.schemas.error, result, 'scanner error');
  return result;
}
