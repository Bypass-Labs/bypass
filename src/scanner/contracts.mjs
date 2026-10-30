import fs from 'node:fs';
import { validateJSON } from '../schema.mjs';
import { need } from '../util.mjs';

// The Python package and Node adapters load this same wire contract.
export const manifest = JSON.parse(fs.readFileSync(new URL('../../scanner/protocol/v1.json', import.meta.url), 'utf8'));
export const protocolVersion = manifest.protocolVersion;

export function validateOperation(operation, arguments_ = {}) {
  const definition = manifest.operations[operation];
  need(Object.hasOwn(manifest.operations, operation), 'Unknown scanner operation.', 2);
  validateJSON(definition.inputSchema, arguments_, 'scanner arguments');
  return arguments_;
}

export function scannerCapabilities() {
  return {
    protocolVersion, status: 'scaffold', analysisImplemented: false,
    independentModelRequests: 0, implementedOperations: ['capabilities'],
    operations: Object.keys(manifest.operations), stages: ['discovery', 'evaluation', 'reporting']
  };
}

export function unavailable(operation) {
  const result = {
    protocolVersion, status: 'not_implemented', code: 'not_implemented', operation,
    message: 'Scanner analysis is not implemented. No run, finding, source read, or model request was created.',
    analysisImplemented: false, modelCalls: 0, sourceReads: 0
  };
  validateJSON(manifest.schemas.error, result, 'scanner error');
  return result;
}
