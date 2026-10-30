import { executionMode, hostAI } from '../execution-mode.mjs';
import { rootFrom, read } from '../store.mjs';
import { outcome, need, abortFault } from '../util.mjs';
import { manifest, scannerCapabilities, unavailable, validateOperation } from './contracts.mjs';
import { scannerDoctor, prepareScanner } from './runtime.mjs';

export function discoveryPlan() {
  const mode = executionMode();
  return {
    kind: 'scanner-plan', status: 'scaffold', protocolVersion: manifest.protocolVersion,
    executionMode: mode, analysisImplemented: false, modelCalls: 0, sourceReads: 0,
    stages: ['discovery', 'evaluation', 'reporting'],
    prerequisites: ['Scanner Docker image (bypass scanner prepare)', 'Explicit source selection when analysis is implemented', ...(mode === 'muse-host' ? ['Active Muse session; no additional LLM setup'] : ['Configured standalone LLM API profile and API-key environment variable'])],
    reasoning: mode === 'muse-host' ? 'Active Muse session; zero independent API requests and no API fallback' : 'Explicit provider API profile; Muse credentials are never used',
    message: 'Scanner scaffold only. Detectors, source investigation, task execution, persistence, and report generation are not implemented.'
  };
}

export async function scannerService(key, args = [], options = {}, context = {}) {
  if (context.signal?.aborted) throw abortFault(context.signal);
  if (key === 'scanner doctor' || key === 'scanner prepare') {
    const diagnostics = await (key === 'scanner doctor' ? scannerDoctor : prepareScanner)(context);
    return outcome({ kind: 'scanner-diagnostics', ...diagnostics, modelCalls: 0, sourceReads: 0 }, diagnostics.status === 'blocked' ? 3 : 0);
  }
  const host = executionMode() === 'muse-host';
  const ai = host ? hostAI() : { mode: 'standalone-api', billing: 'provider API key' };
  if (key === 'discover' && options.plan) return outcome({ plan: discoveryPlan(), ai });
  const operation = key === 'discover' ? 'start' : key.slice('discover '.length);
  let input;
  if (operation === 'start') input = Object.fromEntries(['sarif', 'config'].filter(name => options[name] !== undefined).map(name => [name, options[name]]));
  else if (operation === 'capabilities') input = {};
  else input = { ...Object.fromEntries(['task', 'sourceRevision', 'result', 'operation', 'arguments', 'format'].filter(name => options[name] !== undefined).map(name => [name, options[name]])), run: args[0] };
  validateOperation(operation, input);
  if (operation === 'capabilities') return outcome({ ...scannerCapabilities(), ai });
  if (!host && ['start', 'resume'].includes(operation)) {
    const { runAPIDriver } = await import('./api-driver.mjs');
    const root = rootFrom(options.project || context.cwd, false);
    let state;
    try { state = read(root); } catch { /* Missing configuration is reported by the driver. */ }
    runAPIDriver(state);
  }
  need(Object.hasOwn(manifest.operations, operation), 'Unknown scanner operation.');
  // An unavailable backend needs no Docker launch, source access, or state write.
  return outcome({ ...unavailable(operation), ai }, 3);
}
