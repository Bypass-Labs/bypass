import { AsyncLocalStorage } from 'node:async_hooks';
import { need } from './util.mjs';

const mode = new AsyncLocalStorage();
export const executionMode = () => mode.getStore() || 'standalone-api';
export function inExecutionMode(value, work) {
  need(['muse-host', 'standalone-api'].includes(value), 'Invalid execution mode.');
  return mode.run(value, work);
}
export function requireStandaloneAPI() {
  need(executionMode() === 'standalone-api', 'Muse owns reasoning in plugin mode. Independent model requests are disabled; continue with the host session.', 3, {reason:'host_owned_inference'});
}
export const hostAI = () => ({mode:'muse-host', reasoning:'active Muse session', independentModelRequests:0,
  billing:{status:'unknown',verified:false,reason:'The Muse host does not attest the active session billing mode through this MCP connection. Account allowance is not session billing proof.',action:'Use Muse account/settings to confirm subscription mode. If Muse indicates API billing, switch to subscription before reviewing.'},
  privacy:'For confidential code, select Standard mode (Contributor mode off) in Muse before review. Bypass does not change account settings.',
  recovery:'For host login or allowance errors, use Muse account/usage controls and resume this review. No API fallback.'});
