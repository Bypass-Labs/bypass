import { randomUUID, createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { commandInvocation } from './command.mjs';

export const VERSION = '0.7.0';
export const SCHEMA = 'bypass.v1';
export const now = () => new Date().toISOString();
export const id = prefix => `${prefix}_${randomUUID().slice(0, 8)}`;
export const hash = value => createHash('sha256').update(typeof value === 'string' ? value : JSON.stringify(value)).digest('hex');
export { delay };
export class Fault extends Error {
  constructor(message, code = 2, details = {}) { super(message); this.code = code; this.details = details; }
}
export const abortFault = signal => signal?.reason instanceof Fault ? signal.reason : new Fault('Operation cancelled. Saved choices are retained.',130);
export function abortable(promise, signal) {
  if(!signal)return promise;
  return new Promise((resolve,reject)=>{
    const cancel=()=>reject(abortFault(signal));
    signal.addEventListener('abort',cancel,{once:true});
    promise.then(resolve,reject).finally(()=>signal.removeEventListener('abort',cancel));
    if(signal.aborted)cancel();
  });
}
export function need(value, message, code = 2, details = {}) { if (!value) throw new Fault(message, code, details); return value; }
export function named(list, name, type) { return need(list.find(x => x.name === name || x.id === name), `${type} '${name}' not found.`); }
export function safeName(value) { need(/^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/.test(value ?? ''), 'Use a name starting with a letter, followed by up to 63 letters, numbers, _ or -.'); return value; }
export function envName(value) { need(/^[A-Z_][A-Z0-9_]*$/.test(value ?? ''), 'A secret reference must be an environment variable name, e.g. BYPASS_OWNER_TOKEN.'); return value; }
export function duration(value, min = 1000) {
  const m = /^(\d+)(ms|s|m|h|d)$/.exec(String(value));
  const ms = m && Number(m[1]) * ({ms:1,s:1000,m:60000,h:3600000,d:86400000}[m[2]]);
  need(ms >= min && ms <= 365 * 86400000, `Invalid duration '${value}'. Use e.g. 30s, 5m, 1h (minimum ${min}ms).`); return ms;
}
export function cleanText(value) { return String(value).replace(/[\x00-\x08\x0b-\x1f\x7f]/g, '').slice(0, 2000); }
const registeredSecrets=new Set();
export function registerSecret(value){if(typeof value==='string'&&value.length>=4)registeredSecrets.add(value);}
export function redact(value) {
  let text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const [key, secret] of Object.entries(process.env)) {
    if (/(TOKEN|SECRET|PASSWORD|API_KEY|COOKIE)/i.test(key) && secret?.length >= 4) text = text.split(secret).join('[REDACTED]');
  }
  for(const secret of registeredSecrets)text=text.split(secret).join('[REDACTED]');
  text = text.replace(/(Bearer\s+)[^\s"<>]+/gi, '$1[REDACTED]');
  return typeof value === 'string' ? text : JSON.parse(text);
}
export function execFile(command, args = [], options = {}) {
  return new Promise((resolve, reject) => {
    if(options.signal?.aborted){reject(abortFault(options.signal));return;}
    const group=!!options.killGroup && process.platform!=='win32';
    const env={...process.env,MUSE_NO_AUTO_UPDATE:'1',...options.env};
    const invocation=commandInvocation(command,args,env);
    const child = spawn(invocation.command, invocation.args, { cwd: options.cwd, env, stdio:['pipe','pipe','pipe'], shell:false, detached:group });
    let stdout = '', stderr = '', size = 0, failure=null, closed=false, killTimer;
    const kill=signal=>{try{if(group&&child.pid)process.kill(-child.pid,signal);else child.kill(signal);}catch{/* already exited */}};
    const stop=error=>{if(closed||failure)return;failure=error;kill('SIGTERM');killTimer=setTimeout(()=>kill('SIGKILL'),500);};
    const cancel=()=>stop(abortFault(options.signal));
    const timer = setTimeout(() => stop(new Fault(`${command} timed out.`,3,{reason:'timeout'})), options.timeout ?? 20000);
    const cleanup=()=>{closed=true;clearTimeout(timer);clearTimeout(killTimer);options.signal?.removeEventListener('abort',cancel);};
    const collect = (kind, data) => {
      size += data.length;
      if (size > 2_000_000) { stop(new Fault(`${command} output exceeded the limit.`,3)); return; }
      if (kind === 'out') { stdout += data; try { options.onStdout?.(data.toString()); } catch(error) { stop(error); } }
      else stderr += data;
    };
    child.stdout.on('data', b => collect('out', b)); child.stderr.on('data', b => collect('err', b));
    child.on('error', e => { cleanup();reject(new Fault(`Cannot run ${command}: ${e.code ?? e.message}`,3,{causeCode:e.code})); });
    child.on('close', code => { cleanup();if(failure)reject(failure);else resolve({code:code ?? 130, stdout:stdout.trim(), stderr:stderr.trim()}); });
    child.stdin.on('error',()=>{}); // A child may exit before consuming stdin.
    options.signal?.addEventListener('abort',cancel,{once:true});
    if(options.signal?.aborted)cancel();
    child.stdin.end(options.input ?? '');
  });
}
export function outcome(data, exitCode = 0) { return { schemaVersion:SCHEMA, ...data, exitCode }; }
export function aggregate(results) { return results.some(x => x.status === 'failed') ? 1 : results.some(x => ['blocked','stale','error','cancelled'].includes(x.status)) ? 3 : 0; }
