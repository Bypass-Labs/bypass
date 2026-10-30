import { spawn } from 'node:child_process';
import { StringDecoder } from 'node:string_decoder';
import { manifest, protocolVersion, validateOperation } from './contracts.mjs';
import { validateJSON } from '../schema.mjs';
import { Fault, need, abortFault } from '../util.mjs';

/** Bounded stdio MCP connection. A timeout/cancellation closes its worker. */
export class ScannerClient {
  constructor(command, args = [], { cwd, env, timeoutMs = 10000, maxBytes = 1048576, onClose = async () => {} } = {}) {
    this.timeoutMs = timeoutMs;
    this.maxBytes = maxBytes;
    this.pending = new Map();
    this.sequence = 0;
    this.buffer = '';
    this.initialized = false;
    const decoder = new StringDecoder('utf8');
    this.child = spawn(command, args, { cwd, env, stdio: ['pipe', 'pipe', 'pipe'], shell: false });
    this.closed = new Promise(resolve => {
      this.child.once('close', () => {
        this.exited = true;
        clearTimeout(this.killTimer);
        this.fail(new Fault('Scanner connection closed.', 3), false);
        Promise.resolve().then(onClose).then(resolve, resolve);
      });
    });
    this.child.stdin.on('error', () => {});
    this.child.once('error', () => this.fail(new Fault('Cannot start scanner process.', 3)));
    let diagnosticBytes = 0;
    this.child.stderr.on('data', chunk => {
      diagnosticBytes += chunk.length;
      if (diagnosticBytes > maxBytes) this.fail(new Fault('Scanner diagnostic output exceeded the limit.', 3));
    });
    this.child.stdout.on('data', chunk => {
      if (this.failure) return;
      this.buffer += decoder.write(chunk);
      let index;
      while ((index = this.buffer.indexOf('\n')) !== -1) {
        const line = this.buffer.slice(0, index);
        this.buffer = this.buffer.slice(index + 1);
        if (Buffer.byteLength(line) > maxBytes) { this.fail(new Fault('Scanner response exceeded the limit.', 3)); return; }
        try { this.receive(JSON.parse(line)); }
        catch { this.fail(new Fault('Invalid scanner protocol response.', 3)); return; }
        if (this.failure) return;
      }
      if (Buffer.byteLength(this.buffer) > maxBytes) this.fail(new Fault('Scanner response exceeded the limit.', 3));
    });
  }

  fail(error, terminate = true) {
    this.failure ??= error;
    for (const entry of this.pending.values()) { entry.cleanup(); entry.reject(this.failure); }
    this.pending.clear();
    if (terminate && !this.stopping && !this.exited) {
      this.stopping = true;
      this.child.stdin.end();
      this.child.kill('SIGTERM');
      this.killTimer = setTimeout(() => this.child.kill('SIGKILL'), 500);
      this.killTimer.unref();
    }
  }

  receive(message) {
    need(message && message.jsonrpc === '2.0' && !Array.isArray(message), 'Invalid scanner envelope.', 3);
    // The server advertises no notifications or server-initiated requests.
    const entry = this.pending.get(message.id);
    need(entry && Number.isInteger(message.id) && (Object.hasOwn(message, 'result') !== Object.hasOwn(message, 'error')), 'Unexpected scanner response.', 3);
    if (message.error) need(Number.isInteger(message.error.code) && typeof message.error.message === 'string', 'Invalid scanner error.', 3);
    entry.cleanup();
    this.pending.delete(message.id);
    if (message.error) {
      entry.reject(new Fault('Scanner rejected the MCP request.', 3, { reason: 'scanner_rpc_error', rpcCode: message.error.code }));
    } else entry.resolve(message.result);
  }

  request(method, params = {}, { signal } = {}) {
    if (this.failure) return Promise.reject(this.failure);
    if (signal?.aborted) { this.fail(abortFault(signal)); return Promise.reject(this.failure); }
    if (this.pending.size >= 16) return Promise.reject(new Fault('Too many pending scanner requests.', 3));
    const id = ++this.sequence;
    const frame = JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n';
    if (Buffer.byteLength(frame) > this.maxBytes) return Promise.reject(new Fault('Scanner request exceeded the limit.', 3));
    return new Promise((resolve, reject) => {
      const cancel = () => this.fail(abortFault(signal));
      const timer = setTimeout(() => this.fail(new Fault('Scanner request timed out.', 3, { reason: 'scanner_timeout' })), this.timeoutMs);
      const cleanup = () => { clearTimeout(timer); signal?.removeEventListener('abort', cancel); };
      this.pending.set(id, { resolve, reject, cleanup });
      signal?.addEventListener('abort', cancel, { once: true });
      if (signal?.aborted) cancel();
      else this.child.stdin.write(frame);
    });
  }

  async initialize(options = {}) {
    need(!this.initialized, 'Scanner client is already initialized.', 3);
    const version = manifest.mcpProtocolVersions[0];
    try {
      const result = await this.request('initialize', { protocolVersion: version, capabilities: {}, clientInfo: { name: 'bypass', version: '1' } }, options);
      need(result?.protocolVersion === version && result.capabilities?.tools && typeof result.serverInfo?.name === 'string', 'Unsupported scanner handshake.', 3);
      this.child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
      this.initialized = true;
      return await this.call('capabilities', {}, options);
    } catch (error) { this.fail(error); await this.close(); throw error; }
  }

  async call(operation, arguments_ = {}, options = {}) {
    need(this.initialized, 'Initialize the scanner client first.', 3);
    validateOperation(operation, arguments_);
    const response = await this.request('tools/call', { name: `scanner_${operation}`, arguments: arguments_ }, options);
    try {
      need(Array.isArray(response?.content) && response.content.length === 1 && response.content[0].type === 'text' && typeof response.content[0].text === 'string' && typeof response.isError === 'boolean', 'Invalid scanner tool result.', 3);
      const result = JSON.parse(response.content[0].text);
      need(result?.protocolVersion === protocolVersion, 'Incompatible scanner application protocol. Prepare the matching scanner image.', 3);
      validateJSON(manifest.schemas[manifest.operations[operation].responseSchema], result, 'scanner result');
      need(operation === 'capabilities' || result.operation === operation, 'Scanner result does not match its operation.', 3);
      need(response.isError === ['error','not_implemented'].includes(result.status), 'Scanner error flag does not match its result.', 3);
      return result;
    } catch (error) { this.fail(new Fault('Invalid scanner tool result.', 3)); throw this.failure; }
  }

  async close() {
    this.fail(new Fault('Scanner connection closed by client.', 3));
    await this.closed;
  }
}
