import { redact } from '../util.mjs';

// One live audit per Muse MCP session. Model prompts stay in memory; the audit
// persists only its existing redacted decision summaries and evidence ledger.
export class BlackboxHostBridge {
  constructor() {
    this.job = null;
    this.sequence = 0;
  }

  start(work) {
    if (this.job?.status === 'running')
      throw new Error('A blackbox audit is already running in this Muse session.');
    const controller = new AbortController();
    const job = {status: 'running', controller, pending: new Map(), events: [], eventCursor: 0,
      result: null, error: null, startedAt: new Date().toISOString()};
    this.job = job;
    const infer = (_profile, messages, options = {}) => new Promise((resolve, reject) => {
      if (controller.signal.aborted || options.signal?.aborted) {
        reject(new Error('Blackbox audit stopped.')); return;
      }
      const id = `decision-${++this.sequence}`;
      const request = {id, messages: redact(messages), schema: options.schema ?? null,
        createdAt: new Date().toISOString()};
      const clear = () => {
        job.pending.delete(id);
        controller.signal.removeEventListener('abort', onAbort);
        options.signal?.removeEventListener('abort', onAbort);
        if (timer) clearTimeout(timer);
      };
      const onAbort = () => {clear(); reject(new Error('Blackbox audit stopped.'));};
      const timer = options.timeoutMs ? setTimeout(() => {
        clear(); reject(new Error('Muse host decision timed out.'));
      }, options.timeoutMs) : null;
      job.pending.set(id, {request, accept: value => {clear(); resolve(value);}});
      controller.signal.addEventListener('abort', onAbort, {once: true});
      options.signal?.addEventListener('abort', onAbort, {once: true});
    });
    const onProgress = event => {
      job.events.push({cursor: ++job.eventCursor, ...redact(event)});
      if (job.events.length > 50) job.events.shift();
    };
    job.done = Promise.resolve().then(() => work({infer, signal: controller.signal, onProgress}))
      .then(result => {job.result = result; job.status = 'completed';})
      .catch(error => {job.error = {message: error.message, code: error.code ?? 2};
        job.status = controller.signal.aborted ? 'stopped' : 'failed';})
      .finally(() => {
        for (const item of [...job.pending.values()])
          item.accept(null);
      });
    return this.status();
  }

  status(after = 0) {
    const job = this.job;
    if (!job) return {status: 'idle', pending: [], events: [], cursor: 0};
    return {status: job.status, startedAt: job.startedAt,
      modelBudget: {unit: 'engine model decisions',
        note: 'The model-calls limit counts engine decisions. Muse setup, status, reporting and other host turns are additional; this is not a total session usage or billing cap.'},
      pending: [...job.pending.values()].map(item => item.request),
      events: job.events.filter(item => item.cursor > after).slice(-20),
      cursor: job.eventCursor, result: job.result, error: job.error};
  }

  submit(id, decision) {
    const item = this.job?.pending.get(id);
    if (!item) throw new Error(`No pending Muse decision has ID ${id}.`);
    item.accept(decision);
    return {accepted: true, id, remaining: this.job.pending.size};
  }

  stop() {
    if (this.job?.status !== 'running') return this.status();
    this.job.controller.abort();
    return this.status();
  }
}
