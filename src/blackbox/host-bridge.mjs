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
      summary: {phase: null, phasesDone: 0, requests: 0, modelCalls: 0, checksDone: 0, checksTotal: 0,
        checksUntested: 0, confirmedSignals: 0, latestActivity: 'Preparing the scoped audit'},
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
      const safe=redact(event), summary=job.summary;
      if(safe?.stage==='progress'){
        if(safe.type==='phase'){
          summary.phase={step:safe.step,total:safe.total,title:safe.title,state:safe.state};
          if(safe.state==='done')summary.phasesDone=Math.max(summary.phasesDone,safe.step);
          summary.latestActivity=`${safe.state==='done'?'Completed':'Working on'} ${safe.title}`;
        }
        if(safe.type==='request')summary.requests=Math.max(summary.requests,safe.requests||0);
        if(safe.type==='model')summary.modelCalls=Math.max(summary.modelCalls,safe.modelCalls||0);
        if(safe.type==='model-start'||safe.type==='activity')summary.latestActivity=safe.activity||safe.message||summary.latestActivity;
        if(safe.type==='task-total'||safe.type==='task-estimate')summary.checksTotal=Math.max(summary.checksTotal,safe.total||0);
        if(safe.type==='task-done'){summary.checksDone++;if(safe.confirmed)summary.confirmedSignals++;}
        if(safe.type==='task-untested')summary.checksUntested++;
        if(safe.type==='task-reconcile'){
          summary.checksTotal=safe.total||0;summary.checksDone=safe.done||0;summary.checksUntested=safe.untested||0;
        }
      }else if(safe?.message)summary.latestActivity=safe.message;
      job.events.push({cursor: ++job.eventCursor, ...safe});
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
      summary:{...job.summary,elapsedSeconds:Math.max(0,Math.floor((Date.now()-Date.parse(job.startedAt))/1000)),
        knownChecksPercent:job.summary.checksTotal?Math.min(100,Math.floor(100*job.summary.checksDone/job.summary.checksTotal)):null,
        percentMeaning:'Share of currently planned checks executed; plans can grow and this is not security coverage.'},
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
