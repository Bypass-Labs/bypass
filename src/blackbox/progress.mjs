import {redact} from '../util.mjs';

// The audit retains every event in its evidence. This is only the human terminal view.
export function progressLine(event) {
  const message = String(event?.message ?? '');
  const stage = event?.stage;
  if (!message) return null;
  if (stage === 'assets') {
    if (message.startsWith('off-origin script not fetched:')) return null;
    const mined = /^mined (\d+) files: (\d+) endpoints \((\d+) non-GET\), (\d+) hosts, (\d+) secrets, (\d+) source maps/.exec(message);
    if (mined) return Number(mined[1]) ? {label: 'Assets', text: `${mined[1]} files · ${mined[2]} routes (${mined[3]} non-GET) · ${mined[4]} host references${Number(mined[5]) ? ` · ${mined[5]} secret leads` : ''}${Number(mined[6]) ? ` · ${mined[6]} source maps` : ''}`} : null;
    return /budget reached|cut by/.test(message) ? {label: 'Limit', text: message} : null;
  }
  if (stage === 'asset-model') {
    const accepted = /; (\d+) accepted route notes, (\d+) path proposals$/.exec(message);
    if (accepted) {
      const files = /received (\d+ of \d+) mined files/.exec(message)?.[1] ?? '?';
      const routes = /, (\d+ of \d+) route facts/.exec(message)?.[1] ?? '?';
      return {label: 'Muse assets', text: `${files} files · ${routes} route facts · ${accepted[1]} notes and ${accepted[2]} paths accepted`};
    }
    if (/retrying .* automatically/.test(message)) return {label: 'Muse recovered', text: message.replace(/^Muse /,'')};
    return /failed:/.test(message) ? {label: 'Muse attention', text: message} : null;
  }
  if (stage === 'identity') {
    if (message === 'No test accounts: cross-account tests are skipped') return {label: 'Accounts', text: 'Anonymous only · cross-account checks skipped', once: 'anonymous'};
    if (message.startsWith('Two distinct, usable credentials')) return null;
    if (/none of .* is set;|is not set, so there is no login attempt/.test(message)) return null;
    if (message.startsWith('No identity endpoint found')) return null;
    return {label: 'Accounts', text: message};
  }
  if (stage === 'setup') return {label: 'Scope', text: message};
  if (stage === 'discovery') return {label: 'Hosts', text: message};
  if (stage === 'discovery-model') {
    if (/failed:/.test(message)) return {label: 'Muse', text: message};
    if (/naming page .*: [1-9]\d* scoped names/.test(message)) return {label: 'Muse hosts', text: message.replace(/^Muse /, '')};
    return null;
  }
  if (stage === 'source') return /^0 source files, 0 route facts/.test(message) ? null : {label: 'Source', text: message};
  if (stage === 'recon') {
    if (/^Mapped \d+ public GET route candidates$/.test(message)) return {label: 'Recon', text: message};
    if (/^\d+ patterns,/.test(message)) return {label: 'Routes', text: message};
    if (message.startsWith('Muse reviewed')) return {label: 'Muse recon', text: message.replace(/^Muse reviewed /, '')};
    if (/Muse reconnaissance .* failed/.test(message)) return {label: 'Muse', text: message};
    return null;
  }
  if (stage === 'plan') {
    if (/^\d+ tasks planned;/.test(message)) return {label: 'Access plan', text: message};
    return /failed|exhausted/i.test(message) ? {label: 'Attention', text: message} : null;
  }
  if (stage === 'swarm') {
    if (/^\d+ tasks on \d+ agents$/.test(message)) return {label: 'Access tests', text: message.replace(' agents', ' workers')};
    if (/^\d+ tasks/.test(message)) return {label: 'Access tests', text: message};
    return null;
  }
  if (stage === 'web-plan') {
    if (message.startsWith('Muse reviewed')) {
      const reviewed=/^Muse reviewed (\d+) of (\d+) (remaining )?web candidates in (\d+) of (\d+) pages(.*)$/.exec(message);
      if(reviewed)return {label:'Muse web',text:Number(reviewed[1])?
        `${reviewed[1]} of ${reviewed[2]} ${reviewed[3]||''}candidates reviewed · ${reviewed[4]}/${reviewed[5]} bounded batches completed${reviewed[6]}`:
        `No new candidates reviewed in this pass · ${reviewed[2]} remain available · continuing with saved evidence`};
      return {label: 'Muse web', text: message.replace(/^Muse reviewed /, '')};
    }
    if (/retrying .* automatically/.test(message)) return {label: 'Muse recovered', text: message.replace(/^Muse /,'')};
    if (/Model request timed out/.test(message)) return {label: 'Muse recovered', text: 'A bounded Muse batch exceeded 60 seconds. Earlier evidence is saved; the audit continues with available and later work.'};
    return /failed/.test(message) ? {label: 'Muse attention', text: message} : null;
  }
  if (stage === 'web-probes') {
    const done = /^(\d+) web leads executed; (\d+) queued untested; (\d+) confirmed security findings?(?:; \d+ research observations)?; (\d+) (beyond budget|deferred to later pass)$/.exec(message);
    if (done) return {label: 'Web tests', text: `${done[1]} leads executed${Number(done[2]) ? ` · ${done[2]} queued untested` : ''}${Number(done[3]) ? ` · ${done[3]} confirmed finding${Number(done[3])===1?'':'s'}` : ''}${Number(done[4]) ? ` · ${done[4]} ${done[5]}` : ''}`,confirmed:Number(done[3])};
    return {label: 'Web tests', text: message};
  }
  if (stage === 'research') return {label: 'Muse research', text: message};
  if (stage === 'graphql') return /^0 schemas, 0 root fields, 0 fields cut$/.test(message) ? null : {label: 'GraphQL', text: message};
  if (stage === 'secret-exposure') return /^0 public /.test(message) ? null : {label: 'Secrets', text: message};
  if (stage === 'advisories') return /; 0 advisory leads, 0 cuts, 0 errors$/.test(message) ? null : {label: 'Advisories', text: message};
  if (stage === 'poc') return {label: 'Proof', text: message};
  if (stage === 'followup' || stage === 'graphql-plan' || stage === 'chain-plan')
    return /^Muse (?:reviewed|ranked|selected) 0 of /.test(message) ? null : {label: 'Muse', text: message};
  if (stage === 'request') return message.startsWith('HTTP 429:') ? {label: 'Rate limit', text: message, once: 'rate-limit'} : null;
  if (stage === 'chain' || stage === 'reverify' || stage === 'mirror') return {label: 'Proof', text: message};
  if (/failed|exhausted/i.test(message)) return {label: 'Attention', text: message};
  return null;
}

export function createBlackboxProgress(origin, {write = chunk => process.stderr.write(chunk),
  isTTY = !!process.stderr.isTTY, color = isTTY && !process.env.NO_COLOR,
  columns = () => process.stderr.columns || 100, now = () => Date.now()} = {}) {
  const seen = new Set();
  const counters = {requests: 0, modelCalls: 0, checksDone: 0, checksUntested: 0, checksTotal: 0, confirmed: 0,
    researchAttempts: 0,
    routesReviewed: 0, routesAvailable: 0, pathsAccepted: 0};
  const frames = ['◐', '◓', '◑', '◒'];
  const heartbeatMs = 15000;
  const startedAt = now();
  let started = false, active = null, timer = null, frame = 0, lastPaint = 0, lastHeartbeat = startedAt;
  let estimatedTaskTotal = 0;
  let checksReconciled = false;
  const checksText = () => checksReconciled ?
    `${counters.checksDone}/${counters.checksTotal} checks` :
    `${counters.checksDone} ${counters.checksDone === 1 ? 'check' : 'checks'} run`;
  const paint = (code, value) => color ? `\x1b[${code}m${value}\x1b[0m` : value;
  const elapsed = ms => {
    const seconds = Math.max(0, Math.floor(ms / 1000));
    return `${String(Math.floor(seconds / 60)).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;
  };
  const countersText = () => `${counters.requests} HTTP · ${counters.modelCalls} Muse` +
    (counters.confirmed ? ` · ${counters.confirmed} finding${counters.confirmed === 1 ? '' : 's'}` : '') +
    (active?.step === 4 && counters.researchAttempts ? ` · ${counters.researchAttempts} research tries` : '') +
    (active?.step === 3 && counters.routesAvailable ? ` · ${counters.routesReviewed}/${counters.routesAvailable} routes${counters.pathsAccepted ? ` · +${counters.pathsAccepted} paths` : ''}` :
      counters.checksTotal ? ` · ${checksText()}${counters.checksUntested ? ` · ${counters.checksUntested} untested` : ''}` : '');
  const clear = () => {if (isTTY && active) write('\r\x1b[2K');};
  const header = () => {
    if (started) return;
    started = true;
    write(`\n${paint('1;36', 'BYPASS')}  ${paint('90', '/')}  blackbox  ${paint('90', '·')}  ${redact(origin)}\n`);
  };
  const render = (force = false) => {
    if (!isTTY || !active) return;
    const clock = now();
    if (!force && clock - lastPaint < 120) return;
    lastPaint = clock;
    const ratio = ((active.step - 1) + (active.step === 4 && counters.checksTotal ?
      Math.min(0.95, counters.checksDone / counters.checksTotal) : 0.18)) / active.total;
    const filled = Math.max(0, Math.min(10, Math.floor(ratio * 10)));
    const bar = `${'█'.repeat(filled)}${'░'.repeat(10 - filled)}`;
    const spinner = frames[frame++ % frames.length];
    const shortTitle = ['Scope', 'Assets', 'Routes', 'Probes', 'Proofs', 'Report'][active.step - 1] ?? active.title;
    const checks = active.step === 3 && counters.routesAvailable ?
      ` · ${counters.routesReviewed}/${counters.routesAvailable} routes` :
      counters.checksTotal ? ` · ${checksText()}` : '';
    const width = Math.max(24, columns() - 1);
    const choices = [
      `  ${spinner}  ${bar}  ${active.step}/${active.total}  ${active.title}  ·  ${elapsed(clock - startedAt)}  ·  ${countersText()}`,
      `  ${spinner}  ${bar.slice(0, 6)}  ${active.step}/${active.total} ${shortTitle} · ${elapsed(clock - startedAt)} · ${counters.requests} HTTP · ${counters.modelCalls} Muse${checks}`,
      `  ${spinner} ${active.step}/${active.total} ${shortTitle} · ${elapsed(clock - startedAt)} · ${counters.requests} HTTP · ${counters.modelCalls} Muse${checks}`,
      `  ${spinner} ${active.step}/${active.total} ${shortTitle} ${elapsed(clock - startedAt)} H${counters.requests} M${counters.modelCalls}${active.step === 3 && counters.routesAvailable ? ` R${counters.routesReviewed}/${counters.routesAvailable}` : counters.checksTotal ? checksReconciled ? ` ${counters.checksDone}/${counters.checksTotal}` : ` ${counters.checksDone} run` : ''}`,
    ];
    const plain = choices.find(value => value.length <= width) ?? choices.at(-1).slice(0, width);
    write(`\r\x1b[2K${paint('36', plain)}`);
  };
  const heartbeat = () => {
    if (isTTY || !active) return;
    const clock = now();
    if (clock - lastHeartbeat < heartbeatMs) return;
    lastHeartbeat = clock;
    write(`  … ${active.step}/${active.total}  ${active.title}  ·  ${elapsed(clock - startedAt)}  ·  ${countersText()}\n`);
  };
  const onEvent = event => {
    if (event?.stage === 'progress') {
      if (event.type === 'request') counters.requests = Math.max(counters.requests, event.requests ?? 0);
      if (event.type === 'model') counters.modelCalls = Math.max(counters.modelCalls, event.modelCalls ?? 0);
      if (event.type === 'research-attempt') counters.researchAttempts++;
      if (event.type === 'recon-total') counters.routesAvailable = Math.max(counters.routesAvailable, event.routesAvailable ?? 0);
      if (event.type === 'recon') {
        counters.routesReviewed = Math.max(counters.routesReviewed, event.routesReviewed ?? 0);
        counters.routesAvailable = Math.max(counters.routesAvailable, event.routesAvailable ?? 0);
        counters.pathsAccepted = Math.max(counters.pathsAccepted, event.pathsAccepted ?? 0);
      }
      if (event.type === 'task-estimate') {
        const total = Math.max(0, event.total ?? 0);
        counters.checksTotal += total - estimatedTaskTotal;
        estimatedTaskTotal = total;
      }
      if (event.type === 'task-total') {
        counters.checksTotal += Math.max(0, event.total ?? 0) - estimatedTaskTotal;
        estimatedTaskTotal = 0;
      }
      if (event.type === 'task-done') {
        counters.checksDone++;
        if (event.confirmed) counters.confirmed++;
      }
      if (event.type === 'task-untested') counters.checksUntested++;
      if (event.type === 'task-reconcile') {
        // A later pass can retry early deferred work. Show the unique final
        // task ledger after those pass results have been reconciled.
        counters.checksTotal = Math.max(0, event.total ?? 0);
        counters.checksUntested = Math.max(0, event.untested ?? 0);
        counters.checksDone = Math.max(0, event.done ?? 0);
        estimatedTaskTotal = 0;
        checksReconciled = true;
      }
      if (event.type === 'phase') {
        counters.requests = Math.max(counters.requests, event.requests ?? 0);
        counters.modelCalls = Math.max(counters.modelCalls, event.modelCalls ?? 0);
        header();
        if (event.state === 'doing') {
          clear();
          active = {step: event.step, total: event.total, title: event.title, since: now()};
          lastHeartbeat = now();
          if (isTTY) {
            if (!timer) {timer = setInterval(() => render(true), 800); timer.unref?.();}
            render(true);
          } else {
            // Poll frequently enough that an event just after the timer starts
            // cannot postpone the next heartbeat for nearly two full periods.
            if (!timer) {timer = setInterval(heartbeat, 1000); timer.unref?.();}
            write(`  ${event.step}/${event.total}  Doing  ${event.title}\n`);
          }
        } else if (event.state === 'done') {
          const duration = active?.step === event.step ? elapsed(now() - active.since) : '00:00';
          clear();
          write(`  ${paint('32', '✓')} ${event.step}/${event.total}  Done   ${event.title}  ·  ${duration}  ·  ${countersText()}\n`);
          active = null;
        } else if (event.state === 'skipped') {
          write(`  ${paint('90', '·')} ${event.step}/${event.total}  Skipped  ${event.title}  (dry run)\n`);
        }
        return;
      }
      render(event.type !== 'request');
      return;
    }
    const line = progressLine(event);
    if (!line || (line.once && seen.has(line.once))) return;
    if (line.once) seen.add(line.once);
    header();
    clear();
    write(`  ${paint('90', line.label.padEnd(12))} ${redact(line.text)}\n`);
    lastHeartbeat = now();
    render(true);
  };
  onEvent.heartbeat = heartbeat;
  onEvent.finish = () => {
    if (timer) clearInterval(timer);
    timer = null;
    if (active && isTTY) {clear(); write('\n');}
    active = null;
  };
  return onEvent;
}
