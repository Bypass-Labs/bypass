// Muse selects observed scoped routes and a string field; browser execution decides stored XSS.
import {randomBytes} from 'node:crypto';
import {validateUrl} from './scope.mjs';
import {renderCapturedHtml, responseCached, validModelFixedFields, xssPayload} from './poc-runtime.mjs';
import {MODEL_RESPONSE_BYTES, requestFailureVerdict, responseSizeReason} from './response-size.mjs';

const STYLES = new Set(['html-double', 'html-single', 'script-close']);
const unique = values => [...new Set(values.filter(Boolean))];
const brief = (value, size = 300) => String(value ?? '').replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, size);
const safeField = value => typeof value === 'string' &&
  /^[A-Za-z_][A-Za-z0-9_.-]{0,79}$/.test(value);
const exactGet = record => typeof record?.pattern === 'string' &&
  record.pattern.startsWith('/') && !/[{}?#%]/.test(record.pattern) &&
  (!Array.isArray(record.methods) || !record.methods.length || record.methods.includes('GET'));
const unstable = response => response?.blocked || response?.refused || response?.status == null ||
  response.status === 429 || response.status >= 500 || responseCached(response);
const html = response => response?.status === 200 && /html/i.test(response.type ?? '') &&
  typeof response.body === 'string' && Buffer.byteLength(response.body) <= MODEL_RESPONSE_BYTES;

export async function planStoredXss(surface, scope, {infer, model, env = {}, budget = 0,
  modelCallsAvailable = 0, startOffset = 0, log = () => {}} = {}) {
  const result = {leads: [], decisions: [], modelCalls: 0, modelError: null,
    coverage: {postsAvailable: 0, postsSent: 0, viewsAvailable: 0, viewsSent: 0}};
  const operations = (surface?.jsonBodyOperations ?? []).filter(item => item.method === 'POST' &&
    item.contentType === 'application/json' && Array.isArray(item.fields) &&
    item.fields.some(safeField) && validateUrl(scope, item.path,
      {purpose: 'json-body', method: 'POST', identity: 'anonymous'}).ok);
  result.coverage.postsAvailable = operations.length;
  if (!infer || !model || !operations.length || budget < 1 || modelCallsAvailable < 1) return result;
  const views = (surface?.patterns ?? []).filter(exactGet).filter(item =>
    validateUrl(scope, item.pattern, {identity: 'anonymous'}).ok);
  result.coverage.viewsAvailable = views.length;
  if (!views.length) return result;
  const reviewedViews = new Set();
  const used = new Set();
  for (let offset = startOffset; offset < operations.length &&
      result.modelCalls < modelCallsAvailable && result.leads.length < budget;
      offset += 12) {
    const sentPosts = operations.slice(offset, offset + 12);
    const context = {origin: scope.target.origin,
    ownerAvailable: Boolean(env[scope.identities.owner.env]),
    posts: sentPosts.map(item => ({path: item.path,
      fields: item.fields.filter(safeField).slice(0, 16),
      requiredFields: item.requiredFields ?? [], source: item.source})),
    views: [...views.filter(item => !reviewedViews.has(item.pattern)),
      ...views.filter(item => reviewedViews.has(item.pattern))].map(item => ({path: item.pattern,
      anonymousStatus: item.fingerprint?.anonymous?.status ?? null,
      anonymousType: brief(item.fingerprint?.anonymous?.type, 60),
      ownerStatus: item.fingerprint?.owner?.status ?? null}))};
    while (context.views.length && Buffer.byteLength(JSON.stringify(context)) > 14000)
      context.views.pop();
    if (Buffer.byteLength(JSON.stringify(context)) > 14000) {
      result.modelError = 'Stored-XSS route context exceeded the 14 KB model page.';
      break;
    }
    const sentViews = new Set(context.views.map(item => item.path));
    try {
    result.modelCalls++;
    const reply = await infer(model, [{role: 'system', content:
      `Select up to five ${scope.target.environment === 'local' ? 'local' : 'authorized deployed'} stored-XSS tests using only exact reviewed JSON POST routes and observed GET HTML views. ` +
      'Choose an observed string body field that the POST stores for the GET view, up to three other observed string fields with harmless fixed values if required, and a payload style. ' +
      'The runner generates two inert script canaries and executes only captured HTML in an isolated browser under the original CSP. ' +
      'It checks a plain-text control, confirms storage through a separate GET, and independently replays the proof. ' +
      'Use owner only when ownerAvailable. Do not invent routes, submit credentials, contact external services or choose irreversible actions. ' +
      'Return an empty checks array when no observed pair is plausible.'},
    {role: 'user', content: JSON.stringify(context)}], {schema: {type: 'object',
      properties: {checks: {type: 'array', maxItems: 5, items: {type: 'object', properties: {
        postPath: {type: 'string', maxLength: 300}, field: {type: 'string', maxLength: 80},
        fixedFields: {type: 'array', maxItems: 3, items: {type: 'object',
          properties: {field: {type: 'string', maxLength: 80}, value: {type: 'string', maxLength: 128}},
          required: ['field', 'value'], additionalProperties: false}},
        postAs: {type: 'string', enum: ['anonymous', 'owner']},
        viewPath: {type: 'string', maxLength: 300},
        viewAs: {type: 'string', enum: ['anonymous', 'owner']},
        style: {type: 'string', enum: ['html-double', 'html-single', 'script-close']},
        why: {type: 'string', maxLength: 300}, priority: {type: 'integer'}},
      required: ['postPath', 'field', 'fixedFields', 'postAs', 'viewPath', 'viewAs',
        'style', 'why', 'priority'], additionalProperties: false}}},
      required: ['checks'], additionalProperties: false}});
    result.coverage.postsSent += sentPosts.length;
    sentViews.forEach(path => reviewedViews.add(path));
    result.coverage.viewsSent = reviewedViews.size;
    for (const proposal of Array.isArray(reply?.checks) ? reply.checks.slice(0, 5) : []) {
      const decision = {mode: 'stored-xss', postPath: brief(proposal?.postPath),
        field: brief(proposal?.field, 80), viewPath: brief(proposal?.viewPath),
        hypothesis: brief(proposal?.why), accepted: false};
      const operation = sentPosts.find(item => item.path === proposal?.postPath);
      const fields = operation?.fields.filter(safeField).slice(0, 16) ?? [];
      const view = views.find(item => sentViews.has(item.pattern) &&
        item.pattern === proposal?.viewPath);
      const key = `${proposal?.postPath} ${proposal?.field} ${proposal?.viewPath}`;
      if (!operation || !fields.includes(proposal?.field) || !view)
        decision.reason = 'unobserved-route-or-field';
      else if (used.has(key)) decision.reason = 'duplicate';
      else if (!STYLES.has(proposal.style) || !Number.isInteger(proposal.priority) ||
          !validModelFixedFields(proposal.fixedFields, proposal.field, [], fields) ||
          (operation.requiredFields ?? []).some(field => field !== proposal.field &&
            !proposal.fixedFields.some(item => item.field === field))) decision.reason = 'invalid-input';
      else if (!['anonymous', 'owner'].includes(proposal.postAs) ||
          !['anonymous', 'owner'].includes(proposal.viewAs) ||
          (proposal.postAs === 'owner' || proposal.viewAs === 'owner') && !context.ownerAvailable)
        decision.reason = 'identity';
      else if (!validateUrl(scope, proposal.postPath,
          {purpose: 'json-body', method: 'POST', identity: proposal.postAs}).ok ||
          !validateUrl(scope, proposal.viewPath, {identity: proposal.viewAs}).ok)
        decision.reason = 'scope';
      else if (result.leads.length >= budget) decision.reason = 'task-budget';
      else {
        used.add(key);
        decision.accepted = true;
        result.leads.push({path: proposal.postPath, parameter: proposal.field,
          postAs: proposal.postAs, viewPath: proposal.viewPath, viewAs: proposal.viewAs,
          style: proposal.style, fixedFields: proposal.fixedFields, observedFields: fields,
          why: decision.hypothesis, priority: Math.max(0, Math.min(10, proposal.priority)),
          basis: 'model-stored-xss'});
      }
      result.decisions.push(decision);
    }
    } catch (error) {
      result.modelError = error.message;
      log({stage: 'web-plan', message: error.details?.reason === 'research_deadline' ?
        'Muse stored-XSS planning stopped at the audit deadline; remaining leads are untested.' :
        `Muse stored-XSS planning failed: ${error.message}`});
      break;
    }
  }
  return result;
}

function finding(lead, scope, exchanges, browserEvidence) {
  const postUrl = new URL(lead.path, scope.target.origin);
  const viewUrl = new URL(lead.viewPath, scope.target.origin);
  return {kind: 'xss-stored', title: `Stored XSS executes after JSON POST: ${lead.path}`,
    severity: 'medium', owasp: 'A03 Injection', cwe: 'CWE-79',
    pattern: lead.path, url: postUrl.href, host: postUrl.host, task: null,
    verdict: 'confirmed', rule: 'confirmed/stored-xss/two-browser-canaries',
    evidence: unique([...exchanges.slice(0, 4).map(item => item.evidenceId), ...browserEvidence.slice(0, 2)]),
    confirmation: unique([...exchanges.slice(4).map(item => item.evidenceId), browserEvidence[2]]),
    mirror: {result: 'unverified', evidence: [], reason: 'account boundary was not tested'},
    tags: ['model-selected-route', 'stored-browser-execution', 'reviewed-json-post'],
    reach: {observed: 1, basis: `Two distinct inert script markers executed from separate stored GET responses after JSON POSTs (${browserEvidence[1]}, ${browserEvidence[2]})`},
    dataClasses: [], remediation: 'Encode stored user text for its HTML context and enforce a restrictive Content Security Policy.',
    foundBy: 'model-selected-browser-probe', status: 'open',
    webProof: {kind: 'xss-stored', request: {method: 'POST', url: lead.path, as: lead.postAs},
      jsonPostPath: lead.path, viewPath: lead.viewPath, viewAs: lead.viewAs,
      parameter: lead.parameter, style: lead.style, fixedFields: lead.fixedFields,
      observedFields: lead.observedFields},
    webSteps: exchanges.map((response, index) => ({identity: index % 2 === 0 ?
      lead.viewAs : lead.postAs, method: index % 2 === 0 ? 'GET' : 'POST',
      url: index % 2 === 0 ? viewUrl.href : postUrl.href,
      status: response.status, evidence: response.evidenceId}))};
}

export async function runStoredXss(leads, scope, {requester, ledger} = {}) {
  const findings = [], results = [];
  for (const lead of leads) {
    const exchanges = [], browserEvidence = [];
    let verdict = 'inconclusive', reason = 'stored-XSS controls were unavailable';
    const view = async step => {
      const response = await requester({url: lead.viewPath, identity: lead.viewAs,
        method: 'GET', step, noCache: true, maxBytes: MODEL_RESPONSE_BYTES, omitExcerpt: true,
        headers: {'cache-control': 'no-cache'}});
      exchanges.push(response);
      return response;
    };
    const post = async (value, step) => {
      const response = await requester({url: lead.path, identity: lead.postAs,
        method: 'POST', purpose: 'json-body', step, noCache: true, maxBytes: MODEL_RESPONSE_BYTES,
        omitExcerpt: true, headers: {'content-type': 'application/json',
          'cache-control': 'no-cache'}, body: JSON.stringify({
          ...Object.fromEntries(lead.fixedFields.map(item => [item.field, item.value])),
          [lead.parameter]: value})});
      exchanges.push(response);
      return response;
    };
    const baseline = await view('control');
    if (unstable(baseline)) {
      verdict = requestFailureVerdict([baseline]);
      reason = responseSizeReason(baseline) ?? 'baseline HTML view was unavailable';
    } else if (!html(baseline)) {
      verdict = 'not_reproduced'; reason = 'observed view did not return HTML';
    } else {
      const controlMarker = randomBytes(12).toString('hex');
      const controlPost = await post(controlMarker, 'control');
      if (unstable(controlPost) || controlPost.status < 200 || controlPost.status >= 300) {
        verdict = requestFailureVerdict([controlPost]);
        reason = responseSizeReason(controlPost) ?? 'plain-text POST control was unavailable';
      } else {
        const controlView = await view('control');
        if (unstable(controlView) || !html(controlView) ||
            !controlView.body.includes(controlMarker)) {
          verdict = requestFailureVerdict([controlView]);
          reason = responseSizeReason(controlView) ?? 'plain-text control was not stored in the HTML view';
        } else {
          const controlBrowser = await renderCapturedHtml(controlView.body,
            controlView.headers?.['content-security-policy'], controlMarker,
            {sourceUrl: new URL(lead.viewPath, scope.target.origin).href});
          browserEvidence.push(ledger?.append({step: 'browser', kind: 'xss-stored',
            targetEvidence: controlView.evidenceId, marker: controlMarker,
            executed: controlBrowser.executed,
            originalCspApplied: !!controlView.headers?.['content-security-policy']}));
          if (controlBrowser.blocked || controlBrowser.executed) {
            verdict = 'inconclusive'; reason = controlBrowser.reason ?? 'plain text executed';
          } else {
            for (let index = 0; index < 2; index++) {
              const marker = randomBytes(12).toString('hex');
              if (baseline.body.includes(marker)) {reason = 'marker already appeared in baseline'; break;}
              const sent = await post(xssPayload(lead.style, marker), index ? 'reverify' : 'task');
              if (unstable(sent) || sent.status < 200 || sent.status >= 300) {
                verdict = requestFailureVerdict([sent]);
                reason = responseSizeReason(sent) ?? 'stored-XSS POST was unavailable'; break;
              }
              const page = await view(index ? 'reverify' : 'task');
              if (unstable(page) || !html(page) || !page.body.includes(marker)) {
                verdict = requestFailureVerdict([page]);
                reason = responseSizeReason(page) ?? 'canary did not appear in the stored HTML view'; break;
              }
              const browser = await renderCapturedHtml(page.body,
                page.headers?.['content-security-policy'], marker,
                {sourceUrl: new URL(lead.viewPath, scope.target.origin).href});
              browserEvidence.push(ledger?.append({step: 'browser', kind: 'xss-stored',
                targetEvidence: page.evidenceId, marker, executed: browser.executed,
                originalCspApplied: !!page.headers?.['content-security-policy']}));
              if (browser.blocked) {verdict = 'blocked'; reason = browser.reason; break;}
              if (!browser.executed) {
                verdict = index ? 'inconclusive' : 'not_reproduced';
                reason = 'stored canary did not execute in isolated Chrome'; break;
              }
              if (index === 1) {
                verdict = 'confirmed'; reason = 'two stored canaries executed in isolated Chrome';
              }
            }
          }
        }
      }
    }
    const evidence = unique([...exchanges.map(item => item.evidenceId), ...browserEvidence]);
    results.push({lead: {path: lead.path, parameter: lead.parameter,
      viewPath: lead.viewPath, basis: lead.basis}, kind: 'xss-stored', verdict,
    reason, evidence});
    if (verdict === 'confirmed') findings.push(finding(lead, scope, exchanges, browserEvidence));
  }
  return {findings, results};
}
