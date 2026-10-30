// Bounded Muse follow-up for inconclusive access-control reads.
// Code constructs alternatives from observed query values and response IDs; Muse selects exact candidate IDs.
import {maskSecrets} from './assets.mjs';
import {validateTask} from './planner.mjs';
import {runSwarm} from './swarm.mjs';

const PAGE_TASKS = 8;
const MAX_VARIANTS = 8;
const MAX_PAGES = 8;
const MAX_BYTES = 20000;
const ELIGIBLE = new Set(['inconclusive/different-resource',
  'inconclusive/insufficient-evidence', 'inconclusive/non-json']);
const KINDS = new Set(['idor', 'list-leak', 'param-filter', 'bfla']);
const clean = (value, limit = 200) => maskSecrets(String(value ?? ''))
  .replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, limit);

function safeValue(value) {
  return typeof value === 'string' && value.length <= 100 &&
    !/[\x00-\x1f\x7f]/.test(value) && maskSecrets(value) === value;
}

function withQuery(raw, key, value, origin) {
  const url = new URL(raw, origin);
  url.searchParams.set(key, value);
  return raw.startsWith('/') ? `${url.pathname}${url.search}` : url.href;
}

function signature(task, origin) {
  return `${task.kind} ${task.request.as} ${new URL(task.request.url, origin).href}`;
}

function candidateRows(results, tasks, surface, scope, attempted = new Set()) {
  const seen = new Set(tasks.map(task =>
    signature(task, scope.target.origin)));
  for (const value of attempted) seen.add(value);
  const rows = [];
  let number = 0, variantsCut = 0;
  for (const result of results) {
    const parent = result.task;
    if (result.verdict !== 'inconclusive' || !ELIGIBLE.has(result.rule) ||
        !KINDS.has(parent?.kind)) continue;
    const record = (surface.patterns ?? []).find(item => item.pattern === parent.pattern);
    const candidates = [];
    const observedIds = [...new Set([result.O, result.T, result.A]
      .flatMap(response => response?.ids ?? []).filter(safeValue))];
    for (const [key, values] of Object.entries(record?.params ?? {})) {
      if (!Array.isArray(values)) continue;
      const choices = [...values.map(value => ({value, source: 'recon', evidence: []})),
        ...observedIds.map(value => ({value, source: 'response',
          evidence: [result.O, result.T, result.A].filter(response => response?.ids?.includes(value))
            .map(response => response.evidenceId).filter(Boolean)}))];
      for (const {value, source, evidence} of choices) {
        if (!safeValue(value)) continue;
        const url = withQuery(parent.request.url, key, value, scope.target.origin);
        const proposal = {...parent, origin: 'model',
          request: {...parent.request, url},
          control: {...parent.control, url},
          dependsOn: [parent.id], followupOf: parent.followupOf ?? parent.id,
          supportEvidence: [...new Set([...(parent.supportEvidence ?? []), ...evidence])]};
        const candidateKey = signature(proposal, scope.target.origin);
        if (seen.has(candidateKey) || validateTask(proposal, surface, scope)) continue;
        if (candidates.length >= MAX_VARIANTS) {variantsCut++; continue;}
        seen.add(candidateKey);
        const id = `c-${++number}`;
        candidates.push({id, parameter: key, value, url, source, evidence, task: proposal});
      }
    }
    if (candidates.length) rows.push({result, candidates});
  }
  return {rows, variantsCut};
}

function print(response) {
  return {status: response?.status ?? null, type: clean(response?.type, 80),
    ids: (response?.ids ?? []).slice(0, 4).map(value => clean(value, 100)),
    shape: Object.keys(response?.shape ?? {}).slice(0, 20).map(value => clean(value, 100)),
    fields: Object.keys(response?.fields ?? {}).slice(0, 20).map(value => clean(value, 100)),
    items: response?.items ?? null};
}

function contextRow(row) {
  const {result, candidates} = row;
  return {taskId: result.task.id, kind: result.task.kind,
    pattern: clean(result.task.pattern, 300), rule: result.rule,
    owner: print(result.O), outsider: print(result.T), anonymous: print(result.A),
    evidence: (result.evidence ?? []).slice(0, 8),
    candidates: candidates.map(({id, parameter, value, url, source, evidence}) =>
      ({id, parameter: clean(parameter, 100), value: clean(value, 100), url: clean(url, 500),
        source, evidence: evidence.slice(0, 4)}))};
}

function pagesFor(rows) {
  const fit = entries => {
    if (entries.length === 1 ||
        Buffer.byteLength(JSON.stringify(entries.map(contextRow))) <= MAX_BYTES) return [entries];
    const half = Math.ceil(entries.length / 2);
    return [...fit(entries.slice(0, half)), ...fit(entries.slice(half))];
  };
  const pages = [];
  for (let at = 0; at < rows.length; at += PAGE_TASKS)
    pages.push(...fit(rows.slice(at, at + PAGE_TASKS)));
  return pages;
}

/** Let Muse choose one observed query variant per eligible task in each bounded round. */
export async function followupInconclusive(results, tasks, surface, scope, {requester, decide,
  infer = null, model = null, budget = 0, maxModelPages = MAX_PAGES,
  log = () => {}, run = null} = {}) {
  const limit = Math.max(0, Math.floor(budget));
  const pageLimit = Math.max(0, Math.floor(maxModelPages));
  const active = new Map(results.filter(result => result.verdict === 'inconclusive' &&
    ELIGIBLE.has(result.rule) && KINDS.has(result.task?.kind))
    .map(result => [result.task.id, result]));
  const tried = new Set();
  const seenTasks = new Set(), reviewedTasks = new Set();
  const seenCandidates = new Set(), reviewedCandidates = new Set();
  const coverage = {pagesAvailable: 0, pagesSent: 0, tasksAvailable: 0, tasksSent: 0,
    candidatesAvailable: 0, candidatesSent: 0, variantsCut: 0, rounds: 0,
    probes: 0, budgetCut: 0, modelCut: 0};
  const chosen = [], followupResults = [], selected = [], rejected = [];
  let modelCalls = 0, modelError = null, cut = 0;
  let stats = null;
  do {
    const {rows, variantsCut} = candidateRows([...active.values()], tasks, surface, scope, tried);
    const pages = pagesFor(rows);
    coverage.pagesAvailable += pages.length;
    coverage.variantsCut += variantsCut;
    for (const row of rows) {
      seenTasks.add(row.result.task.followupOf ?? row.result.task.id);
      for (const candidate of row.candidates) seenCandidates.add(signature(candidate.task, scope.target.origin));
    }
    coverage.tasksAvailable = seenTasks.size;
    coverage.candidatesAvailable = seenCandidates.size;
    if (!infer || !model || !rows.length || chosen.length >= limit || modelCalls >= pageLimit || modelError) {
      coverage.budgetCut += chosen.length >= limit ? rows.reduce((sum, row) => sum + row.candidates.length, 0) : 0;
      coverage.modelCut += modelCalls >= pageLimit ? pages.length : 0;
      break;
    }
    const round = coverage.rounds + 1;
    const roundSelected = [];
    const selectedTasks = new Set();
    let sentThisRound = 0;
    for (let at = 0; at < pages.length && modelCalls < pageLimit; at++) {
      const page = pages[at];
      const context = {origin: scope.target.origin, round, page: at + 1, pages: pages.length,
        remainingTasks: limit - chosen.length, leads: page.map(contextRow)};
      if (Buffer.byteLength(JSON.stringify(context)) > MAX_BYTES) {
        modelError = `Follow-up round ${round} page ${at + 1} exceeded ${MAX_BYTES} bytes.`;
        break;
      }
      const known = new Map(page.flatMap(row => row.candidates.map(candidate =>
        [`${row.result.task.id} ${candidate.id}`, {row, candidate}])));
      try {
        modelCalls++;
        const answer = await infer(model, [{role: 'system', content: 'These access-control reads were inconclusive. Choose at most one supplied candidate ID per task for a guarded GET follow-up. The current round includes response facts and evidence from prior probes. Candidates use query values observed during reconnaissance or IDs observed in responses. Return exact taskId and candidateId pairs; do not invent a route, value, request, identity or finding. Code validates each selection and independently proves any finding.'},
          {role: 'user', content: JSON.stringify(context)}], {schema: {type: 'object', properties: {
          choices: {type: 'array', maxItems: PAGE_TASKS, items: {type: 'object', properties: {
            taskId: {type: 'string'}, candidateId: {type: 'string'}, why: {type: 'string', maxLength: 200}},
          required: ['taskId', 'candidateId', 'why'], additionalProperties: false}}},
          required: ['choices'], additionalProperties: false}});
        for (const choice of Array.isArray(answer?.choices) ? answer.choices : []) {
          const match = known.get(`${choice.taskId} ${choice.candidateId}`);
          if (!match || selectedTasks.has(choice.taskId)) {
            rejected.push({taskId: clean(choice.taskId, 100), candidateId: clean(choice.candidateId, 100)});
            continue;
          }
          selectedTasks.add(choice.taskId);
          roundSelected.push({task: match.candidate.task,
            candidateId: match.candidate.id, why: clean(choice.why),
            priorRule: match.row.result.rule,
            priorEvidence: (match.row.result.evidence ?? []).slice(0, 8),
            source: match.candidate.source});
        }
        coverage.pagesSent++;
        sentThisRound++;
        for (const row of page) {
          reviewedTasks.add(row.result.task.followupOf ?? row.result.task.id);
          for (const candidate of row.candidates) reviewedCandidates.add(signature(candidate.task, scope.target.origin));
        }
        coverage.tasksSent = reviewedTasks.size;
        coverage.candidatesSent = reviewedCandidates.size;
      } catch (error) {modelError = error.message; break;}
    }
    if (modelCalls >= pageLimit || modelError)
      coverage.modelCut += Math.max(0, pages.length - sentThisRound);
    if (!roundSelected.length) break;
    const remaining = limit - chosen.length;
    const toRun = roundSelected.slice(0, remaining).map(({task, candidateId, why}) =>
      ({...task, id: `${task.followupOf}-f${round}`, why, followupCandidate: candidateId}));
    cut += roundSelected.length - toRun.length;
    coverage.budgetCut += roundSelected.length - toRun.length;
    if (!toRun.length) break;
    for (const task of toRun) tried.add(signature(task, scope.target.origin));
    const swarm = await runSwarm(toRun, {requester, surface, scope, decide, log, run});
    chosen.push(...toRun);
    followupResults.push(...swarm.results);
    coverage.rounds++;
    coverage.probes += toRun.length;
    if (!stats) stats = {...swarm.stats};
    else {
      for (const field of ['tasks', 'requests', 'cached', 'confirmed', 'notReproduced', 'inconclusive',
        'blocked', 'public', 'shared', 'elapsedMs']) stats[field] = (stats[field] ?? 0) + (swarm.stats[field] ?? 0);
      stats.agents = Math.max(stats.agents ?? 0, swarm.stats.agents ?? 0);
      stats.rps = Math.round((stats.requests * 10000) / Math.max(stats.elapsedMs, 1)) / 10;
    }
    for (let index = 0; index < toRun.length; index++) {
      const task = toRun[index], result = swarm.results[index];
      const decision = roundSelected.find(item => item.task.request.url === task.request.url &&
        item.task.followupOf === task.followupOf);
      selected.push({taskId: task.followupOf, candidateId: task.followupCandidate,
        followupTaskId: task.id, url: task.request.url, why: task.why, round,
        source: decision?.source, priorRule: decision?.priorRule,
        priorEvidence: decision?.priorEvidence, resultRule: result.rule,
        resultEvidence: (result.evidence ?? []).slice(0, 8)});
      if (result.verdict === 'inconclusive' && ELIGIBLE.has(result.rule)) active.set(task.followupOf, result);
      else active.delete(task.followupOf);
    }
    log({stage: 'followup', message: `Round ${round}: ${toRun.length} observed query probes, ${swarm.stats.confirmed} confirmed; ${chosen.length}/${limit} task slots used`});
  } while (active.size && chosen.length < limit && modelCalls < pageLimit && !modelError);
  log({stage: 'followup', message: `Muse reviewed ${coverage.tasksSent} of ${coverage.tasksAvailable} inconclusive tasks and ran ${chosen.length} observed query variants in ${coverage.rounds} rounds`});
  return {tasks: chosen, results: followupResults, stats,
    modelCalls, modelError, coverage, rejected, selected, cut};
}
