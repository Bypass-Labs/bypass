// Prepare a reviewable black-box scope and the local ownership/authorization records it needs.
// Setup never verifies a deployed domain or grants testing authorization on the operator's behalf.
import fs from 'node:fs';
import path from 'node:path';
import {DEFAULT_SCOPE, validateScopeTemplate} from './scope.mjs';
import {appOriginInput, loopback, makeChallenge, pathAllowed, targetURL} from '../network.mjs';
import {atomic, change, initStore, rootFrom} from '../store.mjs';
import {repositoryInfo} from '../repository.mjs';
import {envName, hash, need, safeName} from '../util.mjs';

const list = value => String(value).split(',').map(item => item.trim()).filter(Boolean);
const credentialOrigins = (origin, value) => [...new Set([origin, ...list(value).map(appOriginInput)])];
const quote = value => `'${String(value).replaceAll("'", "'\\''")}'`;
const current = value => Date.parse(value ?? '') > Date.now();

function requestedMatches(options, scope) {
  const same = (input, actual, normalize = value => value) => input == null ||
    JSON.stringify(list(input).map(normalize)) === JSON.stringify(actual);
  return same(options.include, scope.include) &&
    same(options.domains, scope.domains, value => value.toLowerCase()) &&
    same(options['audit-domains'], scope.discovery.auditDomains, value => value.toLowerCase()) &&
    (options['credential-origins'] == null ||
      JSON.stringify(credentialOrigins(scope.target.origin, options['credential-origins'])) ===
        JSON.stringify(scope.credentialOrigins)) &&
    (options.never == null || list(options.never).every(value => scope.never.includes(value))) &&
    (options['owner-env'] == null || options['owner-env'] === scope.identities.owner.env) &&
    (options['other-env'] == null || options['other-env'] === scope.identities.outsider.env) &&
    (options.auth == null || options.auth === scope.identities.auth) &&
    (options['identity-path'] == null || options['identity-path'] === scope.identities.identityPath) &&
    (options['identity-cookie-name'] == null ||
      options['identity-cookie-name'] === scope.identities.identityCookieName) &&
    (options.agents == null || Number(options.agents) === scope.limits.modelConcurrency) &&
    (options['http-workers'] == null || Number(options['http-workers']) === scope.limits.agents) &&
    (options['max-urls'] == null || Number(options['max-urls']) === scope.limits.maxUrls) &&
    (options['max-tasks'] == null || Number(options['max-tasks']) === scope.limits.tasks) &&
    (options['dom-script-bytes'] == null ||
      Number(options['dom-script-bytes']) === scope.limits.domScriptBytes) &&
    (options.environment == null || options.environment === scope.target.environment);
}

/** Write or reuse a validated scope template without registering or contacting a target. */
export function prepareScopeTemplate(working, rawUrl, options = {}, {reuse = false} = {}) {
  need(rawUrl, 'Provide an app URL: bypass blackbox setup <url>.');
  const root = rootFrom(working, false);
  const origin = appOriginInput(rawUrl);
  if (options.rps != null) {
    const requestedRate = Number(options.rps);
    need(Number.isFinite(requestedRate) && requestedRate > 0,
      '--rps must be a positive number.');
  }
  if (options['model-calls'] != null) {
    const requestedCalls = Number(options['model-calls']);
    need(Number.isSafeInteger(requestedCalls) && requestedCalls > 0,
      '--model-calls must be a positive whole number.');
  }
  if (options.minutes != null) {
    const requestedMinutes = Number(options.minutes);
    need(Number.isFinite(requestedMinutes) && requestedMinutes > 0,
      '--minutes must be a positive number.');
  }
  const file = path.resolve(root, options.out || 'blackbox.scope.json');
  if (fs.existsSync(file) && !options.force) {
    need(reuse, `Scope file already exists: ${file}. Use --force to replace it.`);
    let written;
    try {written = JSON.parse(fs.readFileSync(file, 'utf8'));}
    catch {need(false, `Scope file ${file} is not valid JSON. Edit it or use --force to replace it.`);}
    let scope = validateScopeTemplate(written);
    need(scope.target.origin === origin, `Scope file ${file} is written for ${scope.target.origin}, not ${origin}.`);
    need(requestedMatches(options, scope),
      `The existing scope differs from the requested setup flags. Review ${file} or use --force to replace it.`);
    targetURL(origin, scope.target.environment);
    const requestedRate = options.rps == null ? scope.limits.rps : Number(options.rps);
    if (requestedRate > scope.limits.rps) {
      need(scope.target.environment === 'local' || requestedRate <= 10,
        'Deployed black-box scope rates must be at most 10 requests per second.');
      scope = structuredClone(scope);
      scope.limits.rps = requestedRate;
      validateScopeTemplate(scope);
      atomic(file, scope);
      return {root, origin, file, scope, created: false, updated: true};
    }
    return {root, origin, file, scope, created: false, updated: false};
  }
  const local = loopback(new URL(origin).hostname);
  const environment = options.environment || (local ? 'local' : 'staging');
  targetURL(origin, environment);
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.target = {origin, environment, acknowledged: null};
  if (local) scope.limits.minutes = 30;
  scope.credentialOrigins = options['credential-origins'] ?
    credentialOrigins(origin, options['credential-origins']) : [origin];
  for (const credentialOrigin of scope.credentialOrigins) targetURL(credentialOrigin, environment);
  if (!local) {
    scope.limits.rps = 2;
    scope.limits.minutes = 30;
    scope.harvest.thirdParty = 'count-only';
    scope.harvest.sequentialNeighbors = 0;
    scope.probes.crlfResponseHeader = false;
    scope.probes.hostHeaderRedirect = false;
    scope.probes.jwtUnsigned = false;
    scope.probes.commandExecution = false;
    scope.probes.pathTraversal = false;
    scope.probes.xmlExternalEntity = false;
  }
  if (options.rps != null) {
    const rps = Number(options.rps);
    need(Number.isFinite(rps) && rps > 0, '--rps must be a positive number.');
    need(local || rps <= 10, 'Deployed black-box scope rates must be at most 10 requests per second.');
    scope.limits.rps = rps;
  }
  if (options.agents != null) {
    const agents = Number(options.agents);
    need(Number.isSafeInteger(agents) && agents > 0 && agents <= 100,
      '--agents must be a whole number from 1 through 100.');
    scope.limits.modelConcurrency = agents;
  }
  if (options['http-workers'] != null) {
    const httpWorkers = Number(options['http-workers']);
    need(Number.isSafeInteger(httpWorkers) && httpWorkers > 0 && httpWorkers <= 100,
      '--http-workers must be a whole number from 1 through 100.');
    scope.limits.agents = httpWorkers;
  }
  if (options['model-calls'] != null) {
    const modelCalls = Number(options['model-calls']);
    need(Number.isSafeInteger(modelCalls) && modelCalls > 0,
      '--model-calls must be a positive whole number.');
    scope.limits.modelCalls = modelCalls;
  }
  if (options['max-urls'] != null) {
    const maxUrls = Number(options['max-urls']);
    need(Number.isSafeInteger(maxUrls) && maxUrls >= 0,
      '--max-urls must be a nonnegative whole number (0 disables the URL-count cap).');
    scope.limits.maxUrls = maxUrls;
  }
  if (options['max-tasks'] != null) {
    const maxTasks = Number(options['max-tasks']);
    need(Number.isSafeInteger(maxTasks) && maxTasks >= 0,
      '--max-tasks must be a nonnegative whole number (0 disables the task-count cap).');
    scope.limits.tasks = maxTasks;
  }
  if (options.minutes != null) {
    const minutes = Number(options.minutes);
    need(Number.isFinite(minutes) && minutes > 0,
      '--minutes must be a positive number.');
    scope.limits.minutes = minutes;
  }
  if (options['dom-script-bytes'] != null) {
    const domScriptBytes = Number(options['dom-script-bytes']);
    need(Number.isSafeInteger(domScriptBytes) && domScriptBytes > 0 &&
      domScriptBytes <= 16 * 1024 * 1024,
      '--dom-script-bytes must be a whole number from 1 through 16777216.');
    scope.limits.domScriptBytes = domScriptBytes;
  }
  scope.include = options.include ? list(options.include) : ['/'];
  scope.domains = options.domains ? list(options.domains).map(value => value.toLowerCase()) : [];
  scope.discovery.auditDomains = options['audit-domains'] ?
    list(options['audit-domains']).map(value => value.toLowerCase()) : [];
  if (options.never) scope.never = [...new Set([...scope.never, ...list(options.never)])];
  if (options['owner-env']) scope.identities.owner.env = envName(options['owner-env']);
  if (options['other-env']) scope.identities.outsider.env = envName(options['other-env']);
  if (options.auth) scope.identities.auth = options.auth;
  if (options['identity-path']) scope.identities.identityPath = options['identity-path'];
  if (options['identity-cookie-name']) scope.identities.identityCookieName = options['identity-cookie-name'];
  scope.expiresAt = new Date(Date.now() + 7 * 86400000).toISOString();
  need(!local || scope.domains.length === 0,
    'The CLI cannot enumerate synthetic local domains. Omit --domains for a loopback target.');
  validateScopeTemplate(scope);
  atomic(file, scope);
  return {root, origin, file, scope, created: true};
}

function targetName(url, names) {
  const hostname = new URL(url).hostname.replace(/[^A-Za-z0-9]+/g, '-');
  const base = `bx-${hostname}`.slice(0, 56).replace(/-+$/, '');
  let name = base, suffix = 2;
  while (names.has(name)) name = `${base.slice(0, 60 - String(suffix).length)}-${suffix++}`;
  names.add(name);
  return safeName(name);
}

function authorized(target, scope, {primary, credentialed}) {
  const auth = target.authorization;
  const writes = primary ? scope.probes.writeOperations ?? [] : [];
  const methods = [...new Set(['GET', 'HEAD', 'POST', ...writes.map(item => item.method)])];
  return auth?.origin === target.url && current(auth.expiresAt) &&
    scope.include.every(entry => pathAllowed(entry, auth.paths ?? [])) &&
    methods.every(method => auth.methods?.includes(method)) &&
    auth.maxRequestsPerSecond >= scope.limits.rps &&
    (!credentialed || !scope.identities.login?.path || auth.loginPaths?.includes(scope.identities.login.path)) &&
    (!primary || (scope.probes.xmlPostPaths ?? []).every(entry => auth.xmlPostPaths?.includes(entry))) &&
    writes.every(entry => auth.writeOperations?.some(item =>
      item.method === entry.method && item.path === entry.path &&
      item.placement === entry.placement));
}

function authorizationFile(file, target, scope, {primary, credentialed}) {
  const writes = primary ? scope.probes.writeOperations ?? [] : [];
  const contract = {paths: scope.include,
    methods: [...new Set(['GET', 'HEAD', 'POST', ...writes.map(item => item.method)])],
    loginPaths: credentialed && scope.identities.login?.path ? [scope.identities.login.path] : [],
    xmlPostPaths: primary ? scope.probes.xmlPostPaths ?? [] : [],
    writeOperations: writes,
    maxRequestsPerSecond: scope.limits.rps};
  const name = `blackbox.authorization.${target.name}.${hash(contract).slice(0, 8)}.json`;
  const output = path.join(path.dirname(file), name);
  if (!fs.existsSync(output)) atomic(output, {...contract,
    expiresAt: new Date(Math.min(scope.expiresAt ? Date.parse(scope.expiresAt) : Infinity,
      Date.now() + 7 * 86400000)).toISOString(), productionAcknowledged: false});
  else {
    let existing;
    try {existing = JSON.parse(fs.readFileSync(output, 'utf8'));}
    catch {need(false, `Authorization file ${output} is invalid JSON. Review and repair it.`);}
    need(Array.isArray(existing.paths) && contract.paths.every(entry => pathAllowed(entry, existing.paths)) &&
      contract.methods.every(method => existing.methods?.includes(method)) &&
      contract.loginPaths.every(entry => existing.loginPaths?.includes(entry)) &&
      contract.xmlPostPaths.every(entry => existing.xmlPostPaths?.includes(entry)) &&
      contract.writeOperations.every(entry => existing.writeOperations?.some(item =>
        item.method === entry.method && item.path === entry.path &&
        item.placement === entry.placement)) &&
      existing.maxRequestsPerSecond >= contract.maxRequestsPerSecond && current(existing.expiresAt),
    `Authorization file ${output} is stale or narrower than the current scope. Review and update it.`);
  }
  return output;
}

/** One setup command prepares scope and target challenges; the operator performs DNS and authorization steps. */
export async function prepareBlackboxSetup(working, rawUrl, options = {}) {
  const prepared = prepareScopeTemplate(working, rawUrl, options, {reuse: true});
  const {root, origin, file, scope} = prepared;
  const projectFlag = ` --project ${quote(root)}`;
  const modelCheck = `bypass model test${projectFlag}`;
  const scopeFlag = file === path.join(root, 'blackbox.scope.json') ? '' : ` --scope ${quote(file)}`;
  const rateFlag = options.rps != null ? ` --rps ${Number(options.rps)}` : '';
  const modelCallsFlag = options['model-calls'] != null ? ` --model-calls ${Number(options['model-calls'])}` : '';
  const minutesFlag = options.minutes != null ? ` --minutes ${Number(options.minutes)}` : '';
  const auditCommand = `bypass blackbox ${quote(origin)}${scopeFlag}${projectFlag}${rateFlag}${modelCallsFlag}${minutesFlag}`;
  if (scope.target.environment === 'local') return {kind: 'blackbox-setup', root, scopeFile: file,
    origin, credentialOrigins: scope.credentialOrigins, created: prepared.created,
    updated: prepared.updated ?? false, ready: true,
    modelCheck,
    targets: [], steps: [{kind: 'run', command: auditCommand}],
    next: auditCommand};
  need(scope.limits.rps <= 10, 'Deployed black-box scope rates must be at most 10 requests per second.');

  if (!fs.existsSync(path.join(root, '.bypass/state.json'))) initStore(root, await repositoryInfo(root));
  const required = new Map();
  const add = (url, role, dns = false, audit = false) => {
    const entry = required.get(url) ?? {url, roles: [], dns: false, audit: false};
    entry.roles.push(role);
    entry.dns ||= dns;
    entry.audit ||= audit;
    required.set(url, entry);
  };
  add(origin, 'application', false, true);
  for (const credentialOrigin of scope.credentialOrigins) add(credentialOrigin, 'credential-origin', false, true);
  for (const domain of scope.domains) add(`https://${domain}`, 'apex', true,
    scope.discovery.auditDomains.includes(domain));
  for (const entry of required.values()) targetURL(entry.url, scope.target.environment);
  const registered = await change(root, state => {
    const names = new Set(state.targets.map(target => target.name));
    return [...required.values()].map(entry => {
      let target = state.targets.find(item => item.url === entry.url);
      if (!target) {
        const name = targetName(entry.url, names);
        target = {name, url: entry.url, environment: scope.target.environment,
          createdAt: new Date().toISOString(), ownership: {status: 'pending'}, authorization: null};
        target.challenge = makeChallenge(state.project, target);
        state.targets.push(target);
        state.activeTarget ??= name;
      }
      need(target.environment === scope.target.environment,
        `Target ${target.name} is ${target.environment}, but the scope is ${scope.target.environment}. Review the target and scope environment.`);
      const needsOwnership = target.ownership?.status !== 'verified' ||
        !current(target.ownership.expiresAt) || entry.dns && target.ownership.method !== 'dns';
      if (needsOwnership && !current(target.challenge?.expiresAt)) {
        target.challenge = makeChallenge(state.project, target);
        target.ownership = {status: 'pending'};
        target.authorization = null;
      }
      return {...entry, name: target.name, environment: target.environment,
        ownershipReady: !needsOwnership, authorizationReady: entry.audit &&
          authorized(target, scope, {primary: entry.url === origin,
            credentialed: scope.credentialOrigins.includes(entry.url)}),
        challenge: needsOwnership ? target.challenge : null};
    });
  });
  const steps = [];
  for (const target of registered.filter(item => !item.ownershipReady)) steps.push({kind: 'ownership',
    target: target.name, origin: target.url, record: target.challenge.record, value: target.challenge.token,
    httpPath: target.challenge.httpPath,
    command: `bypass target verify ${target.name} --method dns${projectFlag}`});
  for (const target of registered.filter(item => item.audit && !item.authorizationReady)) {
    const authFile = authorizationFile(file, target, scope, {primary: target.url === origin,
      credentialed: scope.credentialOrigins.includes(target.url)});
    steps.push({kind: 'authorization', target: target.name, file: authFile,
      production: target.environment === 'production',
      command: `bypass target authorize ${target.name} --scope-file ${quote(authFile)}${projectFlag}`});
  }
  steps.push({kind: 'run', command: auditCommand});
  return {kind: 'blackbox-setup', root, scopeFile: file, origin, created: prepared.created,
    updated: prepared.updated ?? false,
    credentialOrigins: scope.credentialOrigins, ready: steps.length === 1,
    modelCheck,
    targets: registered, steps, next: steps[0].command};
}
