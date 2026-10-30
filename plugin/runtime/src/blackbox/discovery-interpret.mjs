// Muse interpretation of already observed host and endpoint facts. It cannot add hosts or requests.
const ROLES = new Set(['app', 'api', 'marketing', 'admin', 'docs', 'status', 'staging', 'legacy', 'static', 'unknown']);
const BATCH_HOSTS = 12;
const OPERATIONS_PER_HOST = 12;
const plain = value => String(value ?? '').replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, 300);

export async function interpretDiscovery(discovery, {infer = null, model = null, maxCalls = 20,
  log = () => {}} = {}) {
  const hosts = (discovery?.hosts ?? []).filter(host => host.live);
  const operationsAvailable = hosts.reduce((count, host) => count + (host.operations?.length ?? 0), 0);
  let modelCalls = 0, modelError = null, operationsSent = 0;
  const hostsSent = new Set();
  if (!infer || !model || !hosts.length) {
    discovery.modelAnalysis = {modelCalls, modelError, hostsSent: 0, operationsSent, operationsAvailable,
      operationsCut: operationsAvailable};
    return discovery.modelAnalysis;
  }
  const pages = Math.max(1, Math.ceil(Math.max(...hosts.map(host => host.operations?.length ?? 0)) / OPERATIONS_PER_HOST));
  outer: for (let page = 0; page < pages; page++) for (let at = 0; at < hosts.length; at += BATCH_HOSTS) {
    if (modelCalls >= maxCalls) break outer;
    const batch = hosts.slice(at, at + BATCH_HOSTS).filter(host => page === 0 ||
      (host.operations?.length ?? 0) > page * OPERATIONS_PER_HOST);
    if (!batch.length) continue;
    const context = batch.map(host => ({host: host.host, title: host.title, stack: host.stack,
      operations: (host.operations ?? []).slice(page * OPERATIONS_PER_HOST,
        (page + 1) * OPERATIONS_PER_HOST).map(item => ({method: item.method,
        path: item.path, params: item.params, source: item.source}))}));
    for (const host of batch) hostsSent.add(host.host);
    operationsSent += context.reduce((count, host) => count + host.operations.length, 0);
    try {
      modelCalls++;
      const reply = await infer(model, [{role: 'system', content: 'Interpret only the recorded external host inventory. For each listed host, label its likely role and explain the purpose of documented API operations and their parameters. Return JSON. Do not invent hosts, paths, methods, parameters, findings, or requests. Every label is an unverified interpretation of observed facts.'},
        {role: 'user', content: JSON.stringify({hosts: context})}], {schema: {type: 'object', properties: {
          hosts: {type: 'array', maxItems: BATCH_HOSTS, items: {type: 'object', properties: {
            host: {type: 'string'}, role: {type: 'string'}, why: {type: 'string', maxLength: 300},
            operations: {type: 'array', maxItems: OPERATIONS_PER_HOST, items: {type: 'object', properties: {
              method: {type: 'string'}, path: {type: 'string'}, purpose: {type: 'string', maxLength: 300},
              parameters: {type: 'array', maxItems: 16, items: {type: 'object', properties: {
                name: {type: 'string'}, meaning: {type: 'string', maxLength: 300}},
              required: ['name', 'meaning'], additionalProperties: false}}},
            required: ['method', 'path', 'purpose', 'parameters'], additionalProperties: false}}},
          required: ['host', 'role', 'why', 'operations'], additionalProperties: false}}},
        required: ['hosts'], additionalProperties: false}});
      const known = new Map(batch.map(host => [host.host, host]));
      for (const label of Array.isArray(reply?.hosts) ? reply.hosts : []) {
        const host = known.get(label.host);
        if (!host || !ROLES.has(label.role)) continue;
        host.analysis = {role: label.role, why: plain(label.why), by: 'model'};
        for (const description of Array.isArray(label.operations) ? label.operations : []) {
          const operation = host.operations.find(item => item.method === description.method && item.path === description.path);
          if (!operation) continue;
          operation.purpose = plain(description.purpose);
          const knownParams = new Set(operation.params.map(param => param.name));
          operation.parameterMeanings = (Array.isArray(description.parameters) ? description.parameters : [])
            .filter(item => knownParams.has(item.name)).slice(0, 16).map(item => ({name: item.name, meaning: plain(item.meaning)}));
        }
      }
    } catch (error) {
      modelError ??= error.message;
      log({stage: 'discovery-model', message: `Muse host interpretation failed: ${error.message}`});
    }
  }
  discovery.modelAnalysis = {modelCalls, modelError, hostsSent: hostsSent.size, operationsSent,
    operationsAvailable, operationsCut: operationsAvailable - operationsSent};
  log({stage: 'discovery-model', message: `Muse received ${hostsSent.size} live host records and ${operationsSent} of ${operationsAvailable} recorded operations`});
  return discovery.modelAnalysis;
}
