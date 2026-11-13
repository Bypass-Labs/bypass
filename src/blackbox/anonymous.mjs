import {parseOpenApi} from './recon.mjs';
import {validateUrl, observedMethodAuthorized} from './scope.mjs';

function registrationContract(item, path, fields) {
  const segments = path.split('/').filter(Boolean);
  const last = segments.at(-1) ?? '';
  return fields.some(name => /^(?:password(?:repeat|again|confirm|confirmation|verify|2)|repeatpassword|confirmpassword|verifypassword|password_confirmation)$/i.test(name)) ||
    segments.some(segment => /^(?:register|registration|signup|sign-up|sign_up|create-account|new-account)$/i.test(segment)) ||
    /^(?:users|accounts|members)$/i.test(last) ||
    /\b(?:register|registration|sign[ -]?up|create (?:an? )?account)\b/i.test(item.purpose ?? '');
}

/** Admit exact public JS/OpenAPI method contracts within the reviewed scope. */
export async function deriveLocalPostScope(scope, mined, requester) {
  const postAuthorized = observedMethodAuthorized(scope, 'POST');
  // Check the route shape and include boundary before admitting an observed POST.
  // The GET-only action guard is bypassed for this check; explicit never entries
  // still apply to both read and write methods.
  const candidates = [...(mined?.endpoints ?? []).map(item => ({...item,
    source: item.sources?.includes('public-html') ? 'public-html' : 'public-js'}))];
  for (const pathname of scope.discover.filter(value => /(?:openapi|swagger|api-docs).*\.json$/i.test(value)).slice(0, 5)) {
    const response = await requester({url: pathname, identity: 'anonymous', method: 'GET',
      step: 'recon', purpose: 'discover'});
    if (response.status !== 200) continue;
    let doc;
    try {doc = JSON.parse(response.body);} catch {continue;}
    if (!doc?.openapi && !doc?.swagger) continue;
    candidates.push(...parseOpenApi(doc, scope.target.origin).operations.map(item =>
      ({...item, source: 'public-openapi'})));
  }
  const admitted = new Map(), authAdmitted = new Map(), skipped = [];
  for (const item of candidates) {
    if (item.method !== 'POST' || !['json', 'form'].includes(item.bodyEncoding)) continue;
    const path = item.path;
    const fields = [...new Set(((item.source === 'public-openapi' && item.bodyEncoding !== 'json' ?
      item.bodyStringFields : item.bodyFields) ?? [])
      .filter(name => typeof name === 'string' && /^[A-Za-z_][A-Za-z0-9_.-]{0,79}$/.test(name)))];
    const alreadyReviewed = scope.probes[item.bodyEncoding === 'json' ?
      'jsonPostPaths' : 'formPostPaths'].includes(path);
    const reason = typeof path !== 'string' || !/^\/[A-Za-z0-9/_.-]{1,200}$/.test(path) ||
      path.endsWith('/') ? 'non-concrete-path' :
      item.source === 'public-openapi' && item.contentType !==
        (item.bodyEncoding === 'json' ? 'application/json' : 'application/x-www-form-urlencoded') ?
        'unsupported-content-type' :
      !fields.length || fields.length > 8 ? 'no-bounded-string-body-contract' :
      !postAuthorized ? 'post-not-authorized' :
      !validateUrl({...scope, discover: [...scope.discover, path]}, path, {method: 'GET'}).ok ?
        'outside-scope-or-never' : null;
    if (reason) {skipped.push({path, method: 'POST', reason}); continue;}
    const usernameField = fields.find(name => /^(?:email|username|user|login)$/i.test(name));
    const passwordField = fields.find(name => /^(?:password|passwd|pass|pwd)$/i.test(name));
    if (item.bodyEncoding === 'json' && usernameField && passwordField &&
        !registrationContract(item, path, fields)) {
      authAdmitted.set(path, {path, method: 'POST', contentType: 'application/json',
        fields: [usernameField, passwordField], usernameField, passwordField,
        source: item.source});
      continue;
    }
    if (alreadyReviewed) continue;
    const key = `${item.bodyEncoding} ${path}`;
    const existing = admitted.get(key);
    admitted.set(key, {path, method: 'POST', bodyEncoding: item.bodyEncoding,
      contentType: item.bodyEncoding === 'json' ? 'application/json' : 'application/x-www-form-urlencoded',
      fields: [...new Set([...(existing?.fields ?? []), ...fields])].slice(0, 8),
      source: [...new Set([...(existing?.source ?? []), item.source])]});
  }
  const methodAdmitted = new Map();
  const local = scope.target.environment === 'local';
  const authorized = scope.authorizedOrigins?.[scope.target.origin]?.authorization;
  for (const item of candidates) {
    if (!['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].includes(item.method)) continue;
    const rawPath = item.path;
    if (typeof rawPath !== 'string' || !rawPath.startsWith('/') ||
        rawPath.startsWith('//') || rawPath.includes('{')) continue;
    let parsed;
    try {parsed = new URL(rawPath, scope.target.origin);} catch {continue;}
    const path = parsed.pathname;
    if (item.method === 'POST' && authAdmitted.has(path)) continue;
    if (!/^\/[A-Za-z0-9/_.-]{1,200}$/.test(path) || path.endsWith('/') ||
        !validateUrl({...scope, discover: [...scope.discover, path]}, path,
          {method: 'GET', identity: 'anonymous'}).ok) {
      skipped.push({path, method: item.method, reason: 'outside-scope-or-never'});
      continue;
    }
    const methodAuthorized = scope.methods.includes(item.method) &&
      (local || authorized?.methods?.includes(item.method));
    const safeFields = values => [...new Set((values ?? []).filter(name =>
      typeof name === 'string' && /^[A-Za-z_][A-Za-z0-9_.-]{0,79}$/.test(name)))].slice(0, 8);
    const bodyPlacement = ['json', 'form', 'xml'].includes(item.bodyEncoding) ?
      item.bodyEncoding : null;
    if (item.method === 'OPTIONS' && bodyPlacement) {
      skipped.push({path, method: item.method, placement: bodyPlacement,
        reason: 'options-body-not-reviewed'});
      continue;
    }
    const placements = bodyPlacement ? [bodyPlacement] : ['query', 'header'];
    for (const placement of placements) {
      const fields = bodyPlacement ? safeFields(item.source === 'public-openapi' &&
        !['xml', 'json'].includes(placement) ? item.bodyStringFields : item.bodyFields) :
        safeFields((item.params ?? []).filter(param => placement === 'query' ?
          typeof param === 'string' || param?.in === 'query' :
          param?.in === 'header').map(param => typeof param === 'string' ? param : param.name));
      const contentType = bodyPlacement ? item.contentType ??
        ({json: 'application/json', form: 'application/x-www-form-urlencoded',
          xml: 'application/xml'})[placement] : null;
      const reason = !fields.length ? 'no-controllable-observed-field' :
        !methodAuthorized ? 'method-not-authorized' :
        placement === 'xml' && !item.rootElement ? 'xml-root-unobserved' :
        bodyPlacement && !/^(?:application\/(?:json|[a-z0-9.-]+\+json)|application\/x-www-form-urlencoded|application\/xml)(?:\s*;|$)/i.test(contentType) ?
          'unsupported-content-type' : null;
      if (reason) {
        skipped.push({path, method: item.method, placement, reason});
        continue;
      }
      const key = `${item.method} ${placement} ${path}`;
      const requiredFields = safeFields(item.bodyRequiredFields).filter(name =>
        fields.includes(name));
      const operation = {path, method: item.method, placement, fields,
        requiredFields, contentType,
        ...(placement === 'json' ? {fieldTypes: item.bodyFieldTypes ?? {}} : {}),
        ...(placement === 'json' && item.fieldShapes ? {fieldShapes: item.fieldShapes} : {}),
        ...(placement === 'json' && item.fieldValueExamples ?
          {fieldValueExamples: item.fieldValueExamples} : {}),
        ...(placement === 'xml' ? {rootElement: item.rootElement} : {}),
        ...(item.fieldExamples ? {fieldExamples: item.fieldExamples} : {}),
        source: item.source, purpose: item.purpose ?? ''};
      const existing = methodAdmitted.get(key);
      if (!existing || item.source === 'public-openapi') methodAdmitted.set(key, operation);
    }
  }
  if (!admitted.size && !authAdmitted.size && !methodAdmitted.size)
    return {scope, admitted: [], authAdmitted: [], methodAdmitted: [], skipped};
  const effective = structuredClone(scope);
  effective.probes.jsonPostPaths = [...new Set([...effective.probes.jsonPostPaths,
    ...[...admitted.values()].filter(item => item.bodyEncoding === 'json').map(item => item.path)])];
  effective.probes.formPostPaths = [...new Set([...effective.probes.formPostPaths,
    ...[...admitted.values()].filter(item => item.bodyEncoding === 'form').map(item => item.path)])];
  effective.localAutoPostContracts = Object.fromEntries([...admitted.values()]
    .map(item => [`${item.bodyEncoding} ${item.path}`, {fields: item.fields,
      contentType: item.contentType}]));
  effective.localAuthPostContracts = Object.fromEntries([...authAdmitted.values()]
    .map(item => [item.path, item]));
  effective.localAutoMethodContracts = Object.fromEntries([...methodAdmitted]
    .map(([key, item]) => [key, item]));
  return {scope: effective, admitted: [...admitted.values()],
    authAdmitted: [...authAdmitted.values()], methodAdmitted: [...methodAdmitted.values()], skipped};
}

/** Keep public, scope-admitted POST contracts when account recon maps private routes. */
export function mergeAdmittedOperations(surface, localPosts) {
  const merged = {...surface};
  const add = (field, additions, key) => {
    const entries = new Map((surface[field] ?? []).map(item => [key(item), item]));
    for (const item of additions) {
      const identity = key(item);
      const existing = entries.get(identity);
      entries.set(identity, existing ? {...item, ...existing,
        fields: [...new Set([...(existing.fields ?? []), ...(item.fields ?? [])])]} : item);
    }
    merged[field] = [...entries.values()];
  };
  const posts = localPosts?.admitted ?? [];
  const operation = item => ({path: item.path, method: 'POST',
    contentType: item.contentType, fields: item.fields, requiredFields: [],
    source: item.source});
  add('jsonBodyOperations', posts.filter(item => item.bodyEncoding === 'json')
    .map(operation), item => item.path);
  add('formBodyOperations', posts.filter(item => item.bodyEncoding === 'form')
    .map(operation), item => item.path);
  add('authBodyOperations', localPosts?.authAdmitted ?? [], item => item.path);
  add('methodOperations', localPosts?.methodAdmitted ?? [], item =>
    `${item.method} ${item.placement} ${item.path}`);
  return merged;
}

/** Documented anonymous routes available without an account, for bounded web probes. */
export async function anonymousSurface(scope, requester, mined) {
  const patterns = new Map();
  const readTemplates = new Set();
  const slot = /^\{[A-Za-z_][A-Za-z0-9_.-]{0,79}\}$/;
  const xmlBodyOperations = new Map();
  const jsonBodyOperations = new Map();
  const formBodyOperations = new Map();
  const authBodyOperations = Object.values(scope.localAuthPostContracts ?? {});
  const skippedReadActions = new Set();
  let apiSchemaCuts = 0;
  const add = item => {
    if (!['GET', 'UNKNOWN'].includes(item.method) || !item.path?.startsWith('/') ||
        item.path.startsWith('//') || item.path.includes('{')) return;
    const checked = validateUrl(scope, item.path, {identity: 'anonymous'});
    if (!checked.ok) {
      if (checked.reason === 'read-action-review') skippedReadActions.add(item.path);
      return;
    }
    const parsed = new URL(checked.url);
    const pathname = parsed.pathname;
    const existing = patterns.get(pathname) ?? {pattern: pathname, methods: ['GET'], source: [],
      params: {}, label: {kind: 'unknown'}};
    existing.source.push(item.source ?? 'public-asset');
    const addParam = (name, example) => {
      if (!name) return;
      const values = existing.params[name] ?? [];
      if ((typeof example === 'string' || typeof example === 'number') &&
          !values.includes(String(example)) && values.length < 4) values.push(String(example).slice(0, 100));
      existing.params[name] = values;
    };
    for (const [name, value] of parsed.searchParams) addParam(name, value);
    for (const param of item.params ?? []) {
      const name = typeof param === 'string' ? param : param?.in === 'query' ? param.name : null;
      addParam(name, typeof param === 'object' && param !== null ? param.example : null);
    }
    patterns.set(pathname, existing);
  };
  for (const item of mined?.endpoints ?? []) {
    if (['GET', 'UNKNOWN'].includes(item.method) &&
        typeof item.path === 'string' && item.path.split('/').some(part => slot.test(part)))
      readTemplates.add(item.path);
    add(item);
    // A literal client-side JSON body supplies observed field names, but only an
    // exact path already reviewed in the local scope can become a POST operation.
    if (item.method !== 'POST' || item.bodyEncoding !== 'json' ||
        !Array.isArray(item.bodyFields) || !item.bodyFields.length ||
        item.path?.includes('{') ||
        !scope.probes.jsonPostPaths.includes(item.path) ||
        !validateUrl(scope, item.path, {identity: 'anonymous', method: 'POST', purpose: 'json-body'}).ok)
      continue;
    const fields = [...new Set(item.bodyFields.filter(name =>
      typeof name === 'string' && /^[A-Za-z_][A-Za-z0-9_.-]{0,79}$/.test(name)))].slice(0, 8);
    if (!fields.length) continue;
    jsonBodyOperations.set(item.path, {path: item.path, method: 'POST',
      contentType: 'application/json', fields, requiredFields: [],
      fieldTypes: item.bodyFieldTypes ?? {},
      fieldShapes: item.fieldShapes ?? {},
      fieldValueExamples: item.fieldValueExamples ?? {},
      fieldExamples: Object.fromEntries(Object.entries(item.fieldExamples ?? {})
        .filter(([name]) => fields.includes(name))), source: 'public-js',
      files: (item.files ?? []).slice(0, 4), purpose: item.purpose ?? ''});
  }
  for (const item of mined?.endpoints ?? []) {
    if (item.method !== 'POST' || item.bodyEncoding !== 'form' ||
        !item.bodyFields?.length || item.path?.includes('{') ||
        !scope.probes.formPostPaths.includes(item.path) ||
        !validateUrl(scope, item.path, {identity: 'anonymous', method: 'POST', purpose: 'form-body'}).ok)
      continue;
    formBodyOperations.set(item.path, {path: item.path, method: 'POST',
      contentType: 'application/x-www-form-urlencoded', fields: item.bodyFields,
      requiredFields: item.bodyRequiredFields ?? [],
      source: item.sources?.includes('public-html') ? 'public-html' : 'public-asset',
      files: (item.files ?? []).slice(0, 4), purpose: item.purpose ?? ''});
  }
  for (const pathname of scope.discover.filter(value => /(?:openapi|swagger|api-docs).*\.json$/i.test(value)).slice(0, 5)) {
    const response = await requester({url: pathname, identity: 'anonymous', method: 'GET', step: 'recon', purpose: 'discover'});
    if (response.status !== 200) continue;
    let doc;
    try {doc = JSON.parse(response.body);} catch {continue;}
    const parsed = parseOpenApi(doc, scope.target.origin);
    apiSchemaCuts += parsed.schemaCuts;
    for (const operation of parsed.operations) {
      if (operation.method === 'GET' && operation.path.split('/').some(part => slot.test(part)))
        readTemplates.add(operation.path);
      add({...operation, source: 'public-openapi'});
      if (operation.method === 'POST' && operation.bodyEncoding === 'xml' &&
          !operation.path.includes('{') &&
          validateUrl(scope, operation.path, {identity: 'anonymous', method: 'POST', purpose: 'xml-body'}).ok)
        xmlBodyOperations.set(operation.path, {path: operation.path, method: 'POST',
          contentType: 'application/xml', fields: operation.bodyFields,
          requiredFields: operation.bodyRequiredFields,
          ...(operation.rootElement ? {rootElement: operation.rootElement} : {}),
          source: 'public-openapi', purpose: operation.purpose ?? ''});
      if (operation.method === 'POST' && operation.bodyEncoding === 'json' &&
          !operation.path.includes('{') && operation.bodyFields?.length &&
          validateUrl(scope, operation.path, {identity: 'anonymous', method: 'POST', purpose: 'json-body'}).ok)
        jsonBodyOperations.set(operation.path, {path: operation.path, method: 'POST',
          contentType: 'application/json', fields: operation.bodyFields,
          fieldTypes: operation.bodyFieldTypes ?? {},
          ...(operation.fieldShapes ? {fieldShapes: operation.fieldShapes} : {}),
          ...(operation.fieldValueExamples ? {fieldValueExamples: operation.fieldValueExamples} : {}),
          requiredFields: operation.bodyRequiredFields, source: 'public-openapi',
          ...(operation.fieldExamples ? {fieldExamples: operation.fieldExamples} : {}),
          purpose: operation.purpose ?? ''});
      if (operation.method === 'POST' && operation.bodyEncoding === 'form' &&
          !operation.path.includes('{') && operation.bodyStringFields?.length &&
          validateUrl(scope, operation.path, {identity: 'anonymous', method: 'POST', purpose: 'form-body'}).ok)
        formBodyOperations.set(operation.path, {path: operation.path, method: 'POST',
          contentType: 'application/x-www-form-urlencoded', fields: operation.bodyStringFields,
          requiredFields: operation.bodyRequiredFields, source: 'public-openapi',
          ...(operation.fieldExamples ? {fieldExamples: operation.fieldExamples} : {}),
          purpose: operation.purpose ?? ''});
    }
  }
  // A documented template becomes actionable only when a concrete route was
  // observed separately. Preserve that relationship without ever requesting
  // the literal `{id}` path or changing the executable representative.
  for (const item of patterns.values()) {
    const actual = item.pattern.split('/');
    const matching = [...readTemplates].filter(template => {
      const parts = template.split('/');
      return parts.length === actual.length && parts.some(part => slot.test(part)) &&
        parts.every((part, index) => slot.test(part) ? Boolean(actual[index]) :
          part === actual[index]);
    });
    if (matching.length === 1) item.pathTemplate = matching[0];
  }
  return {patterns: [...patterns.values()], xmlBodyOperations: [...xmlBodyOperations.values()],
    jsonBodyOperations: [...jsonBodyOperations.values()],
    formBodyOperations: [...formBodyOperations.values()],
    methodOperations: Object.values(scope.localAutoMethodContracts ?? {}),
    authBodyOperations, apiSchemaCuts,
    skippedReadActions: [...skippedReadActions]};
}

export async function anonymousPatterns(scope, requester, mined) {
  return (await anonymousSurface(scope, requester, mined)).patterns;
}
