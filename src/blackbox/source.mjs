// Optional source-assisted reconnaissance. Only bounded, redacted excerpts go to the model.
import fs from 'node:fs';
import path from 'node:path';
import {hash, need} from '../util.mjs';
import {maskExcerpt} from './ledger.mjs';
import {maskSecrets, extractFromScript, secretIndicators} from './assets.mjs';
import {credentialQueryKey} from './private-query.mjs';

const SKIP = new Set(['.git', '.bypass', 'node_modules', 'vendor', '.venv', 'venv', 'dist', 'build', 'coverage', '.next']);
const SUFFIX = /\.(?:[cm]?js|[cm]?ts|jsx|tsx|py|php|go|rb|java|kt|cs|rs)$/i;
const SECRET_FILE = /(?:^|\/)(?:\.env(?:\..*)?|.*\.(?:pem|key|p12|pfx|sqlite|db)|id_rsa|credentials(?:\.json)?)$/i;
const SERVER_ROUTE = /\b(?:app|router|server|route)\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*['"`]([^'"`]{1,240})['"`]/g;
const PY_ROUTE = /^[ \t]*@((?:app|router|bp|[A-Za-z_]\w*router))\.(get|post|put|patch|delete|route)\(\s*['"]([^'"]{1,240})['"]/gm;
const PHP_ROUTE = /\bRoute\s*::\s*(get|post|put|patch|delete|head|options)\s*\(\s*['"]([^'"]{1,240})['"]/g;
const SPRING_ROUTE = /@\s*(Get|Post|Put|Patch|Delete)Mapping\s*\(\s*(?:(?:value|path)\s*=\s*)?['"]([^'"]{1,240})['"]/g;
const DOTNET_ROUTE = /\b([A-Za-z_]\w*)\s*\.\s*Map(Get|Post|Put|Patch|Delete)\s*\(\s*['"]([^'"]{1,240})['"]/g;
const GUARDED_METHOD = /\b(?:req(?:uest)?\.)?method\s*===?\s*(['"`])(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\1/i;
const GUARDED_PATH = /\b(?:path|pathname|url\.pathname|req(?:uest)?\.url)\s*===?\s*(['"`])(\/[^'"`]{0,239})\1/;
const PHP_GROUP = /\bRoute\s*::\s*prefix\s*\(\s*(['"])([^'"]{1,240})\1\s*\)\s*->\s*group\s*\(\s*function\s*\([^)]*\)\s*\{/g;
const SPRING_CLASS = /@RequestMapping\s*\(\s*(?:(?:path|value)\s*=\s*)?(['"])([^'"]{1,240})\1\s*\)[\s\S]{0,300}?\bclass\s+[A-Za-z_]\w*[^\{]*\{/g;
const DOTNET_GROUP = /\b(?:var|RouteGroupBuilder)\s+([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\.\s*MapGroup\s*\(\s*(['"])([^'"]{1,240})\3\s*\)/g;
const PY_ROUTER = /^[ \t]*([A-Za-z_]\w*)\s*=\s*APIRouter\s*\(/gm;
const PARAM = /\b(?:req\.(?:query|params|body)|request\.(?:args|json|form)|ctx\.(?:query|params|request\.body))\??\.([A-Za-z_][A-Za-z0-9_]*)/g;
const LITERAL_PARAMS = [
  /\$request\s*->\s*(?:query|input|get)\s*\(\s*['"]([A-Za-z_][A-Za-z0-9_.-]{0,79})['"]/g,
  /@RequestParam\s*\(\s*(?:(?:value|name)\s*=\s*)?['"]([A-Za-z_][A-Za-z0-9_.-]{0,79})['"]/g,
  /\b(?:request|context\.Request|ctx\.Request)\s*\.\s*Query\s*\[\s*['"]([A-Za-z_][A-Za-z0-9_.-]{0,79})['"]\s*\]/g,
  /\brequest\s*\.\s*(?:args|query_params|GET)\s*\.\s*get\s*\(\s*['"]([A-Za-z_][A-Za-z0-9_.-]{0,79})['"]/g,
];
const SOURCE_MODEL_PAGE_ITEMS = 6;
const SOURCE_MODEL_MAX_BYTES = 20000;
const SOURCE_MODEL_MAX_PAGES = 8;
const SOURCE_MAX_ENTRIES = 20000;
const SOURCE_MAX_ROUTES = 1200;
const SOURCE_UNRESOLVED_PER_FILE = 4;
const SOURCE_UNRESOLVED_TOTAL = 24;
const SOURCE_SECRET_PER_FILE = 8;
const SOURCE_SECRET_TOTAL = 64;

function routeWithoutCredentialValues(value) {
  if (typeof value !== 'string' || !value.startsWith('/') || value.includes('#') || value.length > 240 ||
    /[\\;\x00-\x1f]/.test(value) ||
    !URL.canParse(value, 'https://source.invalid')) return null;
  const url = new URL(value, 'https://source.invalid');
  if (url.origin !== 'https://source.invalid') return null;
  let redacted = value;
  if ([...url.searchParams.keys()].some(credentialQueryKey)) {
    const query = new URLSearchParams();
    for (const [name, entry] of url.searchParams)
      query.append(name, credentialQueryKey(name) ? '' : entry);
    redacted = `${url.pathname}?${query}`;
  }
  return maskSecrets(redacted) === redacted ? redacted : null;
}

function safeRoutePath(value) {
  return routeWithoutCredentialValues(value) !== null;
}

function safePrefix(value) {
  return typeof value === 'string' && !!value && !value.startsWith('//') &&
    !value.includes('://') && !/[\\?#%\x00-\x1f]/.test(value) &&
    !value.split('/').includes('..') &&
    safeRoutePath(value.startsWith('/') ? value : `/${value}`);
}

function joinedRoute(parts) {
  let path = parts[0].startsWith('/') ? parts[0] : `/${parts[0]}`;
  for (const part of parts.slice(1)) path = `${path.replace(/\/$/, '')}/${part.replace(/^\//, '')}`;
  return path;
}

// Find a literal group or class body without treating braces in strings and comments as boundaries.
function matchingClose(text, open, left, right) {
  let depth = 0, quote = null;
  for (let at = open; at < text.length; at++) {
    const char = text[at], next = text[at + 1];
    if (quote) {
      if (char === '\\') at++;
      else if (char === quote) quote = null;
      continue;
    }
    if (char === '/' && next === '/') {at = text.indexOf('\n', at + 2); if (at < 0) return -1; continue;}
    if (char === '/' && next === '*') {at = text.indexOf('*/', at + 2); if (at < 0) return -1; at++; continue;}
    if (char === '#') {at = text.indexOf('\n', at + 1); if (at < 0) return -1; continue;}
    if (char === '\'' || char === '"' || char === '`') {quote = char; continue;}
    if (char === left) depth++;
    else if (char === right && --depth === 0) return at;
  }
  return -1;
}

function scopedPrefixes(text, expression, groupIndex) {
  const scopes = [];
  for (const match of text.matchAll(expression)) {
    const prefix = match[groupIndex];
    if (!safePrefix(prefix)) continue;
    const start = match.index + match[0].lastIndexOf('{');
    const end = matchingClose(text, start, '{', '}');
    if (end >= 0) scopes.push({start, end, prefix});
  }
  return scopes;
}

function activePrefixes(scopes, at) {
  return scopes.filter(scope => scope.start < at && at < scope.end)
    .sort((a, b) => a.start - b.start).map(scope => scope.prefix);
}

function dotnetGroups(text) {
  const declarations = [];
  for (const match of text.matchAll(DOTNET_GROUP))
    if (safePrefix(match[4])) declarations.push({at: match.index, name: match[1], parent: match[2],
      prefix: match[4]});
  return (receiver, at) => {
    const parts = [], seen = new Set();
    while (receiver !== 'app') {
      if (seen.has(receiver)) return [];
      seen.add(receiver);
      const declaration = declarations.filter(item => item.name === receiver && item.at < at).at(-1);
      if (!declaration) return [];
      parts.unshift(declaration.prefix);
      receiver = declaration.parent;
      at = declaration.at;
    }
    return parts;
  };
}

function pythonRouters(text) {
  const routers = [];
  for (const match of text.matchAll(PY_ROUTER)) {
    const start = match.index + match[0].lastIndexOf('(');
    const end = matchingClose(text, start, '(', ')');
    if (end < 0) continue;
    const prefix = /\bprefix\s*=\s*(['"])([^'"]{1,240})\1/.exec(text.slice(start + 1, end))?.[2];
    if (safePrefix(prefix)) routers.push({at: match.index, name: match[1], prefix});
  }
  return (receiver, at) => routers.filter(item => item.name === receiver && item.at < at).at(-1)?.prefix ?? null;
}

function listFiles(root, maxFiles) {
  const files = [], queue = [root];
  let filesCut = 0, entriesSeen = 0, traversalCut = false;
  outer: for (let at = 0; at < queue.length; at++) {
    const current = queue[at];
    let entries;
    try {entries = fs.readdirSync(current, {withFileTypes: true});} catch {continue;}
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (++entriesSeen > SOURCE_MAX_ENTRIES) {traversalCut = true; break outer;}
      const full = path.join(current, entry.name);
      if (entry.isSymbolicLink() || SKIP.has(entry.name)) continue;
      if (entry.isDirectory()) queue.push(full);
      else if (entry.isFile() && SUFFIX.test(entry.name) && !SECRET_FILE.test(full)) {
        if (files.length < maxFiles) files.push(full);
        else filesCut++;
      }
    }
  }
  return {files, filesCut, traversalCut};
}

function routeFacts(text, file) {
  const isPython = /\.py$/i.test(file), isPhp = /\.php$/i.test(file),
    isSpring = /\.java$/i.test(file), isDotnet = /\.cs$/i.test(file);
  const expressions = /\.[cm]?[jt]sx?$/i.test(file) ? [SERVER_ROUTE] :
    isPython ? [PY_ROUTE] : isPhp ? [PHP_ROUTE] :
      isSpring ? [SPRING_ROUTE] : isDotnet ? [DOTNET_ROUTE] : [];
  const scopes = isPhp ? scopedPrefixes(text, PHP_GROUP, 2) :
    isSpring ? scopedPrefixes(text, SPRING_CLASS, 2) : [];
  const dotnetPrefix = isDotnet ? dotnetGroups(text) : null;
  const pythonPrefix = isPython ? pythonRouters(text) : null;
  const matches = [];
  for (const expression of expressions) {
    expression.lastIndex = 0;
    for (const match of text.matchAll(expression)) {
      const receiver = isPython || isDotnet ? match[1] : null;
      const method = match[isPython || isDotnet ? 2 : 1];
      const literal = match[isPython || isDotnet ? 3 : 2];
      const pythonValue = isPython ? pythonPrefix(receiver, match.index) : null;
      const prefixes = isPhp || isSpring ? activePrefixes(scopes, match.index) :
        isDotnet ? dotnetPrefix(receiver, match.index) : pythonValue ? [pythonValue] : [];
      const path = safeRoutePath(literal) || (prefixes.length && safePrefix(literal)) ?
        joinedRoute([...prefixes, literal]) : null;
      if (path && !safeRoutePath(path)) continue;
      if (!path) continue;
      matches.push({path: routeWithoutCredentialValues(path),
        method: method.toUpperCase() === 'ROUTE' ? 'UNKNOWN' : method.toUpperCase(),
        index: match.index, receiver});
    }
  }
  // Some small HTTP servers dispatch routes through literal method/path
  // guards rather than a framework router. Read both halves of the guard
  // independently so their order does not change the extracted contract.
  if (/\.[cm]?[jt]sx?$/i.test(file)) for (const match of text.matchAll(/\bif\s*\(/g)) {
    const open = match.index + match[0].lastIndexOf('(');
    const close = matchingClose(text, open, '(', ')');
    if (close < 0) continue;
    const condition = text.slice(open + 1, close);
    if (!condition.includes('&&') || condition.includes('||')) continue;
    const method = GUARDED_METHOD.exec(condition)?.[2]?.toUpperCase();
    const literal = GUARDED_PATH.exec(condition)?.[2];
    const path = routeWithoutCredentialValues(literal);
    if (!method || !path) continue;
    const bodyOpen = /^\s*\{/.exec(text.slice(close + 1))?.[0];
    if (!bodyOpen) continue;
    const start = close + 1 + bodyOpen.lastIndexOf('{');
    const end = matchingClose(text, start, '{', '}');
    if (end < 0) continue;
    const body = text.slice(start + 1, end);
    const bodyFields = [...new Set([
      ...[...body.matchAll(/\bbody(?:\?)?\.([A-Za-z_][A-Za-z0-9_]*)/g)].map(item => item[1]),
      ...[...body.matchAll(/\bbody\s*\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\]/g)].map(item => item[1]),
    ])].slice(0, 20);
    const bodyEncoding = /\b(?:readJson|JSON\.parse)\s*\(|\b(?:req|request)\.json\s*\(/.test(body) ?
      'json' : null;
    matches.push({path, method, index: match.index, bodyFields, bodyEncoding});
  }
  matches.sort((a, b) => a.index - b.index);
  return matches.map((match, index) => {
    const nearby = text.slice(match.index, Math.min(text.length, match.index + 4000,
      matches[index + 1]?.index ?? text.length));
    const params = [...new Set([...((match.bodyFields ?? [])), ...[PARAM, ...LITERAL_PARAMS]
      .flatMap(expression => [...nearby.matchAll(expression)].map(item => item[1]))])].slice(0, 20);
    return {path: match.path, method: match.method, params, file,
      ...(match.bodyFields?.length ? {bodyFields: match.bodyFields} : {}),
      ...(match.bodyEncoding ? {bodyEncoding: match.bodyEncoding} : {}),
      ...(isPython ? {receiver: match.receiver} : {}),
      line: text.slice(0, match.index).split('\n').length, source: 'source-assisted'};
  });
}

function pythonImportAliases(entry, byFile) {
  const aliases = new Map();
  for (const match of entry.body.matchAll(/^[ \t]*from\s+([.A-Za-z_][\w.]*)\s+import\s+([^\n#]+)/gm)) {
    const module = match[1], dots = /^\.+/.exec(module)?.[0].length ?? 0;
    const base = dots ? path.posix.dirname(entry.relative) : '.';
    const parts = [...Array(Math.max(0, dots - 1)).fill('..'),
      ...module.slice(dots).split('.').filter(Boolean)];
    const stem = path.posix.normalize(path.posix.join(base, ...parts));
    if (path.posix.isAbsolute(stem) || stem === '..' || stem.startsWith('../')) continue;
    for (const imported of match[2].split(',')) {
      const name = /^\s*([A-Za-z_]\w*)(?:\s+as\s+([A-Za-z_]\w*))?\s*$/.exec(imported);
      if (!name) continue;
      const child = path.posix.join(stem, `${name[1]}.py`), moduleFile = `${stem}.py`;
      if (byFile.has(child)) aliases.set(name[2] ?? name[1], {file: child, variable: null});
      else if (byFile.has(moduleFile)) aliases.set(name[2] ?? name[1],
        {file: moduleFile, variable: name[1]});
    }
  }
  for (const match of entry.body.matchAll(/^[ \t]*import\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\s+as\s+([A-Za-z_]\w*)\s*$/gm)) {
    const file = `${match[1].replaceAll('.', '/')}.py`;
    if (byFile.has(file)) aliases.set(match[2], {file, variable: null});
  }
  return aliases;
}

function composePythonImports(scanned) {
  const byFile = new Map(scanned.filter(entry => /\.py$/i.test(entry.relative))
    .map(entry => [entry.relative, entry]));
  const included = new Map();
  for (const entry of byFile.values()) {
    const aliases = pythonImportAliases(entry, byFile);
    const appNames = new Set(['app', ...[...entry.body.matchAll(/^[ \t]*([A-Za-z_]\w*)\s*=\s*FastAPI\s*\(/gm)]
      .map(match => match[1])]);
    for (const match of entry.body.matchAll(/^[ \t]*([A-Za-z_]\w*)\s*\.\s*include_router\s*\(/gm)) {
      if (!appNames.has(match[1])) continue;
      const start = match.index + match[0].lastIndexOf('(');
      const end = matchingClose(entry.body, start, '(', ')');
      if (end < 0) continue;
      const args = entry.body.slice(start + 1, end);
      const target = /^\s*([A-Za-z_]\w*)(?:\.([A-Za-z_]\w*))?\s*(?:,|$)/.exec(args);
      if (!target) continue;
      const assigned = /\bprefix\s*=\s*/.exec(args);
      const literal = assigned ? /^(['"])([^'"]{1,240})\1/.exec(args.slice(assigned.index + assigned[0].length)) : null;
      if (assigned && (!literal || !safePrefix(literal[2]))) continue;
      const prefix = literal?.[2] ?? '';
      const imported = aliases.get(target[1]);
      const routerFile = imported?.file ?? (!target[2] ? entry.relative : null);
      const routerName = target[2] ?? imported?.variable ?? (!imported ? target[1] : null);
      if (!routerFile || !routerName || !byFile.has(routerFile)) continue;
      const key = JSON.stringify([routerFile, routerName]);
      if (!included.has(key)) included.set(key, new Set());
      included.get(key).add(prefix);
    }
  }
  let routesCut = 0;
  for (const entry of byFile.values()) {
    const cutBeforeFile = routesCut;
    const expanded = [];
    for (const route of entry.routes) {
      const prefixes = included.get(JSON.stringify([entry.relative, route.receiver]));
      if (!prefixes) {
        if (expanded.length < SOURCE_MAX_ROUTES) expanded.push(route);
        else routesCut++;
        continue;
      }
      if (expanded.length >= SOURCE_MAX_ROUTES) {routesCut += prefixes.size; continue;}
      for (const prefix of prefixes) {
        const candidate = {...route, path: prefix ? joinedRoute([prefix, route.path]) : route.path};
        if (!safeRoutePath(candidate.path)) continue;
        if (expanded.length < SOURCE_MAX_ROUTES) expanded.push(candidate);
        else routesCut++;
      }
    }
    entry.routeCount = expanded.length + routesCut - cutBeforeFile;
    entry.routes = expanded;
  }
  return routesCut;
}

function excerpt(text, route) {
  const lines = text.split('\n');
  const around = lines.slice(Math.max(0, route.line - 3), Math.min(lines.length, route.line + 18)).join('\n');
  return maskExcerpt(maskSecrets(around)).slice(0, 3000);
}

function unresolvedRouteHints(text, file, routes) {
  const expression = /\.php$/i.test(file) ? /^[ \t]*Route\s*::\s*(get|post|put|patch|delete|head|options)\s*\(/gm :
    /\.py$/i.test(file) ? /^[ \t]*@(?:app|router|bp|[A-Za-z_]\w*router)\.(get|post|put|patch|delete|route)\s*\(/gm :
      /\.java$/i.test(file) ? /^[ \t]*@\s*(Get|Post|Put|Patch|Delete)Mapping\s*\(/gm :
        /\.cs$/i.test(file) ? /^[ \t]*[A-Za-z_]\w*\s*\.\s*Map(Get|Post|Put|Patch|Delete)\s*\(/gm :
          /\.[cm]?[jt]sx?$/i.test(file) ? /^[ \t]*(?:app|router|server|route)\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(/gm : null;
  if (!expression) return [];
  const parsedLines = new Set(routes.map(route => route.line).filter(Number.isInteger));
  return [...text.matchAll(expression)].map(match => ({
    method: match[1].toUpperCase() === 'ROUTE' ? 'UNKNOWN' : match[1].toUpperCase(),
    line: text.slice(0, match.index).split('\n').length,
  })).filter(hint => !parsedLines.has(hint.line));
}

function unresolvedExcerpt(text, line) {
  const lines = text.split('\n');
  const around = lines.slice(Math.max(0, line - 13), Math.min(lines.length, line + 19)).join('\n');
  return maskExcerpt(maskSecrets(around)).slice(0, 3000);
}

function sourceModelPages(snippets) {
  const fit = entries => {
    if (entries.length === 1 ||
        Buffer.byteLength(JSON.stringify({page: 999, pages: 999, snippets: entries})) <= SOURCE_MODEL_MAX_BYTES)
      return [entries];
    const middle = Math.ceil(entries.length / 2);
    return [...fit(entries.slice(0, middle)), ...fit(entries.slice(middle))];
  };
  const pages = [];
  for (let at = 0; at < snippets.length; at += SOURCE_MODEL_PAGE_ITEMS)
    pages.push(...fit(snippets.slice(at, at + SOURCE_MODEL_PAGE_ITEMS)));
  return pages;
}

/** Read an explicitly supplied source tree and extract route facts plus optional Muse interpretations. */
export async function reviewSource(sourcePath, {infer = null, model = null, log = () => {},
  origin = null,
  maxFiles = 120, maxFileBytes = 16 * 1024 * 1024, maxTotalBytes = 64 * 1024 * 1024,
  maxModelPages = SOURCE_MODEL_MAX_PAGES} = {}) {
  const root = path.resolve(sourcePath);
  need(fs.existsSync(root) && fs.statSync(root).isDirectory(), `Source path is not a directory: ${root}.`);
  const files = [], endpoints = [], snippets = [], unresolvedSnippets = [], scanned = [], secretLeads = [];
  let total = 0, skipped = 0, routesCut = 0, unresolvedRoutes = 0, unresolvedRoutesCut = 0,
    secretLeadsCut = 0;
  const listed = listFiles(root, maxFiles);
  for (const file of listed.files) {
    let stat;
    try {stat = fs.statSync(file);} catch {skipped++; continue;}
    if (stat.size > maxFileBytes || total + stat.size > maxTotalBytes) {skipped++; continue;}
    const body = fs.readFileSync(file, 'utf8');
    total += stat.size;
    const relative = path.relative(root, file);
    const indicators = secretIndicators(body).filter(item => !item.public);
    for (const [index, indicator] of indicators.entries()) {
      if (index >= SOURCE_SECRET_PER_FILE || secretLeads.length >= SOURCE_SECRET_TOTAL) {
        secretLeadsCut++;
        continue;
      }
      secretLeads.push({file: relative, line: indicator.line, column: indicator.column,
        name: indicator.name, confidence: indicator.confidence});
    }
    const routes = routeFacts(body, relative);
    if (/\.[cm]?[jt]sx?$/i.test(file)) {
      const extracted = extractFromScript(body, {url: `source://${relative}`, origin});
      for (const entry of extracted.endpoints) if (safeRoutePath(entry.path)) {
        if (routes.some(route => route.path === entry.path &&
          (route.method === entry.method || entry.method === 'UNKNOWN' &&
            route.method !== 'UNKNOWN'))) continue;
        const offset = body.indexOf(entry.path);
        routes.push({path: routeWithoutCredentialValues(entry.path),
          method: entry.method, params: entry.params ?? [], file: relative,
          line: entry.line ?? (offset >= 0 ? body.slice(0, offset).split('\n').length : null), source: 'source-assisted'});
      }
    }
    scanned.push({relative, body, routes, hints: unresolvedRouteHints(body, relative, routes), bytes: stat.size});
  }
  routesCut += composePythonImports(scanned);
  for (const entry of scanned) {
    const {relative, body, routes, bytes} = entry;
    const kept = routes.slice(0, Math.max(0, SOURCE_MAX_ROUTES - endpoints.length))
      .map(({receiver, ...route}) => route);
    routesCut += routes.length - kept.length;
    endpoints.push(...kept);
    files.push({path: relative, bytes, hash: `sha256:${hash(body)}`, routes: entry.routeCount ?? routes.length});
    for (const route of kept) if (route.line !== null) snippets.push({path: route.path, method: route.method,
      params: route.params, file: maskExcerpt(maskSecrets(relative)), line: route.line, excerpt: excerpt(body, route)});
    unresolvedRoutes += entry.hints.length;
    for (const [hintIndex, hint] of entry.hints.entries()) {
      if (unresolvedSnippets.length >= SOURCE_UNRESOLVED_TOTAL ||
          hintIndex >= SOURCE_UNRESOLVED_PER_FILE) {unresolvedRoutesCut++; continue;}
      unresolvedSnippets.push({path: null, method: hint.method, params: [],
        file: maskExcerpt(maskSecrets(relative)), line: hint.line,
        excerpt: unresolvedExcerpt(body, hint.line)});
    }
  }
  const pages = sourceModelPages([...unresolvedSnippets, ...snippets]);
  const sourceMethods = new Map();
  for (const endpoint of endpoints) {
    const pathname = new URL(endpoint.path, 'https://source.invalid').pathname;
    if (!sourceMethods.has(pathname)) sourceMethods.set(pathname, new Set());
    sourceMethods.get(pathname).add(endpoint.method);
  }
  const notes = [], proposals = [];
  let modelCalls = 0, modelError = null, snippetsSent = 0;
  if (infer && model && pages.length) {
    for (let page = 0; page < Math.min(pages.length, Math.max(0, maxModelPages)); page++) {
      const batch = pages[page];
      const known = new Map();
      for (const route of batch) {
        if (!route.path) continue;
        if (!known.has(route.path)) known.set(route.path, {methods: new Set(), params: new Set()});
        known.get(route.path).methods.add(route.method);
        for (const param of route.params ?? []) known.get(route.path).params.add(param);
      }
      try {
        modelCalls++;
        snippetsSent += batch.length;
        const answer = await infer(model, [{role: 'system', content: 'Interpret these redacted source route excerpts as hypotheses. Explain accepted methods, parameters, purpose and trust boundaries. Entries with a null path are route declarations whose path expression was not parsed. Infer a GET path from them only when literal constants in the excerpt determine it; include a harmless query value when its parameter is needed, such as ?next=/safe. Never infer a GET path from a non-GET declaration. Propose at most eight GET paths for guarded HTTP verification. Return JSON only. Never include secrets, credentials or executable payloads.'},
          {role: 'user', content: JSON.stringify({page: page + 1, pages: pages.length, snippets: batch})}], {schema: {type: 'object', properties: {
            notes: {type: 'array', maxItems: 12, items: {type: 'object', properties: {path: {type: 'string'},
              purpose: {type: 'string'}, methods: {type: 'array', items: {type: 'string'}},
              parameters: {type: 'array', items: {type: 'string'}}, why: {type: 'string'}},
              required: ['path', 'purpose', 'methods', 'parameters', 'why'], additionalProperties: false}},
            paths: {type: 'array', maxItems: 8, items: {type: 'string'}}},
            required: ['notes', 'paths'], additionalProperties: false}});
        for (const note of (answer.notes ?? []).slice(0, 12)) if (known.has(note.path))
          notes.push({...note, purpose: maskExcerpt(maskSecrets(note.purpose)), why: maskExcerpt(maskSecrets(note.why)),
            methods: (Array.isArray(note.methods) ? note.methods : []).filter(value => known.get(note.path).methods.has(value)),
            parameters: (Array.isArray(note.parameters) ? note.parameters : [])
              .filter(value => known.get(note.path).params.has(value)).map(value => maskExcerpt(maskSecrets(value)))});
        for (const path of (answer.paths ?? []).slice(0, 8)) {
          const redactedPath = routeWithoutCredentialValues(path);
          if (!redactedPath || proposals.includes(redactedPath)) continue;
          const methods = sourceMethods.get(new URL(redactedPath, 'https://source.invalid').pathname);
          if (methods && !methods.has('GET') && !methods.has('UNKNOWN')) continue;
          proposals.push(redactedPath);
        }
      } catch (error) {
        modelError = error.message;
        log({stage: 'source', message: `Muse source interpretation failed: ${error.message}`});
        break;
      }
    }
  }
  const modelCoverage = {pagesAvailable: pages.length, pagesSent: modelCalls,
    snippetsAvailable: unresolvedSnippets.length + snippets.length, snippetsSent};
  log({stage: 'source', message: `${files.length} source files, ${endpoints.length} route facts, ${secretLeads.length} credential-shaped leads, ${unresolvedRoutes} unresolved declarations, ${skipped} skipped by size budget, ${listed.filesCut} cut by file budget`});
  return {root, files, endpoints, notes, proposals, secretLeads,
    stats: {files: files.length, bytes: total, skipped, filesCut: listed.filesCut, routesCut,
      unresolvedRoutes, unresolvedRoutesCut, secretLeadsCut, traversalCut: listed.traversalCut},
    unresolved: unresolvedSnippets.map(({file, line, method}) => ({file, line, method})),
    modelCoverage, modelCalls, modelError};
}
