// The report describes attempted behavior, never infers safety from an absent finding.
const FAMILIES = [
  ['access-control', 'Cross-account and missing-authentication reads'],
  ['exposed-paths', 'Sensitive files and management paths'],
  ['secret-exposure', 'Parseable private keys and credential-shaped values in public assets'],
  ['anonymous-credential-data', 'Credential material in anonymous account-list JSON'],
  ['open-redirect', 'Open redirects on discovered GET parameters'],
  ['host-header-redirect', 'Host-dependent absolute redirects on observed GET routes'],
  ['parameter-pollution', 'Duplicate GET parameters and parser mismatches'],
  ['response-header-injection', 'CRLF response-header injection on documented GET parameters'],
  ['xss', 'Cross-site scripting and HTML injection'],
  ['sql-nosql-injection', 'SQL and NoSQL injection'],
  ['ssti', 'Server-side template expression evaluation'],
  ['command-injection', 'Template-to-command and OS command injection'],
  ['ssrf', 'Server-side request forgery'],
  ['xxe', 'XML external entity processing'],
  ['path-file', 'Path traversal and file handling'],
  ['upload', 'File upload and content handling'],
  ['session-account', 'Session takeover and account flows'],
  ['rate-limit', 'Authentication and access-gate throttling'],
  ['jwt-auth', 'Unsigned JWT acceptance on private JSON reads'],
  ['csrf', 'Cross-site request forgery'],
  ['cors', 'Cross-origin resource sharing'],
  ['business-logic', 'Business logic and workflow abuse'],
  ['dependency', 'Known vulnerable dependencies'],
  ['model-directed', 'Muse-proposed scoped response experiments'],
];

const REQUESTED_CLASSES = {
  'Web Application Vulnerabilities': [
    'Cross-Site Scripting (XSS)', 'Stored XSS', 'Reflected XSS', 'DOM-Based XSS',
    'SQL Injection (SQLi)', 'NoSQL Injection', 'Server-Side Request Forgery (SSRF)',
    'Server-Side Template Injection (SSTI)', 'Cross-Site Request Forgery (CSRF)',
    'XML External Entity Injection (XXE)', 'Remote Code Execution (RCE)',
    'Local File Inclusion (LFI)', 'Remote File Inclusion (RFI)', 'Path Traversal',
    'OS Command Injection', 'HTTP Request Smuggling', 'HTTP Response Splitting',
    'Host Header Injection', 'Open Redirect', 'Prototype Pollution', 'Insecure Deserialization',
    'HTTP Parameter Pollution', 'Web Cache Poisoning', 'Web Cache Deception', 'CRLF Injection',
    'HTML Injection',
  ],
  'Authentication & Authorization': [
    'Broken Access Control', 'Insecure Direct Object Reference (IDOR)',
    'Broken Object Level Authorization (BOLA)', 'Broken Function Level Authorization (BFLA)',
    'Authentication Bypass', 'Authorization Bypass', 'Privilege Escalation',
    'Horizontal Privilege Escalation', 'Vertical Privilege Escalation', 'Account Takeover (ATO)',
    'Session Hijacking', 'Session Fixation', 'JWT Authentication Bypass',
    'JWT Signature Verification Flaws', 'OAuth Misconfiguration', 'OAuth Account Takeover',
    'SAML Authentication Bypass', 'Multi-Factor Authentication (MFA) Bypass',
    'Password Reset Poisoning', 'Password Reset Token Leakage', 'Username Enumeration',
    'Account Enumeration', 'Race Condition', 'Business Logic Bypass',
  ],
  'API Vulnerabilities': [
    'Broken Object Property Level Authorization (BOPLA)', 'Mass Assignment',
    'Excessive Data Exposure', 'API Authentication Bypass', 'API Authorization Bypass',
    'GraphQL Injection', 'GraphQL Introspection Exposure', 'GraphQL Query Complexity DoS',
    'API Rate Limit Bypass', 'Unrestricted Resource Consumption', 'API Key Exposure',
    'API Key Privilege Escalation', 'Webhook Signature Bypass', 'Webhook SSRF',
    'Insecure API Versioning', 'Shadow API Exposure',
  ],
  'Cloud & Infrastructure': [
    'Cloud Metadata Service SSRF', 'IAM Privilege Escalation', 'IAM Policy Misconfiguration',
    'Public S3 Bucket Exposure', 'Cloud Storage Access Control Bypass', 'Container Escape',
    'Kubernetes RBAC Bypass', 'Kubernetes Secret Exposure', 'Docker Socket Exposure',
    'CI/CD Pipeline Injection', 'Dependency Confusion', 'Subdomain Takeover', 'DNS Rebinding',
    'DNS Zone Transfer', 'Internal Service Exposure', 'Secret Leakage',
    'Hardcoded Credentials', 'TLS Misconfiguration', 'Cloud Instance Credential Theft',
  ],
};

/** One bounded coverage ledger, with every unsupported family explicitly marked not tested. */
export function coverageFor({results = [], surface = null, web = null, ownerReady = false, credentialsReady = false,
  discovery = null, applications = [], scope = null, advisories = null} = {}) {
  const decisive = new Set(['confirmed', 'not_reproduced', 'public', 'shared']);
  const webResults = web?.results ?? [];
  const confirmedSequenceResults = webResults.filter(item =>
    ['model-http-sequence', 'model-sequence-boundary', 'model-cookie-access', 'model-raw-boundary',
      'model-state-change', 'model-access-boundary']
      .includes(item.kind) && item.verdict === 'confirmed').length;
  // A model sequence is stored under its generic runner kind. Its impact
  // oracle emits a separate finding kind, so count that exercised class too.
  const modelImpactFindings = (web?.findings ?? []).filter(item =>
    item.verdict === 'confirmed' &&
    ['muse-proposed-http-sequence', 'muse-proposed-http-flow'].includes(item.foundBy));
  const modelImpactCount = kind => Math.min(confirmedSequenceResults,
    modelImpactFindings.filter(item => item.kind === kind).length);
  const modelAccess = modelImpactCount('model-access-boundary');
  const modelSequenceBoundary = modelImpactCount('model-sequence-boundary');
  const modelState = modelImpactCount('model-state-change');
  const modelOutsiderState = Math.min(confirmedSequenceResults,
    modelImpactFindings.filter(item => item.kind === 'model-state-change' &&
      item.webProof?.as === 'outsider').length);
  const modelSsrf = modelImpactCount('ssrf-loopback');
  const modelRemoteContentUse = modelImpactCount('remote-content-use');
  const access = results.length;
  const redirect = webResults.filter(item => item.kind === 'open-redirect').length;
  const hostHeader = webResults.filter(item => item.kind === 'host-header-redirect').length;
  const jwt = webResults.filter(item => item.kind === 'jwt-unsigned').length;
  const pollution = webResults.filter(item => item.kind === 'http-parameter-pollution').length;
  const crlf = webResults.filter(item => item.kind === 'crlf-header').length;
  const cors = webResults.filter(item => item.kind === 'cors-reflection').length;
  const ssrf = webResults.filter(item => item.kind === 'ssrf-loopback').length +
    modelSsrf + modelRemoteContentUse;
  const privateKeys = webResults.filter(item => item.kind === 'public-private-key').length;
  const publicCredentials = webResults.filter(item => item.kind === 'public-api-credential').length;
  const anonymousCredentials = webResults.filter(item => item.kind === 'anonymous-credential-data').length;
  const derivedPrivate = webResults.filter(item => item.kind === 'derived-private-read').length;
  const xss = webResults.filter(item =>
    ['xss-reflected', 'xss-dom-fragment', 'xss-stored',
      'model-browser-execution'].includes(item.kind)).length;
  const htmlInjection = webResults.filter(item => item.kind === 'html-injection').length;
  const sqli = webResults.filter(item => item.kind === 'sql-boolean').length;
  const nosql = webResults.filter(item => item.kind === 'nosql-operator-bypass').length;
  const command = webResults.filter(item => item.kind === 'command-output').length;
  const traversal = webResults.filter(item => item.kind === 'path-traversal-hosts').length;
  const xxe = webResults.filter(item => ['xxe-hosts', 'xxe-body-hosts'].includes(item.kind)).length;
  const ssti = webResults.filter(item => item.kind === 'ssti-arithmetic').length;
  const modelKinds = ['model-differential', 'model-json-differential',
    'model-http-sequence', 'model-sequence-boundary', 'model-cookie-access', 'model-raw-boundary',
    'model-browser-execution',
    'model-json-observation', 'model-http-observation', 'model-raw-observation'];
  // Queued or refused proposals are coverage cuts, not executed experiments.
  const modelDirected = webResults.filter(item => modelKinds.includes(item.kind) &&
    !['untested', 'blocked'].includes(item.verdict)).length;
  const publicSession = webResults.filter(item => item.kind === 'public-session-token').length;
  const authLogin = webResults.filter(item => item.kind === 'model-auth-login').length;
  const authRateLimit = webResults.filter(item => item.kind === 'rate-limit-auth-gate').length;
  const cookieAccess = webResults.filter(item => item.kind === 'model-cookie-access').length;
  const rawBoundary = webResults.filter(item => item.kind === 'model-raw-boundary').length;
  const assetFiles = (surface?.mined?.files?.length ?? 0) +
    (discovery?.hosts ?? []).reduce((count, host) => count + (host.assets?.files?.length ?? 0), 0) +
    applications.reduce((count, app) => count + (app.mined?.files?.length ?? 0), 0);
  const sourceFiles = surface?.sourceReview?.stats?.files ?? 0;
  const exposed = (surface?.exposureStats?.answered ?? 0) +
    applications.reduce((count, app) => count + (app.exposureStats?.answered ?? 0), 0);
  const exposureTotal = (surface?.exposureStats?.total ?? 0) +
    applications.reduce((count, app) => count + (app.exposureStats?.total ?? 0), 0);
  const attempts = {'access-control': access + nosql + derivedPrivate + authLogin +
    cookieAccess + rawBoundary + modelAccess + modelSequenceBoundary + modelState,
    'exposed-paths': exposed,
    'open-redirect': redirect, 'host-header-redirect': hostHeader, 'jwt-auth': jwt,
    'parameter-pollution': pollution,
    'response-header-injection': crlf, 'sql-nosql-injection': sqli + nosql,
    'command-injection': command, 'path-file': traversal,
    cors, ssrf, xxe, xss: xss + htmlInjection, ssti, 'secret-exposure': privateKeys + publicCredentials,
    'anonymous-credential-data': anonymousCredentials,
    dependency: advisories?.records?.length ?? 0, 'model-directed': modelDirected,
    'session-account': publicSession + authLogin + cookieAccess + authRateLimit,
    'rate-limit': authRateLimit};
  const nosqlDone = webResults.filter(item => item.kind === 'nosql-operator-bypass' && decisive.has(item.verdict)).length;
  const completed = {'access-control': results.filter(item => decisive.has(item.verdict)).length + nosqlDone +
    modelAccess + modelState +
    webResults.filter(item => ['derived-private-read', 'model-auth-login',
      'model-cookie-access'].includes(item.kind) &&
      decisive.has(item.verdict)).length,
    'exposed-paths': exposed,
    'open-redirect': webResults.filter(item => item.kind === 'open-redirect' && decisive.has(item.verdict)).length,
    'host-header-redirect': webResults.filter(item => item.kind === 'host-header-redirect' && decisive.has(item.verdict)).length,
    'jwt-auth': webResults.filter(item => item.kind === 'jwt-unsigned' && decisive.has(item.verdict)).length,
    'parameter-pollution': webResults.filter(item => item.kind === 'http-parameter-pollution' &&
      decisive.has(item.verdict)).length,
    'response-header-injection': webResults.filter(item => item.kind === 'crlf-header' && decisive.has(item.verdict)).length,
    cors: webResults.filter(item => item.kind === 'cors-reflection' && decisive.has(item.verdict)).length,
    ssrf: webResults.filter(item => item.kind === 'ssrf-loopback' && decisive.has(item.verdict)).length +
      modelSsrf + modelRemoteContentUse,
    'secret-exposure': webResults.filter(item => ['public-private-key', 'public-api-credential'].includes(item.kind) &&
      decisive.has(item.verdict)).length,
    'anonymous-credential-data': webResults.filter(item => item.kind === 'anonymous-credential-data' &&
      decisive.has(item.verdict)).length,
    xss: webResults.filter(item => ['xss-reflected', 'xss-dom-fragment', 'xss-stored',
      'model-browser-execution',
      'html-injection'].includes(item.kind) &&
      decisive.has(item.verdict)).length,
    'sql-nosql-injection': webResults.filter(item => ['sql-boolean', 'nosql-operator-bypass'].includes(item.kind) &&
      decisive.has(item.verdict)).length,
    'command-injection': webResults.filter(item => item.kind === 'command-output' && decisive.has(item.verdict)).length,
    'path-file': webResults.filter(item => item.kind === 'path-traversal-hosts' && decisive.has(item.verdict)).length,
    xxe: webResults.filter(item => ['xxe-hosts', 'xxe-body-hosts'].includes(item.kind) &&
      decisive.has(item.verdict)).length,
    ssti: webResults.filter(item => item.kind === 'ssti-arithmetic' && decisive.has(item.verdict)).length,
    dependency: advisories?.stats?.checked ?? 0,
    'model-directed': webResults.filter(item =>
      modelKinds.includes(item.kind) &&
      (decisive.has(item.verdict) || item.verdict === 'observed')).length,
    'session-account': webResults.filter(item => ['public-session-token',
      'model-auth-login', 'model-cookie-access', 'model-raw-boundary'].includes(item.kind) &&
      decisive.has(item.verdict)).length + webResults.filter(item =>
      item.kind === 'rate-limit-auth-gate' && decisive.has(item.verdict)).length,
    'rate-limit': webResults.filter(item => item.kind === 'rate-limit-auth-gate' &&
      decisive.has(item.verdict)).length};
  const rows = FAMILIES.map(([family, description]) => {
    const observed = attempts[family] ?? 0;
    const done = completed[family] ?? 0;
    const status = family === 'model-directed' && observed > 0 ? 'partial' :
      observed > 0 && done === 0 ? 'not tested' :
      observed > done ? 'partial' :
      (['ssrf', 'xxe', 'xss', 'ssti', 'sql-nosql-injection', 'command-injection', 'path-file', 'secret-exposure',
        'anonymous-credential-data', 'dependency', 'model-directed', 'session-account',
        'rate-limit',
        'response-header-injection', 'host-header-redirect', 'jwt-auth', 'parameter-pollution'].includes(family) ||
        family === 'access-control' && !credentialsReady) && observed > 0 ? 'partial' :
      family === 'exposed-paths' ? (exposed > 0 ?
      exposed === exposureTotal ? 'exercised' : 'partial' : 'not tested') :
      observed > 0 ? 'exercised' : 'not tested';
    const reason = family === 'model-directed' && observed > 0 ?
      modelImpactFindings.length ?
        'Muse executed an impact-specific HTTP sequence oracle; fresh PoC replay determines which candidates remain findings.' :
        'Muse executed scoped response experiments; observations alone do not establish security impact.' :
      observed > 0 && done === 0 ? 'Probes were attempted, but every result was blocked or inconclusive.' :
      family === 'access-control' && !credentialsReady ? ownerReady ?
      scope?.identities?.identityPath ?
        'Only the configured identity endpoint was checked anonymously; cross-account checks need distinct same-role accounts.' :
        'An identity endpoint must be configured for one-account checks; cross-account checks need distinct same-role accounts.' :
      'Two usable identities were unavailable.' :
      family === 'exposed-paths' && status === 'partial' ?
        `${exposureTotal - exposed} path checks were refused or did not return a response.` :
      family === 'dependency' && observed > 0 ?
        'OSV matched detected client-library names and versions; bundling, vulnerable-code reachability and exploitability were not verified.' :
      family === 'session-account' && observed > 0 ?
        'Only public session-token replay, a Muse-proposed synthetic invalid-password login against a protected GET, or bounded invalid-attempt throttling was checked; password-reset, MFA and other account flows were not tested.' :
      family === 'rate-limit' && observed > 0 ?
        'Only observed login or access-gate POST contracts were checked with 20 synthetic invalid attempts at an authorized rate; registration and distributed-source behavior were not tested.' :
      family === 'open-redirect' && !redirect ? 'No observed redirect parameter was reachable within the budget.' :
      family === 'host-header-redirect' && !scope?.probes?.hostHeaderRedirect ?
        'Disabled by the reviewed scope (probes.hostHeaderRedirect=false).' :
      family === 'host-header-redirect' && observed > 0 ?
        'Only anonymous GET redirects on observed redirect-parameter routes were checked with two fixed Host values; password-reset links and other Host uses were not tested.' :
      family === 'jwt-auth' && !scope?.probes?.jwtUnsigned ?
        'Disabled by the reviewed scope (probes.jwtUnsigned=false).' :
      family === 'jwt-auth' && observed > 0 ?
        'Only two alg:none encodings of an operator-supplied owner JWT were checked on observed private JSON GET routes after an invalid-signature denial.' :
      family === 'response-header-injection' && !scope?.probes?.crlfResponseHeader ?
        'Disabled by the reviewed scope (probes.crlfResponseHeader=false).' :
      family === 'response-header-injection' && observed > 0 ?
        'Only a harmless injected X-Bypass-Audit response header was checked; cache and downstream behavior were not tested.' :
      family === 'ssrf' && observed > 0 ?
        'Only audit-owned loopback callbacks on observed GET inputs or exact reviewed method contracts on local targets were tested.' :
      family === 'secret-exposure' && observed > 0 ?
        'Only parseable PEM private keys and high-confidence credential-shaped values in anonymously served JavaScript or source maps were checked; validity, privileges and other formats were not tested.' :
      family === 'anonymous-credential-data' && observed > 0 ?
        'Only documented account-list GET routes with two distinct records and credential-shaped JSON fields were checked; key validity and other data classes were not tested.' :
      family === 'parameter-pollution' && observed > 0 ?
        'Only duplicate redirect parameters that bypass a rejected scalar external destination were checked.' :
      family === 'ssrf' && scope?.target?.environment !== 'local' ? 'A deployed callback profile is not configured.' :
      family === 'xss' && observed > 0 ? 'Reflected GET inputs, fragment-driven DOM sinks, and exact reviewed local JSON POSTs followed by an observed HTML GET can be checked in isolated Chrome; other stored input shapes and DOM sources remain untested.' :
      family === 'sql-nosql-injection' && observed > 0 ? 'Only read-only SQL boolean pairs and bracketed equality-operator cross-account lookups on documented GET parameters were checked; other SQL and NoSQL techniques were not tested.' :
      family === 'command-injection' && observed > 0 ? 'Only two harmless printf output canaries on documented GET parameters were checked; blind, delayed and write-side command execution were not tested.' :
      family === 'command-injection' && !scope?.probes?.commandExecution ?
        'Disabled by the reviewed scope (probes.commandExecution=false).' :
      family === 'path-file' && observed > 0 ?
        'Only two relative paths to /etc/hosts on documented GET file parameters were checked; other files and inclusion variants were not tested.' :
      family === 'path-file' && !scope?.probes?.pathTraversal ?
        'Disabled by the reviewed scope (probes.pathTraversal=false).' :
      family === 'xxe' && observed > 0 ?
        'Only a benign /etc/hosts external entity on a documented GET XML parameter or an exact reviewed XML POST path was checked; other entity behaviors were not tested.' :
      family === 'xxe' && !scope?.probes?.xmlExternalEntity ?
        'Disabled by the reviewed scope (probes.xmlExternalEntity=false).' :
      family === 'ssti' && observed > 0 ? 'Only harmless arithmetic expressions on documented GET parameters were checked; code execution was not tested.' :
      family === 'exposed-paths' && !scope?.discovery?.sensitivePaths ? 'Disabled by scope.' :
      status === 'not tested' ? 'No authorized probe and independent oracle ran for this family.' : null;
    return {family, description, status, attempts: observed, reason};
  });
  const webClass = kind => {
    const selected = webResults.filter(item => item.kind === kind);
    return {attempts: selected.length, completed: selected.filter(item => decisive.has(item.verdict)).length};
  };
  const browserClass = kind => {
    const selected = webResults.filter(item => item.kind === 'model-browser-execution' &&
      (kind === 'stored' ? !['GET', 'HEAD'].includes(item.lead?.method) &&
        item.lead?.assertionStep === 'observe' :
        ['GET', 'HEAD'].includes(item.lead?.method) &&
          item.lead?.assertionStep === 'subject'));
    return {attempts: selected.length,
      completed: selected.filter(item => decisive.has(item.verdict)).length};
  };
  const taskClass = kinds => {
    const selected = results.filter(item => kinds.includes(item.task?.kind));
    return {attempts: selected.length, completed: selected.filter(item => decisive.has(item.verdict)).length};
  };
  const operatorClass = webClass('nosql-operator-bypass');
  const directModelAccess = webClass('model-access-boundary');
  const modelAccessClass = {attempts: directModelAccess.attempts + modelAccess,
    completed: directModelAccess.completed + modelAccess};
  const modelStateClass = {attempts: modelState, completed: modelState,
    reason: 'Only an anonymous change to an owner-only disposable record, followed by an owner read and restoration, was checked.'};
  const authLoginClass = webClass('model-auth-login');
  const authRateLimitClass = {...webClass('rate-limit-auth-gate'),
    reason: 'Only an observed login or access-gate POST contract was checked with 20 synthetic invalid attempts at an authorized rate; registration, valid-account lockout and distributed-source behavior were not tested.'};
  const cookieAccessClass = webClass('model-cookie-access');
  const rawBoundaryClass = webClass('model-raw-boundary');
  const sequenceBoundaryClass = webClass('model-sequence-boundary');
  const derivedPrivateClass = {...webClass('derived-private-read'),
    reason: 'Only newly mapped GET routes whose JSON explicitly declares private account data were checked with a fresh authenticated response and two exact anonymous reads; other access controls remain untested.'};
  const allAccess = {attempts: results.length + operatorClass.attempts + modelAccessClass.attempts +
      modelStateClass.attempts +
      derivedPrivateClass.attempts + authLoginClass.attempts + cookieAccessClass.attempts +
      rawBoundaryClass.attempts + sequenceBoundaryClass.attempts,
    completed: results.filter(item => decisive.has(item.verdict)).length +
      operatorClass.completed + modelAccessClass.completed + modelStateClass.completed +
      derivedPrivateClass.completed + authLoginClass.completed + cookieAccessClass.completed +
      rawBoundaryClass.completed + sequenceBoundaryClass.completed};
  const idorClass = taskClass(['idor', 'nested-idor', 'graphql-bola']);
  const bolaClass = {attempts: idorClass.attempts + operatorClass.attempts +
      modelAccessClass.attempts + modelOutsiderState,
    completed: idorClass.completed + operatorClass.completed +
      modelAccessClass.completed + modelOutsiderState};
  const missingAuthClass = taskClass(['missing-auth']);
  const jwtClass = {...webClass('jwt-unsigned'),
    reason: 'Only alg:none acceptance of an operator-supplied JWT on observed private JSON GET routes was checked; other JWT flaws remain untested.'};
  const authBypassClass = {attempts: missingAuthClass.attempts + jwtClass.attempts + derivedPrivateClass.attempts + authLoginClass.attempts + cookieAccessClass.attempts + rawBoundaryClass.attempts + sequenceBoundaryClass.attempts,
    completed: missingAuthClass.completed + jwtClass.completed + derivedPrivateClass.completed + authLoginClass.completed + cookieAccessClass.completed + rawBoundaryClass.completed + sequenceBoundaryClass.completed,
    reason: 'Only missing authentication on observed or configured private reads, alg:none acceptance on an observed private JSON GET, or a Muse-proposed synthetic invalid-password login with a protected GET control was checked.'};
  const keyScan = {attempts: assetFiles, completed: 0,
    reason: 'Downloaded client assets were scanned for key-shaped strings, but API key validity and privileges were not checked.'};
  const privateKeyExposure = {...webClass('public-private-key'),
    reason: 'Only complete, parseable PEM private keys in public JavaScript and source maps were independently re-fetched and proved; key use and other credential formats were not checked.'};
  const publicCredentialExposure = {...webClass('public-api-credential'),
    reason: 'Only high-confidence credential-shaped GitHub, Stripe or SendGrid values in public JavaScript or source maps were independently re-fetched; validity and privileges were not checked.'};
  const anonymousCredentialClass = {...webClass('anonymous-credential-data'),
    reason: 'Only two anonymous uncached JSON reads of a documented account-list GET route, each with two distinct records and credential-shaped fields, were checked; key validity was not tested.'};
  const anonymousApiKeyResults = webResults.filter(item => item.kind === 'anonymous-credential-data' &&
    /^api_?key$/i.test(item.field ?? ''));
  const anonymousApiKeyClass = {attempts: anonymousApiKeyResults.length,
    completed: anonymousApiKeyResults.filter(item => decisive.has(item.verdict)).length,
    reason: anonymousCredentialClass.reason};
  const excessiveDataClass = taskClass(['list-leak', 'param-filter']);
  const mapped = new Map([
    ['Cross-Site Scripting (XSS)', {attempts: xss, completed: completed.xss}],
    ['Reflected XSS', {attempts: webClass('xss-reflected').attempts +
      browserClass('reflected').attempts,
    completed: webClass('xss-reflected').completed + browserClass('reflected').completed,
    reason: 'Only observed GET inputs selected for browser execution or the existing reflected GET probe were checked with two isolated-browser script canaries.'}],
    ['Stored XSS', {attempts: webClass('xss-stored').attempts +
      browserClass('stored').attempts,
    completed: webClass('xss-stored').completed + browserClass('stored').completed,
    reason: 'Only a reviewed local write followed by an observed HTML GET, or an exact reviewed JSON POST-to-HTML pair, was checked with a plain control and two isolated-browser script canaries.'}],
    ['DOM-Based XSS', {...webClass('xss-dom-fragment'),
      reason: 'Only URL-fragment sources and up to eight captured static scripts per page were checked in isolated Chrome.'}],
    ['HTML Injection', {...webClass('html-injection'),
      reason: 'Only inert markup insertion through documented GET parameters was checked with two unique elements in isolated Chrome; script execution and other HTML contexts were not established.'}],
    ['Server-Side Template Injection (SSTI)', webClass('ssti-arithmetic')],
    ['SQL Injection (SQLi)', {...webClass('sql-boolean'),
      reason: 'Only read-only boolean conditions on documented GET record lookups or a bounded search-result differential on observed search GET parameters were checked.'}],
    ['NoSQL Injection', {...operatorClass,
      reason: 'Only a bracketed $eq lookup that exposes an owner record to another account was checked; the backend technology is not verified.'}],
    ['OS Command Injection', {...webClass('command-output'),
      reason: 'Only a harmless printf output canary on documented GET parameters was checked.'}],
    ['Remote Code Execution (RCE)', {...webClass('command-output'),
      reason: 'Only benign command output was proved; no shell installation, persistence or broader execution path was attempted.'}],
    ['Path Traversal', {...webClass('path-traversal-hosts'),
      reason: 'Only two relative paths to the benign /etc/hosts file on documented GET parameters were checked.'}],
    ['Local File Inclusion (LFI)', {...webClass('path-traversal-hosts'),
      reason: 'Only a benign local hosts-file read through a documented GET parameter was checked; code inclusion was not tested.'}],
    ['XML External Entity Injection (XXE)', {
      attempts: xxe, completed: completed.xxe,
      reason: 'Only external-entity expansion of the benign /etc/hosts file through a documented GET XML parameter or an exact reviewed XML POST path was checked; other XML entry points were not tested.'}],
    ['Server-Side Request Forgery (SSRF)', {attempts: ssrf, completed: completed.ssrf,
      reason: 'Only an audit-owned loopback callback on a local target was checked; one model-directed oracle also proves use of the fetched response body. Other SSRF variants remain untested.'}],
    ['Open Redirect', webClass('open-redirect')],
    ['Host Header Injection', {...webClass('host-header-redirect'),
      reason: 'Only anonymous GET redirect Location poisoning on observed redirect-parameter routes was checked with two fixed Host values.'}],
    ['HTTP Parameter Pollution', {...webClass('http-parameter-pollution'),
      reason: 'Only a duplicate redirect parameter that bypasses a rejected scalar external destination was checked.'}],
    ['CRLF Injection', {...webClass('crlf-header'),
      reason: 'Only a harmless response-header canary on documented GET parameters was checked.'}],
    ['HTTP Response Splitting', {...webClass('crlf-header'),
      reason: 'Only an extra response header was proved; a second response or cache impact was not tested.'}],
    ['Broken Access Control', allAccess], ['Insecure Direct Object Reference (IDOR)', idorClass],
    ['Broken Object Level Authorization (BOLA)', {...bolaClass,
      reason: 'Observed REST/GraphQL item reads, bracketed equality lookups, model-selected public JSON operations, or outsider writes to an owner-only test record were checked with independent owner controls; other object boundaries remain untested.'}],
    ['Broken Function Level Authorization (BFLA)', {attempts:
      taskClass(['bfla']).attempts + modelStateClass.attempts,
    completed: taskClass(['bfla']).completed + modelStateClass.completed,
    reason: modelStateClass.attempts ? modelStateClass.reason :
      'Only a documented restricted function was checked with supplied role fixtures.'}],
    ['Authentication Bypass', authBypassClass], ['Authorization Bypass', allAccess],
    ['JWT Authentication Bypass', jwtClass], ['JWT Signature Verification Flaws', jwtClass],
    ['Horizontal Privilege Escalation', {attempts: idorClass.attempts + modelOutsiderState,
      completed: idorClass.completed + modelOutsiderState,
      reason: 'Only cross-account object reads or an outsider write to an owner-only disposable record were checked.'}],
    ['Account Takeover (ATO)', {...webClass('public-session-token'),
      reason: 'Only public exposure and replay of the exact operator-supplied owner test bearer on a private JSON GET were checked; other account flows were not tested.'}],
    ['Broken Object Property Level Authorization (BOPLA)', {attempts: taskClass(['param-filter']).attempts + anonymousCredentialClass.attempts,
      completed: taskClass(['param-filter']).completed + anonymousCredentialClass.completed,
      reason: anonymousCredentialClass.reason}],
    ['Excessive Data Exposure', {attempts: excessiveDataClass.attempts + anonymousCredentialClass.attempts,
      completed: excessiveDataClass.completed + anonymousCredentialClass.completed,
      reason: anonymousCredentialClass.reason}],
    ['API Authentication Bypass', authBypassClass], ['API Authorization Bypass', allAccess],
    ['API Key Exposure', {attempts: keyScan.attempts + anonymousApiKeyClass.attempts + publicCredentialExposure.attempts,
      completed: anonymousApiKeyClass.completed + publicCredentialExposure.completed,
      reason: publicCredentialExposure.attempts ? publicCredentialExposure.reason :
        anonymousApiKeyClass.attempts ? anonymousApiKeyClass.reason : keyScan.reason}],
    ['API Rate Limit Bypass', authRateLimitClass],
    ['Secret Leakage', {attempts: privateKeyExposure.attempts + publicCredentialExposure.attempts + anonymousCredentialClass.attempts,
      completed: privateKeyExposure.completed + publicCredentialExposure.completed + anonymousCredentialClass.completed,
      reason: publicCredentialExposure.attempts ? publicCredentialExposure.reason :
        anonymousCredentialClass.attempts ? anonymousCredentialClass.reason : privateKeyExposure.reason}],
    ['Hardcoded Credentials', {attempts: sourceFiles + privateKeyExposure.attempts + publicCredentialExposure.attempts,
      completed: sourceFiles + privateKeyExposure.completed + publicCredentialExposure.completed,
      reason: 'Eligible local source files were scanned for credential-shaped literals, and public-asset private keys or high-confidence credentials were separately re-fetched when observed. Source matches are leads; credential validity, use and public exposure of local source were not verified.'}],
  ]);
  const requestedClasses = Object.entries(REQUESTED_CLASSES).flatMap(([category, classes]) =>
    classes.map(name => {
      const coverage = mapped.get(name) ?? {attempts: 0, completed: 0};
      const status = coverage.completed > 0 ? 'partial' : 'not tested';
      return {category, name, status, attempts: coverage.attempts,
        reason: status === 'partial' ? coverage.reason ?? 'A bounded subset of this class was checked; see family coverage and evidence.' :
          coverage.attempts > 0 ? coverage.reason ?? 'Probes were attempted, but no independent oracle completed.' :
            'No authorized probe and independent oracle ran for this class.'};
    }));
  return {rows, hosts: {resolved: discovery?.stats?.hostsFound ?? 0, live: discovery?.stats?.hostsLive ?? 0,
    cut: discovery?.stats?.cut ?? 0}, requestedClasses, complete: false,
    statement: 'This is partial, bounded coverage. A not tested class or unobserved host is not evidence of safety.'};
}
