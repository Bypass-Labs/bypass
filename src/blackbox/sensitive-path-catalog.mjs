// Additional low-impact GET candidates for the anonymous sensitive-path pass.
// A candidate is an exposure only when its body has a format-specific signature.
// Interface and directory signatures use `info`: their presence alone is not a bug.

const isHtml = (body, type) => /html/i.test(type ?? '') || /^\s*<(?:!doctype html|html|head|body)\b/i.test(body);
const text = regex => (body, type) => !isHtml(body, type) && regex.test(body);
const page = regex => body => regex.test(body);
const json = predicate => (body, type) => {
  if (isHtml(body, type) || !/^\s*[\[{]/.test(body)) return false;
  try { return Boolean(predicate(JSON.parse(body))); } catch { return false; }
};
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const paths = (items, severity, signature, matches) => items.map(path => ({path, severity, signature, matches}));

const secretValue = value => typeof value === 'string' && value.trim().replace(/^["']|["']$/g, '').length >= 8 &&
  !/^(?:changeme|example|placeholder|test|dummy|default|redacted|\$\{|%|<|\{|null|none|false|true)/i.test(value.trim());
const keyValue = (body, type, separator) => !isHtml(body, type) && body.split(/\r?\n/).some(line => {
  const match = line.match(separator);
  return match && secretValue(match[1]);
});
const env = (body, type) => keyValue(body, type,
  /^\s*(?:export\s+)?(?:APP_KEY|SECRET(?:_KEY)?|DATABASE_URL|DB_PASS(?:WORD)?|API_?KEY|ACCESS_TOKEN|AWS_(?:SECRET_ACCESS_KEY|ACCESS_KEY_ID)|JWT_SECRET)\s*=\s*(.+?)\s*$/i);
const yamlConfig = (body, type) => keyValue(body, type,
  /^\s*(?:password|secret(?:_key)?|api[_-]?key|access[_-]?token|database_url|connectionstring)\s*:\s*(.+?)\s*$/i);
const jsonConfig = json(value => object(value) && Object.entries(value).some(([name, entry]) =>
  /secret|password|credential|token|api_?key|connectionstring/i.test(name) &&
  (secretValue(entry) || object(entry) && Object.entries(entry).some(([child, value]) =>
    /secret|password|credential|token|api_?key/i.test(child) && secretValue(value)))));
const properties = (body, type) => keyValue(body, type,
  /^\s*(?:[\w.-]*\.)?(?:password|secret(?:_key)?|api[._-]?key|access[._-]?token|connectionstring)\s*=\s*(.+?)\s*$/i);
const apacheDirectives = text(/^\s*(?:RewriteEngine|RewriteRule|Deny from|Allow from|Require |Options |AuthType|<IfModule)/mi);
const directoryIndex = page(/<(?:title|h1)>\s*(?:Index of|Directory listing for|Directory Listing)\b/i);
const zip = body => body.startsWith('PK\u0003\u0004');
const gzip = (body, type) => !isHtml(body, type) && body.charCodeAt(0) === 31 &&
  (body.charCodeAt(1) === 139 || body.charCodeAt(1) === 0xfffd);
const tar = body => body.slice(257, 262) === 'ustar';
const sqlDump = text(/\b(?:CREATE TABLE|INSERT INTO|COPY [\w".]+ FROM stdin)\b|--\s*(?:MySQL|PostgreSQL|SQLite)\s+(?:database\s+)?dump/i);
const key = text(/-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/);
const packageJson = json(value => object(value) && typeof value.name === 'string' && (object(value.dependencies) || object(value.scripts)));
const openApi = json(value => object(value) && (typeof value.openapi === 'string' || typeof value.swagger === 'string') && object(value.paths));
const phpSource = text(/<\?php[\s\S]{0,5000}(?:\b(?:define|require|include|return|namespace)\b|\$[A-Za-z_])/i);
const phpConfig = text(/<\?php[\s\S]{0,6000}(?:DB_(?:NAME|USER|PASSWORD|HOST)|\$databases|\$db(?:name|user|password)|['"](?:password|secret|database)['"]\s*=>|\b(?:crypt|backend|secret)\b)/i);

export const additionalSensitivePathEntries = Object.freeze([
  ...paths(['/.env.local', '/.env.production', '/.env.backup', '/.env.development', '/.env.staging'],
    'critical', 'environment assignments', env),
  ...paths(['/.hg/hgrc'], 'high', 'Mercurial configuration', text(/^\s*\[(?:paths|ui|auth|extensions)\]/mi)),
  ...paths(['/.gitignore'], 'info', 'Git ignore rules', text(/^\s*(?:\*\.|\/|node_modules|vendor|\.env)/mi)),
  ...paths(['/config.yml', '/config.yaml', '/config/database.yml', '/config/secrets.yml',
    '/config/credentials.yml', '/config/application.yml', '/application.yml'],
  'high', 'YAML configuration keys', yamlConfig),
  ...paths(['/config.php'], 'high', 'PHP configuration assignments',
    text(/<\?php[\s\S]{0,5000}(?:\$\w*(?:password|secret|database|db|key)\w*\s*=|['"](?:password|secret|db_password)['"]\s*=>)/i)),
  ...paths(['/config.xml', '/WEB-INF/web.xml'], 'medium', 'XML application configuration',
    text(/<\?xml[\s\S]{0,5000}<(?:configuration|web-app|properties|beans)\b/i)),
  ...paths(['/application.properties', '/config/application.properties'],
    'high', 'application properties', properties),
  ...paths(['/appsettings.json', '/appsettings.Production.json'],
    'high', 'JSON application configuration', jsonConfig),
  ...paths(['/.npmrc'], 'high', 'npm registry credential setting',
    text(/^\s*(?:\/\/[^\s]+\/:)?(?:_authToken|_auth|password)\s*=\s*\S+/mi)),
  ...paths(['/.pypirc'], 'high', 'Python package index credentials',
    text(/^\s*\[(?:distutils|pypi|testpypi)\][\s\S]{0,3000}^\s*password\s*=\s*\S+/mi)),
  ...paths(['/.htpasswd'], 'high', 'Apache password hash entry',
    text(/^[A-Za-z0-9._-]+:(?:\$apr1\$|\$2[aby]\$|\{SHA\}|\$6\$|\$5\$)/m)),
  ...paths(['/id_rsa', '/.ssh/id_rsa'], 'critical', 'private key PEM header', key),
  ...paths(['/.aws/credentials'], 'critical', 'AWS shared credentials',
    text(/^\s*\[[\w.-]+\][\s\S]{0,3000}^\s*aws_access_key_id\s*=/mi)),
  ...paths(['/.docker/config.json'], 'high', 'Docker registry authentication configuration',
    json(value => object(value?.auths) && Object.values(value.auths).some(item => object(item) &&
      (typeof item.auth === 'string' || typeof item.identitytoken === 'string')))),
  ...paths(['/.kube/config'], 'high', 'Kubernetes client configuration',
    text(/^\s*(?:apiVersion:\s*v1|clusters:)\s*$[\s\S]{0,3000}^\s*(?:clusters|users|contexts):/mi)),
  ...paths(['/terraform.tfstate'], 'high', 'Terraform state resources',
    json(value => object(value) && typeof value.terraform_version === 'string' && Array.isArray(value.resources))),
  ...paths(['/terraform.tfvars'], 'high', 'Terraform variable assignments',
    text(/^\s*(?:[\w.-]*(?:secret|password|token|key|credential|database)[\w.-]*)\s*=.+$/mi)),
  ...paths(['/.terraform/'], 'info', 'directory listing', directoryIndex),

  ...paths(['/backup.zip', '/site.zip', '/www.zip'], 'critical', 'ZIP archive header', zip),
  ...paths(['/backup.tar.gz'], 'critical', 'gzip archive header', gzip),
  ...paths(['/backup.tar'], 'critical', 'tar archive header', tar),
  ...paths(['/backup.sql', '/database.sql', '/db.sql'], 'critical', 'SQL dump statements', sqlDump),
  ...paths(['/backup/', '/backups/', '/old/', '/archive/'], 'info', 'directory listing', directoryIndex),

  ...paths(['/composer.json'], 'info', 'Composer package manifest',
    json(value => object(value) && typeof value.name === 'string' && object(value.require))),
  ...paths(['/composer.lock'], 'info', 'Composer lockfile',
    json(value => object(value) && Array.isArray(value.packages) && typeof value['content-hash'] === 'string')),
  ...paths(['/package.json'], 'info', 'Node package manifest', packageJson),
  ...paths(['/package-lock.json'], 'info', 'Node lockfile',
    json(value => object(value) && Number.isInteger(value.lockfileVersion) && object(value.packages))),
  ...paths(['/yarn.lock'], 'info', 'Yarn lockfile',
    text(/^(?:# yarn lockfile v\d+|__metadata:)/m)),
  ...paths(['/Dockerfile'], 'info', 'Docker build instructions', text(/^\s*FROM\s+\S+/mi)),
  ...paths(['/docker-compose.yml', '/docker-compose.yaml'], 'info', 'Docker Compose service configuration',
    text(/^\s*(?:version:\s*['"]?\d|services:)\s*$/mi)),
  ...paths(['/.gitlab-ci.yml', '/.circleci/config.yml'], 'info', 'CI pipeline configuration',
    text(/^\s*(?:stages:|jobs:|workflows:|version:\s*[\d.]+|image:\s*\S+)/mi)),
  ...paths(['/.github/workflows/'], 'info', 'directory listing', directoryIndex),

  ...paths(['/actuator/configprops', '/actuator/beans'], 'high', 'Spring Actuator data',
    json(value => object(value) && object(value.contexts))),
  ...paths(['/actuator/heapdump'], 'info', 'Java heap dump header',
    body => body.startsWith('JAVA PROFILE ')),
  ...paths(['/actuator/prometheus'], 'medium', 'Prometheus metrics exposition',
    text(/^# (?:HELP|TYPE) [A-Za-z_:][\w:]*/m)),
  ...paths(['/debug/pprof/', '/debug/pprof/heap', '/debug/pprof/goroutine'], 'high', 'Go profiler response',
    (body, type) => directoryIndex(body, type) || /Types of profiles available|goroutine profile: total|heap profile:/.test(body)),
  ...paths(['/debug', '/debug/'], 'info', 'debug interface',
    page(/\b(?:debug toolbar|debug panel|developer console|Debug Information)\b/i)),
  ...paths(['/info.php'], 'high', 'PHP information output', page(/<title>phpinfo\(\)|PHP Version \d/i)),
  ...paths(['/_telescope/', '/horizon/'], 'info', 'framework debugging dashboard',
    page(/(?:Laravel Telescope|Laravel Horizon)/i)),
  ...paths(['/nginx_status'], 'medium', 'nginx status counters',
    text(/^Active connections:\s*\d+/m)),

  ...paths(['/swagger-ui/', '/swagger-ui.html'], 'info', 'Swagger UI',
    page(/SwaggerUIBundle|swagger-ui-bundle|<title>\s*Swagger UI/i)),
  ...paths(['/swagger.json', '/openapi.json', '/v3/api-docs'], 'info', 'OpenAPI document', openApi),
  ...paths(['/openapi.yaml'], 'info', 'OpenAPI YAML document',
    text(/^\s*(?:openapi|swagger):\s*['"]?\d/m)),
  ...paths(['/docs', '/docs/', '/redoc'], 'info', 'API documentation UI',
    page(/SwaggerUIBundle|swagger-ui-bundle|<redoc\b|Redoc\.init/i)),
  ...paths(['/api', '/api/', '/api/v1/', '/api/v2/', '/api/internal/', '/api/admin/'],
    'info', 'API index or schema', (body, type) => openApi(body, type) ||
      json(value => object(value) && (Array.isArray(value.endpoints) || Array.isArray(value.routes) ||
        typeof value.version === 'string'))(body, type)),
  ...paths(['/health', '/healthz', '/readyz', '/status'], 'info', 'health status response',
    (body, type) => !isHtml(body, type) && (/^\s*(?:ok|healthy|ready|up)\s*$/i.test(body) ||
      json(value => object(value) && /^(?:ok|healthy|ready|up)$/i.test(value.status))(body, type))),
  ...paths(['/version'], 'info', 'version response',
    (body, type) => !isHtml(body, type) && (/^\s*v?\d+\.\d+(?:\.\d+)?\s*$/.test(body) ||
      json(value => object(value) && typeof value.version === 'string')(body, type))),
  ...paths(['/.well-known/security.txt'], 'info', 'security contact metadata', text(/^Contact:\s*\S+/mi)),
  ...paths(['/crossdomain.xml', '/clientaccesspolicy.xml'], 'info', 'cross-domain policy XML',
    text(/<(?:cross-domain-policy|access-policy)\b/i)),

  ...paths(['/admin/', '/wp-admin/', '/manager/html', '/dashboard'],
    'info', 'administrative interface', page(/<input[^>]+type=["']?password|<title>[^<]*(?:admin|manager|dashboard)/i)),
  ...paths(['/internal/', '/private/', '/staff/'], 'info', 'directory listing', directoryIndex),
  ...paths(['/vendor/', '/node_modules/', '/storage/', '/uploads/', '/files/', '/tmp/', '/temp/',
    '/test/', '/staging/', '/dev/', '/logs/', '/log/', '/storage/logs/'],
  'info', 'directory listing', directoryIndex),
  ...paths(['/error.log', '/debug.log', '/access.log'], 'high', 'HTTP or application log lines',
    text(/^(?:\[[^\]]+\]\s+\w+\.|\d{1,3}(?:\.\d{1,3}){3}\s+-\s+-\s+\[|\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d.*\b(?:ERROR|DEBUG|WARN)\b)/m)),
  ...paths(['/cgi-bin/'], 'info', 'directory listing', directoryIndex),
  ...paths(['/jenkins/'], 'info', 'Jenkins interface', page(/Jenkins|<title>Dashboard \[/i)),
  ...paths(['/trace'], 'info', 'HTTP trace response', text(/^TRACE\s+\/|^Host:\s*\S+/mi)),
  ...paths(['/.dockerenv'], 'info', 'Docker environment marker',
    (body, type) => !isHtml(body, type) && body.trim() === 'docker'),

  // PHP source/configuration is useful only if the server serves it as text; an
  // executed PHP page or a generic 200 response never satisfies these signatures.
  ...paths(['/php.ini', '/.user.ini'], 'info', 'PHP INI settings',
    text(/^\s*(?:display_errors|expose_php|allow_url_fopen|allow_url_include|auto_prepend_file|open_basedir|session\.save_path)\s*=/mi)),
  ...paths(['/config.inc.php', '/configuration.php', '/database.php', '/db.php', '/settings.php',
    '/connection.php', '/constants.php', '/bootstrap.php'], 'high', 'PHP configuration source', phpConfig),
  ...paths(['/phpunit.xml', '/phpunit.xml.dist'], 'info', 'PHPUnit configuration',
    text(/<phpunit\b/i)),
  ...paths(['/composer.phar'], 'info', 'Composer PHAR header',
    text(/^<\?php[\s\S]{0,12000}__HALT_COMPILER\s*\(/i)),
  ...paths(['/vendor/composer/installed.json'], 'info', 'Composer installed packages',
    json(value => Array.isArray(value) || Array.isArray(value?.packages))),
  ...paths(['/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'], 'info', 'PHPUnit PHP source', phpSource),
  ...paths(['/wp-config.php', '/wp-config.php.bak', '/wp-config.php.old', '/wp-config.php.save',
    '/wp-config.php.txt', '/wp-config.php~'], 'critical', 'WordPress configuration source',
    text(/<\?php[\s\S]{0,6000}define\s*\(\s*['"]DB_(?:NAME|USER|PASSWORD|HOST)['"]/i)),
  ...paths(['/wp-content/debug.log'], 'high', 'WordPress debug log',
    text(/^\[[^\]]+\]\s+(?:PHP\s+)?(?:Warning|Notice|Fatal error|Deprecated):/mi)),
  ...paths(['/xmlrpc.php'], 'info', 'WordPress XML-RPC endpoint',
    text(/XML-RPC server accepts POST requests only/i)),
  ...paths(['/artisan'], 'info', 'Laravel Artisan PHP source',
    text(/(?:#!\/usr\/bin\/env php|<\?php)[\s\S]{0,6000}(?:Illuminate\\Foundation|artisan)/i)),
  ...paths(['/storage/logs/laravel.log'], 'high', 'Laravel application log',
    text(/^\[\d{4}-\d\d-\d\d[^\]]*\]\s+\w+\.(?:ERROR|WARNING|DEBUG|INFO):/m)),
  ...paths(['/_ignition/health-check'], 'info', 'Laravel Ignition metadata',
    json(value => object(value) && (typeof value.can_execute_commands === 'boolean' || typeof value.health === 'string'))),
  ...paths(['/.env.local.php'], 'critical', 'Symfony PHP environment source', phpConfig),
  ...paths(['/_wdt/'], 'info', 'Symfony web debug toolbar', page(/Symfony Web Debug Toolbar|sf-toolbar/i)),
  ...paths(['/sites/default/settings.php', '/sites/default/settings.php.bak', '/sites/default/settings.php.txt'],
    'critical', 'Drupal database configuration source', text(/<\?php[\s\S]{0,7000}\$databases\s*\[/i)),
  ...paths(['/administrator/', '/installation/'], 'info', 'Joomla interface',
    page(/Joomla!|Joomla Installer/i)),
  ...paths(['/app/etc/env.php'], 'critical', 'Magento environment configuration source', phpConfig),
  ...paths(['/var/log/'], 'info', 'directory listing', directoryIndex),
  ...paths(['/backup.tgz', '/site.tar.gz', '/www.tar.gz'], 'critical', 'gzip archive header', gzip),
  ...paths(['/database.zip', '/db.zip', '/wwwroot.zip'], 'critical', 'ZIP archive header', zip),
  ...paths(['/backup.sql.gz', '/db.sql.gz'], 'critical', 'gzip SQL backup header', gzip)
].map(entry => Object.freeze({...entry, technology: technologyForPath(entry.path)})));

// A short cross-stack baseline plus small framework probes runs even when the
// public page gives no usable stack clue. Remaining paths need an observed
// route, asset, response signature, or technology fingerprint to enter a run.
const BASELINE = new Set([
  '/.env', '/.env.local', '/.env.production', '/.git/HEAD', '/.git/config', '/config.json',
  '/backup.zip', '/dump.sql', '/server-status', '/metrics', '/api-docs', '/openapi.json',
  '/swagger', '/graphql', '/admin', '/.well-known/openid-configuration', '/.aws/credentials',
  '/robots.txt', '/sitemap.xml'
]);
const FINGERPRINT_PROBES = new Set([
  '/phpinfo.php', '/wp-login.php', '/actuator', '/debug/pprof', '/package.json',
  '/composer.json', '/appsettings.json', '/WEB-INF/web.xml', '/_profiler'
]);

function technologyForPath(path) {
  if (/^\/wp-|^\/wp\/|^\/xmlrpc\.php$/.test(path)) return 'wordpress';
  if (/^\/storage\/logs\/laravel|^\/artisan$|^\/_ignition|^\/_telescope|^\/horizon/.test(path)) return 'laravel';
  if (/^\/_profiler|^\/_wdt|^\/\.env\.local\.php$/.test(path)) return 'symfony';
  if (/^\/sites\/default\//.test(path)) return 'drupal';
  if (/^\/administrator\/$|^\/installation\//.test(path)) return 'joomla';
  if (/^\/app\/etc\//.test(path)) return 'magento';
  if (/^\/actuator|^\/application\.(?:properties|yml)$|^\/config\/application\.(?:properties|yml)$/.test(path)) return 'spring';
  if (/^\/WEB-INF\/|^\/manager\/html/.test(path)) return 'java';
  if (/^\/debug\/pprof|^\/debug\/vars/.test(path)) return 'go';
  if (/^\/appsettings\.|^\/web\.config$|^\/trace\.axd$/.test(path)) return 'dotnet';
  if (/^\/settings\.py$|^\/console$/.test(path)) return 'python';
  if (/^\/package(?:-lock)?\.json$|^\/yarn\.lock$|^\/\.npmrc$|^\/node_modules\//.test(path)) return 'node';
  if (/^\/composer|^\/vendor\//.test(path) || /\.(?:php|ini)$/.test(path) || /^\/phpmyadmin|^\/adminer/.test(path)) return 'php';
  if (/^\/\.kube\//.test(path)) return 'kubernetes';
  if (/^\/\.docker\/|^\/Dockerfile$|^\/docker-compose|^\/\.dockerenv$/.test(path)) return 'docker';
  if (/^\/terraform|^\/\.terraform\//.test(path)) return 'terraform';
  if (/^\/nginx_status$/.test(path)) return 'nginx';
  if (/^\/jenkins\//.test(path)) return 'jenkins';
  return 'generic';
}

function observedPath(value) {
  const raw = typeof value === 'string' ? value : value?.path ?? value?.pattern ?? value?.url;
  if (typeof raw !== 'string') return null;
  try { return new URL(raw, 'https://bypass.invalid').pathname; } catch { return null; }
}

function detectTechnologies(values) {
  const sources = values.filter(value => typeof value === 'string').join(' ').toLowerCase();
  const detected = new Set();
  if (/\.php\b|phpinfo|composer|phpmyadmin|adminer/.test(sources)) detected.add('php');
  if (/wordpress|wp-(?:admin|content|includes|json|login|config)|xmlrpc\.php/.test(sources)) detected.add('wordpress');
  if (/laravel|\/artisan|\/_ignition|\/_telescope|\/horizon/.test(sources)) detected.add('laravel');
  if (/symfony|\/_profiler|\/_wdt/.test(sources)) detected.add('symfony');
  if (/drupal|\/sites\/default\//.test(sources)) detected.add('drupal');
  if (/joomla|\/administrator\/|\/installation\//.test(sources)) detected.add('joomla');
  if (/magento|\/app\/etc\//.test(sources)) detected.add('magento');
  if (/spring|actuator|application\.properties/.test(sources)) detected.add('spring');
  if (/\.jsp\b|\/WEB-INF\/|\/manager\/html/.test(sources)) detected.add('java');
  if (/\/debug\/pprof|\.go\b|\bgolang\b/.test(sources)) detected.add('go');
  if (/\.aspx\b|appsettings|web\.config|\.net\b|asp\.net/.test(sources)) detected.add('dotnet');
  if (/django|flask|settings\.py|\.py\b/.test(sources)) detected.add('python');
  if (/node\.js|express|\/node_modules\/|package(?:-lock)?\.json/.test(sources)) detected.add('node');
  if (/kubernetes|\.kube\//.test(sources)) detected.add('kubernetes');
  if (/docker|container/.test(sources)) detected.add('docker');
  if (/terraform/.test(sources)) detected.add('terraform');
  if (/nginx/.test(sources)) detected.add('nginx');
  if (/jenkins/.test(sources)) detected.add('jenkins');
  if ([...detected].some(name => ['wordpress', 'laravel', 'symfony', 'drupal', 'joomla', 'magento'].includes(name)))
    detected.add('php');
  if (detected.has('spring')) detected.add('java');
  return detected;
}

function technologiesFromEvidence({mined, routes, observedPaths, fingerprints, modelNotes}) {
  // A queued path or a 404 response is a lead, not a technology fingerprint.
  const liveRoutes = routes.filter(route => route && typeof route === 'object' &&
    [route.status, route.response?.status, route.anonymous?.status, route.owner?.status]
      .some(status => Number.isInteger(status) && status >= 200 && status < 400));
  const heuristics = [
    ...(mined?.files ?? []).map(file => file.url),
    ...(mined?.libraries ?? []).map(library => library.name),
    ...(mined?.endpoints ?? []).map(endpoint => endpoint.path),
    ...liveRoutes.map(route => route.path ?? route.pattern ?? route.url),
    ...fingerprints
  ];
  const acceptedModel = [
    ...(mined?.files ?? []).filter(file => file.analysis?.by === 'model')
      .flatMap(file => [file.analysis.why, file.analysis.authFlow]),
    ...modelNotes.filter(note => note?.by === 'asset-model' || note?.by === 'model')
      .flatMap(note => [note.purpose, note.why])
  ];
  const heuristic = detectTechnologies(heuristics);
  const model = detectTechnologies(acceptedModel);
  return {all: new Set([...heuristic, ...model]), heuristic, model};
}

/**
 * Rank catalog candidates using only public evidence; do not gate an exact
 * observed route because its stack is unknown. A later pass may supply paths
 * whose response signatures were confirmed to expand a detected framework.
 * All unselected candidates are returned as explicit cuts for coverage.
 */
export function selectSensitivePathEntries({entries = additionalSensitivePathEntries, mined = {}, routes = [],
  observedPaths = [], fingerprints = [], modelNotes = [], maxCandidates = 64} = {}) {
  const observed = new Set([...observedPaths, ...(mined?.endpoints ?? []), ...routes]
    .map(observedPath).filter(Boolean));
  const detected = technologiesFromEvidence({mined, routes, observedPaths, fingerprints, modelNotes});
  const candidates = [], skipped = [];
  for (const [index, entry] of entries.entries()) {
    const technology = entry.technology ?? technologyForPath(entry.path);
    let reason, score;
    if (observed.has(entry.path)) {reason = 'observed'; score = 1000;}
    else if (technology !== 'generic' && detected.all.has(technology)) {
      reason = `fingerprint:${technology}:${detected.heuristic.has(technology) ? 'observed' : 'muse'}`;
      score = 500;
    } else if (BASELINE.has(entry.path)) {reason = 'cross-stack-baseline'; score = 300;}
    else if (FINGERPRINT_PROBES.has(entry.path)) {reason = 'framework-probe'; score = 200;}
    else {skipped.push({path: entry.path, reason: `no-observed-${technology}-evidence`}); continue;}
    candidates.push({entry: {...entry, technology, selectionReason: reason}, score, index});
  }
  candidates.sort((a, b) => b.score - a.score || a.index - b.index);
  const limit = Number.isInteger(maxCandidates) && maxCandidates >= 0 ? maxCandidates : 64;
  const selected = candidates.slice(0, limit).map(item => item.entry);
  skipped.push(...candidates.slice(limit).map(item => ({path: item.entry.path, reason: 'candidate-budget'})));
  return {entries: selected, skipped, fingerprints: [...detected.all].sort(),
    heuristicFingerprints: [...detected.heuristic].sort(), modelFingerprints: [...detected.model].sort(),
    available: entries.length, selected: selected.length};
}
