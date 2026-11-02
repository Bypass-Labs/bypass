// One catalog drives strict CLI parsing, help, and the command reference.
const command=(usage,description,flags='',extra={})=>({usage,description,flags:flags.split(' ').filter(Boolean),...extra});
export const commands={
  blackbox:command('blackbox <url>','Run a scoped black-box audit and save evidence under .bypass/runs/.','scope include domains audit-domains owner-env other-env auth identity-path model agents http-workers rps model-calls max-urls max-tasks minutes dom-script-bytes out source accept-local no-model dry-run no-discovery offline'),
  'blackbox scope':command('blackbox scope <url>','Write a reviewable blackbox.scope.json.','include methods domains audit-domains credential-origins never owner-env other-env auth identity-path identity-cookie-name environment agents http-workers rps model-calls max-urls max-tasks minutes dom-script-bytes out force'),
  'blackbox setup':command('blackbox setup <url>','Prepare scope, target challenges and reviewable authorization files.','include methods domains audit-domains credential-origins never owner-env other-env auth identity-path identity-cookie-name environment agents http-workers rps model-calls max-urls max-tasks minutes dom-script-bytes out force'),
  'blackbox verify':command('blackbox verify <run-id>','Re-execute generated proofs and check ledger integrity.'),
  'blackbox export':command('blackbox export <run-id>','Write Node regression tests for confirmed findings.','out'),
  'blackbox resume':command('blackbox resume <run-id>','Continue saved Muse research in a fresh scoped audit.','scope model offline agents http-workers rps model-calls max-urls max-tasks minutes dom-script-bytes'),
  discover:command('discover','Discover SAST/policy signals and evaluate them against source by default.','detector languages rule exclude-rule policy exclude-policy include-tests include-examples include-generated sarif config plan discovery-only'),
  'discover evaluate':command('discover evaluate <run>','Evaluate saved detector signals against their source snapshot; no runtime reproduction.'),
  'discover status':command('discover status <run>','Read durable SAST/policy progress and coverage.'),
  'discover resume':command('discover resume <run>','Resume discovery/evaluation after identity checks; standalone reasoning requires an API profile.'),
  'discover cancel':command('discover cancel <run>','Cancel discovery and retain accepted artifacts.'),
  'discover report':command('discover report <run>','Write a discovery report and return its artifact reference.','format'),
  'discover signals':command('discover signals <run>','Read a bounded page of unevaluated SAST/policy signals.','cursor limit'),
  'discover artifact':command('discover artifact <run>','Read a bounded page of a recorded discovery artifact.','path offset'),
  'scanner rules':command('scanner rules','Browse exact rule IDs from the pinned upstream packs.','language query cursor limit'),
  'scanner policies':command('scanner policies','List exact bundled policy IDs without Docker or inference.','query'),
  'scanner doctor':command('scanner doctor','Inspect the selected detector runtime and image readiness; no inference.','detector'),
  'scanner prepare':command('scanner prepare','Prepare the lightweight policy or pinned SAST runtime.','detector'),
  poc:command('poc','Open a real-AI, two-container POC with a local test app.','dir model'),
  'poc start':command('poc start','Create a separate POC app with public accounts and real Docker agents.','dir port model'),
  'poc resume':command('poc resume','Restart the saved generated local fixture; preserve findings and tests.'),
  'poc stop':command('poc stop','Stop this POC fixture app; preserve its evidence.'),
  demo:command('demo','Guided local walkthrough: prove, fix, retest, and catch a regression.','dir'),
  onboard:command('onboard [path]','Guided QuickStart, resumable app verification, or local demo.','repo dir flow mode'),
  init:command('init [path]','Connect a repository and configure a project.','repo dir config name'),
  'app connect':command('app connect <url>','Connect a running app without a source repository.','environment'),
  'repo show':command('repo show','Inspect the connected repository.'),
  'repo connect':command('repo connect <path-or-url>','Connect or clone a repository.','dir name'),
  status:command('status','Show project readiness, results, and next actions.'),
  doctor:command('doctor','Check Node, Git, Muse, configuration, and worker health.'),
  'config show':command('config show','Show nonsecret project configuration.'),
  'config set':command('config set <key> <value>','Set autoSave, requestTimeoutMs, or project.name.'),
  'auth login':command('auth login','Use local mode or launch official Muse account login.','provider device'),
  'auth status':command('auth status','Show local mode and Muse account integration status.'),
  'auth logout':command('auth logout','Clear Bypass-local account metadata; Muse account is separate.'),
  'integrate muse':command('integrate muse','Reuse an existing Muse plugin or install the bundled plugin.','scope install replace'),
  'integrate status':command('integrate status','Inspect the Muse plugin installation.'),
  'integrate remove':command('integrate remove <muse>','Remove the native Muse plugin.'),
  'target add':command('target add <name>','Add a local or HTTPS deployed target.','url environment'),
  'target list':command('target list','List targets and ownership state.'),
  'target show':command('target show [name]','Show target, challenge, and scope.'),
  'target use':command('target use <name>','Select an active target.'),
  'target verify':command('target verify [name]','Check DNS/HTTP control, or acknowledge local ownership.','method wait renew'),
  'target authorize':command('target authorize [name]','Record explicit paths, HTTP methods and expiring testing scope.','scope-file paths methods accept production public-config'),
  request:command('request','Send one scoped HTTP request; record status and an optional resource ID without replaying writes.','target method path identity body-file id-field'),
  'target revoke':command('target revoke <name>','Revoke testing and pause target monitors.'),
  'target remove':command('target remove <name>','Disconnect a target while retaining historical evidence.'),
  'identity add':command('identity add <name>','Reference a bearer token, cookie, or header in an environment variable.','target type secret-env header check-path'),
  'identity import':command('identity import <name>','Connect a test account from a private file, available immediately. Firebase refreshes automatically.','file token-field provider refresh-token-field config-file api-key-field project-id target type secret-env header check-path'),
  'identity refresh':command('identity refresh <name>','Refresh a privately connected Firebase account without restarting.'),
  'identity list':command('identity list','List credential references, never values.','target'),
  'identity test':command('identity test <name>','Make one authorized request to the configured identity-check path.'),
  'identity update':command('identity update <name>','Update a credential reference.','secret-env check-path'),
  'identity remove':command('identity remove <name>','Remove an identity reference; dependent tests become blocked.'),
  'model add':command('model add <name>','Add a standalone API-key provider profile.','provider base-url model secret-env allow-private effort transport max-output-tokens timeout-ms stream workspace-env'),
  'model list':command('model list','List model profiles and inference destinations.'),
  'model use':command('model use <name>','Select the model profile.'),
  'model test':command('model test [name]','Send a synthetic smoke prompt, without repository content.'),
  'model remove':command('model remove <name>','Remove a model profile.'),
  'engine use':command('engine use <docker|mock>','Select real Docker agents or the offline mocked preview.'),
  'engine doctor':command('engine doctor','Check Docker and the shared inference profile.'),
  'engine prepare':command('engine prepare','Build the agent image for both Docker services.'),
  'registration discover':command('registration discover','Find public Firebase config in authorized app pages and linked scripts. No accounts created.','target path project-id'),
  'registration choose':command('registration choose','Save the test-account choice: create, existing or skip. Creating accounts requires explicit permission.','target mode accept email-domain'),
  'registration configure':command('registration configure','Authorize up to two dedicated JSON signup attempts on the verified app.','target provider config-file api-key-field project-id path check-path access-path email-domain email-field password-field token-field verified-field identity-field require-verification accept'),
  'registration test':command('registration test','Attempt signup, privately connect generated accounts and check unverified access.','target'),
  'registration status':command('registration status','Show registration coverage and created account cleanup information.','target'),
  'probe add':command('probe add <name>','Configure an exact authorized JSON resource and account controls.','target path resource-id owner outsider id-field identity-field kind response match-text expected'),
  'probe discover':command('probe discover','Select owned test IDs from an authorized JSON collection without exposing contents.','target path resource-prefix items-field owner-field id-field resource-id-field identity-field owner outsider'),
  'probe test':command('probe test <name>','Validate both logins and the exact owner resource with three GET requests; zero model calls.','target'),
  'probe list':command('probe list','List approved resources for live agent probes.','target'),
  scan:command('scan','Replay saved checks, then review with the selected analysis engine.','mode target base full plan detach'),
  'finding list':command('finding list','List findings, with simulation and evidence labels.','target run status severity'),
  'finding show':command('finding show <id>','Show evidence, history, and remediation context.'),
  verify:command('verify <finding-id>','Reproduce a finding using its scoped HTTP controls.','target'),
  retest:command('retest <finding-id>','Check a deployed fix and save a standalone regression.','target build'),
  'test list':command('test list','List saved regression checks.','target'),
  'test show':command('test show <id>','Show a check and environment bindings.'),
  'test save':command('test save <finding-id>','Save a failing reproduction immediately, or a verified fixed regression.'),
  'test run':command('test run [id]','Replay deterministic checks with zero model calls.','all target detach'),
  'test bind':command('test bind [id]','Bind a saved check to an authorized environment.','all target file'),
  'test export':command('test export [id]','Write ordinary Node tests with no Bypass dependency.','all target out force'),
  'test disable':command('test disable <id>','Disable a saved check with an audit reason.','reason'),
  'test enable':command('test enable <id>','Enable a saved check.'),
  coverage:command('coverage','Show assessment work remaining, source ranges, actual controls and specific blockers.','run target'),
  context:command('context','Get security context for feature work, or general session history.','finding task files target'),
  memory:command('memory','Inspect local security memory and its evidence.','query target'),
  'memory list':command('memory list','Inspect or search security memory.','query target'),
  'memory show':command('memory show <id>','Read one memory record and its provenance.'),
  'memory forget':command('memory forget <id>','Forget a memory record; retain original audit evidence.'),
  'memory use':command('memory use <on|off>','Enable or disable memory recording and agent retrieval.'),
  report:command('report','Export a run as JSON or Markdown.','run format out'),
  'run list':command('run list','List durable runs.'),
  'run show':command('run show <id>','Inspect one run.'),
  'run watch':command('run watch <id>','Wait for completion and return the final exit code.','timeout'),
  'run stop':command('run stop <id>','Request cancellation of a running worker.'),
  'monitor add':command('monitor add <name>','Schedule saved regression replay.','target every runner'),
  'monitor list':command('monitor list','Show schedules and local worker health.'),
  'monitor run':command('monitor run <name>','Run a schedule immediately.'),
  'monitor pause':command('monitor pause <name>','Pause a monitor.'),
  'monitor resume':command('monitor resume <name>','Resume a monitor.'),
  'monitor remove':command('monitor remove <name>','Remove a monitor; retain run evidence.'),
  'monitor worker':command('monitor worker','Run the real local scheduler (machine must remain awake).','detach once stop'),
  'ci init':command('ci init','Generate GitHub saved checks, or a Meta API security agent with --agent.','provider target force agent action-ref every revision-path revision-field'),
  'mcp serve':command('mcp serve','Start the typed stdio MCP server.'),
  'demo start':command('demo start','Create the Ledger Git fixture and start its HTTP server.','dir port'),
  'demo status':command('demo status','Show the fixture state.'),
  'demo fix':command('demo fix','Enable ownership enforcement in the local fixture.'),
  'demo regress':command('demo regress','Reintroduce the local fixture defect.'),
  'demo add-route':command('demo add-route','Add an uncovered export route to the fixture.'),
  'demo reset':command('demo reset','Reset fixture behavior while retaining evidence.'),
  'demo stop':command('demo stop','Stop the local fixture server.'),
  _run:command('_run <id>','Internal detached run entry point.','',{hidden:true}),
  '_demo-serve':command('_demo-serve','Internal fixture server.','',{hidden:true})
};
export const booleanFlags=new Set(['discovery-only','include-tests','include-examples','include-generated','agent','public-config','reference','require-verification','json','help','version','non-interactive','plan','full','detach','all','force','accept','production','renew','once','stop','device','install','replace','allow-private','accept-local','no-model','dry-run','no-discovery','offline']);
export const globalFlags=['project','json','help','version','non-interactive','reference'];
export function parse(argv){
  const options={},words=[];
  for(let i=0;i<argv.length;i++){
    const token=argv[i];
    if(token==='-h'){options.help=true;continue;}
    if(token==='-v'){options.version=true;continue;}
    if(token.startsWith('--')){
      const equal=token.indexOf('='),key=token.slice(2,equal<0?undefined:equal);
      if(booleanFlags.has(key)){if(equal>=0)throw new Error(`--${key} does not take a value.`);options[key]=true;}
      else {const value=equal>=0?token.slice(equal+1):argv[++i];if(!value||value.startsWith('--'))throw new Error(`--${key} requires a value.`);options[key]=value;}
    }else words.push(token);
  }
  const key=commands[words.slice(0,2).join(' ')]?words.splice(0,2).join(' '):words.shift()||'';
  if(key&&commands[key]){
    const allowed=new Set([...globalFlags,...commands[key].flags]);for(const flag of Object.keys(options))if(!allowed.has(flag))throw new Error(`Unknown option --${flag} for ${key}.`);
    if(!options.help){const required=(commands[key].usage.match(/<[^>]+>/g)||[]).length,optional=(commands[key].usage.match(/\[[^\]]+\]/g)||[]).length;if(words.length<required||words.length>required+optional)throw new Error(`Usage: bypass ${commands[key].usage}`);}
  }else if(key&&!options.help)throw new Error(`Unknown command '${key}'. Run bypass --help.`);
  if(!key)for(const flag of Object.keys(options))if(!globalFlags.includes(flag))throw new Error(`Unknown global option --${flag}.`);
  return {key,args:words,options};
}
export function help(key,reference=false){
  if(!key&&!reference)return `BYPASS  /  security checks that stay with your code\n\nMuse plugin (recommended): /bypass:start inside Muse\n\n  bypass onboard       Connect your application\n  bypass poc           Try the real local demonstration\n  bypass status        See what is done and what comes next\n  bypass scan          Review configured source and live checks\n  bypass discover --plan  Plan deterministic CodeQL discovery (no LLM)\n  bypass test run --all  Replay saved regressions without AI\n\nCredentials are optional. Account-boundary tests need two accounts.\nStandalone AI needs an API-key profile; Muse uses its active session.\n\nFull reference: bypass --help --reference\nCommand details: bypass <command> --help\n`;
  const selected=commands[key];
  if(selected)return `bypass ${selected.usage}\n\n${selected.description}\n\nOptions: ${selected.flags.map(x=>'--'+x).join(', ')||'(none)'}\nGlobal: --project <path>, --json, --non-interactive, --help\n`;
  const entries=Object.entries(commands).filter(([k,v])=>!v.hidden&&(!key||k.startsWith(key+' ')));
  return `BYPASS  /  security checks that stay with your code\n\nStart here: bypass demo — complete guided walkthrough; no DNS or login needed.\nYour project: bypass onboard — connect a repository and preview a review.\n\nPOC · real Docker agents via engine use docker; offline mock preview available\n\n${entries.map(([,v])=>`  ${v.usage.padEnd(38)} ${v.description}`).join('\n')}\n\nGlobal: --project <path>, --json, --non-interactive, --help, --version\nExit codes: 0 success · 1 failed regression · 2 usage/config · 3 blocked/incomplete (including mock scan results) · 130 cancelled\n`;
}
