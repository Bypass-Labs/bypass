import { commands } from './catalog.mjs';

// Presentation/lifecycle aliases are explicit. All other CLI operations map to
// their shared service command; new CLI features must pass the parity test.
export const pluginAliases={
  poc:{tool:'bypass_demo_start',arguments:{kind:'real'},note:'Conversational real demo replaces the standalone terminal screen.'},
  'poc start':{tool:'bypass_demo_start',arguments:{kind:'real'},note:'Create a separate real fixture for Muse to investigate; no plugin API key or Docker required.'},
  'poc stop':{tool:'bypass_demo_control',arguments:{action:'stop'}},
  demo:{tool:'bypass_demo_start',arguments:{kind:'preview'},note:'Muse guides the same six-step walkthrough.'},
  'demo start':{tool:'bypass_demo_start',arguments:{kind:'preview'}},
  onboard:{tool:'bypass_onboarding',note:'Conversational checklist, with bypass_connect_repository for repository and config input.'},
  init:{tool:'bypass_connect_repository'},'repo connect':{tool:'bypass_connect_repository'},
  'memory list':{tool:'bypass_memory'},
  scan:{tool:'bypass_scan',note:'Prepare a durable host review. Muse drives bypass_review_step read/source/probe/finish; no independent AI worker.'},
  'model add':{tool:'bypass_add_model',note:'Explains host-owned reasoning; cannot configure API inference inside Muse. API profiles are standalone-only.'},
  'model use':{tool:'bypass_use_model',note:'Explains host-owned reasoning; choose the active Muse model through host settings.'},
  'model test':{tool:'bypass_test_model',note:'Explains host-owned reasoning without sending an independent model request.'},
  'model list':{tool:'bypass_models',note:'Inspect saved standalone profiles; these are not used for plugin reasoning.'},
  'engine use':{tool:'bypass_engine',note:'Set the standalone engine preference. Real plugin reviews remain Muse-directed.'},
  'engine doctor':{tool:'bypass_engine_doctor',note:'Explain native host execution; no Docker or API profile is needed in Muse.'},
  'engine prepare':{tool:'bypass_prepare_engine',note:'Optional preparation of standalone Docker workers; unnecessary for native plugin reviews.'},
  'run watch':{tool:'bypass_watch_run',note:'Bounded progress for deterministic replay. For awaiting_host reviews use bypass_review_step status, then let Muse continue.'},
  'mcp serve':{hostOwned:true,note:'Muse starts this already-approved server. Starting a second stdio server is a transport action, not an application operation.'},
  ...Object.fromEntries(['status','fix','regress','add-route','reset','stop'].map(action=>['demo '+action,{tool:'bypass_demo_control',arguments:{action}}]))
};
export const flagEquivalents={
  poc:{project:'selected application profile'},onboard:{repo:'bypass_connect_repository.repository',dir:'bypass_connect_repository.dir',flow:'real/preview onboarding and conversational choices'},
  init:{repo:'repository'},
  scan:{plan:'bypass_prepare_scan',detach:'Host review uses explicit read/source/probe/finish steps'},
  'test run':{detach:'bypass_run_tests always starts a durable run'},
  'monitor worker':{detach:'action=start',once:'action=once',stop:'action=stop'}
};
export function capabilityCatalog(tools){
  return Object.entries(commands).filter(([,c])=>!c.hidden).map(([command,definition])=>{
    const alias=pluginAliases[command],matches=tools.filter(t=>t.command===command),primary=alias?.tool?tools.find(t=>t.name===alias.tool):matches[0];
    return {command,description:definition.description,tool:primary?.name||null,alternatives:matches.slice(1).map(t=>t.name),...(alias||{}),
      options:definition.flags.map(flag=>({flag,argument:flagEquivalents[command]?.[flag]||flag,available:!!primary?.inputSchema.properties[flag]||!!flagEquivalents[command]?.[flag]||matches.some(t=>Object.hasOwn(t.inputSchema.properties,flag))}))};
  });
}
export function pluginHelp(tools,query=''){
  const needle=query.trim().toLowerCase(),catalog=capabilityCatalog(tools);
  return {kind:'plugin-command-guide',primaryExperience:'Muse plugin',
    shortcuts:[['/bypass:start','Connect your application and finish setup'],['/bypass:demo','Real local proof-to-regression demo; preview is an explicit option'],['/bypass:status','Done / Now / Next and current evidence'],['/bypass:review','Start or resume a review'],['/bypass:tests','Inspect, retest, bind, export, enable or disable saved checks'],['/bypass:monitor','Schedule, start, stop or inspect local monitoring'],['/bypass:build','Use security memory while coding'],['/bypass:context','Read saved context'],['/bypass:help','Find any operation']],
    workflows:[{name:'Application review',steps:['bypass_onboarding','bypass_connect_repository','bypass_add_target','bypass_verify_target','bypass_authorize_target','bypass_import_identity','bypass_add_probe','bypass_test_probe','bypass_prepare_scan','bypass_scan','bypass_review_step']},
      {name:'Proof to regression',steps:['bypass_finding','bypass_verify','bypass_retest','bypass_export_tests','bypass_run_tests','bypass_watch_run']},
      {name:'Local monitoring',steps:['bypass_add_monitor','bypass_monitor_worker','bypass_monitors','bypass_context']},
      {name:'Feature work',steps:['bypass_feature_context','Muse coding tools','bypass_run_tests']}],
    capabilities:catalog.filter(c=>!needle||JSON.stringify(c).toLowerCase().includes(needle)),
    hostSteps:[{operation:'Official Muse sign-in',reason:'Interactive authentication belongs to Muse; Bypass never collects Muse login credentials.',command:'muse login'},
      {operation:'Plugin capability approval or loading an update',reason:'Muse owns approval and session lifecycle.',commands:['/plugins → Installed → Bypass → Runtime','Start a new Muse session, then /bypass:start']}],
    guidance:'Perform tools yourself in this Muse session. Show plain-language choices, not MCP syntax or a request to switch to the standalone CLI. Preserve explicit user scope and secrets. A local schedule needs a running worker and awake machine.'};
}
