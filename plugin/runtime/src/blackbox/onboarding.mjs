import fs from 'node:fs';
import path from 'node:path';
import {read, rootFrom} from '../store.mjs';
import {appOriginInput} from '../network.mjs';
import {choiceInput} from '../interaction.mjs';
import {validateScopeTemplate} from './scope.mjs';

// Preview only. A selected app or recommended preset is not testing permission.
export function blackboxOnboarding(working, rawUrl, options = {}) {
  const root = rootFrom(working, false);
  const state = fs.existsSync(path.join(root, '.bypass/state.json')) ? read(root) : null;
  const selected = state?.targets.find(t => t.name === state.activeTarget);
  const base = {kind: 'blackbox-onboarding', readOnly: true, liveRequestsStarted: false};
  if (!rawUrl) return {...base, selectedApp: selected ?
    {url: selected.url, environment: selected.environment} : null,
    input: choiceInput('url', [
      ...(selected ? [{id: 'selected', label: 'Use selected app', description: selected.url,
        value: selected.url}] : []),
      {id: 'another', label: selected ? 'Another app' : 'Connect an app',
        description: 'Enter the address you open in your browser.'}
    ], {recommended: selected ? 'selected' : undefined, custom: 'value',
      question: 'Which app should Bypass test?'})};

  const origin = appOriginInput(rawUrl);
  const target = state?.targets.find(t => t.url === origin);
  const file = path.resolve(root, options.out || 'blackbox.scope.json');
  let scope = null;
  if (fs.existsSync(file)) {
    // Malformed or mismatched saved scope is never silently replaced by a preset.
    scope = validateScopeTemplate(JSON.parse(fs.readFileSync(file, 'utf8')));
    if (scope.target.origin !== origin) return {...base, origin, scopeFile: file,
      input: choiceInput('scope', [
        {id: 'connect', label: 'Connect this app', description: 'Use its own app profile and scope.'},
        {id: 'saved', label: 'Keep saved app', description: scope.target.origin, value: scope.target.origin}
      ], {recommended: 'connect', question: 'This folder has a scope for another app.'})};
  }
  const auth = target?.authorization;
  const settings = {url: origin,
    include: options.include ?? scope?.include.join(',') ?? auth?.paths.join(',') ?? '/',
    rps: Number(options.rps ?? Math.min(scope?.limits.rps ?? 2, auth?.maxRequestsPerSecond ?? Infinity)),
    'model-calls': Number(options['model-calls'] ?? scope?.limits.modelCalls ?? 120),
    minutes: Number(options.minutes ?? scope?.limits.minutes ?? 30)};
  return {...base, origin, savedScope: !!scope, settings,
    input: choiceInput('preset', [
      {id: 'recommended', label: scope ? 'Use saved settings' : 'Recommended review',
        description: `${settings.include} · ${settings.rps} requests/sec · ${settings['model-calls']} engine decisions · up to ${settings.minutes} minutes`,
        arguments: settings},
      {id: 'custom', label: 'Customize settings', description: 'Change paths, request rate or review limits.'}
    ], {recommended: 'recommended', question: 'How should Bypass test this app?'}),
    customFields: [
      {field: 'include', value: settings.include, label: 'Allowed paths'},
      {field: 'rps', value: settings.rps, label: 'Requests per second', minimumExclusive: 0, maximum: 10},
      {field: 'model-calls', value: settings['model-calls'], label: 'Engine decisions', minimum: 1, integer: true},
      {field: 'minutes', value: settings.minutes, label: 'Time limit in minutes', minimumExclusive: 0}
    ],
    nextAction: {tool: 'bypass_blackbox_setup', arguments: settings, requiresSelection: true},
    note: 'Reuse saved accounts when available. Without accounts, continue anonymous checks and scoped account-creation discovery. Review ownership and exact permissions before testing. Engine decisions exclude Muse setup and reporting turns.'};
}
