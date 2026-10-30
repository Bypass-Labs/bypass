import fs from 'node:fs';
import path from 'node:path';
import {read} from '../store.mjs';
import {credentialStatus, resolveCredential} from '../credentials.mjs';

const roles = ['owner', 'outsider'];
const defaults = {owner: 'OWNER_TOKEN', outsider: 'OTHER_TOKEN'};
function project(root, origin) {
  if (!fs.existsSync(path.join(root, '.bypass/state.json'))) return {};
  const state = read(root);
  return {state, target: state.targets.find(item => item.url === origin)};
}
const placement = identity => identity.type === 'header' ? `header:${identity.header}` : identity.type;

// Reuse an unambiguous saved pair when preparing a NEW scope. An existing
// reviewed scope and explicit credential choices always retain precedence.
export function savedAccountOptions(root, origin, options) {
  if (options['owner-env'] || options['other-env']) return options;
  const {state, target} = project(root, origin);
  if (!target) return options;
  const identities = state.identities.filter(item => item.target === target.name);
  const generated = target.registration?.lastResult?.accounts;
  const pair = generated?.length === 2 ? generated.map(item => identities.find(i => i.name === item.name)) :
    identities.length === 2 ? identities : [];
  if (pair.length !== 2 || pair.some(item => !item) ||
      pair[0].secretEnv === pair[1].secretEnv || placement(pair[0]) !== placement(pair[1]) ||
      pair[0].checkPath !== pair[1].checkPath) return options;
  if (options.auth && options.auth !== placement(pair[0]) ||
      options['identity-path'] && options['identity-path'] !== pair[0].checkPath) return options;
  return {...options, 'owner-env': pair[0].secretEnv, 'other-env': pair[1].secretEnv,
    auth: options.auth || placement(pair[0]), 'identity-path': options['identity-path'] || pair[0].checkPath};
}

// Read-only readiness: never refresh a token or contact an app during setup.
export function blackboxAccounts(root, scope, {env = process.env, required = []} = {}) {
  const {state, target} = project(root, scope.target.origin);
  const accounts = roles.map(role => {
    const reference = scope.identities[role]?.env;
    const matches = target ? state.identities.filter(item => item.target === target.name && item.secretEnv === reference) : [];
    const identity = matches.length === 1 ? matches[0] : null;
    const status = identity ? credentialStatus(state, target, identity, env) :
      {available: !!env[reference], source: 'environment', status: env[reference] ? 'ready' : 'missing'};
    const configured = matches.length > 0 || required.includes(role) || !!reference && reference !== defaults[role];
    const login = scope.identities[role]?.login || (role === 'owner' ?
      {usernameEnv: 'OWNER_USER', passwordEnv: 'OWNER_PASS'} : {usernameEnv: 'OTHER_USER', passwordEnv: 'OTHER_PASS'});
    const canLogin = !!((scope.target.environment === 'local' || scope.identities.login) &&
      env[login.usernameEnv] && env[login.passwordEnv]);
    const compatible = !identity || placement(identity) === scope.identities.auth &&
      (!scope.identities.identityPath || identity.checkPath === scope.identities.identityPath);
    return {role, reference, name: identity?.name || null, ...status,
      available: (status.available || canLogin) && compatible && matches.length <= 1,
      status: !compatible ? 'configuration_mismatch' : matches.length > 1 ? 'ambiguous' : status.status,
      required: configured};
  });
  const missing = accounts.filter(item => item.required && !item.available);
  return {accounts, ready: true,
    mode: accounts.every(item => item.available) ? 'two-accounts' : accounts.some(item => item.available) ? 'one-account' : 'anonymous-only',
    warnings: missing.map(item => `${item.role} account ${item.reference} is unavailable (${item.status}). Continue available checks and authorized account creation; authenticated coverage remains limited until an identity is established.`),
    note: 'Account availability is configuration readiness; distinct signed-in identities still need HTTP validation.'};
}

export async function blackboxEnvironment(root, scope, {env = process.env, signal, request} = {}) {
  const {state, target} = project(root, scope.target.origin);
  const result = {...env};
  for (const role of roles) {
    const reference = scope.identities[role]?.env;
    if (!reference || !target) continue;
    const matches = state.identities.filter(item => item.target === target.name && item.secretEnv === reference);
    if (matches.length !== 1) continue;
    const identity = matches[0];
    if (placement(identity) !== scope.identities.auth ||
        scope.identities.identityPath && identity.checkPath !== scope.identities.identityPath) continue;
    if (!credentialStatus(state, target, identity, env).available) continue;
    const value = await resolveCredential(state, target, identity, {env, signal, ...(request ? {request} : {})});
    if (value) result[reference] = value;
  }
  return result;
}
