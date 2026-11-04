import {credentialEnvironment} from '../credentials.mjs';

function placement(identity) {
  if (identity?.type === 'bearer' || identity?.type === 'cookie') return identity.type;
  if (identity?.type === 'header' && identity.header) return `header:${identity.header}`;
  return null;
}

/**
 * Translate the project's saved account references into the black-box runner's
 * credential contract. The project remains the source of truth; a scope file is
 * only an immutable run snapshot.
 */
export function projectIdentityBridge(state, target) {
  if (!target) return null;
  const identities = state.identities.filter(identity => identity.target === target.name);
  const preferred = target.probes?.find(probe => probe.binding?.owner && probe.binding?.outsider)?.binding;
  const owner = identities.find(identity => identity.name === preferred?.owner) ?? identities[0];
  const outsider = identities.find(identity => identity.name === preferred?.outsider) ??
    identities.find(identity => identity.name !== owner?.name);
  if (!owner || !outsider || owner.name === outsider.name) return null;
  const auth = placement(owner);
  if (!auth || auth !== placement(outsider) || owner.checkPath !== outsider.checkPath || !owner.checkPath)
    return null;
  return {owner, outsider, options: {'owner-env': owner.secretEnv,
    'other-env': outsider.secretEnv, auth, 'identity-path': owner.checkPath}};
}

export async function projectBlackboxEnvironment(state, target, bridge,
  {env = process.env, signal} = {}) {
  if (!bridge) return env;
  return credentialEnvironment(state, target, [bridge.owner, bridge.outsider], {env, signal});
}
