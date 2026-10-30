import { requireStandaloneAPI } from '../execution-mode.mjs';
import { checkedProfile } from '../providers.mjs';
import { need } from '../util.mjs';
import { unavailable } from './contracts.mjs';

/** Future generic task/model/tool loop. The scaffold never constructs a session. */
export function runAPIDriver(state) {
  requireStandaloneAPI();
  const profile = state?.models?.find(model => model.name === state.activeModel);
  need(profile, 'Configure and select an LLM API profile with bypass model add and bypass model use. Muse login credentials are not used.', 3, { reason: 'model_configuration_required' });
  checkedProfile(profile);
  return unavailable('api_driver');
}
