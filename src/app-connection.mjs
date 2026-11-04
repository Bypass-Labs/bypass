import { choiceInput } from './interaction.mjs';
import { appOriginInput, loopback, targetURL } from './network.mjs';

export const appAddressQuestion='What address do you open in your browser to use this app?';
export const appAddressHelp='Enter the URL you use to open this app, for example https://your-app.com.';
export const appEnvironmentChoices=[
  {label:'Production',id:'production',description:'A live deployment, including apps with no users yet.'},
  {label:'Staging',id:'staging',description:'A separate deployment used for testing.'},
  {label:'Preview',id:'preview',description:'A temporary deployment for a branch or pull request.'},
  {label:'Local development',id:'local',description:'An app running on your computer.'}
];
// Muse's native picker accepts at most three options. Loopback selects local
// automatically; other explicit local choices travel through the custom input.
const remoteEnvironmentChoices=appEnvironmentChoices.filter(choice=>choice.id!=='local');
export const appEnvironmentQuestion=url=>`Which environment is this? App: ${url}`;
export const codeOnlyInput=value=>/^(code[ -]only|source[ -]only|skip)$/i.test(value.trim());

// Read-only planning: an address is an input, never proof of a running app or permission.
// No repository scanning, port guessing, DNS queries or HTTP requests happen here.
export function appConnection({url,environment}={}){
  if(!url)return {id:'app',tool:'bypass_add_target',question:appAddressQuestion,help:appAddressHelp,input:{kind:'text',field:'url',allowCustom:true,reason:'No app URL is known yet. An exact user-selected URL cannot be invented.',guidance:'Use already supplied or saved app addresses as picker suggestions when present; otherwise collect this one missing URL.'},
    guidance:'Do not invent app URL suggestions. Reuse saved/user-supplied addresses; when none exists, ask only for the exact URL. Reuse an app URL explicitly supplied for this repository in the conversation. A README, example, framework port or listening socket is only a candidate, not a selected or verified running app. Do not preselect it.'};
  const origin=appOriginInput(url);
  const selectedEnvironment=environment||(loopback(new URL(origin).hostname)?'local':null);
  if(!selectedEnvironment)return {id:'environment',tool:'bypass_add_target',url:origin,question:appEnvironmentQuestion(origin),
    input:choiceInput('environment',remoteEnvironmentChoices),
    guidance:'Open the host selection UI with production, staging and preview. Local is selected automatically for loopback URLs. Ask this only when the user has not already identified the environment. Do not guess a remote environment from its hostname. No choice is preselected. If the host requires a default, put production first; this choice never authorizes requests.'};
  targetURL(origin,selectedEnvironment);
  return {id:'app',tool:'bypass_add_target',automatic:true,arguments:{name:selectedEnvironment,url:origin,environment:selectedEnvironment},
    message:'Save the supplied app address, then continue to ownership verification and testing permission. No app request has been made.'};
}
