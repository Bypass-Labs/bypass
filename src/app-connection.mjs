import { appOriginInput, loopback, targetURL } from './network.mjs';

export const appAddressQuestion='What address do you open in your browser to use this app?';
export const appAddressHelp='Paste the app URL, or say "code only" to review the code now. You can connect an app later.';
export const appEnvironmentChoices=[
  {label:'Real users use it',id:'production',description:'The live app used by customers or other users.'},
  {label:'Only for testing',id:'staging',description:'A staging, preview or other test deployment.'}
];
export const appEnvironmentQuestion=url=>`Do real users use ${url}, or is it only for testing?`;
export const codeOnlyInput=value=>/^(code[ -]only|source[ -]only|skip)$/i.test(value.trim());

// Read-only planning: an address is an input, never proof of a running app or permission.
// No repository scanning, port guessing, DNS queries or HTTP requests happen here.
export function appConnection({url,environment}={}){
  if(!url)return {id:'app',tool:'bypass_add_target',question:appAddressQuestion,help:appAddressHelp,input:{kind:'text',field:'url'},
    guidance:'Ask for the address as free text, not a menu of local/source-only/another URL. Reuse an app URL explicitly supplied for this repository in the conversation. A README, example, framework port or listening socket is only a candidate, not a selected or verified running app. Do not preselect it.'};
  const origin=appOriginInput(url);
  const selectedEnvironment=environment||(loopback(new URL(origin).hostname)?'local':null);
  if(!selectedEnvironment)return {id:'environment',tool:'bypass_add_target',url:origin,question:appEnvironmentQuestion(origin),
    input:{kind:'choice',field:'environment',choices:appEnvironmentChoices},
    guidance:'Ask this only when the user has not already identified production, staging, preview or a test app. Do not guess from the hostname. No choice is preselected. If the host requires a default, put production first; this choice never authorizes requests.'};
  targetURL(origin,selectedEnvironment);
  return {id:'app',tool:'bypass_add_target',automatic:true,arguments:{name:selectedEnvironment,url:origin,environment:selectedEnvironment},
    message:'Save the supplied app address, then continue to ownership verification and testing permission. No app request has been made.'};
}
