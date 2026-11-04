import { Fault } from './util.mjs';

// Shared presentation contract. A suggestion is never consent or a verified fact.
export function choiceInput(field,choices,{recommended,custom='instructions',...extra}={}){
  if(choices.length>3)throw new Fault(`Native picker ${field} supports at most three choices.`);
  return {kind:'choice',field,hostControl:'request_user_input',allowCustom:true,
    choices:choices.map(c=>({...c,...(c.id===recommended?{recommended:true,label:/recommended/i.test(c.label)?c.label:c.label+' (recommended)'}:{})})),
    customInput:{kind:custom,label:custom==='value'?'Enter a custom value':'Custom instructions',optional:true},
    guidance:'Open the native picker. Preserve its custom-answer or note field; if unavailable, add a Custom instructions option. Reuse explicit answers already given. Suggestions and defaults are not consent. Interpret custom instructions before acting; clarify conflicts, never silently expand permission.',...extra};
}

// One explicit approval covers the displayed plan. A custom reply never counts as consent.
export function testingApproval(target,scope){
  return choiceInput('approval',[
    {id:'approve',label:'Approve',description:'I control this app and authorize the displayed tests.',arguments:{accept:true,production:target.environment==='production'}},
    {id:'decline',label:'Decline',description:'Save setup without running tests.'},
    {id:'custom',label:'Custom instructions',description:'Change the proposed methods, paths or limits before approving.'}
  ],{question:`Do you control ${target.url} and authorize these tests?`,scope,
    guidance:'Show the exact app, environment, paths, methods and rate in a compact plan, then this native picker. Only an explicit Approve answer authorizes that plan; a default selection or custom instructions do not. Keep code fixes separate. If the plan changes, show the changes and obtain approval again.'});
}

const itemFor=value=>typeof value==='object'?value:{value:String(value),label:String(value)};
export async function promptValue(ask,title,values=[],{fallback,write=console.log,customLabel='Enter a custom value',recommended=true}={}){
  const seen=new Set(),items=values.map(itemFor).filter(i=>i.value!==undefined&&!seen.has(String(i.value))&&seen.add(String(i.value))).map((i,n)=>({...i,id:i.id||String(n),label:i.label||String(i.value)}));
  fallback??=items[0]?.value||'';
  if(!items.length)return ask(title,fallback); // A genuinely unknown URL/path/ID.
  if(recommended&&!/recommended/i.test(items[0].label))items[0].label+=' (recommended)';
  if(ask.select){
    const picked=await ask.select(title,[...items,{id:'__custom',label:customLabel,custom:true}],{allowCustom:true});
    if(!picked)throw new Fault('Choice cancelled. Saved setup is retained.',130);
    return picked.custom?picked.value??await ask(title+' — custom',String(fallback)):String(picked.value);
  }
  write('\n'+title);items.forEach((i,n)=>write(`  ${n+1}  ${i.label}${i.description?' — '+i.description:''}`));write(`  ${items.length+1}  ${customLabel} (or type it directly)`);
  const answer=String(await ask(title,String(fallback))).trim();
  const index=/^\d+$/.test(answer)?Number(answer)-1:-1;
  if(index===items.length)return ask(title+' — custom',String(fallback));
  return index>=0&&items[index]?String(items[index].value):answer||String(fallback);
}

export async function confirmChoice(ask,title,{yes='Yes, continue',no='Not now',fallback=false,recommended,write=console.log}={}){
  const items=[{id:'yes',label:yes},{id:'no',label:no}].map(i=>({...i,label:i.id===recommended?i.label+' (recommended)':i.label}));
  if(ask.select){const chosen=await ask.select(title,items,{fallback:fallback?0:1});return chosen?.id==='yes';}
  write('\n'+title);items.forEach((i,n)=>write(`  ${n+1}  ${i.label}`));
  while(true){const answer=String(await ask(title+' (y/n)',fallback?'y':'n')).trim().toLowerCase();if(['1','y','yes'].includes(answer))return true;if(['2','n','no',''].includes(answer))return false;write('Choose 1 / yes or 2 / no.');}
}

export const syntheticEmailDomain=target=>target.environment==='local'?'bypass-test.example.invalid':`bypass-test.${new URL(target.url).hostname}`;
export function accountInput(target){
  return choiceInput('accounts',[
    {id:'create',label:'Create two test accounts',description:'Authorize up to two dedicated signup attempts. Bypass discovers config and stores credentials privately.',accept:true},
    {id:'existing',label:'Use existing test accounts',description:'Connect a private account file; never paste tokens into chat.'},
    {id:'skip',label:'Continue without accounts',description:'Keep source and anonymous checks; report account-boundary coverage gaps.'}
  ],{recommended:'create',question:'How should Bypass test signed-in account access?',permission:{origin:target?.url||null,maxAccounts:2,emailDomain:target?syntheticEmailDomain(target):null},
    guidance:'Use this picker only when account creation permission or an account choice is missing. Already-authorized creation continues automatically. Do not combine it with requests for Firebase project ID, API key, email domain or selectors: discover/derive those. The user can override the email namespace or give custom instructions in the note. A custom note is not automatic consent; resolve conflicting instructions before any signup.'});
}

export const credentialTypes=[
  {value:'bearer',label:'Bearer token',description:'Typical API or Firebase ID token'},
  {value:'cookie',label:'Session cookie',description:'Existing signed-in cookie'},
  {value:'header',label:'Custom header',description:'An app-specific authentication header'}
];
export const verificationChoices=target=>target.environment==='local'?[{value:'local',label:'Confirm local ownership'}]:[{value:'dns',label:'DNS TXT record'},{value:'http',label:'HTTPS verification file'}];
export const scopeSuggestions=target=>{
  const all={value:'/',label:'Entire app (/)',description:'Includes every path on this origin for the most complete review; requires explicit permission.'};
  if(!target?.authorization)return [all,
    {value:'/api',label:'API routes only (/api)',description:'Limits testing to a common API prefix; choose custom paths if your app differs.'}];
  const saved={value:target.authorization.paths.join(','),label:'Keep saved paths',description:target.authorization.paths.join(', ')};
  return saved.value==='/'?[saved]:[saved,all];
};
