import { need } from './util.mjs';

export const methodChoices=[
  {id:'GET',label:'GET',description:'Read resources'},
  {id:'HEAD',label:'HEAD',description:'Read response headers'},
  {id:'POST',label:'POST',description:'Create test data or start jobs'},
  {id:'PUT',label:'PUT',description:'Replace test data'},
  {id:'PATCH',label:'PATCH',description:'Update test data'},
  {id:'DELETE',label:'DELETE',description:'Delete test data'},
  {id:'OPTIONS',label:'OPTIONS',description:'Inspect supported operations'}
];
export function httpMethod(value){
  need(typeof value==='string','Provide an HTTP method.');
  const method=value.trim().toUpperCase();
  need(/^[A-Z][A-Z0-9!#$%&'+.^_`|~-]{0,31}$/.test(method),'Use an HTTP method name such as POST or PROPFIND; wildcards and control characters are not allowed.');
  need(!['CONNECT','PRI'].includes(method),'CONNECT tunnels and HTTP/2 prefaces are not supported by the scoped HTTP request runner.');
  return method;
}
export function httpMethods(value=['GET','HEAD']){
  const items=typeof value==='string'?value.split(/[,\s]+/).filter(Boolean):value;
  need(Array.isArray(items)&&items.length>0&&items.length<=16,'Choose 1–16 HTTP methods, separated by commas.');
  return [...new Set(items.map(httpMethod))];
}
export const mayChangeData=methods=>methods.some(method=>!['GET','HEAD','OPTIONS'].includes(method));
export function methodInput(current=['GET','HEAD']){
  return {kind:'multiselect',field:'methods',question:'Which HTTP methods may Bypass use?',choices:methodChoices,selected:current,allowCustom:true,
    help:'Select individual methods or enter a comma-separated list, including custom methods. POST can create data or start jobs; PUT/PATCH change data and DELETE removes it. Only the selected methods and approved paths are allowed.'};
}
export async function promptMethods(ask,say=console.log,current=['GET','HEAD']){
  while(true){
    const value=ask.multiselect?await ask.multiselect('Which HTTP methods may Bypass use?',methodChoices,{selected:current,allowCustom:true}):await (async()=>{
      say(methodChoices.map((m,i)=>`  ${i+1}  ${m.label} — ${m.description}`).join('\n'));
      return ask('Allowed methods (names or numbers, comma-separated; custom names accepted)',current.join(','));
    })();
    try{
      const values=Array.isArray(value)?value:String(value).split(/[,\s]+/).filter(Boolean);
      return httpMethods(values.map(v=>/^\d+$/.test(v)?methodChoices[Number(v)-1]?.id||v:v));
    }catch(error){if(error.code===130||error.name==='AbortError')throw error;say(error.message);}
  }
}
