import { need, Fault } from './util.mjs';
import { ProviderSession } from './providers.mjs';
export const INFERENCE_TIMEOUT_MS=60000;
export function modelResponseSchema(role){
  if(role==='orchestrator')return {type:'object',properties:{focus:{type:'string',maxLength:2000}},required:['focus'],additionalProperties:false};
  need(['white-box','white-box-live'].includes(role),`Unknown model response role: ${role}.`);
  const live=role==='white-box-live';
  const properties={action:{type:'string',enum:['read_files','finish']},summary:{type:'string',...(live?{maxLength:300}:{})}};
  {
    properties.knowledge={type:'array',maxItems:live?2:8,items:{type:'object',properties:{topic:{type:'string',enum:['authentication','authorization','data-model','routing','trust-boundary']},title:{type:'string',maxLength:160},summary:{type:'string',maxLength:live?300:700},file:{type:'string'},line:{type:'integer',minimum:1},quote:{type:'string',maxLength:2000}},required:['topic','title','summary','file','line','quote'],additionalProperties:false}};
    properties.paths={type:'array',maxItems:8,items:{anyOf:[{type:'string'},{type:'object',properties:{path:{type:'string'},startLine:{type:'integer',minimum:1},endLine:{type:'integer',minimum:1}},required:['path','startLine','endLine'],additionalProperties:false}]}};
    const candidateProperties={title:{type:'string',...(live?{maxLength:160}:{})},category:{type:'string',minLength:1,maxLength:120},file:{type:'string'},line:{type:'integer',minimum:1},quote:{type:'string'},resourcePath:live?{type:'string',minLength:1,maxLength:300}:{type:['string','null']},...(live?{method:{type:'string',enum:['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS','UNKNOWN']},privateFields:{type:'array',maxItems:8,items:{type:'string',minLength:1,maxLength:80}}}:{}),hypothesis:{type:'string',...(live?{maxLength:500}:{})},recommendation:{type:'string',...(live?{maxLength:500}:{})}};
    properties.candidates={type:'array',maxItems:live?3:8,items:{type:'object',properties:candidateProperties,required:Object.keys(candidateProperties),additionalProperties:false}};
  }
  // Every action uses one locally validated schema; unused arrays are empty.
  return {type:'object',properties,required:Object.keys(properties),additionalProperties:false};
}

export async function infer(profile,messages,options={}) {
  return (options.session || new ProviderSession(profile)).turn(messages,options);
}

export function parseModelJSON(text){
  need(typeof text==='string'&&text.length<=64000,'Model response is absent or too large.',3);
  const plain=text.trim().replace(/^```(?:json)?\s*/,'').replace(/\s*```$/,'');
  try {const value=JSON.parse(plain);need(value&&typeof value==='object'&&!Array.isArray(value),'Expected a JSON object.',3);return value;}catch{throw new Fault('Model response was not the required JSON object. No finding was confirmed by this response.',3);}
}
