import { need } from './util.mjs';

// Validate the JSON-schema subset used by every exposed security action, even
// when a provider accepts strict schemas. Never execute unvalidated arguments.
export function validateJSON(schema, value, label='arguments', depth=0) {
  need(depth<24, 'Structured data exceeds nesting limit.', 3);
  if(schema.anyOf){need(schema.anyOf.some(s=>{try{validateJSON(s,value,label,depth+1);return true;}catch{return false;}}),`Invalid ${label}.`,3);return value;}
  const types=Array.isArray(schema.type)?schema.type:[schema.type];
  const matches=t=>t==='null'?value===null:t==='array'?Array.isArray(value):t==='object'?value!==null&&typeof value==='object'&&!Array.isArray(value):t==='integer'?Number.isInteger(value):typeof value===t;
  need(types.some(matches),`Invalid type for ${label}.`,3);
  if(schema.enum)need(schema.enum.includes(value),`Unsupported ${label}.`,3);
  if(typeof value==='string')need(value.length>=(schema.minLength??0)&&value.length<=(schema.maxLength??64000),`${label} outside length limits.`,3);
  if(typeof value==='number')need(Number.isFinite(value)&&(schema.minimum===undefined||value>=schema.minimum)&&(schema.maximum===undefined||value<=schema.maximum),`${label} outside bounds.`,3);
  if(Array.isArray(value)){need(value.length<=(schema.maxItems??1000),`${label} exceeds item limit.`,3);value.forEach(v=>validateJSON(schema.items,v,label,depth+1));}
  else if(value&&typeof value==='object'){
    for(const key of schema.required||[])need(Object.hasOwn(value,key),`Missing ${label}.${key}.`,3);
    for(const [key,v] of Object.entries(value)){
      need(!['__proto__','constructor','prototype'].includes(key),'Unsafe structured property.',3);
      const property=schema.properties?.[key];
      if(!property)need(schema.additionalProperties!==false,`Unknown ${label} field.`,3);
      else validateJSON(property,v,`${label}.${key}`,depth+1);
    }
  }
  return value;
}
