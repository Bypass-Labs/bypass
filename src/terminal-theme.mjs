import { stripVTControlCharacters } from 'node:util';

// Bypass's published identity: vermilion split mark, ink and warm paper.
// Supporting colors communicate outcomes, never replace the written status.
export const palette = {
  ink:'#090708', paper:'#eee9e0', brand:'#ff4a2c', accent:'#ff745e',
  muted:'#b6aaa1', rule:'#655650', panel:'#211a18',
  success:'#89cba5', warning:'#efc475', error:'#ff8b83', info:'#9dc5d0',
};
const rgb = hex => hex.slice(1).match(/../g).map(x=>parseInt(x,16));
const indexed={paper:255,brand:202,accent:209,muted:249,rule:240,panel:235,ink:232,success:115,warning:222,error:210,info:152};
const basic={paper:39,brand:91,accent:91,muted:37,rule:90,panel:40,ink:30,success:92,warning:93,error:91,info:96};

export function createTheme({output=process.stdout,env=process.env}={}) {
  const enabled=!!output.isTTY&&env.TERM!=='dumb'&&env.NO_COLOR===undefined;
  const depth=output.getColorDepth?.(env)||(/truecolor|24bit/.test(env.COLORTERM||'')?24:/256/.test(env.TERM||'')?8:4);
  const code=(name,background=false)=>depth>=24?`${background?48:38};2;${rgb(palette[name]).join(';')}`:depth>=8?`${background?48:38};5;${indexed[name]}`:background?(name==='brand'?101:40):basic[name];
  const tones={normal:'paper',title:'paper',brand:'brand',accent:'accent',muted:'muted',rule:'rule',success:'success',warning:'warning',error:'error',info:'info',selection:'ink',panel:'paper'};
  const paint=(tone,text,{surface=false}={})=>{
    const clean=stripVTControlCharacters(String(text));
    if(!enabled)return clean;
    const bg=tone==='selection'?'brand':tone==='panel'?'panel':'ink';
    return `\x1b[${['title','brand','selection'].includes(tone)?'1;':''}${code(tones[tone]||'paper')}${surface?';'+code(bg,true):''}m${clean}\x1b[0m`;
  };
  return {enabled,depth,paint};
}

export function brandHeading(subtitle,{output=process.stdout,env=process.env}={}) {
  const {paint}=createTheme({output,env});
  return `${paint('brand','▰╲')}${paint('title','▰  BYPASS LABS')}\n${paint('muted',subtitle)}`;
}
