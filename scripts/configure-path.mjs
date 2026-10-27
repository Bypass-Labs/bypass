import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const start='# >>> Bypass PATH >>>',end='# <<< Bypass PATH <<<';
const quote=value=>"'"+value.replaceAll("'","'\\''")+"'";
export function configurePath({binDir,homeDirectory=os.homedir(),shell=process.env.SHELL||'/bin/bash',zdotdir=process.env.ZDOTDIR,skip=process.env.BYPASS_NO_MODIFY_PATH==='1'}={}){
  if(!path.isAbsolute(binDir)||/[\r\n:]/.test(binDir))throw new Error('The executable directory must be absolute and contain no colon or newline.');
  const activation=`export PATH=${quote(binDir)}\${PATH:+":$PATH"}`;
  const result={shell:path.basename(shell),files:[],changed:[],errors:[],activation,skipped:skip};
  if(skip)return result;
  let files;
  if(result.shell==='bash'){
    const login=['.bash_profile','.bash_login','.profile'].map(name=>path.join(homeDirectory,name));
    files=[path.join(homeDirectory,'.bashrc'),login.find(file=>fs.existsSync(file))||login[0]];
  }else if(result.shell==='zsh'){
    const directory=zdotdir?path.resolve(zdotdir):homeDirectory;
    files=['.zshrc','.zprofile'].map(name=>path.join(directory,name));
  }else return {...result,unsupported:true};
  const block=`${start}\ncase ":\${PATH-}:" in\n  *:${quote(binDir)}:*) ;;\n  *) ${activation} ;;\nesac\n${end}\n`;
  for(const file of files){
    let temporary;
    try{
      // Update a symlink's target without replacing the user's symlink or modes.
      let target=file,mode=0o644,previous='';
      let link;try{link=fs.lstatSync(file);}catch(error){if(error.code!=='ENOENT')throw error;}
      if(link){if(link.isSymbolicLink())target=fs.realpathSync(file);const stat=fs.statSync(target);if(!stat.isFile())throw new Error('Profile is not a regular file');fs.accessSync(target,fs.constants.W_OK);mode=stat.mode&0o777;previous=fs.readFileSync(target,'utf8');}
      const blocks=previous.match(/^# >>> Bypass PATH >>>\r?\n[\s\S]*?^# <<< Bypass PATH <<<\r?(?:\n|$)/gm)||[];
      if(previous.split(start).length-1!==blocks.length||previous.split(end).length-1!==blocks.length)throw new Error('Incomplete Bypass PATH block; repair it before retrying');
      if(blocks.length===1&&blocks[0]===block){result.files.push(file);continue;}
      const kept=previous.replace(/^# >>> Bypass PATH >>>\r?\n[\s\S]*?^# <<< Bypass PATH <<<\r?(?:\n|$)/gm,'');
      const next=kept+(kept&&!kept.endsWith('\n')?'\n':'')+block;
      fs.mkdirSync(path.dirname(target),{recursive:true});
      temporary=path.join(path.dirname(target),'.bypass-path-'+randomUUID());
      fs.writeFileSync(temporary,next,{mode,flag:'wx'});fs.chmodSync(temporary,mode);fs.renameSync(temporary,target);temporary=undefined;
      result.files.push(file);result.changed.push(file);
    }catch(error){result.errors.push({file,message:String(error.message).replace(/[\r\n]/g,' ').slice(0,200)});}
    finally{if(temporary)fs.rmSync(temporary,{force:true});}
  }
  return result;
}

if(process.argv[1]&&fs.existsSync(process.argv[1])&&fs.realpathSync(process.argv[1])===fileURLToPath(import.meta.url)){
  const binDir=process.argv[2],result=configurePath({binDir});
  const quiet=process.argv[3]==='muse';
  if(!quiet)for(const file of result.files)console.log(`${result.changed.includes(file)?'Added Bypass to PATH':'Bypass PATH already configured'} in ${file}`);
  for(const error of result.errors)console.log(`Could not update ${error.file}: ${error.message}`);
  if(result.unsupported)console.log(`Automatic PATH setup supports Bash and Zsh; configure ${result.shell} to include ${binDir}.`);
  else if(result.skipped){if(!quiet)console.log('Automatic PATH setup skipped (BYPASS_NO_MODIFY_PATH=1).');}
  else if(result.errors.length)console.log('Some shell profiles could not be updated. Use the activation command or full executable path below.');
  else if(result.files.length)console.log(quiet?'✓ Terminal command configured':'New terminal windows will find bypass automatically.');
  if(!quiet&&!(process.env.PATH||'').split(path.delimiter).includes(binDir)&&!result.unsupported)console.log(`\nTo use bypass in this terminal now, run:\n  ${result.activation}`);
}
