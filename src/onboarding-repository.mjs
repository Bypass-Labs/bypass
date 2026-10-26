import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execute, PACKAGE_ROOT } from './service.mjs';
import { repositoryInfo } from './repository.mjs';
import { execFile, Fault, need } from './util.mjs';
import { isBypassSource } from './project-selection.mjs';

const expand = value => value === '~' ? os.homedir() : value.startsWith('~/') ? path.join(os.homedir(), value.slice(2)) : value;
const display = value => value.startsWith(os.homedir()+path.sep) ? '~'+value.slice(os.homedir().length) : value;
const unwrap = value => value.trim().replace(/^\[[^\]\n]*\]\(([^)\n]+)\)$/, '$1').replace(/^<([^>\n]+)>$/, '$1');
const isRemote = value => /^(https:\/\/|ssh:\/\/|git@)/.test(value);
const stopped = error => error.code===130 || error.name==='AbortError';
const cancel = () => { throw new Fault('Setup stopped. Existing files and saved choices are retained.',130); };

function remoteKey(value) {
  try {
    const url=new URL(value.startsWith('git@') ? value.replace(/^git@([^:]+):/, 'ssh://git@$1/') : value);
    return `${url.host}${url.pathname.replace(/\/$/, '').replace(/\.git$/, '')}`;
  } catch { return null; }
}

function repositoryName(location) {
  const name=remoteKey(location)?.split('/').at(-1)?.replace(/[^a-zA-Z0-9._-]/g,'-').replace(/^\.+/,'');
  return name || 'repository';
}

function availableFolder(base) {
  let candidate=base, number=2;
  while(fs.existsSync(candidate)) candidate=`${base}-${number++}`;
  return candidate;
}

// Keep the source while correcting the destination; never merge into an occupied folder.
export async function connectProject(options, args, {ask, say, yes, pick}) {
  let location=options.repo||args[0]||options.project;
  let fallback=process.cwd()===PACKAGE_ROOT||isBypassSource(process.cwd()) ? '' : process.cwd();
  let suppliedDirectory=options.dir;
  const init=(source,dir) => execute('init',[source],{...options,repo:undefined,dir,'non-interactive':true});

  while(true) {
    location=unwrap(location || await ask('Repository directory or Git URL',fallback));
    if(!location) { say('Enter your repository URL or an existing local folder.'); continue; }
    const remote=isRemote(location);
    if(!remote) {
      if(isBypassSource(path.resolve(expand(location)))){
        say('This is Bypass’s own tooling source. For white-box review, choose your application repository.');
        if(!await yes('Do you specifically want to review Bypass itself?','n')){location=null;fallback='';continue;}
      }
      try { return await init(expand(location)); }
      catch(error) {
        if(stopped(error)) throw error;
        say(error.message);
        if(!await yes('Choose another repository?','y')) cancel();
        fallback=location;location=null;continue;
      }
    }

    // Reject embedded HTTPS credentials before displaying or reusing a remote.
    try {
      if(location.startsWith('https://')) {
        const url=new URL(location);
        need(!url.username&&!url.password,'Use your Git credential helper; do not put credentials in a repository URL.');
      }
    } catch(error) { say(error.message);location=null;fallback='';continue; }

    const name=repositoryName(location);
    let directory=suppliedDirectory || path.join(os.homedir(),'Projects',name);
    let useSupplied=Boolean(suppliedDirectory);suppliedDirectory=null;
    say(`\nWhere should we save ${name}? Press Enter to use the suggested folder.\nYou can also enter a different path, or type back to change the repository.`);
    while(true) {
      const answer=useSupplied ? directory : await ask('Clone into folder',display(directory));
      useSupplied=false;
      if(answer.toLowerCase()==='back') { location=null;fallback='';break; }
      directory=path.resolve(expand(answer));
      try {
        if(fs.existsSync(directory) && (!fs.statSync(directory).isDirectory() || fs.readdirSync(directory).length)) {
          const isDirectory=fs.statSync(directory).isDirectory();
          const info=isDirectory ? await repositoryInfo(directory) : null;
          const checkoutRoot=info?.gitRoot && fs.realpathSync(info.gitRoot)===fs.realpathSync(directory);
          // Match the configured URL before any user-defined Git transport rewrites.
          const origin=checkoutRoot ? await execFile('git',['-C',directory,'config','--get','remote.origin.url']) : null;
          if(origin?.code===0 && remoteKey(location) && remoteKey(origin.stdout)===remoteKey(location)) {
            say(`This repository is already checked out at ${display(directory)}.`);
            if(await yes('Use this existing checkout and keep its files?','y')) return await init(directory);
          } else if(origin?.code===0 && remoteKey(origin.stdout)) {
            say(`\n${display(directory)} contains a checkout of ${remoteKey(origin.stdout)}.\nYou requested ${remoteKey(location)||name}.`);
            const choice=await pick('Which repository would you like to use?',[
              {label:`Clone the requested repository into a new folder`,id:'clone'},
              {label:`Use the existing local checkout (${remoteKey(origin.stdout)})`,id:'local'},
              {label:'Enter another repository',id:'back'}
            ]);
            if(choice.id==='local')return await init(directory);
            if(choice.id==='back'){location=null;fallback='';break;}
          } else say(`${display(directory)} ${isDirectory?'already contains files':'is a file'}. Choose a new folder for ${name}.`);
          const base=isDirectory && path.basename(directory)!==name ? path.join(directory,name) : path.join(path.dirname(directory),name);
          directory=availableFolder(base);
          say(`Suggested folder: ${display(directory)}`);
          continue;
        }
        say(`Cloning ${name} into ${display(directory)}…`);
        return await init(location,directory);
      } catch(error) {
        if(stopped(error)) throw error;
        say(error.message);
        const action=await pick('How would you like to continue?',[
          {label:'Retry — keep this repository and choose a folder',id:'retry'},
          {label:'Change repository URL or use a local checkout',id:'change'},
          {label:'Stop setup',id:'stop'}
        ]);
        if(action.id==='stop') cancel();
        if(action.id==='change') { location=null;fallback='';break; }
      }
    }
  }
}
