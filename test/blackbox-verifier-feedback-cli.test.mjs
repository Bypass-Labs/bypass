import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';

test('later protected Muse planning receives an earlier verifier result and pivots',
  {timeout: 180000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-verifier-feedback-'));
    t.after(() => {if (!process.env.BX_KEEP_TEST_ROOT)
      fs.rmSync(root, {recursive: true, force: true});});
    const target = path.join(root, 'target');
    const fixture = path.join(import.meta.dirname, 'fixtures/blackbox-cookie-blind.mjs');
    const server = spawn(process.execPath, [fixture, target],
      {stdio: ['ignore', 'pipe', 'inherit']});
    t.after(() => server.kill());
    const origin = await new Promise((resolve, reject) => {
      server.stdout.once('data', chunk => resolve(String(chunk).trim()));
      server.once('error', reject);
      server.once('exit', code => reject(Error(`fixture exited ${code}`)));
    });
    const {loginPath, identityPath, renderPath} = JSON.parse(fs.readFileSync(
      path.join(target, 'routes.json'), 'utf8'));
    const bin = path.join(root, 'bin');
    fs.mkdirSync(bin);
    const feedbackLog = path.join(root, 'feedback.jsonl');
    const choiceLog = path.join(root, 'choices.jsonl');
    fs.writeFileSync(path.join(bin, 'muse'), [
      '#!' + process.execPath,
      "const fs=require('node:fs');",
      'const args=process.argv.slice(2);',
      'const value=flag=>args[args.indexOf(flag)+1];',
      "if(args.includes('--version')){console.log('muse fixture');process.exit(0);}",
      "if(args[0]!=='exec'||!args.includes('--disable-shell')||!args.includes('--output-schema')||value('--provider')!=='meta')process.exit(2);",
      "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
      'const system=messages[0].content;',
      'const context=JSON.parse(messages[1].content);',
      'let answer;',
      "if(system.startsWith('From only the observed authorized JSON login operations')){",
      " const post=context.posts.find(item=>item.path===process.env.BX_LOGIN);",
      " const read=context.reads.find(item=>item.path===process.env.BX_IDENTITY);",
      " answer={checks:post&&read?[{loginPath:post.path,userField:'username',passwordField:'password',proofMode:'protected-status',userPayloads:[\"admin' OR '1'='1\"],tokenPointer:'',privatePath:read.path,why:'Synthetic invalid-password experiment on an observed login contract'}]:[]};",
      '}',
      "else if(system.startsWith('Allocate the next black-box investigation effort')){",
      " answer={priorities:context.tracks.map(row=>({name:row.name,weight:row.name==='sequence'?100:1,why:'Observed protected read input'})).sort((a,b)=>b.weight-a.weight)};",
      '}',
      "else if(system.startsWith('You are planning bounded, authorized HTTP research.')){",
      " const route=context.routes.find(item=>item.path===process.env.BX_RENDER&&item.kind==='read'&&item.fields.includes('q'));",
      " if((context.priorVerifierResults??[]).length)fs.appendFileSync(process.env.BX_FEEDBACK_LOG,JSON.stringify(context.priorVerifierResults)+'\\n');",
      " answer={flows:route?[{family:'render-processing',why:'Observed protected render input can alter a response',priority:10,as:'derived',oracle:'observation',prelude:[],subject:{method:'GET',path:route.path,placement:'query',key:'q',fixedFields:[],bodyTemplate:'',headers:[]},observe:[],controlValue:'hello',firstValue:'world',secondValue:'again',marker:'',secondMarker:'',assertion:{step:'subject',index:0,location:'body',name:''}}]:[]};",
      '}',
      "else if(system.startsWith('Revise at most one bounded, authorized HTTP experiment')){",
      " const prior=context.priorVerifierResults??[];",
      " if(prior.length)fs.appendFileSync(process.env.BX_FEEDBACK_LOG,JSON.stringify(prior)+'\\n');",
      " const choices=context.verifierChoices??[];",
      " if(prior.length)fs.appendFileSync(process.env.BX_CHOICE_LOG,JSON.stringify(choices)+'\\n');",
      " const previousXss=choices.some(item=>item.kind==='xss-reflected'&&item.path===process.env.BX_RENDER&&item.parameter==='q'&&item.prior?.verdict==='not_reproduced');",
      " const kind=previousXss?'ssti-arithmetic':'xss-reflected';",
      " const selected=choices.find(item=>item.kind===kind&&item.path===process.env.BX_RENDER);",
      " answer={flows:[],...(selected?{verifierId:selected.id}:{})};",
      '}',
      "else if(system.includes('Rank only the supplied observed read-only web-test candidates'))answer={priorities:[],strategies:[],experiments:[]};",
      "else if(system.includes('Interpret only the extracted'))answer={files:context.files.map(file=>({id:file.id,role:'app',why:'Observed asset',authFlow:'',routes:[],proposals:[]}))};",
      "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
      "else if(system.includes('Continue mapping this authorized primary application'))answer={paths:[]};",
      "else if(system.startsWith('Map this authorized authenticated web surface'))answer={paths:[]};",
      "else if(system.includes('mapping an authorized web API'))answer={paths:[],notes:[]};",
      "else if(system.includes('Propose bounded GET access-control'))answer={tasks:[]};",
      'else {',
      " const schema=JSON.parse(fs.readFileSync(value('--output-schema'),'utf8'));",
      " const blank=s=>s?.type==='object'?Object.fromEntries((s.required??[]).map(key=>[key,blank(s.properties?.[key])])):s?.type==='array'?[]:s?.type==='integer'||s?.type==='number'?0:s?.type==='boolean'?false:s?.enum?.[0]??'';",
      ' answer=blank(schema);',
      '}',
      "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
    ].join('\n') + '\n', {mode: 0o700});
    const env = {...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`,
      BX_LOGIN: loginPath, BX_IDENTITY: identityPath, BX_RENDER: renderPath,
      BX_FEEDBACK_LOG: feedbackLog, BX_CHOICE_LOG: choiceLog};
    const project = path.join(root, 'project');
    const cli = async (...args) => {
      const done = await execFile(process.execPath,
        [CLI, 'blackbox', ...args, '--project', project, '--json', '--non-interactive'],
        {cwd: root, env, timeout: 120000});
      return {code: done.code, data: JSON.parse(done.stdout)};
    };
    const audit = await cli(origin, '--accept-local', '--rps', '30',
      '--model-calls', '60', '--max-tasks', '32', '--max-urls', '80',
      '--minutes', '3', '--offline');
    assert.ok(audit.data.runDir, JSON.stringify(audit));
    const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir,
      'web-probes.json'), 'utf8'));
    const feedback = fs.existsSync(feedbackLog) ? fs.readFileSync(feedbackLog, 'utf8')
      .trim().split('\n').filter(Boolean).map(line => JSON.parse(line)) : [];
    const choicePages = fs.existsSync(choiceLog) ? fs.readFileSync(choiceLog, 'utf8')
      .trim().split('\n').filter(Boolean).map(line => JSON.parse(line)) : [];
    assert.ok(feedback.some(page => page.some(item => item.kind === 'xss-reflected' &&
      item.path === renderPath && item.parameter === 'q' &&
      item.as === 'derived' && item.verdict === 'not_reproduced' &&
      Array.isArray(item.evidenceIds))), JSON.stringify({feedback, results: web.results}));
    const lateChoices = choicePages.find(page => page.some(item => item.kind ===
      'xss-reflected' && item.path === renderPath && item.prior?.verdict === 'not_reproduced'));
    assert.ok(lateChoices, JSON.stringify({choicePages, decisions: web.strategyDecisions}));
    const xssIndex = lateChoices.findIndex(item => item.kind === 'xss-reflected' &&
      item.path === renderPath);
    const sstiIndex = lateChoices.findIndex(item => item.kind === 'ssti-arithmetic' &&
      item.path === renderPath);
    assert.ok(sstiIndex >= 0 && sstiIndex < xssIndex,
      'untried SSTI choice should precede the retained negative XSS choice');
    assert.equal(typeof lateChoices[xssIndex].prior.reason, 'string');
    assert.ok(Array.isArray(lateChoices[xssIndex].prior.evidenceIds));
    assert.ok(web.strategyDecisions.some(item => item.verifier?.kind === 'xss-reflected' &&
      item.accepted), 'early Muse choice should run the XSS verifier');
    assert.ok(web.strategyDecisions.some(item => item.verifier?.kind === 'ssti-arithmetic' &&
      item.accepted && item.priorVerifierFactsSent > 0),
    'later Muse choice should receive the XSS-negative feedback');
    const ssti = audit.data.findings.find(item => item.kind === 'ssti-arithmetic' &&
      item.pattern === renderPath);
    assert.ok(ssti?.proof, JSON.stringify({findings: audit.data.findings,
      decisions: web.strategyDecisions, feedback}));
    assert.equal((await cli('verify', audit.data.run)).code, 1);
    const exported = await cli('export', audit.data.run,
      '--out', path.join(root, 'regression'));
    assert.equal(exported.code, 0);
    const regressionEnv = {...env, NODE_TEST_CONTEXT: undefined};
    const regression = async () => await execFile(process.execPath,
      ['--test', ...exported.data.files], {env: regressionEnv, timeout: 30000});
    const vulnerableRegression = await regression();
    assert.equal(vulnerableRegression.code, 1, vulnerableRegression.stdout);
    fs.writeFileSync(path.join(target, 'mode'), 'fixed');
    assert.equal((await cli('verify', audit.data.run)).code, 0);
    assert.equal((await regression()).code, 0);
  });
