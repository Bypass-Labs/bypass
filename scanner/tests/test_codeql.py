"""Real subprocess/workflow tests using a disposable deterministic CodeQL fixture."""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from bypass_scanner.discovery.catalog import digest, metadata, select_rules
from bypass_scanner.contracts import MANIFEST, validate
from bypass_scanner.discovery.languages import LANGUAGES, detect
from bypass_scanner.discovery.sarif import normalize
from bypass_scanner.repository.snapshot import snapshot, contained
from bypass_scanner.service import invoke
from bypass_scanner.workflow import Workflow, settings
from bypass_scanner.worker import run as network_worker


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='bypass-codeql-test-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.source = self.base/'source with spaces'; self.source.mkdir()
        self.output = self.base/'output'
        self.control = self.base/'control'; self.control.mkdir()
        self.binary = self.base/'codeql'
        self.binary.write_text('#!'+sys.executable+'\n'+r'''
import json, os, pathlib, subprocess, sys, time
args=sys.argv[1:]
control=pathlib.Path(CONTROL)
def option(prefix): return next(x.split('=',1)[1] for x in args if x.startswith(prefix+'='))
with (control/'calls').open('a') as f: f.write(json.dumps(args)+'\n')
if 'UNSAFE_TOKEN' in os.environ: raise SystemExit(99)
if args[:2]==['database','create']:
 db=pathlib.Path(args[2]); db.mkdir()
 root=option('--source-root'); language=option('--language')
 if (control/('slow-'+language)).exists():
  (control/'pid').write_text(str(os.getpid())); time.sleep(20)
 if (control/('fail-'+language)).exists(): raise SystemExit(7)
 if (control/('semantic-warning-'+language)).exists(): print('ERROR failed to load workspace; semantic analyzer unavailable')
 (db/'codeql-database.yml').write_text(json.dumps({'root':root,'language':language}))
 if any(x.startswith('--command=') for x in args):
  import shlex
  subprocess.run(shlex.split(option('--command')),check=True)
elif args[:2]==['database','analyze']:
 db=pathlib.Path(args[2]); info=json.loads((db/'codeql-database.yml').read_text())
 if (control/('query-fail-'+info['language'])).exists(): raise SystemExit(8)
 results=[]
 for line in pathlib.Path(args[3]).read_text().splitlines():
  query=pathlib.Path(json.loads(line.split(': ',1)[1]))
  if query.name=='metric.ql': continue
  for source in pathlib.Path(info['root']).rglob('*'):
   if source.is_file() and source.suffix=={'cpp':'.cpp','csharp':'.cs','go':'.go','java':'.java','javascript':'.ts','python':'.py','ruby':'.rb','rust':'.rs','actions':'.yml'}[info['language']] and b'VULNERABLE' in source.read_bytes():
    results.append({'ruleId':query.read_text().strip(),'message':{'text':'suspected issue'},'locations':[{'physicalLocation':{'artifactLocation':{'uri':source.as_uri()},'region':{'startLine':1}}}]})
 document={'version':'2.1.0','runs':[{'tool':{'driver':{'name':'CodeQL','rules':[]}},'results':results}]}
 pathlib.Path(option('--output')).write_text(json.dumps(document))
elif args[:2]==['database','export-diagnostics']:
 pathlib.Path(option('--output')).write_text(json.dumps({'version':'2.1.0','runs':[]}))
else: raise SystemExit(10)
'''.replace('CONTROL',repr(str(self.control))))
        self.binary.chmod(0o755)
        self.env = patch.dict(os.environ, {'BYPASS_CODEQL':str(self.binary), 'BYPASS_SCANNER_SOURCE':str(self.source), 'BYPASS_SCANNER_OUTPUT':str(self.output), 'UNSAFE_TOKEN':'not-forwarded'})
        self.env.start(); self.addCleanup(self.env.stop)
        rules=[]
        for language in LANGUAGES:
            for name in ('example','excluded'):
                filename=self.base/(language+'-'+name+'.ql'); filename.write_text(language+'/'+name)
                rules.append({'id':language+'/'+name,'language':language,'name':name,'path':str(filename),'defaultSuite':name=='example','kind':'problem','severity':'warning','packVersion':'1'})
        metric=self.base/'metric.ql';metric.write_text('metric')
        self.catalog={'rules':rules,'packs':{},'auxiliary':{language:[str(metric)] for language in LANGUAGES}}
        self.catalog['identity']=digest(self.catalog)
        self.engine=Workflow(self.source,self.output,self.catalog)
        self.addCleanup(self.engine.close)

    def wait(self, run):
        deadline=time.monotonic()+8
        while time.monotonic()<deadline:
            status=self.engine.status(run)
            if status['status'] in ('completed','incomplete','failed','cancelled','interrupted'): return status
            time.sleep(.03)
        self.fail('Workflow did not finish: '+str(self.engine.status(run)))

    def start(self, config=None, **arguments):
        return self.engine.start({'config':config or {}, **arguments})['id']

    def calls(self):
        file=self.control/'calls'
        return [json.loads(line) for line in file.read_text().splitlines()] if file.exists() else []

    def test_every_family_emits_signals_with_no_model_and_preserves_source(self):
        for language, filename in [('cpp','a.cpp'),('csharp','a.cs'),('go','a.go'),('java','a.java'),('javascript','a.ts'),('python','a.py'),('ruby','a.rb'),('rust','a.rs'),('actions','.github/workflows/a.yml')]:
            with self.subTest(language=language):
                for child in self.source.iterdir():
                    shutil.rmtree(child) if child.is_dir() else child.unlink()
                path=self.source/filename;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('VULNERABLE')
                before=snapshot(self.source)['revision']
                run=self.start({'languages':[language]})
                status=self.wait(run)
                self.assertEqual(status['status'],'completed',status)
                self.assertEqual(status['modelCalls'],0)
                self.assertEqual(status['signalCount'],1)
                self.assertFalse(status['coverageComplete'])
                self.assertEqual(status['evaluation'],'not_run')
                self.assertEqual(before,snapshot(self.source)['revision'])
                values=json.loads((self.engine.directory(run)/'signals.json').read_text())
                self.assertEqual(values[0]['ruleId'],language+'/example')
                self.assertEqual(values[0]['locations'][0]['path'],filename)
                validate(MANIFEST['schemas']['signal'], values[0])
                self.assertEqual(values[0]['evidence'][0]['contentHash'], snapshot(self.source)['files'][filename]['sha256'])
                self.assertTrue((self.engine.directory(run)/'report.md').is_file())

    def test_rule_selection_exclusion_and_unknown_ids(self):
        self.source.joinpath('a.py').write_text('VULNERABLE')
        run=self.start({'includeRules':['python/example','python/excluded'],'excludeRules':['python/example']})
        self.assertEqual(self.wait(run)['signalCount'],1)
        selection=json.loads((self.engine.directory(run)/'rule-selection.json').read_text())
        self.assertEqual([rule['id'] for rule in selection['selected']],['python/excluded'])
        with self.assertRaisesRegex(ValueError,'Unknown CodeQL'):
            self.start({'includeRules':['python/typo']})
        before=len(self.calls())
        empty=self.start({'includeRules':['python/example'],'excludeRules':['python/example']})
        self.assertEqual(self.wait(empty)['status'],'incomplete')
        self.assertEqual(len(self.calls()),before)

    def test_safe_zero_alerts_and_no_applicable_files(self):
        self.source.joinpath('safe.py').write_text('safe')
        run=self.start();self.assertEqual(self.wait(run)['signalCount'],0)
        run=self.start({'languages':['javascript']})
        self.assertEqual(self.wait(run)['status'],'incomplete')
        self.assertEqual(self.engine.read(run)['languages'][0]['status'],'no_files')

    def test_default_scope_filters_alerts_and_can_include_each_category(self):
        names=['src/main.py','tests/vulnerable.py','src/helper_test.py','examples/main.py','plugin/runtime/main.py','generated/main.py']
        for name in names:
            file=self.source/name;file.parent.mkdir(parents=True,exist_ok=True);file.write_text('VULNERABLE')
        run=self.start();status=self.wait(run)
        self.assertEqual(status['status'],'completed',status)
        self.assertEqual(status['signalCount'],1)
        self.assertEqual(status['scope']['analysisFiles'],1)
        self.assertEqual(status['scope']['contextFiles'],6)
        self.assertEqual(status['scope']['excludedFiles'],5)
        # The fake detector ignores CodeQL path filters, exercising the required
        # primary-location filter for compiled builds and imported SARIF too.
        self.assertEqual(status['scope']['filteredSignals'],5)
        directory=self.engine.directory(run)
        self.assertEqual(len(json.loads((directory/'languages/python/raw.sarif').read_text())['runs'][0]['results']),6)
        self.assertTrue((directory/'snapshot/tests/vulnerable.py').is_file())
        self.assertTrue((directory/'languages/python/work/tests/vulnerable.py').is_file())
        self.assertIn('analysis-scope.json',{a['path'] for a in self.engine.artifacts(run)})
        self.assertIn('languages/python/filtered-signals.json',{a['path'] for a in self.engine.artifacts(run)})
        for config,count in [({'includeTests':True},3),({'includeExamples':True},2),({'includeGenerated':True},3),
                             ({'includeTests':True,'includeExamples':True,'includeGenerated':True},6)]:
            current=self.wait(self.start(config));self.assertEqual(current['signalCount'],count,(config,current))
            self.assertEqual(current['sourceRevision'],status['sourceRevision'])

    def test_manual_build_keeps_test_inputs_and_filters_test_alerts(self):
        self.source.joinpath('main.cpp').write_text('VULNERABLE')
        self.source.joinpath('tests').mkdir()
        self.source.joinpath('tests/helper.cpp').write_text('VULNERABLE')
        command=[sys.executable,'-c',"from pathlib import Path; assert Path('tests/helper.cpp').read_text() == 'VULNERABLE'"]
        run=self.start({'builds':{'cpp':{'mode':'manual','command':command}}})
        status=self.wait(run)
        self.assertEqual(status['status'],'completed',status)
        self.assertEqual(status['signalCount'],1)
        create=next(c for c in self.calls() if c[:2]==['database','create'])
        self.assertFalse(any(c.startswith('--codescanning-config=') for c in create))
        self.assertEqual(status['scope']['filteredSignals'],1)

    def test_only_test_sources_require_explicit_inclusion(self):
        self.source.joinpath('tests').mkdir();self.source.joinpath('tests/main.py').write_text('VULNERABLE')
        run=self.start({'languages':['python']});status=self.wait(run)
        self.assertEqual(status['status'],'incomplete')
        self.assertEqual(status['languages'][0]['status'],'no_files')
        self.assertEqual(self.calls(),[])
        self.assertEqual(self.wait(self.start({'includeTests':True}))['signalCount'],1)

    def test_extractor_semantic_fallback_is_partial_even_with_zero_exit(self):
        self.source.joinpath('main.rs').write_text('safe')
        (self.control/'semantic-warning-rust').touch()
        run=self.start();status=self.wait(run)
        self.assertEqual(status['status'],'incomplete')
        self.assertTrue(status['languages'][0]['queryComplete'])
        self.assertEqual(status['languages'][0]['coverage'],'partial')
        evidence=json.loads((self.engine.directory(run)/'languages/rust/coverage.json').read_text())
        self.assertGreater(evidence['warnings'],0)

    def test_language_failure_preserves_others_and_resume_reuses_completed_queries(self):
        self.source.joinpath('a.py').write_text('VULNERABLE')
        self.source.joinpath('a.ts').write_text('VULNERABLE')
        fault=self.control/'query-fail-python';fault.touch()
        run=self.start();first=self.wait(run)
        self.assertEqual(first['status'],'incomplete')
        self.assertEqual(first['signalCount'],1)
        before=sum(call[:2]==['database','create'] for call in self.calls())
        fault.unlink();self.engine.resume(run)
        second=self.wait(run)
        self.assertEqual(second['status'],'completed',second)
        self.assertEqual(second['signalCount'],2)
        self.assertEqual(before,sum(call[:2]==['database','create'] for call in self.calls()))
        self.source.joinpath('a.py').write_text('changed')
        # Revalidation occurs for incomplete runs; completed runs are idempotent.
        state=self.engine.read(run);state['status']='interrupted';self.engine.save(state)
        self.engine.resume(run)
        self.assertIn('Source changed',self.wait(run)['message'])

    def test_cancel_kills_process_group_and_preserves_artifacts(self):
        self.source.joinpath('a.py').write_text('VULNERABLE')
        (self.control/'slow-python').touch()
        run=self.start()
        deadline=time.monotonic()+5
        while not (self.control/'pid').exists() and time.monotonic()<deadline: time.sleep(.03)
        self.assertTrue((self.control/'pid').exists())
        pid=int((self.control/'pid').read_text())
        Workflow(self.source,self.output,self.catalog).cancel(run)
        self.assertEqual(self.wait(run)['status'],'cancelled')
        with self.assertRaises(ProcessLookupError): os.kill(pid,0)
        self.assertTrue((self.engine.directory(run)/'source-manifest.json').is_file())

    def test_explicit_network_job_separates_extraction_and_analysis(self):
        self.source.joinpath('a.py').write_text('VULNERABLE')
        run=self.start({'builds':{'python':{'network':'on'}}})
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            state=self.engine.status(run)
            if state.get('networkJob'): break
            time.sleep(.03)
        self.assertIn('networkJob',state)
        self.assertEqual(network_worker(run,state['networkJob']['id']),0)
        self.assertEqual(self.wait(run)['status'],'completed')
        self.assertEqual(self.engine.read(run)['languages'][0]['network'],'on')

    def test_default_timeout_and_preparation_share_an_extraction_budget(self):
        self.assertEqual(settings({})['resources'], MANIFEST['resourceDefaults'])
        self.assertGreater(settings({})['resources']['timeoutSeconds'], 0)
        self.source.joinpath('a.py').write_text('VULNERABLE')
        prepare = [[sys.executable, '-c', 'import time; time.sleep(.7)']] * 2
        run = self.start({'resources':{'timeoutSeconds':1}, 'builds':{'python':{'prepare':prepare}}})
        status = self.wait(run)
        self.assertEqual(status['status'], 'incomplete')
        self.assertIn('prepare-', status['languages'][0]['message'])
        self.assertIn('exceeded its configured timeout', status['languages'][0]['message'])
        self.assertEqual(self.calls(), [])

    def test_network_extraction_without_a_helper_times_out_and_retires_job(self):
        self.source.joinpath('a.py').write_text('VULNERABLE')
        with patch.dict(MANIFEST, {'networkStartupSeconds':0}):
            run = self.start({'resources':{'timeoutSeconds':1}, 'builds':{'python':{'network':'on'}}})
            status = self.wait(run)
        self.assertEqual(status['status'], 'incomplete')
        self.assertIn('exceeded its configured timeout', status['languages'][0]['message'])
        self.assertNotIn('networkJob', status)
        self.assertEqual(len(list((self.engine.directory(run)/'network').glob('*.cancel.json'))), 1)
        self.assertEqual(self.calls(), [])

    def test_project_lease_and_invalid_builds(self):
        (self.control/'slow-python').touch();self.source.joinpath('a.py').write_text('VULNERABLE')
        self.start()
        with self.assertRaisesRegex(ValueError,'already active'): Workflow(self.source,self.output,self.catalog).start({})
        for config in [{'builds':{'rust':{'mode':'manual','command':['cargo','build']}}},{'builds':{'java':{'mode':'manual'}}},{'builds':{'java':{'cwd':'../escape'}}}]:
            with self.assertRaises(ValueError): settings(config)

    def test_reports_artifacts_and_pagination(self):
        self.source.joinpath('a.py').write_text('VULNERABLE')
        run=self.start();self.wait(run)
        report=invoke('report',{'run':run,'format':'md'},self.engine)
        self.assertEqual(report['artifacts'][0]['path'],'report.md')
        data=invoke('artifact',{'run':run,'path':'report.md'},self.engine)
        self.assertIn('unevaluated',data['text'])
        for value in ('../source/a.py','snapshot/a.py','languages/python/work/a.py'):
            self.assertEqual(invoke('artifact',{'run':run,'path':value},self.engine)['status'],'error')
        page=invoke('rules',{'limit':1},self.engine)
        self.assertEqual(len(page['rules']),1);self.assertEqual(page['nextCursor'],1)
        self.assertEqual(len(invoke('signals',{'run':run},self.engine)['signals']),1)

    def test_sarif_import_and_invalid_locations_keep_raw_evidence(self):
        self.source.joinpath('a.py').write_text('safe')
        document={'version':'2.1.0','runs':[{'tool':{'driver':{'name':'Other','rules':[{'id':'r'}]}},'results':[
            {'ruleIndex':0,'message':{'text':'candidate'},'locations':[{'physicalLocation':{'artifactLocation':{'uri':'../../secret'},'region':{'startLine':1}}}]},
            {'message':{'text':'missing rule'}}]}]}
        imported=self.base/'input.sarif';imported.write_text(json.dumps(document))
        with patch.dict(os.environ,{'BYPASS_SCANNER_SARIF':str(imported)}):
            run=self.start(importSarif=True);status=self.wait(run)
        self.assertEqual(status['status'],'incomplete')
        self.assertEqual(status['signalCount'],1)
        signal=json.loads((self.engine.directory(run)/'signals.json').read_text())[0]
        self.assertEqual(signal['locations'],[])
        self.assertEqual(signal['detector'],'sarif')
        self.assertEqual(json.loads((self.engine.directory(run)/'import.sarif').read_text()),document)

    def test_snapshot_filters_secrets_and_symlinks_but_keeps_workflows_and_cxx(self):
        for name in ('a.cpp','.env','token.key','plain.txt'):
            self.source.joinpath(name).write_text('safe')
        self.source.joinpath('.github/workflows').mkdir(parents=True)
        self.source.joinpath('.github/workflows/test.yml').write_text('workflow')
        self.source.joinpath('escape').symlink_to(self.control,target_is_directory=True)
        self.source.joinpath('link.cpp').symlink_to(self.control/'calls')
        recorded=snapshot(self.source)
        self.assertEqual(set(recorded['files']),{'a.cpp','plain.txt','.github/workflows/test.yml'})
        self.assertGreaterEqual(len(recorded['exclusions']),4)
        with self.assertRaises(ValueError): contained(self.source,'escape/calls')
        self.assertEqual(detect(recorded['files'])[0].keys(),{'cpp','actions'})

    def test_sarif_source_range_and_driver_validation(self):
        self.source.joinpath('a.py').write_text('safe\n')
        recorded=snapshot(self.source)
        self.assertEqual(recorded['files']['a.py']['lineCount'],1)
        document={'version':'2.1.0','runs':[None, {'tool':{'driver':None}}, {'tool':{'driver':{'rules':[]}}, 'results':[
            {'ruleId':'r','message':{'text':'candidate'},'locations':[{'physicalLocation':{'artifactLocation':{'uri':'a.py'},'region':{'startLine':1,'endLine':50}}}]}]}]}
        values,warnings=normalize(document,'python',recorded,self.source,'raw.sarif')
        self.assertEqual(len(warnings),2)
        self.assertEqual(values[0]['locations'],[])
        self.assertIn('exceeds',values[0]['limitations'][0])
        validate(MANIFEST['schemas']['signal'],values[0])

    def test_catalog_metadata_parser_and_exclusion_precedence(self):
        fields=metadata('/**\n * @name Test rule\n * @id js/example\n * @kind path-problem\n * @tags security\n *       external/cwe/cwe-078\n */')
        self.assertEqual(fields['id'],'js/example')
        self.assertEqual(fields['kind'],'path-problem')
        with self.assertRaises(ValueError): select_rules(self.catalog,['python'],['javascript/example'],[])
