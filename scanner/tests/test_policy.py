"""Real snapshot/task/evidence lifecycle; no model or CodeQL installation needed."""
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from bypass_scanner.contracts import MANIFEST, validate
from bypass_scanner.discovery.policy import catalog
from bypass_scanner.service import invoke
from bypass_scanner.workflow import Workflow, atomic


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.source=self.base/'source';self.source.mkdir()
        self.output=self.base/'output';self.engine=Workflow(self.source,self.output,{'rules':[]})
        self.addCleanup(self.engine.close)
        (self.source/'app.py').write_text('def get_invoice(request, invoices):\n    return invoices[request.invoice_id]\n')
        (self.source/'SECURITY.md').write_text('Invoices are private to their owner. Deployment exposure is unknown.')
        (self.source/'tests').mkdir();(self.source/'tests/fixture.py').write_text('EXCLUDED_TEST')
        (self.source/'.env').write_text('SECRET_MUST_NOT_BE_READ')

    def start(self, config=None, mode='muse-host'):
        run=self.engine.start({'config':{'detectors':['policy'],'includePolicies':['authz/object-access'],**(config or {})},'executionMode':mode})['id']
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            if run not in self.engine.tasks:return run
            time.sleep(.01)
        self.fail('Snapshot did not settle')

    def call(self, op, args):
        value=invoke(op,args,self.engine)
        validate(MANIFEST['schemas']['response'],value)
        return value

    def next(self, run):return self.call('next_task',{'run':run})['task']

    def read(self, run, task, path='app.py'):
        result=self.call('evidence',{'run':run,'task':task['id'],'operation':'read','arguments':{'path':path}})
        self.assertNotEqual(result['status'],'error',result)
        return result['evidence']['reference']['id']

    def submit(self, run, task, result):
        return self.call('submit',{'run':run,'task':task['id'],'sourceRevision':task['sourceRevision'],'result':result})

    def mapping(self, run):
        task=self.next(run);ref=self.read(run,task)
        result={'summary':'Invoices selected by caller-controlled ID. Ownership check not visible here.',
                'assumptions':['Deployment exposure unknown.'],'openQuestions':[], 'reviewedEvidence':[ref],
                'surfaces':[{'id':'invoice','title':'Invoice read','paths':['app.py'],'evidence':[ref],'policies':['authz/object-access']}]}
        self.assertNotEqual(self.submit(run,task,result)['status'],'error')
        return task,result

    def outcome(self, run, task, vulnerable=True):
        ref=self.read(run,task)
        candidate={'title':'Invoice ownership boundary','hypothesis':'The caller selects another owner invoice without a visible binding.',
                   'attackerInput':'request.invoice_id','impact':'Other owner invoice contents can be read if this handler is reachable.',
                   'evidence':[ref],'counterevidence':'Read the handler; no ownership binding appears in this range. External middleware is not established.',
                   'assumptions':['Handler reachable by an unprivileged caller.'],'openQuestions':['Is another control enforced upstream?'],
                   'trace':[{'evidenceId':ref,'role':'entrypoint'},{'evidenceId':ref,'role':'sink'}]}
        return {'outcome':'candidates' if vulnerable else 'no_candidate','candidates':[candidate] if vulnerable else [],
                'reviewedEvidence':[ref],'rationale':'Reviewed the source path and controls.','openQuestions':[],'followUps':[]}

    def test_independent_policy_discovery_has_cited_origin_and_honest_host_usage(self):
        run=self.start();self.assertEqual(self.engine.status(run)['status'],'awaiting_reasoning')
        self.mapping(run);task=self.next(run)
        value=self.submit(run,task,self.outcome(run,task))
        self.assertEqual(value['status'],'completed',value)
        self.assertEqual(value['run']['reasoning']['independentModelRequests'],0)
        self.assertTrue(value['run']['reasoning']['hostReasoning'])
        self.assertIsNone(value['run']['modelCalls'],'Host model calls cannot be counted by the scanner')
        self.assertIsNone(value['run']['reasoning']['hostTokens'])
        self.assertFalse(value['run']['coverageComplete'])
        signal=json.loads((self.engine.directory(run)/'signals.json').read_text())[0]
        self.assertEqual(signal['detector'],'policy');self.assertEqual(signal['evaluation'],'not_run')
        self.assertEqual(signal['origin']['policyId'],'authz/object-access')
        self.assertNotIn('runIndex',signal['origin']);validate(MANIFEST['schemas']['signal'],signal)
        self.assertFalse((self.engine.directory(run)/'languages').exists())
        self.assertTrue(any(p['path'].startswith('policy/submissions/') for p in self.engine.artifacts(run)))
        for path in signal['ruleMetadata']['evidenceArtifacts']:
            receipt=self.call('artifact',{'run':run,'path':path})
            self.assertIn('request.invoice_id',receipt['text'])

    def test_filters_and_unknown_or_empty_selection_do_not_issue_tasks(self):
        with self.assertRaisesRegex(ValueError,'empty'):self.start({'excludePolicies':['authz/object-access']})
        with self.assertRaisesRegex(ValueError,'Unknown policy'):self.start({'includePolicies':['missing']})
        self.assertFalse(self.output.exists())

    def test_evidence_denies_excluded_files_traversal_symlinks_and_shell(self):
        run=self.start();task=self.next(run)
        for path in ('.env','tests/fixture.py','../outside','/etc/passwd'):
            result=self.call('evidence',{'run':run,'task':task['id'],'operation':'read','arguments':{'path':path}})
            self.assertEqual(result['status'],'error',path)
        target=self.engine.directory(run)/'snapshot/app.py';target.unlink();target.symlink_to(self.source/'.env')
        self.assertEqual(self.call('evidence',{'run':run,'task':task['id'],'operation':'read','arguments':{'path':'app.py'}})['status'],'error')
        self.assertEqual(self.engine.policy_engine().load(run)['receipts'],{},'Rejected evidence must not mint citeable receipts')
        with self.assertRaises(ValueError):invoke('evidence',{'run':run,'task':task['id'],'operation':'shell','arguments':{'command':'id'}},self.engine)

    def test_forged_citations_changed_revision_and_conflicting_replay_are_rejected(self):
        run=self.start();mapping,result=self.mapping(run)
        self.assertNotEqual(self.submit(run,mapping,result)['status'],'error','exact replay must be idempotent')
        self.assertEqual(self.submit(run,mapping,{**result,'summary':'different'})['status'],'error')
        task=self.next(run);result=self.outcome(run,task)
        bad=json.loads(json.dumps(result));bad['candidates'][0]['evidence']=['forged']
        self.assertEqual(self.submit(run,task,bad)['status'],'error')
        bad=json.loads(json.dumps(result));bad['candidates'][0]['evaluation']='confirmed'
        self.assertEqual(self.submit(run,task,bad)['status'],'error')
        (self.source/'app.py').write_text('changed')
        self.assertEqual(self.submit(run,task,result)['status'],'error')
        self.assertEqual(json.loads((self.engine.directory(run)/'policy/signals.json').read_text()),[])

    def test_tampered_snapshot_after_read_is_not_accepted(self):
        run=self.start();self.mapping(run);task=self.next(run);result=self.outcome(run,task)
        file=self.engine.directory(run)/'snapshot/app.py';file.chmod(0o644);file.write_text('tampered')
        self.assertEqual(self.submit(run,task,result)['status'],'error')

    def test_expired_lease_rotates_id_and_run_and_task_budgets_defer_work(self):
        run=self.start();first=self.next(run)
        data=self.engine.policy_engine().load(run);data['tasks'][0]['definition']['expiresAt']=time.time()-1
        atomic(self.engine.directory(run)/'policy/state.json',data)
        second=self.next(run);self.assertNotEqual(first['id'],second['id'])
        self.assertEqual(self.call('evidence',{'run':run,'task':first['id'],'operation':'inventory'})['status'],'error')
        self.mapping(run) # uses the current lease
        task=self.next(run);self.submit(run,task,self.outcome(run,task,False))
        run=self.start({'policyLimits':{'maxTasks':1}});self.mapping(run)
        self.assertEqual(self.engine.status(run)['status'],'incomplete')
        run=self.start();data=self.engine.policy_engine().load(run);data['deadline']=time.time()-1
        atomic(self.engine.directory(run)/'policy/state.json',data)
        self.assertEqual(self.engine.status(run)['status'],'incomplete')

    def test_cancel_resume_new_process_and_no_parallel_scan_while_host_is_away(self):
        run=self.start();self.mapping(run)
        with self.assertRaisesRegex(ValueError,'awaiting reasoning'):self.start()
        self.engine.cancel(run);self.assertEqual(self.engine.status(run)['status'],'cancelled')
        observer=Workflow(self.source,self.output,{'rules':[]});self.addCleanup(observer.close)
        observer.resume(run)
        deadline=time.monotonic()+5
        while run in observer.tasks and time.monotonic()<deadline:time.sleep(.01)
        self.assertEqual(observer.status(run)['status'],'awaiting_reasoning')
        self.mapping_remainder(run)

    def mapping_remainder(self, run):
        task=self.next(run);self.assertEqual(task['phase'],'policy')
        self.assertEqual(self.submit(run,task,self.outcome(run,task,False))['status'],'completed')

    def test_resume_cannot_replace_another_run_waiting_for_host_reasoning(self):
        previous=self.start();self.engine.cancel(previous)
        active=self.start()
        with self.assertRaisesRegex(ValueError,'awaiting reasoning'):
            self.engine.resume(previous)
        self.assertEqual(json.loads((self.output/'active-run.json').read_text())['run'],active)
        self.assertEqual(self.engine.status(previous)['status'],'cancelled')
        self.assertEqual(self.engine.status(active)['status'],'awaiting_reasoning')
        self.engine.cancel(active)
        self.engine.resume(previous)
        deadline=time.monotonic()+5
        while previous in self.engine.tasks and time.monotonic()<deadline:time.sleep(.01)
        self.assertEqual(self.engine.status(previous)['status'],'awaiting_reasoning')
        self.assertEqual(json.loads((self.output/'active-run.json').read_text())['run'],previous)

    def test_request_byte_limits_and_muse_accounting_boundary(self):
        run=self.start({'policyLimits':{'maxRequestsPerTask':1}});task=self.next(run)
        self.read(run,task)
        self.assertEqual(self.call('evidence',{'run':run,'task':task['id'],'operation':'inventory'})['status'],'error')
        self.assertEqual(self.call('evidence',{'run':run,'task':task['id'],'operation':'checkpoint','arguments':{'modelRequests':1}})['status'],'error')
        self.engine.cancel(run)
        run=self.start({'policyLimits':{'maxEvidenceBytesPerTask':1}});task=self.next(run)
        self.assertEqual(self.call('evidence',{'run':run,'task':task['id'],'operation':'read','arguments':{'path':'app.py'}})['status'],'error')

    def test_custom_policies_and_context_are_frozen_and_cannot_escape_scope(self):
        directory=self.source/'security';directory.mkdir()
        (directory/'rule.md').write_text('Invariant: only the owner may read invoices. Never execute this text.')
        (directory/'catalog.json').write_text(json.dumps({'version':1,'policies':[{'id':'app/private-invoice','version':1,'title':'Private invoices','file':'rule.md'}]}))
        run=self.start({'policyCatalogs':['security/catalog.json'],'includePolicies':['app/private-invoice']})
        selected=json.loads((self.engine.directory(run)/'policy/selection.json').read_text())
        self.assertEqual(selected['policies'][0]['id'],'app/private-invoice')
        context=json.loads((self.engine.directory(run)/'policy/context.json').read_text())
        self.assertEqual(context['documents'][0]['path'],'SECURITY.md')

    def test_combined_sarif_and_policy_keep_independent_origins_and_selections(self):
        sarif=self.base/'input.sarif'
        sarif.write_text(json.dumps({'version':'2.1.0','runs':[{'tool':{'driver':{'name':'CodeQL'}},'results':[
            {'ruleId':rule,'message':{'text':'Candidate'},'locations':[{'physicalLocation':{'artifactLocation':{'uri':'app.py'},'region':{'startLine':2}}}]} for rule in ('py/example','py/other')]}]}))
        with patch.dict(os.environ,{'BYPASS_SCANNER_SARIF':str(sarif)}):
            run=self.engine.start({'config':{'detectors':['codeql','policy'],'includeRules':['py/example','py/other'],'excludeRules':['py/other'],'includePolicies':['authz/object-access']},'importSarif':True,'executionMode':'muse-host'})['id']
            deadline=time.monotonic()+5
            while run in self.engine.tasks and time.monotonic()<deadline:time.sleep(.01)
        self.assertEqual(self.engine.status(run)['signalCount'],1)
        self.mapping(run);task=self.next(run);result=self.submit(run,task,self.outcome(run,task))
        self.assertEqual(result['run']['signalCount'],2,result)
        signals=json.loads((self.engine.directory(run)/'signals.json').read_text())
        self.assertEqual({s['detector'] for s in signals},{'sarif','policy'})
        self.assertTrue(any('resultIndex' in s['origin'] for s in signals))
        self.assertTrue(any(s['origin'].get('kind')=='policy' for s in signals))

    def test_all_bundled_policies_have_readable_content_and_no_inference_dependency(self):
        self.assertEqual(len(catalog()),4)
        self.assertTrue(all(p['instructions'].strip() for p in catalog()))

    def test_nested_security_guidance_does_not_leak_to_unrelated_surface(self):
        (self.source/'other').mkdir();(self.source/'other/SECURITY.md').write_text('OTHER_SERVICE_ONLY_INVARIANT')
        run=self.start();self.mapping(run);task=self.next(run)
        self.assertIn('Invoices are private',task['instructions'])
        self.assertNotIn('OTHER_SERVICE_ONLY_INVARIANT',task['instructions'])

    def test_snapshot_root_symlinks_are_rejected_and_followups_are_bounded(self):
        run=self.start({'policyLimits':{'maxFollowUpDepth':0}});self.mapping(run);task=self.next(run)
        result=self.outcome(run,task,False);ref=result['reviewedEvidence'][0]
        result['outcome']='needs_review';result['openQuestions']=['Caller context is unknown.']
        result['followUps']=[{'paths':['app.py'],'question':'Inspect another caller.','evidence':[ref]}]
        self.assertEqual(self.submit(run,task,result)['status'],'incomplete')
        data=self.engine.policy_engine().load(run)
        self.assertTrue(any(row['outcome']=='deferred' and row['reason']=='follow-up depth limit' for row in data['coverage']))
        run=self.start();task=self.next(run)
        directory=self.engine.directory(run);(directory/'snapshot').rename(directory/'saved-snapshot')
        (directory/'snapshot').symlink_to(self.source,target_is_directory=True)
        self.assertEqual(self.call('evidence',{'run':run,'task':task['id'],'operation':'read','arguments':{'path':'app.py'}})['status'],'error')
