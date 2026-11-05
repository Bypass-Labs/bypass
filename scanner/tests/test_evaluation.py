"""Source-only evaluation contracts and durable lifecycle, with scripted reasoning."""
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from bypass_scanner.contracts import MANIFEST, validate
from bypass_scanner.service import invoke
from bypass_scanner.workflow import Workflow, atomic


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.source=self.root/'source'
        self.source.mkdir()
        (self.source/'app.py').write_text(
            'def read_invoice(actor, key, invoices):\n'
            '    return invoices[key]\n'
            '\n'
            'def read_owned(actor, key, invoices):\n'
            '    invoice = invoices[key]\n'
            '    if invoice.owner != actor.id:\n'
            '        raise PermissionError()\n'
            '    return invoice\n')
        (self.source/'tests').mkdir()
        (self.source/'tests/fixture.py').write_text('EXCLUDED\n')
        (self.source/'.env').write_text('SECRET\n')
        self.sarif=self.root/'alerts.sarif'
        self.sarif.write_text(json.dumps({'version':'2.1.0','runs':[{'results':[
            {'ruleId':'invoice-access','message':{'text':title},
             'locations':[{'physicalLocation':{'artifactLocation':{'uri':'app.py'},
                                              'region':{'startLine':line}}}]}
            for title,line in [('Unrestricted invoice read',2),('Potential unsafe read with a guard',8)]
        ]}]}))
        env=patch.dict(os.environ, {'BYPASS_SCANNER_SARIF':str(self.sarif)})
        env.start()
        self.addCleanup(env.stop)
        self.w=Workflow(self.source,self.root/'output',{'rules':[]})
        self.addCleanup(self.w.close)

    def settle(self, run):
        deadline=time.monotonic()+5
        while run in self.w.tasks and time.monotonic()<deadline:
            time.sleep(.01)
        self.assertNotIn(run,self.w.tasks)
        return self.w.status(run)

    def start(self, config=None, mode='muse-host'):
        run=self.w.start({'config':config or {},'importSarif':True,'executionMode':mode})['id']
        self.settle(run)
        return run

    def call(self, name, **arguments):
        result=invoke(name,arguments,self.w)
        validate(MANIFEST['schemas']['response'],result)
        return result

    def task(self, run):
        result=self.call('next_task',run=run)
        self.assertNotEqual(result['status'],'error',result)
        return result['task']

    def read(self, run, task, path='app.py'):
        return self.call('evidence',run=run,task=task['id'],operation='read',arguments={'path':path})

    def result(self, run, task, outcome='confirmed', follow=False):
        ref=self.read(run,task)['evidence']['reference']['id']
        return {'caseId':task['caseId'],'outcome':outcome,'severity':'medium' if outcome=='confirmed' else 'unknown',
                'severityRationale':'Source shows a private-data boundary.' if outcome=='confirmed' else 'No supported vulnerability severity.',
                'rationale':'Reviewed lookup and relevant ownership controls.',
                'evidence':[ref],'counterevidence':'The second handler has an explicit owner check.',
                'prerequisites':['Caller can reach the source-level function with an actor and invoice key.'],
                'impact':'Invoice contents may cross the owner boundary.',
                'openQuestions':['Is an upstream guard enforced?'] if outcome=='needs_review' else [],
                'nextAction':'Inspect the caller and shared guard.' if outcome=='needs_review' else 'Review the cited source conclusion.',
                'followUpQuestions':['Trace callers and upstream controls.'] if follow else []}

    def submit(self, run, task, result):
        return self.call('submit',run=run,task=task['id'],sourceRevision=task['sourceRevision'],result=result)

    def cases(self, run):
        return json.loads((self.w.directory(run)/'evaluation/cases.json').read_text())

    def test_auto_evaluation_keeps_original_signals_and_reports_source_verdicts(self):
        run=self.start()
        self.assertEqual(self.w.status(run)['stage'],'evaluation')
        original=(self.w.directory(run)/'signals.json').read_text()
        for outcome in ('confirmed','refuted'):
            task=self.task(run)
            self.assertEqual(task['kind'],'evaluation')
            result=self.result(run,task,outcome)
            response=self.submit(run,task,result)
            self.assertNotEqual(response['status'],'error',response)
        self.assertEqual(response['status'],'completed',response)
        self.assertEqual(response['run']['evaluation'],'completed')
        self.assertEqual(response['run']['reasoning']['independentModelRequests'],0)
        self.assertIsNone(response['run']['modelCalls'])
        self.assertFalse(response['run']['coverageComplete'])
        self.assertEqual((self.w.directory(run)/'signals.json').read_text(),original)
        self.assertEqual([c['outcome'] for c in self.cases(run)],['confirmed','refuted'])
        self.assertTrue(all(c['evaluation']['runtimeReproduced'] is False for c in self.cases(run)))
        page=self.call('signals',run=run,limit=1)
        self.assertEqual(page['signals'][0]['evaluationOutcome'],'confirmed')
        self.assertEqual(page['nextCursor'],1)
        report=json.loads((self.w.directory(run)/'report.json').read_text())
        self.assertEqual(len(report['cases']),2)
        markdown=(self.w.directory(run)/'report.md').read_text()
        self.assertIn('## Confirmed findings',markdown)
        self.assertIn('Refuted',markdown)
        self.assertIn('**Prerequisites**',markdown)
        self.assertIn('`app.py:1-8`',markdown)
        self.assertTrue(any(a['path'].startswith('evaluation/evidence/') for a in self.w.artifacts(run)))
        self.assertEqual(self.submit(run,task,result)['status'],'completed','Exact final submission is idempotent.')
        self.assertEqual(self.submit(run,task,{**result,'impact':'changed'})['status'],'error')

    def test_markdown_report_details_only_confirmed_findings_and_counts_unanalysed_cases(self):
        sarif=json.loads(self.sarif.read_text())
        results=sarif['runs'][0]['results']
        for title in ('UNRESOLVED_PRIVATE_DETAILS','UNANALYSED_PRIVATE_DETAILS'):
            results.append({'ruleId':'invoice-access','message':{'text':title},
                            'locations':[{'physicalLocation':{'artifactLocation':{'uri':'app.py'},
                                                             'region':{'startLine':2}}}]})
        self.sarif.write_text(json.dumps(sarif))
        run=self.start({'evaluationLimits':{'maxTasks':3}})
        signals_path=self.w.directory(run)/'signals.json'
        signals=json.loads(signals_path.read_text())
        signals[0]['ruleMetadata']['shortDescription']={'text':'Missing invoice ownership check'}
        atomic(signals_path,signals)
        for outcome in ('confirmed','refuted','needs_review'):
            task=self.task(run)
            result=self.result(run,task,outcome)
            if outcome!='confirmed':
                result['rationale']='REFUTED_PRIVATE_DETAILS' if outcome=='refuted' else 'UNRESOLVED_PRIVATE_DETAILS'
            self.assertNotEqual(self.submit(run,task,result)['status'],'error')
        markdown=(self.w.directory(run)/'report.md').read_text()
        self.assertIn('### Finding 1: Missing invoice ownership check',markdown)
        self.assertEqual(markdown.count('### Finding '),1)
        self.assertIn('**Issue**',markdown)
        self.assertIn('Reviewed lookup and relevant ownership controls.',markdown)
        self.assertLess(markdown.index('**Issue**'),markdown.index('#### Details'))
        self.assertIn('**Affected locations**',markdown)
        self.assertIn('`app.py:2`',markdown)
        self.assertIn('**Supporting evidence**',markdown)
        self.assertIn('`app.py:1-8`',markdown)
        self.assertIn('**Severity:** Medium',markdown)
        self.assertIn('| Source-confirmed findings | 1 |',markdown)
        self.assertIn('| Refuted | 1 |',markdown)
        self.assertIn('| Unresolved after analysis | 1 |',markdown)
        self.assertIn('| Not analysed | 1 |',markdown)
        self.assertIn('| Total candidate signals | 4 |',markdown)
        for text in ('REFUTED_PRIVATE_DETAILS','UNRESOLVED_PRIVATE_DETAILS','UNANALYSED_PRIVATE_DETAILS',
                     '## Refuted','## Needs review','## Unevaluated signals'):
            self.assertNotIn(text,markdown)
        report=json.loads((self.w.directory(run)/'report.json').read_text())
        self.assertEqual(len(report['signals']),4)
        self.assertEqual(len(report['cases']),4)
        self.assertEqual([c['outcome'] for c in report['cases']],['confirmed','refuted','needs_review','needs_review'])
        self.assertIsNone(report['cases'][-1]['evaluation'])
        self.assertIn('REFUTED_PRIVATE_DETAILS',json.dumps(report))
        self.assertIn('UNRESOLVED_PRIVATE_DETAILS',json.dumps(report))

    def test_markdown_report_separates_findings_and_orders_supported_severity(self):
        run=self.start()
        for severity in ('medium','high'):
            task=self.task(run)
            result=self.result(run,task)
            result['severity']=severity
            self.assertNotEqual(self.submit(run,task,result)['status'],'error')
        markdown=(self.w.directory(run)/'report.md').read_text()
        self.assertEqual(markdown.count('### Finding '),2)
        self.assertIn('### Finding 1: Potential unsafe read with a guard',markdown)
        self.assertIn('### Finding 2: Unrestricted invoice read',markdown)
        self.assertIn('\n---\n',markdown)
        self.assertLess(markdown.index('**Severity:** High'),markdown.index('**Severity:** Medium'))

    def test_markdown_report_without_confirmed_findings_contains_only_aggregates(self):
        run=self.start()
        for _ in range(2):
            task=self.task(run)
            self.assertNotEqual(self.submit(run,task,self.result(run,task,'refuted'))['status'],'error')
        markdown=(self.w.directory(run)/'report.md').read_text()
        self.assertIn('No source-confirmed findings.',markdown)
        self.assertIn('| Refuted | 2 |',markdown)
        self.assertIn('| Not analysed | 0 |',markdown)
        self.assertNotIn('### Finding ',markdown)
        self.assertNotIn('Reviewed lookup and relevant ownership controls.',markdown)

    def test_discovery_only_markdown_counts_all_signals_as_unanalysed(self):
        run=self.start({'evaluation':'off'})
        markdown=(self.w.directory(run)/'report.md').read_text()
        self.assertIn('| Source-confirmed findings | 0 |',markdown)
        self.assertIn('| Not analysed | 2 |',markdown)
        self.assertIn('No source-confirmed findings.',markdown)
        self.assertNotIn('Unrestricted invoice read',markdown)

    def test_standalone_evaluation_without_task_timeout_can_read_and_submit_after_300_seconds(self):
        run=self.start(mode='standalone-api')
        task=self.call('next_task',run=run,disableTaskTimeout=True)['task']
        data=self.w.evaluation_engine().load(run)
        self.assertTrue(task['taskTimeoutDisabled'])
        self.assertEqual(task['expiresAt'],data['deadline'])
        with patch('bypass_scanner.tasks.time.time',return_value=time.time()+301):
            response=self.submit(run,task,self.result(run,task,'needs_review'))
            self.assertNotEqual(response['status'],'error',response)
        self.w.cancel(run)

    def test_unlimited_evaluation_can_submit_past_original_stage_deadline(self):
        run=self.start(mode='standalone-api')
        self.w.cancel(run);self.w.evaluate(run,True)
        data=self.w.evaluation_engine().load(run)
        with patch('bypass_scanner.tasks.time.time',return_value=data['deadline']+1):
            task=self.call('next_task',run=run,disableTaskTimeout=True)['task']
            self.assertTrue(task['stageTimeoutDisabled']);self.assertEqual(task['expiresAt'],0)
            response=self.submit(run,task,self.result(run,task,'needs_review'))
            self.assertNotEqual(response['status'],'error',response)
        self.w.cancel(run)

    def test_unlimited_evaluation_records_requests_beyond_configured_limits(self):
        run=self.start(mode='standalone-api')
        self.w.cancel(run);self.w.evaluate(run,True)
        task=self.call('next_task',run=run,disableTaskTimeout=True)['task']
        engine=self.w.evaluation_engine();data=engine.load(run)
        data['modelRequests']=256
        active=next(t for t in data['tasks'] if t['definition']['id']==task['id'])
        active['requests']=32
        engine.save(self.w.read(run),data)
        receipt=self.call('evidence',run=run,task=task['id'],operation='checkpoint',arguments={'modelRequests':1})
        self.assertNotEqual(receipt['status'],'error',receipt)
        self.assertNotEqual(self.read(run,task)['status'],'error')
        saved=engine.load(run)
        self.assertEqual(saved['modelRequests'],257)
        self.assertEqual(next(t for t in saved['tasks'] if t['definition']['id']==task['id'])['requests'],33)
        self.w.cancel(run)

    def test_opt_out_saved_run_and_legacy_configuration(self):
        run=self.start({'evaluation':'off'})
        self.assertEqual(self.w.status(run)['evaluation'],'not_run')
        state=self.w.read(run)
        state['config'].pop('evaluation')
        self.w.save(state)
        self.assertEqual(self.call('report',run=run)['status'],'completed')
        result=self.call('evaluate',run=run)
        self.assertEqual(result['status'],'awaiting_reasoning',result)
        self.assertEqual(self.task(run)['kind'],'evaluation')

    def test_no_candidates_finishes_without_reasoning(self):
        self.sarif.write_text('{"version":"2.1.0","runs":[]}')
        run=self.start(mode='standalone-api')
        status=self.w.status(run)
        self.assertEqual(status['status'],'completed')
        self.assertEqual(status['evaluationSummary']['cases'],0)
        self.assertEqual(status['modelCalls'],0)
        self.assertFalse(status['coverageComplete'])

    def test_needs_review_and_bounded_deep_investigation(self):
        run=self.start({'evaluationLimits':{'maxTasks':3,'maxFollowUpDepth':1}})
        task=self.task(run)
        unresolved=self.result(run,task,'needs_review',True)
        self.assertNotEqual(self.submit(run,task,unresolved)['status'],'error')
        sibling=self.task(run)
        self.submit(run,sibling,self.result(run,sibling,'refuted'))
        follow=self.task(run)
        self.assertEqual(follow['kind'],'deep_investigation')
        self.assertEqual(follow['caseId'],task['caseId'])
        self.assertTrue(follow['inputEvidence'])
        self.assertEqual(self.submit(run,follow,self.result(run,follow,'needs_review',True))['status'],'incomplete')
        case=self.cases(run)[0]
        self.assertEqual(case['outcome'],'needs_review')
        self.assertIn('budget exhausted',case['reason'])

    def test_invalid_conclusions_and_cross_task_citations_are_rejected(self):
        run=self.start()
        task=self.task(run)
        good=self.result(run,task)
        for fields in ({'caseId':'other'}, {'evidence':['fabricated']}, {'rationale':' '},
                       {'openQuestions':['Unknown deployment']}, {'severity':'unknown'},
                       {'outcome':'needs_review','openQuestions':[]}):
            self.assertEqual(self.submit(run,task,{**good,**fields})['status'],'error',fields)
        self.submit(run,task,good)
        sibling=self.task(run)
        bad={**self.result(run,sibling),'evidence':good['evidence']}
        self.assertEqual(self.submit(run,sibling,bad)['status'],'error')
        for path in ('.env','tests/fixture.py','../outside','/etc/passwd'):
            self.assertEqual(self.read(run,sibling,path)['status'],'error')
        with self.assertRaises(ValueError):
            self.call('evidence',run=run,task=sibling['id'],operation='shell',arguments={})

    def test_cancel_resume_keeps_cases_and_rejects_stale_leases(self):
        run=self.start()
        first=self.task(run)
        self.submit(run,first,self.result(run,first))
        second=self.task(run)
        pending=self.result(run,second,'refuted')
        self.assertEqual(self.call('cancel',run=run)['status'],'cancelled')
        self.assertEqual(self.submit(run,second,pending)['status'],'error')
        self.w.resume(run)
        self.assertEqual(self.settle(run)['status'],'awaiting_reasoning')
        renewed=self.task(run)
        self.assertNotEqual(second['id'],renewed['id'])
        self.assertEqual(self.cases(run)[0]['outcome'],'confirmed')
        self.assertEqual(self.submit(run,renewed,self.result(run,renewed,'refuted'))['status'],'completed')

    def test_deadline_and_task_limit_leave_explicit_unresolved_cases(self):
        run=self.start({'evaluationLimits':{'maxTasks':1}})
        self.assertEqual(self.cases(run)[1]['outcome'],'needs_review')
        data=self.w.evaluation_engine().load(run)
        data['deadline']=time.time()-1
        atomic(self.w.evaluation_engine().directory(run)/'state.json',data)
        self.assertEqual(self.w.status(run)['status'],'incomplete')
        self.assertTrue(all(c['outcome']=='needs_review' for c in self.cases(run)))
        with self.assertRaisesRegex(ValueError,'expired'):
            self.w.evaluation_engine().prepare(self.w.read(run))

    def test_changed_source_and_snapshot_cannot_be_used_for_verdicts(self):
        for changed in ('original','snapshot'):
            with self.subTest(changed=changed):
                run=self.start()
                task=self.task(run)
                result=self.result(run,task)
                root=self.source if changed=='original' else self.w.directory(run)/'snapshot'
                (root/'app.py').chmod(0o600)
                (root/'app.py').write_text('changed\n')
                self.assertEqual(self.submit(run,task,result)['status'],'error')
                self.assertEqual(self.w.status(run)['status'],'incomplete')
                self.assertEqual(self.cases(run)[0]['outcome'],'not_run')
                if changed=='original':
                    (root/'app.py').write_text((self.w.directory(run)/'snapshot/app.py').read_text())

    def test_request_usage_is_separate_and_retained_after_final_submission(self):
        run=self.start(mode='standalone-api')
        task=self.task(run)
        receipt=self.call('evidence',run=run,task=task['id'],operation='checkpoint',arguments={'modelRequests':1})
        self.assertEqual(receipt['run']['reasoning']['independentModelRequests'],1)
        self.submit(run,task,self.result(run,task))
        second=self.task(run)
        self.submit(run,second,self.result(run,second,'refuted'))
        self.assertEqual(self.w.status(run)['modelCalls'],1)

    def test_expired_leases_exhaust_attempts_without_confirming_candidates(self):
        run=self.start({'evaluationLimits':{'maxTasks':1,'maxAttempts':1}})
        task=self.task(run)
        data=self.w.evaluation_engine().load(run)
        data['tasks'][0]['definition']['expiresAt']=time.time()-1
        atomic(self.w.evaluation_engine().directory(run)/'state.json',data)
        result=self.call('next_task',run=run)
        self.assertEqual(result['status'],'incomplete')
        self.assertNotIn('task',result)
        self.assertTrue(all(c['outcome']=='needs_review' for c in self.cases(run)))
        self.assertEqual(self.read(run,task)['status'],'error')

    def test_bad_candidate_provenance_is_unresolved_not_refuted(self):
        run=self.start({'evaluation':'off'})
        path=self.w.directory(run)/'signals.json'
        signals=json.loads(path.read_text())
        signals[0]['evidence'][0]['contentHash']='stale'
        atomic(path,signals)
        self.assertEqual(self.call('evaluate',run=run)['status'],'awaiting_reasoning')
        self.assertEqual(self.cases(run)[0]['outcome'],'needs_review')
        self.assertIsNone(self.cases(run)[0]['evaluation'])
        self.assertNotEqual(self.task(run)['caseId'],self.cases(run)[0]['id'])

    def test_historical_reports_read_without_source_freshness_or_new_inference(self):
        run=self.start({'evaluation':'off'})
        state=self.w.read(run)
        state['config'].pop('evaluation')
        state['config'].pop('evaluationLimits')
        state['stage']='discovery'
        state['modelCalls']=0
        self.w.save(state)
        (self.source/'app.py').write_text('changed\n')
        result=self.call('report',run=run)
        self.assertEqual(result['status'],'completed')
        self.assertEqual(result['modelCalls'],0)
        self.assertEqual(self.call('evaluate',run=run)['status'],'error')

    def test_observer_does_not_publish_a_stage_transition_before_the_lease_is_released(self):
        run=self.start()
        observer=Workflow(self.source,self.root/'output',{'rules':[]})
        self.addCleanup(observer.close)
        fd=self.w.lease()
        try:
            self.assertEqual(observer.status(run)['status'],'running')
        finally:
            os.close(fd)
        self.assertEqual(observer.status(run)['status'],'awaiting_reasoning')
