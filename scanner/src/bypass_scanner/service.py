"""Transport-independent discovery operations; no LLM or provider access."""
import json
import os
from pathlib import Path

from bypass_scanner.contracts import MANIFEST, PROTOCOL_VERSION, validate
from bypass_scanner.discovery.languages import LANGUAGES

_WORKFLOW = None
IMPLEMENTED = ['capabilities', 'rules', 'policies', 'start', 'status', 'resume', 'cancel', 'report', 'signals', 'artifact', 'build_failed','next_task','evidence','submit','evaluate']


def workflow():
    global _WORKFLOW
    if _WORKFLOW is None:
        from bypass_scanner.workflow import Workflow
        _WORKFLOW = Workflow()
    return _WORKFLOW


def capabilities():
    return {'protocolVersion': PROTOCOL_VERSION, 'status': 'ready', 'analysisImplemented': True,
            'independentModelRequests': 0, 'implementedOperations': IMPLEMENTED,
            'operations': list(MANIFEST['operations']), 'stages': ['discovery', 'evaluation', 'reporting'],
            'features': {'codeqlDiscovery': True, 'aiDiscovery': True, 'evaluation': True,
                         'codeqlReady': Path(os.environ.get('BYPASS_CODEQL_CATALOG', '/opt/bypass-codeql-catalog.json')).is_file()},
            'languages': list(LANGUAGES)}


def response(operation, status='ready', message='', **values):
    return {'protocolVersion': PROTOCOL_VERSION, 'operation': operation, 'status': status,
            'modelCalls': values.get('run',{}).get('modelCalls',0), 'message': message, **values}


def unavailable(operation):
    return response(operation, 'not_implemented', 'The requested scanner operation is unavailable.', code='not_implemented')


def invoke(operation, arguments, engine=None):
    if operation not in MANIFEST['operations']:
        raise ValueError('Unknown scanner operation.')
    validate(MANIFEST['operations'][operation]['inputSchema'], arguments)
    if operation == 'capabilities':
        return capabilities()
    if operation not in IMPLEMENTED:
        return unavailable(operation)
    engine = engine or workflow()
    try:
        if operation=='policies':
            from bypass_scanner.discovery.policy import catalog
            items=[{k:p[k] for k in ('id','version','title','file')} for p in catalog()]
            query=arguments.get('query','').lower()
            result=response(operation,policies=[p for p in items if query in (p['id']+' '+p['title']).lower()])
        elif operation in ('next_task','evidence','submit'):
            tasks=engine.task_engine(arguments['run'], arguments.get('task'))
            if operation=='next_task':
                run,task=tasks.next_task(arguments['run'])
                result=response(operation,run['status'],run['message'],run=run,**({'task':task} if task else {}))
            elif operation=='evidence':
                run,evidence=tasks.evidence(arguments['run'],arguments['task'],arguments['operation'],arguments.get('arguments',{}))
                result=response(operation,run['status'],run['message'],run=run,evidence=evidence)
            else:
                run=tasks.submit(arguments['run'],arguments['task'],arguments['sourceRevision'],arguments['result'])
                result=response(operation,run['status'],run['message'],run=run)
        elif operation == 'rules':
            items = engine.catalog()['rules']
            if arguments.get('language'):
                items = [rule for rule in items if rule['language'] == arguments['language']]
            if arguments.get('query'):
                items = [rule for rule in items if arguments['query'].lower() in (rule['id'] + ' ' + rule['name']).lower()]
            cursor, limit = arguments.get('cursor', 0), arguments.get('limit', 50)
            page = [{k: v for k, v in item.items() if k != 'path'} for item in items[cursor:cursor + limit]]
            result = response(operation, rules=page, nextCursor=cursor + len(page) if cursor + len(page) < len(items) else -1)
        elif operation in ('start', 'resume', 'status', 'cancel', 'build_failed', 'evaluate'):
            if operation == 'start':
                run = engine.start(arguments)
            elif operation == 'build_failed':
                run = engine.build_failed(arguments['run'], arguments['job'])
            else:
                run = getattr(engine, operation)(arguments['run'])
            result = response(operation, run['status'], run['message'], run=run)
        elif operation == 'artifact':
            result = response(operation, **engine.artifact(arguments['run'], arguments['path'], arguments.get('offset', 0)))
        elif operation == 'report':
            run = engine.status(arguments['run'])
            state = engine.read(arguments['run'])
            engine.render(state)
            result = response(operation, run['status'], run['message'], run=run, artifacts=[item for item in engine.artifacts(arguments['run']) if item['path'] == 'report.' + arguments.get('format', 'json')])
        elif operation == 'signals':
            path = engine.directory(arguments['run']) / 'signals.json'
            run = engine.status(arguments['run'])
            items = json.loads(path.read_text()) if path.is_file() else []
            cursor, limit = arguments.get('cursor', 0), arguments.get('limit', 50)
            page = []
            cases_path = engine.directory(arguments['run'])/'evaluation/cases.json'
            cases = json.loads(cases_path.read_text()) if cases_path.is_file() else []
            evaluations = {identity:case for case in cases for identity in case['signalIds']}
            for item in items[cursor:cursor + limit]:
                page.append({key: item[key] for key in ('id', 'ruleId', 'language', 'origin', 'evaluation', 'detectorSeverity')})
                page[-1].update(suspectedIssue=item['suspectedIssue'][:2000], locations=item['locations'][:20], detailArtifact='signals.json')
                if item['id'] in evaluations:
                    case = evaluations[item['id']]
                    page[-1].update(caseId=case['id'],evaluationOutcome=case['outcome'],evaluationArtifact='evaluation/cases.json')
            result = response(operation, run['status'], run['message'], run=run, signals=page,
                              nextCursor=cursor + len(page) if cursor + len(page) < len(items) else -1)
        else:
            return unavailable(operation)
        # Bound list pages by encoded bytes, not only item count. Full data stays on disk.
        key = 'signals' if 'signals' in result else 'rules' if 'rules' in result else None
        if key:
            while len(json.dumps(result).encode()) > 512000 and result[key]:
                result[key].pop()
                result['nextCursor'] = arguments.get('cursor', 0) + len(result[key])
        validate(MANIFEST['schemas']['response'], result, 'response')
        return result
    except (ValueError, OSError, RuntimeError, KeyError, TypeError) as error:
        return response(operation, 'error', str(error)[:4000], code='scanner_error')


def close():
    if _WORKFLOW is not None:
        _WORKFLOW.close()
