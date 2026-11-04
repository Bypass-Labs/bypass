"""Shared durable source-only task leases and evidence receipts."""
from contextlib import contextmanager
import hashlib
import json
import os
import time
from uuid import uuid4

from bypass_scanner.repository.snapshot import contained, snapshot
from bypass_scanner.workflow import atomic, TERMINAL


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


class TaskEngine:
    namespace = ''

    def __init__(self, workflow):
        self.w = workflow

    def directory(self, run):
        return contained(self.w.directory(run), self.namespace)

    def snapshot_root(self, run):
        return contained(self.w.directory(run), 'snapshot')

    def load(self, run):
        return json.loads(contained(self.directory(run), 'state.json').read_text())

    @contextmanager
    def locked(self, run):
        with self.w.guard:
            fd = self.w.lease()
            try:
                state = self.w.read(run)
                yield state, self.load(run)
            finally:
                os.close(fd)

    def usage(self, state, data):
        prior = {'policy':state.get('reasoning',{}).get('independentModelRequests',0)} if self.namespace=='evaluation' else {}
        counts = state.setdefault('reasoningRequests', prior)
        counts[self.namespace] = data['modelRequests']
        requests = sum(counts.values())
        state['reasoning'] = {'executor':state['executionMode'], 'independentModelRequests':requests,
                              'hostReasoning':state['executionMode']=='muse-host', 'hostTokens':None, 'providerTokens':None}
        state['modelCalls'] = None if state['executionMode']=='muse-host' else requests

    def verify_source(self, state):
        if state['imageIdentity'] != os.environ.get('BYPASS_SCANNER_IMAGE', 'development'):
            state.update(status='incomplete',message='Scanner image changed; start a new scan. Accepted results are retained.')
            self.w.save(state)
            self.w.render(state)
            raise ValueError(state['message'])
        recorded = json.loads((self.w.directory(state['id'])/'source-manifest.json').read_text())
        options = {'include_generated':state['config'].get('includeGenerated', False)}
        if (snapshot(self.w.source, **options)['revision'] != state['sourceRevision']
                or snapshot(self.snapshot_root(state['id']), **options)['revision'] != recorded['revision']):
            state.update(status='incomplete', message='Source changed. Accepted results are retained; start a new scan.')
            self.w.save(state)
            self.w.render(state)
            raise ValueError(state['message'])

    def expire(self, state, data):
        if not state.get('reasoningTimeoutDisabled',False) and time.time() >= data['deadline'] and state['status'] not in TERMINAL:
            for task in data['tasks']:
                if task['status'] != 'done':
                    task['status'] = 'deferred'
                    data['coverage'].append({'workUnitId':task['definition']['workUnitId'], 'outcome':'deferred', 'reason':'run deadline'})
            self.finish(state, data, expired=True)

    def next_task(self, run, disable_task_timeout=False):
        with self.locked(run) as (state, data):
            if disable_task_timeout and state['executionMode']!='standalone-api':
                raise ValueError('Disabling task timeouts requires standalone API execution.')
            self.expire(state, data)
            if state['status'] in TERMINAL:
                return self.w.public(state), None
            self.verify_source(state)
            stage_disabled=state.get('reasoningTimeoutDisabled',False)
            def expires():
                return 0 if stage_disabled else data['deadline'] if disable_task_timeout else min(time.time()+data['limits']['taskTimeoutSeconds'],data['deadline'])
            for task in data['tasks']:
                if task['status']=='leased' and (task['definition'].get('stageTimeoutDisabled',False) or task['definition']['expiresAt']>time.time()):
                    if (task['definition'].get('taskTimeoutDisabled',False)!=disable_task_timeout
                            or task['definition'].get('stageTimeoutDisabled',False)!=stage_disabled):
                        task['definition'].update(taskTimeoutDisabled=disable_task_timeout,
                                                  stageTimeoutDisabled=stage_disabled,expiresAt=expires())
                        self.save(state,data)
                    return self.w.public(state), task['definition']
                if task['status']=='leased':
                    task['status']='pending'
                if task['status']!='pending':
                    continue
                if task['attempts']>=data['limits']['maxAttempts']:
                    task['status']='deferred'
                    data['coverage'].append({'workUnitId':task['definition']['workUnitId'], 'outcome':'deferred', 'reason':'task lease attempts exhausted'})
                    continue
                task.update(attempts=task['attempts']+1, requests=0, bytes=0, status='leased')
                task['evidenceIds']=[r['id'] for r in task['definition']['inputEvidence']]
                task['definition'].update(id='task_'+uuid4().hex, taskTimeoutDisabled=disable_task_timeout,
                                          stageTimeoutDisabled=stage_disabled,expiresAt=expires())
                state.update(status='awaiting_reasoning', phase=self.namespace+'/'+task['definition']['phase'],
                             message='Source-only task leased; read evidence and submit its declared result.')
                self.save(state,data)
                return self.w.public(state), task['definition']
            self.finish(state,data)
            return self.w.public(state), None

    def active(self, state, data, identity):
        self.expire(state,data)
        if state['status'] in TERMINAL:
            raise ValueError('Reasoning run is terminal; resume interrupted work explicitly.')
        task=next((t for t in data['tasks'] if t['definition']['id']==identity and t['status']=='leased'),None)
        if task is None or (not task['definition'].get('stageTimeoutDisabled',False) and task['definition']['expiresAt']<=time.time()):
            raise ValueError('Stale or expired task lease; request next_task.')
        return task

    def read_evidence(self, state, data, task, path, start=1, end=None):
        if path not in data['files']:
            raise ValueError('Evidence path is outside the selected analysis scope.')
        if type(start) is not int or start<1 or (end is not None and (type(end) is not int or end<start)):
            raise ValueError('Invalid evidence line range.')
        file=contained(self.snapshot_root(state['id']),path)
        if file.stat().st_size>2097152:
            raise ValueError('Source file exceeds the 2 MiB evidence limit; record a proof gap.')
        body=file.read_bytes()
        if hashlib.sha256(body).hexdigest()!=data['files'][path]['sha256']:
            raise ValueError('Saved source evidence changed.')
        lines=body.decode('utf-8').splitlines()
        end=min(end or start+79,start+119,len(lines))
        if start>len(lines):
            raise ValueError('Evidence starts beyond the file.')
        excerpt='\n'.join(lines[start-1:end])
        if len(excerpt.encode())>16000:
            raise ValueError('Evidence excerpt exceeds 16000 bytes; request fewer lines.')
        identity='evidence_'+digest([task['definition']['id'],path,start,end])[:24]
        receipt={'id':identity,'path':path,'startLine':start,'endLine':end,'sourceRevision':data['revision'],'contentHash':data['files'][path]['sha256']}
        data['receipts'][identity]=receipt
        if identity not in task['evidenceIds']:
            task['evidenceIds'].append(identity)
        return {'reference':receipt,'text':excerpt,'nextLine':end+1 if end<len(lines) else -1}

    def evidence(self, run, identity, operation, arguments):
        if not isinstance(arguments,dict):
            raise ValueError('Evidence arguments must be an object.')
        with self.locked(run) as (state,data):
            if operation=='checkpoint' and ('modelRequests' in arguments or arguments.get('interrupt')):
                known=next((t for t in data['tasks'] if t['definition']['id']==identity),None)
                if known is None:
                    raise ValueError('Unknown task accounting receipt.')
                if any(k not in ('modelRequests','interrupt','reason') for k in arguments):
                    raise ValueError('Unsupported checkpoint field.')
                count=arguments.get('modelRequests',0)
                if type(count) is not int or not 0<=count<=1 or ('modelRequests' in arguments and count!=1):
                    raise ValueError('Usage receipts must record one attempted request.')
                if count and state['executionMode']!='standalone-api':
                    raise ValueError('Muse reasoning cannot record independent API requests.')
                if data['modelRequests']+count>data['limits']['maxModelRequests']:
                    raise ValueError('Run model request limit reached.')
                data['modelRequests']+=count
                if arguments.get('interrupt'):
                    if known['status']!='leased' or state['status'] in TERMINAL:
                        raise ValueError('Only an active task can be interrupted.')
                    known['status']='pending'
                    state.update(status='interrupted',message=str(arguments.get('reason','Reasoning interrupted.'))[:1000])
                self.save(state,data)
                self.w.render(state)
                return self.w.public(state), {'checkpointed':True}
            task=self.active(state,data,identity)
            if task['requests']>=data['limits']['maxRequestsPerTask']:
                raise ValueError('Task evidence request limit reached; submit or checkpoint.')
            task['requests']+=1
            previous_receipts=set(data['receipts'])
            previous_ids=list(task['evidenceIds'])
            try:
                allowed={'inventory':{'cursor','limit'},'read':{'path','startLine','endLine'},'navigate':{'path','startLine','endLine'},
                         'search':{'query','path','cursor','limit'},'checkpoint':{'reason'}}
                if operation not in allowed or any(k not in allowed[operation] for k in arguments):
                    raise ValueError('Unsupported evidence operation or argument.')
                if operation in ('read','navigate'):
                    value=self.read_evidence(state,data,task,arguments.get('path'),arguments.get('startLine',1),arguments.get('endLine'))
                elif operation in ('inventory','search'):
                    cursor=arguments.get('cursor',0)
                    limit=arguments.get('limit',50)
                    if type(cursor) is not int or type(limit) is not int or cursor<0 or cursor>100000 or not 1<=limit<=100:
                        raise ValueError('Invalid evidence page bounds.')
                    paths=sorted(data['files'])
                    if operation=='inventory':
                        value={'paths':paths[cursor:cursor+limit],'nextCursor':cursor+limit if cursor+limit<len(paths) else -1}
                    else:
                        query=arguments.get('query')
                        selected_path=arguments.get('path')
                        if not isinstance(query,str) or not 1<=len(query)<=200:
                            raise ValueError('Use a bounded literal search query.')
                        if selected_path is not None:
                            if selected_path not in data['files']:
                                raise ValueError('Search path is outside analysis scope.')
                            paths=[selected_path]
                        matches=[]
                        skipped=[]
                        truncated=[]
                        scanned=0
                        for name in paths[cursor:cursor+min(limit,20)]:
                            scanned+=1
                            file=contained(self.snapshot_root(run),name)
                            if file.stat().st_size>2097152:
                                skipped.append(name)
                                continue
                            try:
                                lines=file.read_text(encoding='utf-8').splitlines()
                            except UnicodeError:
                                skipped.append(name)
                                continue
                            if hashlib.sha256(file.read_bytes()).hexdigest()!=data['files'][name]['sha256']:
                                raise ValueError('Saved source evidence changed.')
                            for number,line in enumerate(lines,1):
                                if query in line:
                                    matches.append({'path':name,'line':number,'preview':line[:300]})
                                    if len(matches)>=50:
                                        break
                            if len(matches)>=50:
                                truncated.append(name)
                                break
                        value={'matches':matches,'skippedPaths':skipped,'truncatedPaths':truncated,
                               'nextCursor':cursor+scanned if cursor+scanned<len(paths) else -1,
                               'notice':'Search previews are navigation hints. Read ranges for citations and remaining matches on truncated paths.'}
                else:
                    value={'checkpointed':True}
                size=len(json.dumps(value).encode())
                task['bytes']+=size
                data['bytes']+=size
                if task['bytes']>data['limits']['maxEvidenceBytesPerTask'] or data['bytes']>data['limits']['maxEvidenceBytes']:
                    raise ValueError('Evidence byte budget exhausted; submit retained evidence or checkpoint.')
                event=value.get('reference',{}).get('id',uuid4().hex)
                atomic(self.directory(run)/'evidence'/f'{event}.json',{'task':identity,'operation':operation,'result':value})
            except Exception:
                data['receipts']={k:v for k,v in data['receipts'].items() if k in previous_receipts}
                task['evidenceIds']=previous_ids
                raise
            finally:
                self.save(state,data)
            return self.w.public(state),value

    def citations(self, data, task, ids):
        if not ids or any(key not in task['evidenceIds'] or key not in data['receipts'] for key in ids):
            raise ValueError('Submission cites evidence not issued for this task.')
        for path in {data['receipts'][key]['path'] for key in ids}:
            file=contained(self.snapshot_root(data['run']),path)
            if file.stat().st_size>2097152 or hashlib.sha256(file.read_bytes()).hexdigest()!=data['files'][path]['sha256']:
                raise ValueError('Saved source evidence changed since its receipt was issued.')
        return [data['receipts'][key] for key in ids]
