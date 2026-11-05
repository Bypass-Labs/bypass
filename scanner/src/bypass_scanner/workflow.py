"""Durable, single-project CodeQL discovery. No model client is used."""
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import threading
import time
from uuid import uuid4

from bypass_scanner.contracts import MANIFEST, validate
from bypass_scanner.discovery.catalog import load_catalog, select_rules
from bypass_scanner.discovery.languages import LANGUAGES, detect
from bypass_scanner.discovery import codeql
from bypass_scanner.discovery.sarif import normalize, coverage
from bypass_scanner.repository.snapshot import snapshot, contained, relative
from bypass_scanner.repository.scope import options as scope_options, select as select_scope

STAGES = ('discovery', 'evaluation', 'reporting')
TERMINAL = {'completed', 'incomplete', 'cancelled', 'failed', 'interrupted'}


def now():
    return datetime.now(timezone.utc).isoformat()


class CancellationToken(threading.Event):
    """Cancellation survives client/container boundaries through a durable marker."""
    def __init__(self, path, *additional_paths):
        super().__init__()
        self.path = path
        self.additional_paths = additional_paths

    def is_set(self):
        return super().is_set() or self.path.is_file() or any(path.is_file() for path in self.additional_paths)

    def wait(self, timeout=None):
        if self.is_set():
            return True
        super().wait(timeout)
        return self.is_set()


def atomic(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.' + uuid4().hex + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.chmod(0o600)
    temporary.replace(path)


def settings(value):
    validate(MANIFEST['schemas']['config'], value)
    result = {'detectors':list(dict.fromkeys('codeql' if d=='sast' else d for d in value.get('detectors',['codeql']))),
              'languages': list(dict.fromkeys(value.get('languages', []))), 'includeRules': list(dict.fromkeys(value.get('includeRules', []))),
              'excludeRules': list(dict.fromkeys(value.get('excludeRules', []))), 'builds': value.get('builds', {}), **scope_options(value),
              'resources': {**MANIFEST['resourceDefaults'], **value.get('resources', {})}}
    result.update({k:value.get(k,[]) for k in ('includePolicies','excludePolicies','policyCatalogs','contextFiles')})
    result['policyLimits']={**MANIFEST['policyLimits'],**value.get('policyLimits',{})}
    result['evaluation'] = value.get('evaluation', 'auto')
    result['evaluationLimits'] = {**MANIFEST['policyLimits'], **value.get('evaluationLimits', {})}
    for name in result['policyCatalogs']+result['contextFiles']:
        relative(name)
    if result['resources']['memoryMb'] < result['resources']['ramMb'] + 1024:
        raise ValueError('Container memory must exceed CodeQL RAM by at least 1024 MB.')
    for language, build in result['builds'].items():
        mode = build.get('mode', LANGUAGES[language]['mode'])
        if mode not in LANGUAGES[language]['modes']:
            raise ValueError(f'Unsupported build mode for {language}.')
        if mode == 'manual' and not build.get('command'):
            raise ValueError(f'{language} manual extraction requires a command argv array.')
        if mode != 'manual' and build.get('command'):
            raise ValueError('A command is valid only with manual build mode.')
        if build.get('cwd', '.') != '.':
            relative(build['cwd'])
        for command in [*build.get('prepare', []), *([build['command']] if build.get('command') else [])]:
            if not command or not command[0].strip() or any('\x00' in item for item in command):
                raise ValueError('Build commands must be nonempty argv arrays without NUL bytes.')
    return result


class Workflow:
    def __init__(self, source=None, output=None, catalog=None):
        self.source = Path(source or os.environ.get('BYPASS_SCANNER_SOURCE', '/inputs/source'))
        self.output = Path(output or os.environ.get('BYPASS_SCANNER_OUTPUT', '/outputs'))
        self.catalog_override = catalog
        self.tasks = {}
        self.guard = threading.RLock()

    def catalog(self):
        return self.catalog_override if self.catalog_override is not None else load_catalog()

    def policy_engine(self):
        from bypass_scanner.discovery.policy import PolicyEngine
        return PolicyEngine(self)

    def evaluation_engine(self):
        from bypass_scanner.evaluation.engine import EvaluationEngine
        return EvaluationEngine(self)

    def task_engine(self, run, identity=None):
        state = self.read(run)
        if identity:
            for engine in (self.policy_engine(), self.evaluation_engine()):
                if (engine.directory(run)/'state.json').is_file():
                    if any(t['definition']['id']==identity for t in engine.load(run)['tasks']):
                        return engine
            raise ValueError('Unknown task identity for this run.')
        return self.evaluation_engine() if state['stage'] in ('evaluation','reporting') and (self.directory(run)/'evaluation/state.json').is_file() else self.policy_engine()

    def discovery_finished(self, state):
        state['discoveryStatus'] = state['status']
        if state['config'].get('evaluation', 'off')=='auto':
            self.evaluation_engine().prepare(state)
        else:
            state['stage'] = 'reporting'
            self.save(state)
            self.render(state)

    def reasoning_timeout(self, state, disabled):
        if disabled and state['executionMode']!='standalone-api':
            raise ValueError('Disabling reasoning timeouts requires standalone API execution.')
        state['reasoningTimeoutDisabled']=disabled

    def evaluate(self, run, disable_reasoning_timeout=False):
        with self.guard:
            fd = self.lease()
            try:
                state = self.read(run)
                self.reasoning_timeout(state,disable_reasoning_timeout)
                if state['status'] not in TERMINAL:
                    raise ValueError('Finish or cancel the current discovery/evaluation before evaluating a saved run.')
                active = self.output/'active-run.json'
                if active.is_file():
                    previous = self.read(json.loads(active.read_text())['run'])
                    if previous['id']!=run and previous['status']=='awaiting_reasoning':
                        raise ValueError('Another scanner run is awaiting reasoning; finish or cancel it first.')
                if not state['sourceRevision'] or not (self.directory(run)/'signals.json').is_file():
                    raise ValueError('Saved discovery has no completed source snapshot and signals to evaluate.')
                state.setdefault('discoveryStatus', state['status'])
                self.evaluation_engine().prepare(state)
                atomic(active, {'run':run})
                self.save(state)
                self.render(state)
                return self.public(state)
            finally:
                os.close(fd)

    def directory(self, run):
        if not re.fullmatch(r'scan_[a-f0-9]{24}', run):
            raise ValueError('Invalid scanner run ID.')
        return contained(self.output, run)

    def read(self, run):
        return json.loads(contained(self.directory(run), 'manifest.json').read_text())

    def lease(self):
        self.output.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.output / '.scan.lock', os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise ValueError('A scanner run is already active for this project.') from None
        return fd

    def save(self, state):
        with self.guard:
            state['updatedAt'] = now()
            atomic(self.directory(state['id']) / 'manifest.json', state)

    @staticmethod
    def public(state):
        names = ('id', 'status', 'stage', 'phase', 'sourceRevision', 'executionMode', 'modelCalls',
                 'signalCount', 'sourceReads', 'languages', 'coverageComplete', 'evaluation', 'message', 'createdAt', 'updatedAt')
        result = {name: state[name] for name in names}
        if state.get('networkJob'):
            result['networkJob'] = {name: state['networkJob'][name] for name in ('id', 'language')}
        if state.get('scope'):
            result['scope'] = state['scope']
        result['detectors']=state.get('config',{}).get('detectors',['codeql'])
        for key in ('policy','reasoning','evaluationSummary'):
            if key in state:result[key]=state[key]
        return result

    def status(self, run):
        with self.guard:
            state = self.read(run)
            if run in self.tasks:
                return self.public({**state, 'status':'running'})
            active = self.output/'active-run.json'
            if (state['status'] in TERMINAL or state['status']=='awaiting_reasoning') and active.is_file() and json.loads(active.read_text())['run']==run:
                try:
                    fd = self.lease()
                except ValueError:
                    return self.public({**state, 'status':'running'})
                try:
                    if state['status']=='awaiting_reasoning':
                        engine=self.task_engine(run)
                        engine.expire(state,engine.load(run))
                finally:
                    os.close(fd)
            if state['status'] not in TERMINAL and state['status']!='awaiting_reasoning' and run not in self.tasks:
                try:
                    fd = self.lease()
                except ValueError:
                    pass
                else:
                    try:
                        cancelled = (self.directory(run) / 'cancel-request.json').is_file()
                        state.update(status='cancelled' if cancelled else 'interrupted', message='Cancellation recorded.' if cancelled else 'The prior scanner process exited; resume to retry unfinished work.')
                        self.save(state)
                    finally:
                        os.close(fd)
            return self.public(state)

    def start(self, arguments):
        config_value=dict(arguments.get('config', {}))
        if arguments.get('detector'):
            config_value['detectors']=MANIFEST['detectorAliases'][arguments['detector']]
        config = settings(config_value)
        importing = arguments.get('importSarif', False)
        if not self.source.is_dir():
            raise ValueError('Connect an explicit source repository before discovery.')
        if importing and not Path(os.environ.get('BYPASS_SCANNER_SARIF', '/inputs/findings.sarif')).is_file():
            raise ValueError('The selected SARIF input is unavailable.')
        if importing and 'codeql' not in config['detectors']:
            raise ValueError('SARIF import requires the SAST detector.')
        if 'policy' in config['detectors'] and not config['policyCatalogs']:
            from bypass_scanner.discovery.policy import selected
            selected(config)
        if not importing and 'codeql' in config['detectors']:
            catalog = self.catalog()
            known = {rule['id'] for rule in catalog['rules']}
            if any(item not in known for item in [*config['includeRules'], *config['excludeRules']]):
                raise ValueError('Unknown CodeQL rule ID; inspect scanner rules before scanning.')
        fd = self.lease()
        run = 'scan_' + uuid4().hex[:24]
        try:
            active=self.output/'active-run.json'
            if active.is_file():
                previous=self.read(json.loads(active.read_text())['run'])
                if previous['status']=='awaiting_reasoning':
                    engine=self.task_engine(previous['id'])
                    engine.expire(previous,engine.load(previous['id']))
                    if previous['status']=='awaiting_reasoning':raise ValueError(f"Scanner run {previous['id']} is awaiting reasoning; resume or cancel it first.")
            self.directory(run).mkdir(mode=0o700)
            state = {'id': run, 'status': 'queued', 'stage': 'discovery', 'phase': 'snapshot', 'sourceRevision': '',
                     'executionMode': arguments.get('executionMode', 'standalone-api'), 'modelCalls': 0,
                     'signalCount': 0, 'sourceReads': 0, 'languages': [], 'coverageComplete': False, 'evaluation': 'not_run',
                     'message': 'Preparing source snapshot.', 'createdAt': now(), 'updatedAt': now(), 'config': config,
                     'importSarif': importing, 'imageIdentity': os.environ.get('BYPASS_SCANNER_IMAGE', 'development')}
            if 'projectDetails' in arguments:
                state['projectDetails']=arguments['projectDetails']
            self.reasoning_timeout(state,arguments.get('disableReasoningTimeout',False))
            self.save(state)
            atomic(active,{'run':run})
            self.launch(state, fd, False)
            return self.public(state)
        except BaseException:
            os.close(fd)
            raise

    def resume(self, run, disable_reasoning_timeout=False):
        state = self.read(run)
        self.reasoning_timeout(state,disable_reasoning_timeout)
        if state['status'] == 'completed' or run in self.tasks:
            return self.status(run)
        fd = self.lease()
        try:
            active = self.output / 'active-run.json'
            if active.is_file():
                previous = self.read(json.loads(active.read_text())['run'])
                if previous['id'] != run and previous['status'] == 'awaiting_reasoning':
                    engine=self.task_engine(previous['id'])
                    engine.expire(previous, engine.load(previous['id']))
                    if previous['status'] == 'awaiting_reasoning':
                        raise ValueError(f"Scanner run {previous['id']} is awaiting reasoning; resume or cancel it first.")
            if state['imageIdentity'] != os.environ.get('BYPASS_SCANNER_IMAGE', 'development'):
                raise ValueError('Scanner image changed; start a new scan instead of reusing this run.')
            atomic(active, {'run': run})
            self.launch(state, fd, True)
        except BaseException:
            os.close(fd)
            raise
        return self.public(state)

    def launch(self, state, fd, resuming):
        marker = self.directory(state['id']) / 'cancel-request.json'
        marker.unlink(missing_ok=True)
        event = CancellationToken(marker)
        worker = threading.Thread(target=self.run, args=(state, event, fd, resuming), daemon=True)
        self.tasks[state['id']] = (event, worker)
        state.update(status='running', message='Discovery running; results are unevaluated signals.')
        self.save(state)
        worker.start()

    def cancel(self, run):
        with self.guard:
            state = self.read(run)
            if state['status'] in TERMINAL:
                return self.public(state)
            atomic(self.directory(run) / 'cancel-request.json', {'requestedAt': now()})
            if state['status']=='awaiting_reasoning':
                state.update(status='cancelled',message='Scanner reasoning cancelled. Accepted signals, evaluations and evidence are retained.')
                self.save(state);self.render(state)
                return self.public(state)
            task = self.tasks.get(run)
            if task:
                task[0].set()
        result = self.status(run)
        if result['status'] not in TERMINAL:
            result['message'] = 'Cancellation requested; waiting for the active subprocess to stop. Completed artifacts are retained.'
        return result

    def run(self, state, cancel, fd, resuming):
        directory = self.directory(state['id'])
        try:
            if resuming and state['sourceRevision']:
                current = snapshot(self.source, cancel=cancel, include_generated=state['config'].get('includeGenerated', False))
                if current['revision'] != state['sourceRevision']:
                    raise ValueError('Source changed; start a new scan. Prior artifacts are retained.')
                recorded = json.loads((directory / 'source-manifest.json').read_text())
                if snapshot(directory / 'snapshot', cancel=cancel, include_generated=state['config'].get('includeGenerated', False))['revision'] != recorded['revision']:
                    raise ValueError('Saved source snapshot changed; start a new scan.')
            else:
                if (directory / 'snapshot').exists():
                    shutil.rmtree(directory / 'snapshot')
                recorded = snapshot(self.source, directory / 'snapshot', cancel, include_generated=state['config']['includeGenerated'])
                atomic(directory / 'source-manifest.json', recorded)
                state.update(sourceRevision=recorded['revision'], sourceReads=len(recorded['files']))
                self.save(state)
            if resuming and (directory/'evaluation/state.json').is_file():
                if not state['importSarif'] and any(not entry.get('queryComplete') for entry in state['languages']):
                    analysis, _ = select_scope(recorded, state['config'])
                    self.scan(state, analysis, cancel)
                    policy_gaps = state.get('policy') and any(c['outcome'] in ('needs_review','deferred')
                        for c in self.policy_engine().load(state['id'])['coverage'])
                    incomplete = policy_gaps or any(entry['status']!='completed' for entry in state['languages'])
                    state['discoveryStatus'] = 'incomplete' if incomplete else 'completed'
                if cancel.is_set():
                    raise InterruptedError('Cancellation requested.')
                self.evaluation_engine().prepare(state)
                return
            analysis, scope_manifest = select_scope(recorded, state['config'])
            atomic(directory / 'analysis-scope.json', scope_manifest)
            state['scope'] = scope_manifest['summary']
            self.save(state)
            if 'policy' in state['config'].get('detectors',[]):
                from bypass_scanner.discovery.policy import selected
                selected(state['config'],directory/'snapshot',analysis['files'])
            if state['importSarif']:
                self.import_sarif(state, analysis)
            elif 'codeql' in state['config'].get('detectors',['codeql']):
                try:self.scan(state, analysis, cancel)
                except InterruptedError:raise
                except Exception as error:
                    if 'policy' not in state['config'].get('detectors',[]):raise
                    state['languages'].append({'language':'codeql','status':'failed','message':str(error)[:2000]})
            if cancel.is_set():
                raise InterruptedError('Cancellation requested.')
            if 'policy' in state['config'].get('detectors',[]):
                self.policy_engine().prepare(state,analysis)
                return
            state.update(status='incomplete' if any(item['status'] in ('failed', 'partial', 'unknown', 'no_files') for item in state['languages']) else 'completed',
                         phase='done', message='Discovery finished. Signals are not evaluated vulnerabilities; inspect coverage gaps.')
            self.discovery_finished(state)
        except InterruptedError:
            state.update(status='cancelled', message='Scan cancelled. Completed artifacts are retained.')
        except Exception as error:
            # Configuration/tool errors contain no provider response or credential.
            state.update(status='incomplete', message=str(error)[:4000])
        finally:
            state.pop('networkJob', None)
            # Status must not advertise completion before artifacts and the
            # project lease are settled; a caller can start its next run at once.
            with self.guard:
                try:
                    self.save(state)
                    self.render(state)
                finally:
                    self.tasks.pop(state['id'], None)
                    os.close(fd)

    def scan(self, state, recorded, cancel):
        directory, config = self.directory(state['id']), state['config']
        catalog = self.catalog()
        if state.get('catalogIdentity') and state['catalogIdentity'] != catalog['identity']:
            raise ValueError('Pinned rule catalog changed; start a new scan.')
        state['catalogIdentity'] = catalog['identity']
        detected, unsupported = detect(recorded['files'])
        languages = config['languages'] or list(detected)
        if not languages:
            raise ValueError('No supported in-scope source language detected. Tests, examples, and generated copies are excluded by default; use include options when needed. Swift extraction is deferred.')
        selected = select_rules(catalog, languages, config['includeRules'], config['excludeRules'])
        atomic(directory / 'rule-selection.json', {'catalogIdentity': catalog['identity'], 'packs': catalog['packs'],
               'requested': config['includeRules'], 'excluded': config['excludeRules'], 'selected': selected})
        state['unsupportedLanguages'] = unsupported
        previous = {entry['language']: entry for entry in state['languages']}
        state['languages'] = []
        for language in languages:
            rules = [rule for rule in selected if rule['language'] == language]
            old = previous.get(language)
            entry = dict(old) if old else {'language': language, 'status': 'pending', 'phase': 'extract', 'ruleCount': len(rules), 'network': 'off'}
            state['languages'].append(entry)
        self.save(state)
        for entry in state['languages']:
            language = entry['language']
            if cancel.is_set():
                raise InterruptedError()
            if entry.get('queryComplete'):
                continue
            rules = [rule for rule in selected if rule['language'] == language]
            if not detected.get(language):
                entry.update(status='no_files', message='No applicable files in the source snapshot.')
                self.save(state)
                continue
            if not rules:
                entry.update(status='partial', message='No rules selected for this language; extraction not performed.')
                self.save(state)
                continue
            mode = LANGUAGES[language]['mode']
            if language == 'java' and any(path.endswith(('.kt', '.kts')) for path in detected[language]):
                mode = 'autobuild'
            build = {'mode': mode, 'network': 'off', **config['builds'].get(language, {})}
            if language == 'java' and build['mode'] == 'none' and any(path.endswith(('.kt', '.kts')) for path in detected[language]):
                entry['limitation'] = 'Java no-build extraction does not cover Kotlin.'
            entry['network'] = build['network']
            state['phase'] = 'extract/' + language
            self.save(state)
            try:
                if not entry.get('extractionComplete'):
                    if build['network'] == 'on':
                        self.network_extract(state, entry, build, cancel)
                    else:
                        codeql.extraction(directory, language, build, config['resources'], cancel)
                    entry['extractionComplete'] = True
                entry.update(status='running', phase='analyze')
                state['phase'] = 'analyze/' + language
                self.save(state)
                raw = codeql.analyze(directory, language, rules, catalog['auxiliary'].get(language, []), config['resources'], cancel)
                diagnostic = codeql.diagnostics(directory, language, cancel)
                document = json.loads(raw.read_text())
                filtered = []
                values, warnings = normalize(document, language, recorded, directory / 'languages' / language / 'work', raw.relative_to(directory).as_posix(), filtered=filtered)
                atomic(directory / 'languages' / language / 'signals.json', values)
                atomic(directory / 'languages' / language / 'filtered-signals.json', filtered)
                atomic(directory / 'languages' / language / 'normalization-warnings.json', warnings)
                evidence = coverage(document, json.loads(diagnostic.read_text()) if diagnostic else None,
                                    directory / 'languages' / language / 'extract.log')
                atomic(directory / 'languages' / language / 'coverage.json', evidence)
                entry.update(status='partial' if warnings or evidence['status'] == 'partial' or entry.get('limitation') else 'completed',
                             phase='done', queryComplete=True, signalCount=len(values), coverage=evidence['status'],
                             coverageArtifact=f'languages/{language}/coverage.json', rawArtifact=f'languages/{language}/raw.sarif',
                             filteredSignalCount=len(filtered), filteredArtifact=f'languages/{language}/filtered-signals.json',
                             message='Queries executed; full extraction coverage is not established.')
                self.aggregate(state)
            except InterruptedError:
                raise
            except Exception as error:
                entry.update(status='failed', message=str(error)[:2000])
                # Keep extraction diagnostics even after an unsuccessful build/query.
                if (directory / 'languages' / language / 'database').is_dir():
                    codeql.diagnostics(directory, language, cancel)
            self.save(state)
        self.aggregate(state)

    def network_extract(self, state, entry, build, cancel):
        directory = self.directory(state['id'])
        job = uuid4().hex
        atomic(directory / 'network' / (job + '.json'), {'id': job, 'language': entry['language'], 'build': build, 'resources': state['config']['resources']})
        state['networkJob'] = {'id': job, 'language': entry['language']}
        self.save(state)
        result = directory / 'network' / (job + '.result.json')
        deadline = time.monotonic() + state['config']['resources'].get('timeoutSeconds', MANIFEST['resourceDefaults']['timeoutSeconds']) + MANIFEST['networkStartupSeconds']
        try:
            while not result.is_file():
                if time.monotonic() >= deadline:
                    atomic(directory / 'network' / (job + '.cancel.json'), {'requestedAt': now()})
                    raise RuntimeError('Network-enabled extraction exceeded its configured timeout; retry or resume the run.')
                if cancel.wait(0.2):
                    raise InterruptedError()
        finally:
            state.pop('networkJob', None)
            self.save(state)
        value = json.loads(result.read_text())
        if not value.get('success'):
            raise RuntimeError(value.get('message', 'Network-enabled extraction failed.'))

    def build_failed(self, run, job):
        state = self.read(run)
        if state.get('networkJob', {}).get('id') != job:
            raise ValueError('Build job does not match the active extraction request.')
        path = self.directory(run) / 'network' / (job + '.result.json')
        if not path.exists():
            atomic(path, {'success': False, 'message': 'Build container exited without a completed extraction receipt.'})
        return self.status(run)

    def import_sarif(self, state, recorded):
        directory = self.directory(state['id'])
        target = directory / 'import.sarif'
        if not target.exists():
            shutil.copyfile(os.environ.get('BYPASS_SCANNER_SARIF', '/inputs/findings.sarif'), target)
        filtered = []
        values, warnings = normalize(json.loads(target.read_text()), 'import', recorded, self.source, 'import.sarif', filtered=filtered)
        included=set(state['config'].get('includeRules',[]));excluded=set(state['config'].get('excludeRules',[]))
        selected=[]
        for value in values:
            if (included and value['ruleId'] not in included) or value['ruleId'] in excluded:
                filtered.append({'ruleId':value['ruleId'],'origin':value['origin'],'reason':'SAST rule selection'})
            else:selected.append(value)
        values=selected
        atomic(directory / 'sarif-signals.json', values)
        atomic(directory / 'signals.json', values)
        atomic(directory / 'filtered-signals.json', filtered)
        atomic(directory / 'normalization-warnings.json', warnings)
        state.update(signalCount=len(values), languages=[{'language': 'import', 'status': 'partial' if warnings else 'completed', 'phase': 'done', 'signalCount': len(values), 'coverage': 'unknown','filteredSignalCount':len(filtered)}])
        state['scope']['filteredSignals'] = len(filtered)

    def aggregate(self, state):
        directory = self.directory(state['id'])
        values = []
        if state.get('importSarif'):
            imported=directory/'sarif-signals.json'
            if imported.is_file():values=json.loads(imported.read_text())
            elif not state.get('policy') and (directory/'signals.json').exists():values=json.loads((directory/'signals.json').read_text())
        for entry in state['languages']:
            path = directory / 'languages' / entry['language'] / 'signals.json'
            if path.is_file():
                values.extend(json.loads(path.read_text()))
        if state.get('policy'):
            policy=contained(directory,'policy/signals.json')
            if policy.is_file():values.extend(json.loads(policy.read_text()))
        atomic(directory / 'signals.json', values)
        state['signalCount'] = len(values)
        if state.get('scope'):
            state['scope']['filteredSignals'] = sum(entry.get('filteredSignalCount', 0) for entry in state['languages'])

    def render(self, state, project_details=None):
        directory = self.directory(state['id'])
        scope_file = directory / 'analysis-scope.json'
        if state.get('scope') and scope_file.is_file():
            scope_manifest = json.loads(scope_file.read_text())
            scope_manifest['summary'] = state['scope']
            atomic(scope_file, scope_manifest)
        signals = json.loads((directory / 'signals.json').read_text()) if (directory / 'signals.json').exists() else []
        cases_path = directory/'evaluation/cases.json'
        cases = json.loads(cases_path.read_text()) if cases_path.is_file() else []
        def recorded(name):
            filename=contained(directory,name)
            return json.loads(filename.read_text()) if filename.is_file() else None
        snapshot_record=recorded('source-manifest.json')
        rule_selection=recorded('rule-selection.json')
        policy_selection=recorded('policy/selection.json')
        policy_state=recorded('policy/state.json')
        identity=state.get('projectDetails') or project_details
        project={**(identity or {'name':self.source.name,'path':str(self.source)}),
                 'identitySource':'scan-start' if state.get('projectDetails') else 'current-connection' if project_details else 'scanner-path',
                 'snapshotFileCount':len(snapshot_record['files']) if snapshot_record else None,
                 'languages':list(detect(snapshot_record['files'])[0]) if snapshot_record else None}
        static_mode='sarif-import' if state.get('importSarif') else 'codeql' if 'codeql' in state['config'].get('detectors',['codeql']) else 'disabled'
        static={'mode':static_mode,
                'selectedRules':len(rule_selection['selected']) if rule_selection else 0 if static_mode=='disabled' else None,
                'completedQueryRules':sum(entry['ruleCount'] for entry in state['languages'] if entry.get('queryComplete')) if rule_selection else 0 if static_mode!='codeql' else None,
                'languages':[{'language':entry['language'],'selectedRules':entry['ruleCount'],
                              'completedQueryRules':entry['ruleCount'] if entry.get('queryComplete') else 0}
                             for entry in state['languages'] if 'ruleCount' in entry]}
        policy_tasks=[task for task in policy_state['tasks'] if task['status']=='done' and task['definition']['phase']=='policy'] if policy_state else None
        policy_analysis={'selectedRules':len(policy_selection['policies']) if policy_selection else None,
                         'reviewedRules':len({task['definition']['policyId'] for task in policy_tasks}) if policy_tasks is not None else None,
                         'completedTasks':len(policy_tasks) if policy_tasks is not None else None,
                         'deferredInvestigations':state['policy']['deferred'] if state.get('policy') else None}
        report = {'run': self.public(state), 'signals': signals, 'unsupportedLanguages': state.get('unsupportedLanguages', []),
                  'cases':cases,
                  'project':project, 'analysis':{'static':static,'policy':policy_analysis},
                  'scope': state.get('scope', {'status': 'not_recorded_for_this_run'}),
                  'artifacts': [item for item in self.artifacts(state['id']) if item['path'] not in ('report.json', 'report.md')],
                  'selection': 'rule-selection.json' if (directory / 'rule-selection.json').exists() else None,
                  'notice': 'Original detector signals are retained unchanged. Evaluation verdicts are source-based, not runtime reproductions. Unresolved and unevaluated cases are not safety claims. Complete security coverage is not established.'}
        atomic(directory / 'report.json', report)
        confirmed = [case for case in cases if case['outcome']=='confirmed']
        if any(not case.get('evaluation') for case in confirmed):
            raise ValueError('A confirmed report case is missing its source evaluation.')
        severity_order = {'critical':0,'high':1,'medium':2,'low':3,'info':4,'unknown':5}
        confirmed.sort(key=lambda case:severity_order.get(case['evaluation']['severity'],5))
        by_id = {item['id']:item for item in signals}
        findings=[]
        for case in confirmed:
            related=[by_id[identity] for identity in case['signalIds']]
            metadata=related[0].get('ruleMetadata',{})
            description=metadata.get('shortDescription')
            titles=[description.get('text') if isinstance(description,dict) else None,
                    metadata.get('title'),related[0]['suspectedIssue']]
            title=' '.join(next(value for value in titles if isinstance(value,str) and value.strip()).split())
            findings.append((case,related,title))
        analysed_ids = {identity for case in cases if case.get('evaluation') for identity in case['signalIds']}
        unanalysed = sum(item['id'] not in analysed_ids for item in signals)
        unresolved = sum(case['outcome']=='needs_review' and bool(case.get('evaluation')) for case in cases)
        lines = ['# Security scan report', '', report['notice'], '', '## Contents', '',
                 '- [Analysed project](#analysed-project)', '- [Executed analysis](#executed-analysis)',
                 '- [Summary](#summary)', '- [Confirmed findings](#confirmed-findings)']
        for number,(case,_,title) in enumerate(findings,1):
            link_title=title.replace('\\','\\\\').replace('[','\\[').replace(']','\\]')
            lines.append(f"  - [{number}. {link_title} - {case['evaluation']['severity'].title()}](#finding-{number})")
        lines.extend(['- [Scan details](#scan-details)', '', '## Analysed project', '',
                      f"**Project:** {project['name']}  ", f"**Source path:** `{project['path']}`  ",
                      f"**Source snapshot digest:** `{state['sourceRevision']}`  ",
                      f"**Snapshot files:** {project['snapshotFileCount'] if project['snapshotFileCount'] is not None else 'Not recorded'}  ",
                      '**Detected source languages:** '+(', '.join(project['languages']) if project['languages'] is not None else 'Not recorded')])
        if project['identitySource']=='current-connection':
            lines.extend(['', 'Project name and path describe the current selected connection; they were not recorded when this scan started.'])
        elif project['identitySource']=='scanner-path':
            lines.extend(['', 'Only the scanner-visible source path is available; the original host project identity was not recorded.'])
        scope=state.get('scope')
        if scope:
            lines.extend(['', f"**Source files eligible for analysis:** {scope['analysisFiles']}  ",
                          f"**Build-context files retained:** {scope['contextFiles']}  ",
                          f"**Snapshot files outside analysis scope:** {scope['excludedFiles']}  ",
                          f"**Include tests / examples / generated files:** {scope['includeTests']} / {scope['includeExamples']} / {scope['includeGenerated']}",
                          'Eligible source files are a subset of the retained snapshot, not an additional file count.'])
        lines.extend(['', '## Executed analysis', '',
                      '| Analysis | Count |', '| --- | ---: |',
                      f"| Static rules selected | {static['selectedRules'] if static['selectedRules'] is not None else 'Not recorded'} |",
                      f"| Static rules in completed query runs | {static['completedQueryRules'] if static['completedQueryRules'] is not None else 'Not recorded'} |"])
        if static_mode=='sarif-import':
            lines.extend(['', 'SARIF import: No static-analysis rules were executed by this scan. The imported alerts do not establish rule-execution coverage.'])
        elif static_mode=='disabled':
            lines.extend(['', 'Static code analysis was not enabled.'])
        if static['languages']:
            lines.extend(['', '| Static-analysis language | Rules selected | Rules in completed query runs |',
                          '| --- | ---: | ---: |'])
            lines.extend(f"| {entry['language']} | {entry['selectedRules']} | {entry['completedQueryRules']} |" for entry in static['languages'])
        if policy_selection or state.get('policy'):
            lines.extend(['', '| Policy analysis | Count |', '| --- | ---: |'])
            for label,key in (('Policy rules selected','selectedRules'),('Distinct policy rules reviewed','reviewedRules'),
                              ('Completed policy review tasks','completedTasks'),('Deferred policy investigations','deferredInvestigations')):
                count=policy_analysis[key]
                lines.append(f"| {label} | {count if count is not None else 'Not recorded'} |")
            lines.extend(['', 'A reviewed policy rule has at least one completed surface review; this is not exhaustive coverage. '
                          'Mapping tasks and repeated follow-ups are not additional distinct rules.'])
        else:
            lines.extend(['', 'Policy analysis was not enabled.'])
        lines.extend(['', 'Rules in completed query runs count successfully completed query batches, not failed or partial query attempts.',
                      f"Evaluation: {state['evaluation']}  ",
                      f"Independent policy / evaluation API requests: {state.get('policy',{}).get('modelRequests','Not recorded') if state.get('policy') else 0} / "
                      f"{state.get('evaluationSummary',{}).get('modelRequests','Not recorded') if state.get('evaluationSummary') else 0}  ",
                      f"Started: {state['createdAt']}  ", f"Last scan checkpoint: {state['updatedAt']}",
                      '', '## Summary', '',
                 '| Outcome | Count |', '| --- | ---: |',
                 f'| Source-confirmed findings | {len(confirmed)} |',
                 f"| Refuted | {sum(case['outcome']=='refuted' for case in cases)} |",
                 f'| Unresolved after analysis | {unresolved} |',
                 f'| Not analysed | {unanalysed} |',
                 f'| Total candidate signals | {len(signals)} |', '',
                 'Not analysed includes candidates marked `needs_review` without an evidence-backed evaluation.',
                 'Only confirmed findings are detailed below. Full records for every outcome remain in '
                 '`report.json` and `evaluation/cases.json`.', '', '## Confirmed findings', ''])
        if not confirmed:
            lines.append('No source-confirmed findings.')
        for number, (case,related,title) in enumerate(findings,1):
            evaluation = case['evaluation']
            lines.extend(['', '---', '', f'<a id="finding-{number}"></a>', '', f'### Finding {number}: {title}', '',
                          f"**Severity:** {evaluation['severity'].replace('_',' ').title()}", '',
                          '**Issue**', '', evaluation['rationale'], '',
                          '**Impact**', '', evaluation['impact'], '',
                          '**Recommended next action**', '', evaluation['nextAction'], '',
                          '#### Details', '', '**Affected locations**', ''])
            locations = sorted({(ref['path'],ref['startLine'],ref['endLine'])
                                for item in related for ref in item['locations']})
            for filename, start, end in locations:
                location = f'{filename}:{start}' if start==end else f'{filename}:{start}-{end}'
                lines.append(f'- `{location}`')
            lines.extend(['', '**Supporting evidence**', ''])
            lines.extend(f"- `{ref['path']}:{ref['startLine']}-{ref['endLine']}`" for ref in evaluation['evidence'])
            lines.extend(['', '**Severity explanation**', '', evaluation['severityRationale'],
                          '', '**Counterevidence considered**', '', evaluation['counterevidence']])
            for label, key in (('Prerequisites','prerequisites'),('Open questions','openQuestions')):
                if evaluation[key]:
                    lines.extend(['', '**'+label+'**', ''])
                    lines.extend('- '+item for item in evaluation[key])
            if case.get('reason'):
                lines.extend(['', '**Limitation**', '', case['reason']])
            rules = ', '.join('`'+name+'`' for name in dict.fromkeys(item['ruleId'] for item in related))
            detectors = ', '.join(dict.fromkeys('CodeQL' if item['detector']=='codeql' else item['detector'].title() for item in related))
            lines.extend(['', f'**Detector:** {detectors}  ', f'**Rule:** {rules}  ',
                          f"**Case reference:** `{case['id']}`"])
        lines.extend(['', '---', '', '## Scan details', '',
                      f"Run: `{state['id']}`  ", f"Status: **{state['status']}**  ",
                      f"Source revision: `{state['sourceRevision']}`  ",
                      f"Independent API request attempts: {state.get('reasoning',{}).get('independentModelRequests',state.get('modelCalls',0))}",
                      'Muse host reasoning usage: unknown' if state.get('reasoning',{}).get('hostReasoning') else 'Muse host reasoning: not used'])
        policy = state.get('policy')
        if policy:
            lines.extend(['', f"Policy tasks completed: {policy['finished']}/{policy['tasks']}. "
                          f"Deferred policy investigations: {policy['deferred']}. See `policy/coverage.json` for coverage gaps."])
        lines.extend(f"- {entry['language']}: {entry['status']}; {entry.get('message','')}" for entry in state['languages'])
        if state.get('unsupportedLanguages'):
            lines.append('- Unsupported/deferred languages: '+', '.join(state['unsupportedLanguages']))
        if scope:
            lines.extend(['', f"Filtered detector alerts: {scope['filteredSignals']}. See `analysis-scope.json` for source selection.",
                          'File counts do not establish extraction or complete security coverage.'])
        lines.extend(['', '**Run note**', '', state['message']])
        (directory / 'report.md').write_text('\n'.join(lines) + '\n')

    def artifacts(self, run):
        directory = self.directory(run)
        allowed = [directory / name for name in ('manifest.json', 'source-manifest.json', 'analysis-scope.json', 'rule-selection.json', 'signals.json', 'sarif-signals.json', 'filtered-signals.json', 'normalization-warnings.json', 'import.sarif', 'report.json', 'report.md')]
        for folder in (directory / 'languages').glob('*') if (directory / 'languages').exists() else []:
            allowed.extend(folder / name for name in ('raw.sarif', 'diagnostics.sarif', 'coverage.json', 'signals.json', 'filtered-signals.json', 'normalization-warnings.json', 'selected.qls', 'codeql-scope.json'))
            allowed.extend(folder.glob('*.log'))
        policy=directory/'policy'
        if policy.is_dir() and not policy.is_symlink():
            allowed.extend(policy/name for name in ('selection.json','context.json','threat-model.json','coverage.json','signals.json'))
            for name in ('submissions','evidence'):
                folder=policy/name
                if folder.is_dir() and not folder.is_symlink():allowed.extend(folder.glob('*.json'))
        evaluation=directory/'evaluation'
        if evaluation.is_dir() and not evaluation.is_symlink():
            allowed.extend(evaluation/name for name in ('cases.json','coverage.json'))
            for name in ('submissions','evidence'):
                folder=evaluation/name
                if folder.is_dir() and not folder.is_symlink():
                    allowed.extend(folder.glob('*.json'))
        return [{'path': path.relative_to(directory).as_posix(), 'bytes': path.stat().st_size}
                for path in allowed if path.is_file() and not path.is_symlink()]

    def artifact(self, run, path, offset):
        if path not in {item['path'] for item in self.artifacts(run)}:
            raise ValueError('Artifact is not available in this scan.')
        file = contained(self.directory(run), path)
        if offset > file.stat().st_size:
            raise ValueError('Artifact offset exceeds its size.')
        with file.open('rb') as stream:
            stream.seek(offset)
            data = stream.read(12000)
        if offset + len(data) < file.stat().st_size:
            while data:
                try:
                    text = data.decode('utf-8')
                    break
                except UnicodeDecodeError as error:
                    if error.end == len(data):
                        data = data[:error.start]
                    else:
                        text = data.decode('utf-8', errors='replace')
                        break
            else:
                text = ''
        else:
            text = data.decode('utf-8', errors='replace')
        return {'text': text, 'nextOffset': offset + len(data) if offset + len(data) < file.stat().st_size else -1}

    def close(self):
        for run in list(self.tasks):
            self.cancel(run)
        for _, worker in list(self.tasks.values()):
            worker.join(timeout=5)
