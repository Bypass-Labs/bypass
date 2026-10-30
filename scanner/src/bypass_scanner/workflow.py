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
    result = {'languages': list(dict.fromkeys(value.get('languages', []))), 'includeRules': list(dict.fromkeys(value.get('includeRules', []))),
              'excludeRules': list(dict.fromkeys(value.get('excludeRules', []))), 'builds': value.get('builds', {}), **scope_options(value),
              'resources': {**MANIFEST['resourceDefaults'], **value.get('resources', {})}}
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
        return result

    def status(self, run):
        with self.guard:
            state = self.read(run)
            if state['status'] not in TERMINAL and run not in self.tasks:
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
        config = settings(arguments.get('config', {}))
        importing = arguments.get('importSarif', False)
        if not self.source.is_dir():
            raise ValueError('Connect an explicit source repository before discovery.')
        if importing and not Path(os.environ.get('BYPASS_SCANNER_SARIF', '/inputs/findings.sarif')).is_file():
            raise ValueError('The selected SARIF input is unavailable.')
        if not importing:
            catalog = self.catalog()
            known = {rule['id'] for rule in catalog['rules']}
            if any(item not in known for item in [*config['includeRules'], *config['excludeRules']]):
                raise ValueError('Unknown CodeQL rule ID; inspect scanner rules before scanning.')
        fd = self.lease()
        run = 'scan_' + uuid4().hex[:24]
        try:
            self.directory(run).mkdir(mode=0o700)
            state = {'id': run, 'status': 'queued', 'stage': 'discovery', 'phase': 'snapshot', 'sourceRevision': '',
                     'executionMode': arguments.get('executionMode', 'standalone-api'), 'modelCalls': 0,
                     'signalCount': 0, 'sourceReads': 0, 'languages': [], 'coverageComplete': False, 'evaluation': 'not_run',
                     'message': 'Preparing source snapshot.', 'createdAt': now(), 'updatedAt': now(), 'config': config,
                     'importSarif': importing, 'imageIdentity': os.environ.get('BYPASS_SCANNER_IMAGE', 'development')}
            self.save(state)
            self.launch(state, fd, False)
            return self.public(state)
        except BaseException:
            os.close(fd)
            raise

    def resume(self, run):
        state = self.read(run)
        if state['status'] == 'completed' or run in self.tasks:
            return self.status(run)
        fd = self.lease()
        if state['imageIdentity'] != os.environ.get('BYPASS_SCANNER_IMAGE', 'development'):
            os.close(fd)
            raise ValueError('Scanner image changed; start a new scan instead of reusing this run.')
        self.launch(state, fd, True)
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
            analysis, scope_manifest = select_scope(recorded, state['config'])
            atomic(directory / 'analysis-scope.json', scope_manifest)
            state['scope'] = scope_manifest['summary']
            self.save(state)
            if state['importSarif']:
                self.import_sarif(state, analysis)
            else:
                self.scan(state, analysis, cancel)
            if cancel.is_set():
                raise InterruptedError('Cancellation requested.')
            state.update(status='incomplete' if any(item['status'] in ('failed', 'partial', 'unknown', 'no_files') for item in state['languages']) else 'completed',
                         phase='done', message='Discovery finished. Signals are not evaluated vulnerabilities; inspect coverage gaps.')
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
        atomic(directory / 'signals.json', values)
        atomic(directory / 'filtered-signals.json', filtered)
        atomic(directory / 'normalization-warnings.json', warnings)
        state.update(signalCount=len(values), languages=[{'language': 'import', 'status': 'partial' if warnings else 'completed', 'phase': 'done', 'signalCount': len(values), 'coverage': 'unknown'}])
        state['scope']['filteredSignals'] = len(filtered)

    def aggregate(self, state):
        directory = self.directory(state['id'])
        values = []
        for entry in state['languages']:
            path = directory / 'languages' / entry['language'] / 'signals.json'
            if path.is_file():
                values.extend(json.loads(path.read_text()))
        atomic(directory / 'signals.json', values)
        state['signalCount'] = len(values)
        if state.get('scope'):
            state['scope']['filteredSignals'] = sum(entry.get('filteredSignalCount', 0) for entry in state['languages'])

    def render(self, state):
        directory = self.directory(state['id'])
        scope_file = directory / 'analysis-scope.json'
        if state.get('scope') and scope_file.is_file():
            scope_manifest = json.loads(scope_file.read_text())
            scope_manifest['summary'] = state['scope']
            atomic(scope_file, scope_manifest)
        signals = json.loads((directory / 'signals.json').read_text()) if (directory / 'signals.json').exists() else []
        report = {'run': self.public(state), 'signals': signals, 'unsupportedLanguages': state.get('unsupportedLanguages', []),
                  'scope': state.get('scope', {'status': 'not_recorded_for_this_run'}),
                  'artifacts': [item for item in self.artifacts(state['id']) if item['path'] not in ('report.json', 'report.md')],
                  'selection': 'rule-selection.json' if (directory / 'rule-selection.json').exists() else None,
                  'notice': 'Detector signals are unevaluated. No confirmed/refuted vulnerability verdict or complete security coverage is claimed.'}
        atomic(directory / 'report.json', report)
        lines = ['# CodeQL discovery report', '', f"Run: {state['id']}", f"Status: {state['status']}",
                 f"Source revision: {state['sourceRevision']}", f"Signals: {len(signals)}", 'Model calls: 0', '', report['notice'], '', '## Coverage', '']
        lines.extend(f"- {entry['language']}: {entry['status']}; {entry.get('message', '')}" for entry in state['languages'])
        if state.get('unsupportedLanguages'):
            lines.append('- Unsupported/deferred: ' + ', '.join(state['unsupportedLanguages']))
        scope = state.get('scope')
        if scope:
            lines.extend(['', '## Analysis scope', '',
                          f"Eligible files: {scope['analysisFiles']}; build-context files: {scope['contextFiles']}; excluded files: {scope['excludedFiles']}.",
                          f"Include tests: {scope['includeTests']}; examples/benchmarks: {scope['includeExamples']}; generated/vendor copies: {scope['includeGenerated']}.",
                          f"Filtered detector alerts: {scope['filteredSignals']}. See analysis-scope.json and filtered-signals.json artifacts.",
                          'Build context is retained; compiled builds can extract excluded inputs. Candidate alerts are filtered by primary location. These file counts do not establish extraction coverage.'])
        lines.extend(['', '## Unevaluated signals', ''])
        lines.extend(f"- `{item['ruleId']}`: {item['suspectedIssue'].replace(chr(10), ' ')} (raw: {item['origin']['artifact']}, result {item['origin']['resultIndex']})" for item in signals)
        lines.extend(['', '## Run diagnostics', '', state['message']])
        (directory / 'report.md').write_text('\n'.join(lines) + '\n')

    def artifacts(self, run):
        directory = self.directory(run)
        allowed = [directory / name for name in ('manifest.json', 'source-manifest.json', 'analysis-scope.json', 'rule-selection.json', 'signals.json', 'filtered-signals.json', 'normalization-warnings.json', 'import.sarif', 'report.json', 'report.md')]
        for folder in (directory / 'languages').glob('*') if (directory / 'languages').exists() else []:
            allowed.extend(folder / name for name in ('raw.sarif', 'diagnostics.sarif', 'coverage.json', 'signals.json', 'filtered-signals.json', 'normalization-warnings.json', 'selected.qls', 'codeql-scope.json'))
            allowed.extend(folder.glob('*.log'))
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
