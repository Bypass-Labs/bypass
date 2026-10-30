"""Execute pinned CodeQL subprocesses with file logs and cancellable process groups."""
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import time

from bypass_scanner.discovery.languages import LANGUAGES
from bypass_scanner.repository.snapshot import contained


def codeql():
    return os.environ.get('BYPASS_CODEQL', '/opt/codeql/codeql')


def environment(directory):
    # Never inherit user credentials, proxies, registry auth, or CodeQL settings.
    env = {key: os.environ[key] for key in ('PATH', 'JAVA_HOME', 'DOTNET_ROOT', 'RUSTUP_HOME', 'LD_LIBRARY_PATH') if key in os.environ}
    home = directory / 'home'
    home.mkdir(exist_ok=True)
    env.update(HOME=str(home), TMPDIR=str(home), PYTHONDONTWRITEBYTECODE='1',
               DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1',
               CARGO_HOME=str(home / 'cargo'), GOCACHE=str(home / 'go-build'), GOPATH=str(home / 'go'),
               CODEQL_EXTRACTOR_CPP_AUTOINSTALL_DEPENDENCIES='false')
    return env


def execute(argv, cwd, directory, name, cancel, timeout=None):
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / (name + '.log')).open('ab') as log:
        child = subprocess.Popen(argv, cwd=cwd, env=environment(directory), stdout=log, stderr=log, start_new_session=True)
        started = time.monotonic()
        try:
            while child.poll() is None:
                if cancel.is_set() or (timeout is not None and time.monotonic() - started > timeout):
                    os.killpg(child.pid, signal.SIGTERM)
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                    if cancel.is_set():
                        raise InterruptedError('Scan cancelled.')
                    raise RuntimeError(f'{name} exceeded its configured timeout; see its log.')
                time.sleep(0.1)
            if child.returncode:
                raise RuntimeError(f'{name} failed with exit code {child.returncode}; see its log.')
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
            child.wait()


def extraction(directory, language, build, resources, cancel):
    target = directory / 'languages' / language
    target.mkdir(parents=True, exist_ok=True)
    work = target / 'work'
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(directory / 'snapshot', work)
    for root, dirs, files in os.walk(work):
        os.chmod(root, 0o755)
        for name in files:
            path = Path(root) / name
            path.chmod(0o644 | (path.stat().st_mode & 0o111))
    cwd_value = build.get('cwd', '.')
    cwd = work if cwd_value == '.' else contained(work, cwd_value)
    if not cwd.is_dir():
        raise ValueError('Build working directory must exist inside the source snapshot.')
    timeout = resources.get('timeoutSeconds')
    for index, command in enumerate(build.get('prepare', [])):
        execute(command, cwd, target, f'prepare-{index}', cancel, timeout)
    database = target / 'database'
    if database.exists():
        shutil.rmtree(database)
    mode = build['mode']
    args = [codeql(), 'database', 'create', str(database), f'--language={language}',
            f'--source-root={work}', f'--threads={resources["threads"]}', f'--ram={resources["ramMb"]}']
    scope_file = directory / 'analysis-scope.json'
    if mode == 'none' and scope_file.is_file():
        ignored = json.loads(scope_file.read_text())['codeqlIgnorePaths']
        if ignored:
            scope_config = target / 'codeql-scope.json'
            scope_config.write_text(json.dumps({'paths-ignore': ignored}) + '\n')
            args.append('--codescanning-config=' + str(scope_config))
    if mode == 'manual':
        launcher = target / 'build.sh'
        launcher.write_text('#!/bin/sh\nset -eu\nexec ' + shlex.join(build['command']) + '\n')
        # CodeQL tokenizes --command itself; it understands double-quoted paths.
        args.append('--command=/bin/sh ' + json.dumps(str(launcher)))
    else:
        args.append('--build-mode=' + mode)
    execute(args, cwd, target, 'extract', cancel, timeout)
    if not (database / 'codeql-database.yml').is_file():
        raise RuntimeError('CodeQL did not create a finalized database.')


def analyze(directory, language, rules, auxiliary, resources, cancel):
    target = directory / 'languages' / language
    suite = target / 'selected.qls'
    paths = sorted(set([rule['path'] for rule in rules] + auxiliary))
    # JSON string quoting is also valid YAML quoting; IDs never become shell text.
    suite.write_text('\n'.join('- query: ' + json.dumps(path) for path in paths) + '\n')
    execute([codeql(), 'database', 'analyze', str(target / 'database'), str(suite),
             '--format=sarifv2.1.0', '--output=' + str(target / 'raw.sarif'),
             '--sarif-category=bypass/' + language, '--sarif-add-baseline-file-info',
             '--threads=' + str(resources['threads']), '--ram=' + str(resources['ramMb'])],
            target, target, 'analyze', cancel, resources.get('timeoutSeconds'))
    return target / 'raw.sarif'


def diagnostics(directory, language, cancel):
    target = directory / 'languages' / language
    path = target / 'diagnostics.sarif'
    try:
        execute([codeql(), 'database', 'export-diagnostics', str(target / 'database'),
                 '--format=sarifv2.1.0', '--output=' + str(path)], target, target, 'diagnostics', cancel, 60)
    except (OSError, RuntimeError):
        return None
    return path
