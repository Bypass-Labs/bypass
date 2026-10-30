"""Snapshot selected regular files without executing code or changing the source."""
import fnmatch
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess

EXCLUDED = {'.git', '.bypass', 'node_modules', '.venv', '__pycache__'}
BUILD_CACHES = {'.next', 'coverage', 'dist', 'target'}


def relative(value):
    path = PurePosixPath(value)
    if not value or path.is_absolute() or '\\' in value or any(part in ('..', '') for part in path.parts):
        raise ValueError('Use a repository-relative path without traversal.')
    return path.as_posix()


def contained(root, value):
    value = relative(value)
    target = root / value
    current = root
    for part in PurePosixPath(value).parts:
        current /= part
        if current.is_symlink():
            raise ValueError('Symlinked paths are outside scanner scope.')
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError('Path escapes scanner scope.')
    return target


def patterns(root):
    file = root / '.bypassignore'
    if file.is_file() and not file.is_symlink():
        return [line.strip() for line in file.read_text().splitlines() if line.strip() and not line.startswith('#')]
    return []


def ignored(name, custom, include_generated=False):
    path = PurePosixPath(name)
    if any(part in EXCLUDED or part == '.env' or part.startswith('.env.') for part in path.parts):
        return True
    if not include_generated and any(part in BUILD_CACHES for part in path.parts):
        return True
    if path.suffix.lower() in ('.pem', '.key', '.p12', '.pfx'):
        return True
    return any(fnmatch.fnmatchcase(name, pattern.rstrip('/')) or
               fnmatch.fnmatchcase(path.name, pattern) or name.startswith(pattern.rstrip('/') + '/')
               for pattern in custom)


def inventory(root, include_generated=False):
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Source must be a directory.')
    custom, exclusions = patterns(root), []
    try:
        result = subprocess.run(['git', '-c', f'safe.directory={root}', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
                                 '-C', str(root), 'ls-files', '-z', '--cached', '--others', '--exclude-standard'],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        result = None
    if result is not None and result.returncode == 0:
        candidates = result.stdout.decode('utf-8').split('\0')
    else:
        candidates = []
        def walk(directory):
            for entry in sorted(os.scandir(directory), key=lambda item: item.name):
                name = Path(entry.path).relative_to(root).as_posix()
                if ignored(name, custom, include_generated) or entry.is_symlink():
                    exclusions.append({'path': name, 'reason': 'excluded path or symlink'})
                elif entry.is_dir(follow_symlinks=False):
                    walk(entry.path)
                else:
                    candidates.append(name)
        walk(root)
    files = []
    for name in sorted(set(candidates)):
        if not name:
            continue
        if ignored(name, custom, include_generated):
            exclusions.append({'path': name, 'reason': 'excluded by source policy'})
            continue
        try:
            path = contained(root, name)
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError('Not a regular file.')
            files.append(name)
        except (OSError, ValueError):
            exclusions.append({'path': name, 'reason': 'missing, symlinked, or special file'})
    return files, exclusions


def snapshot(root, destination=None, cancel=None, include_generated=False):
    files, exclusions = inventory(root, include_generated)
    hashes = {}
    for name in files:
        if cancel and cancel.is_set():
            raise InterruptedError('Scan cancelled during source snapshot.')
        source = contained(root, name)
        fd = os.open(source, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError('Source changed to a special file during snapshot.')
            sha = hashlib.sha256()
            newlines, size, last = 0, 0, b''
            output = None
            if destination is not None:
                target = destination / name
                target.parent.mkdir(parents=True, exist_ok=True)
                output = target.open('wb')
            try:
                while chunk := stream.read(1024 * 1024):
                    sha.update(chunk)
                    newlines += chunk.count(b'\n')
                    size += len(chunk)
                    last = chunk[-1:]
                    if output:
                        output.write(chunk)
                after = os.fstat(stream.fileno())
                if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    raise ValueError('Source changed during snapshot; start a new scan.')
            finally:
                if output:
                    output.close()
            executable = stat.S_IMODE(before.st_mode) & 0o111
            hashes[name] = {'sha256': sha.hexdigest(), 'executable': executable, 'lineCount': newlines + int(size > 0 and last != b'\n')}
            if destination is not None:
                os.chmod(destination / name, 0o444 | executable)
    revision = hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'revision': revision, 'files': hashes, 'exclusions': exclusions}
