"""Shared nonproduction path policy; build context and analysis scope are distinct."""
import fnmatch
from pathlib import PurePosixPath

from bypass_scanner.contracts import MANIFEST

POLICY = MANIFEST['sourceScope']


def options(config):
    return {entry['option']: config.get(entry['option'], False) for entry in POLICY['categories'].values()}


def excluded_category(name, config):
    path = PurePosixPath(name)
    directories = [part.lower() for part in path.parts[:-1]]
    lowered = path.as_posix().lower()
    for category, entry in POLICY['categories'].items():
        if config.get(entry['option'], False):
            continue
        if (any(part in entry['directories'] or any(part.endswith(suffix) for suffix in entry['directorySuffixes']) for part in directories)
                or any(fnmatch.fnmatchcase(path.name, pattern) for pattern in entry['filePatterns'])
                or any(lowered == prefix or lowered.startswith(prefix + '/') for prefix in entry['paths'])):
            return category
    return None


def select(recorded, config):
    includes = options(config)
    files, excluded = {}, []
    counts = {category: 0 for category in POLICY['categories']}
    for name, metadata in recorded['files'].items():
        category = excluded_category(name, includes)
        if category:
            counts[category] += 1
            excluded.append({'path': name, 'category': category, 'reason': 'excluded by default analysis scope'})
        else:
            files[name] = metadata
    summary = {'policyVersion': POLICY['version'], **includes, 'contextFiles': len(recorded['files']),
               'analysisFiles': len(files), 'excludedFiles': len(excluded), 'excludedByCategory': counts,
               'filteredSignals': 0, 'artifact': 'analysis-scope.json'}
    manifest = {'summary': summary, 'includedPaths': list(files), 'exclusions': excluded,
                'codeqlIgnorePaths': ignore_patterns(includes),
                'notice': 'Build context is retained. No-build extraction uses path filters; built languages can still extract excluded inputs. Alerts are filtered by primary location. Inline tests in production files remain in scope.'}
    return {**recorded, 'files': files, 'scopeOptions': includes,
            'contextExcludedPaths': [entry['path'] for entry in recorded.get('exclusions', [])]}, manifest


def alert_exclusion(name, recorded):
    category = excluded_category(name, recorded['scopeOptions'])
    if category:
        return category
    if any(name == prefix or name.startswith(prefix.rstrip('/') + '/') for prefix in recorded.get('contextExcludedPaths', [])):
        return 'source_policy'
    return None


def ignore_patterns(config):
    """CodeQL path filters support ** path segments and * within a segment."""
    patterns = set()
    for entry in POLICY['categories'].values():
        if config.get(entry['option'], False):
            continue
        for directory in entry['directories']:
            for variant in {directory, directory.capitalize(), directory.upper()}:
                patterns.add('**/' + variant + '/**')
        for suffix in entry['directorySuffixes']:
            for variant in {suffix, suffix.title(), suffix.upper()}:
                patterns.add('**/*' + variant + '/**')
        patterns.update('**/' + pattern for pattern in entry['filePatterns'])
        patterns.update(prefix + '/**' for prefix in entry['paths'])
    return sorted(patterns)
