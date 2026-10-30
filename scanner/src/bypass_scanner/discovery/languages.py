"""Pinned CodeQL language-family registry; language detection is local."""
LANGUAGES = {
    'cpp': {'extensions': ['.c', '.cc', '.cpp', '.cxx', '.c++', '.h', '.hh', '.hpp', '.hxx'], 'mode': 'none', 'modes': ['none', 'autobuild', 'manual']},
    'csharp': {'extensions': ['.cs', '.cshtml'], 'mode': 'none', 'modes': ['none', 'autobuild', 'manual']},
    'go': {'extensions': ['.go'], 'mode': 'autobuild', 'modes': ['autobuild', 'manual']},
    'java': {'extensions': ['.java', '.kt', '.kts'], 'mode': 'none', 'modes': ['none', 'autobuild', 'manual']},
    'javascript': {'extensions': ['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts', '.vue'], 'mode': 'none', 'modes': ['none']},
    'python': {'extensions': ['.py'], 'mode': 'none', 'modes': ['none']},
    'ruby': {'extensions': ['.rb', '.erb', '.gemspec'], 'mode': 'none', 'modes': ['none']},
    'rust': {'extensions': ['.rs'], 'mode': 'none', 'modes': ['none']},
    'actions': {'extensions': [], 'mode': 'none', 'modes': ['none']},
}


def detect(files):
    from pathlib import PurePosixPath
    found = {name: [] for name in LANGUAGES}
    unsupported = set()
    for filename in files:
        path = PurePosixPath(filename)
        if path.suffix.lower() == '.swift':
            unsupported.add('swift')
        if (filename.startswith('.github/workflows/') or path.name in ('action.yml', 'action.yaml')) and path.suffix in ('.yml', '.yaml'):
            found['actions'].append(filename)
        for language, settings in LANGUAGES.items():
            if path.suffix.lower() in settings['extensions']:
                found[language].append(filename)
    return {name: paths for name, paths in found.items() if paths}, sorted(unsupported)
