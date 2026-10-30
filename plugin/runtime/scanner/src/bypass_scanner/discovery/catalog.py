"""Build an offline rule catalog from the pinned official CodeQL query packs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from bypass_scanner.discovery.languages import LANGUAGES


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def metadata(text):
    return {key: re.sub(r'\s+', ' ', value.replace('\n *', ' ')).strip(' */\n')
            for key, value in re.findall(r'@([\w.]+)\s+([^@]*?)(?=\n\s*\*\s*@|\*/)', text, re.S)}


def build(root, output, executable):
    rules, packs, auxiliary = [], {}, {}
    lock = json.loads((Path(__file__).resolve().parents[3] / 'codeql-lock.json').read_text())
    for language in LANGUAGES:
        candidates = sorted(root.glob(f'qlpacks/codeql/{language}-queries/*/qlpack.yml'))
        candidates += sorted(root.glob(f'qlpacks/codeql/{language}-queries/*/qlpack.yaml'))
        if len(candidates) != 1:
            raise ValueError(f'Expected exactly one pinned {language} query pack; found {len(candidates)}.')
        pack = candidates[0].parent
        version = re.search(r'^version:\s*[\'"]?([^\s\'"]+)', candidates[0].read_text(), re.M).group(1)
        if version != lock['packs'][language]:
            raise ValueError(f'Unexpected upstream pack version for {language}: {version}')
        packs[language] = {'name': f'codeql/{language}-queries', 'version': version}
        suite = pack / f'codeql-suites/{language}-security-extended.qls'
        default = set(json.loads(subprocess.check_output([executable, 'resolve', 'queries', str(suite), '--format=json'], text=True)))
        auxiliary[language] = []
        for path in sorted(pack.rglob('*.ql')):
            fields = metadata(path.read_text())
            if fields.get('kind') in ('diagnostic', 'metric') and str(path) in default:
                auxiliary[language].append(str(path))
            if fields.get('kind') not in ('problem', 'path-problem') or not fields.get('id'):
                continue
            rules.append({'id': fields['id'], 'language': language, 'name': fields.get('name', fields['id']),
                          'kind': fields['kind'], 'severity': fields.get('problem.severity', 'warning'),
                          'securitySeverity': fields.get('security-severity', ''), 'tags': fields.get('tags', '').split(),
                          'defaultSuite': str(path) in default, 'path': str(path), 'packVersion': version})
    identities = [rule['id'] for rule in rules]
    if len(set(identities)) != len(identities):
        raise ValueError('Duplicate upstream rule IDs in the pinned catalog.')
    data = {'version': 1, 'codeqlVersion': subprocess.check_output([executable, 'version', '--format=json'], text=True).strip(),
            'packs': packs, 'rules': rules, 'auxiliary': auxiliary}
    data['identity'] = digest(data)
    output.write_text(json.dumps(data, indent=2) + '\n')


def load_catalog():
    path = Path(os.environ.get('BYPASS_CODEQL_CATALOG', '/opt/bypass-codeql-catalog.json'))
    if not path.is_file():
        raise ValueError('The pinned CodeQL catalog is unavailable; prepare the scanner image.')
    data = json.loads(path.read_text())
    claimed = data.pop('identity', None)
    if claimed != digest(data):
        raise ValueError('CodeQL catalog identity mismatch.')
    data['identity'] = claimed
    return data


def select_rules(catalog, languages, included, excluded):
    by_id = {rule['id']: rule for rule in catalog['rules']}
    for rule_id in [*included, *excluded]:
        if rule_id not in by_id:
            raise ValueError(f'Unknown CodeQL rule ID: {rule_id}. Use scanner rules to inspect the pinned catalog.')
    if included and any(by_id[rule_id]['language'] not in languages for rule_id in included):
        raise ValueError('An included rule does not apply to the selected/detected languages.')
    selected = [rule for rule in catalog['rules'] if rule['language'] in languages
                and (rule['id'] in included if included else rule['defaultSuite']) and rule['id'] not in excluded]
    if not selected:
        raise ValueError('Rule selection is empty; no database was created.')
    return selected


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=Path('/opt/codeql'))
    parser.add_argument('--output', type=Path, default=Path('/opt/bypass-codeql-catalog.json'))
    parser.add_argument('--codeql', default='/opt/codeql/codeql')
    args = parser.parse_args()
    build(args.root, args.output, args.codeql)
