"""Preserve raw alerts while normalizing source-safe, unevaluated signals."""
import hashlib
import json
from pathlib import PurePosixPath
from urllib.parse import unquote, urlparse, urljoin
from bypass_scanner.repository.scope import alert_exclusion


def source_path(value, run, work_root):
    physical = value.get('physicalLocation', {})
    artifact = physical.get('artifactLocation', {})
    if not artifact.get('uri') and isinstance(artifact.get('index'), int):
        entries = run.get('artifacts', [])
        index = artifact['index']
        if 0 <= index < len(entries):
            artifact = entries[index].get('location', {})
    uri, base, seen = artifact.get('uri', ''), artifact.get('uriBaseId'), set()
    while base:
        if base in seen:
            raise ValueError('Cyclic SARIF URI base.')
        seen.add(base)
        entry = run.get('originalUriBaseIds', {}).get(base)
        if entry is None:
            if base == '%SRCROOT%':
                break
            raise ValueError('Unknown SARIF URI base.')
        uri = urljoin(entry.get('uri', ''), uri)
        base = entry.get('uriBaseId')
    parsed = urlparse(uri)
    if parsed.scheme not in ('', 'file') or parsed.netloc not in ('', 'localhost'):
        raise ValueError('Non-local SARIF location.')
    name = unquote(parsed.path)
    if name.startswith(str(work_root).rstrip('/') + '/'):
        name = name[len(str(work_root).rstrip('/')) + 1:]
    relative = PurePosixPath(name)
    if not name or relative.is_absolute() or '..' in relative.parts or '\\' in name:
        raise ValueError('SARIF location is outside repository scope.')
    return name


def source_location(value, run, files, work_root):
    name = source_path(value, run, work_root)
    if name not in files:
        raise ValueError('SARIF location is outside the recorded source snapshot.')
    region = value.get('physicalLocation', {}).get('region', {})
    line = region.get('startLine')
    if type(line) is not int or line < 1:
        raise ValueError('SARIF location has no valid source line.')
    end = region.get('endLine', line)
    if type(end) is not int or end < line:
        raise ValueError('SARIF location has an invalid source range.')
    if end > files[name].get('lineCount', end):
        raise ValueError('SARIF source range exceeds the recorded file.')
    return {'path': name, 'startLine': line, 'endLine': end}


def normalize(document, language, snapshot, work_root, raw_path, filtered=None):
    if not isinstance(document, dict) or document.get('version') != '2.1.0' or not isinstance(document.get('runs'), list):
        raise ValueError('Expected a SARIF 2.1.0 document with runs.')
    signals, warnings = [], []
    occurrences = {}
    for run_index, run in enumerate(document['runs']):
        if not isinstance(run, dict) or not isinstance(run.get('results', []), list):
            warnings.append({'origin': {'artifact': raw_path, 'runIndex': run_index}, 'message': 'Malformed SARIF run; raw evidence retained.'})
            continue
        tool = run.get('tool', {})
        driver = tool.get('driver', {}) if isinstance(tool, dict) else {}
        if not isinstance(driver, dict) or not isinstance(driver.get('rules', []), list):
            warnings.append({'origin': {'artifact': raw_path, 'runIndex': run_index}, 'message': 'Malformed SARIF driver; raw evidence retained.'})
            continue
        rules = driver.get('rules', [])
        for result_index, result in enumerate(run.get('results', [])):
            origin = {'artifact': raw_path, 'runIndex': run_index, 'resultIndex': result_index}
            try:
                index = result.get('ruleIndex')
                rule = rules[index] if type(index) is int and 0 <= index < len(rules) else {}
                if not isinstance(rule, dict):
                    raise ValueError('Alert references malformed rule metadata.')
                rule_id = result.get('ruleId') or rule.get('id')
                if rule_id and not rule:
                    rule = next((item for item in rules if isinstance(item, dict) and item.get('id') == rule_id), {})
                message = result.get('message', {}).get('text') or result.get('message', {}).get('markdown')
                if not isinstance(rule_id, str) or not rule_id or not isinstance(message, str) or not message:
                    raise ValueError('Alert has no rule identity or message.')
                # Scope follows primary alert locations, not related/code-flow
                # locations that can mention application code from a test sink.
                primary = []
                for location in result.get('locations', []):
                    try:
                        primary.append(source_path(location, run, work_root))
                    except (ValueError, TypeError, AttributeError):
                        primary.append(None)
                if 'scopeOptions' in snapshot and primary and all(name and alert_exclusion(name, snapshot) for name in primary):
                    if filtered is not None:
                        filtered.append({'origin': origin, 'ruleId': rule_id, 'paths': primary,
                                         'categories': sorted({alert_exclusion(name, snapshot) for name in primary}),
                                         'reason': 'All primary locations are excluded by analysis scope; raw SARIF retained.'})
                    continue
                locations, limitations = [], []
                raw_locations = list(result.get('locations', [])) + list(result.get('relatedLocations', []))
                for flow in result.get('codeFlows', []):
                    for thread in flow.get('threadFlows', []):
                        raw_locations.extend(item.get('location', {}) for item in thread.get('locations', []))
                for location in raw_locations:
                    try:
                        item = source_location(location, run, snapshot['files'], work_root)
                        if item not in locations:
                            locations.append(item)
                    except (ValueError, TypeError, AttributeError) as error:
                        limitations.append(str(error))
                if not locations:
                    limitations.append('No citable location in the recorded source snapshot; raw alert retained.')
                identity = json.dumps([language, driver.get('name'), rule_id, locations, message], sort_keys=True)
                occurrence = occurrences.get(identity, 0)
                occurrences[identity] = occurrence + 1
                key = hashlib.sha256((identity + ':' + str(occurrence)).encode()).hexdigest()
                references = [{**location, 'id': hashlib.sha256((key + json.dumps(location, sort_keys=True)).encode()).hexdigest(),
                               'sourceRevision': snapshot['revision'], 'contentHash': snapshot['files'][location['path']]['sha256']}
                              for location in locations]
                if len(message) > 2000:
                    limitations.append('Signal message abbreviated; complete text is retained in raw SARIF.')
                signals.append({'id': key, 'detector': 'sarif' if language == 'import' else 'codeql', 'language': language, 'ruleId': rule_id,
                                'suspectedIssue': message[:2000], 'locations': locations, 'sourceRevision': snapshot['revision'],
                                'evidence': references, 'assumptions': ['Detector alert is a candidate; AI evaluation has not run.'],
                                'evaluation': 'not_run', 'detectorSeverity': str(rule.get('properties', {}).get('security-severity', result.get('level', rule.get('defaultConfiguration', {}).get('level', 'warning')))),
                                'ruleMetadata': rule, 'origin': origin, 'limitations': limitations,
                                'codeFlows': result.get('codeFlows', [])})
            except (ValueError, TypeError, KeyError, AttributeError, IndexError) as error:
                warnings.append({'origin': origin, 'message': str(error)})
    return signals, warnings


def coverage(document, diagnostic_document=None, extract_log=None):
    notifications, metrics, baseline = [], [], 0
    for run in [*document.get('runs', []), *(diagnostic_document or {}).get('runs', [])]:
        for invocation in run.get('invocations', []):
            notifications.extend(invocation.get('toolExecutionNotifications', []))
            notifications.extend(invocation.get('toolConfigurationNotifications', []))
        metrics.extend(run.get('properties', {}).get('metricResults', []))
        baseline += sum('baseline' in artifact.get('properties', {}) for artifact in run.get('artifacts', []))
    # The Rust extractor can exit zero after a workspace load failure without
    # exporting a corresponding SARIF warning. Preserve that known partial mode.
    if extract_log and extract_log.is_file():
        with extract_log.open(errors='replace') as stream:
            for line in stream:
                if any(text in line.lower() for text in ('failed to load workspace', 'semantic analyzer unavailable')):
                    notifications.append({'level': 'warning', 'message': {'text': line.strip()[:2000]}, 'artifact': 'extract.log'})
    errors = [item for item in notifications if item.get('level') == 'error']
    warnings = [item for item in notifications if item.get('level') == 'warning']
    # Do not infer full coverage from zero alerts or generic language-specific metrics.
    return {'status': 'partial' if errors or warnings else 'unknown', 'errors': len(errors),
            'warnings': len(warnings), 'baselineFiles': baseline, 'metrics': metrics,
            'notifications': notifications, 'complete': False}
