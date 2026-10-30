"""One explicitly requested network-enabled extraction, separate from offline queries."""
import argparse
import json
from pathlib import Path
import re
import threading

from bypass_scanner.discovery.codeql import extraction
from bypass_scanner.workflow import Workflow, atomic, CancellationToken


def run(run_id, job):
    if not re.fullmatch(r'[a-f0-9]{32}', job):
        raise ValueError('Invalid network build job ID.')
    workflow = Workflow()
    directory = workflow.directory(run_id)
    state = workflow.read(run_id)
    if state.get('networkJob', {}).get('id') != job:
        raise ValueError('Network build job is not active.')
    request = json.loads((directory / 'network' / (job + '.json')).read_text())
    if request['build'].get('network') != 'on':
        raise ValueError('This extraction was not configured for network access.')
    try:
        extraction(directory, request['language'], request['build'], request['resources'], CancellationToken(directory / 'cancel-request.json'))
        result = {'success': True}
    except Exception as error:
        result = {'success': False, 'message': str(error)[:2000]}
    atomic(directory / 'network' / (job + '.result.json'), result)
    return 0 if result['success'] else 3


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('run')
    parser.add_argument('job')
    args = parser.parse_args()
    raise SystemExit(run(args.run, args.job))
