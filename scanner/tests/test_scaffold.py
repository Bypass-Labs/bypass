import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from bypass_scanner.service import MANIFEST, capabilities, invoke, validate
from bypass_scanner.transports.mcp import MAX_BYTES, Server, serve


class ScaffoldTests(unittest.TestCase):
    def test_contract_and_capabilities(self):
        self.assertEqual(MANIFEST['protocolVersion'], 'bypass-scanner.v1')
        self.assertEqual(set(MANIFEST['schemas']), {'capabilities', 'run', 'signal', 'task', 'evidence', 'evaluation', 'error'})
        validate(MANIFEST['schemas']['capabilities'], capabilities())
        self.assertFalse(capabilities()['analysisImplemented'])
        self.assertEqual(capabilities()['implementedOperations'], ['capabilities'])

    def test_all_analysis_operations_are_unavailable_without_side_effects(self):
        inputs = {
            'start': {'sarif': '/nonexistent/findings.sarif', 'config': '/nonexistent/config'},
            'status': {'run': 'r'}, 'next_task': {'run': 'r'},
            'evidence': {'run': 'r', 'task': 't', 'operation': 'read', 'arguments': {'path': '/nonexistent/source'}},
            'submit': {'run': 'r', 'task': 't', 'sourceRevision': 's', 'result': {}},
            'resume': {'run': 'r'}, 'cancel': {'run': 'r'}, 'report': {'run': 'r', 'format': 'md'},
        }
        original = Path.cwd()
        with tempfile.TemporaryDirectory() as directory:
            try:
                os.chdir(directory)
                for operation, arguments in inputs.items():
                    with self.subTest(operation=operation):
                        result = invoke(operation, arguments)
                        validate(MANIFEST['schemas']['error'], result)
                        self.assertEqual(result['status'], 'not_implemented')
                        self.assertEqual(result['modelCalls'], 0)
                        self.assertEqual(result['sourceReads'], 0)
                self.assertEqual(list(Path('.').iterdir()), [])
            finally:
                os.chdir(original)

    def test_invalid_operation_arguments(self):
        for operation, value in [('status', {}), ('status', {'run': ''}), ('status', {'run': 1}), ('start', {'apiKey': 'secret'}), ('report', {'run': 'r', 'format': 'html'}), ('__proto__', {})]:
            with self.subTest(operation=operation, value=value), self.assertRaises(ValueError):
                invoke(operation, value)

    def test_evaluation_schema_rejects_legacy_verdict(self):
        schema = MANIFEST['schemas']['evaluation']['properties']['outcome']
        for value in ('confirmed', 'refuted', 'needs_review'):
            validate(schema, value)
        with self.assertRaises(ValueError):
            validate(schema, 'true_positive')

    def test_transport_lifecycle_and_errors(self):
        server = Server()
        request = lambda method, params={}: server.handle({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params})
        self.assertEqual(request('tools/list')['error']['code'], -32002)
        self.assertEqual(request('initialize', {'protocolVersion': 'unknown'})['error']['code'], -32602)
        self.assertIn('serverInfo', request('initialize', {'protocolVersion': '2025-11-25'})['result'])
        self.assertIsNone(server.handle({'jsonrpc': '2.0', 'method': 'notifications/initialized'}))
        tools = request('tools/list')['result']['tools']
        self.assertEqual({tool['name'] for tool in tools}, {'scanner_' + name for name in MANIFEST['operations']})
        self.assertEqual(request('ping')['result'], {})
        inspected = request('tools/call', {'name': 'scanner_capabilities', 'arguments': {}})['result']
        self.assertFalse(inspected['isError'])
        result = request('tools/call', {'name': 'scanner_start', 'arguments': {}})['result']
        self.assertTrue(result['isError'])
        self.assertEqual(json.loads(result['content'][0]['text'])['code'], 'not_implemented')
        self.assertEqual(request('tools/call', {'name': 'scanner_status', 'arguments': {}})['error']['code'], -32602)
        self.assertEqual(request('tools/call', {'name': []})['error']['code'], -32602)
        self.assertEqual(request('unknown')['error']['code'], -32601)
        self.assertEqual(request('initialize', {'protocolVersion': '2025-11-25'})['error']['code'], -32602)

    def test_wire_parse_and_size_bounds(self):
        for line in (b'not json\n', b'[]\n', b'{"x":NaN}\n', b'\xff\n', b'x' * (MAX_BYTES + 1)):
            output = io.StringIO()
            serve(io.BytesIO(line), output)
            self.assertIn('error', json.loads(output.getvalue()))


if __name__ == '__main__':
    unittest.main()
