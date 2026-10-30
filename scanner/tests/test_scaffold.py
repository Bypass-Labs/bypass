"""Protocol v2 and read-only capability checks (no local CodeQL required)."""
import io
import json
import unittest

from bypass_scanner.contracts import MANIFEST, validate, resolve_manifest
from bypass_scanner.service import capabilities, invoke
from bypass_scanner.transports.mcp import MAX_BYTES, Server, serve


class ProtocolTests(unittest.TestCase):
    def test_shared_definitions_expand_without_wire_references(self):
        self.assertNotIn('"$ref"', json.dumps(MANIFEST))
        self.assertEqual(MANIFEST['operations']['start']['inputSchema']['properties']['config'], MANIFEST['schemas']['config'])
        self.assertEqual(MANIFEST['schemas']['response']['properties']['run'], MANIFEST['schemas']['run'])
        self.assertEqual(MANIFEST['schemas']['error'], MANIFEST['schemas']['response'])
        self.assertEqual(MANIFEST['schemas']['signal']['properties']['evidence']['items'], MANIFEST['schemas']['evidence'])

    def test_invalid_contract_references_fail_without_external_reads(self):
        for value in [{'$ref':'https://example.invalid/schema'}, {'$ref':'file:///etc/hosts'}, {'$ref':'#/missing'},
                      {'a':{'$ref':'#/a'}}, {'a':{'$ref':'#/b'},'b':{'$ref':'#/a'}},
                      {'a':{'type':'string'},'b':{'$ref':'#/a','description':'sibling'}},
                      {'a':[],'b':{'$ref':'#/a'}}, {'a':'text','b':{'$ref':'#/a'}}]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                resolve_manifest(value)
        self.assertEqual(resolve_manifest({'a/b':{'type':'string'},'schema':{'$ref':'#/a~1b'}})['schema'],{'type':'string'})

    def test_contract_and_capabilities(self):
        self.assertEqual(MANIFEST['protocolVersion'], 'bypass-scanner.v2')
        self.assertEqual(len(capabilities()['languages']), 9)
        validate(MANIFEST['schemas']['capabilities'], capabilities())
        self.assertTrue(capabilities()['features']['codeqlDiscovery'])
        self.assertFalse(capabilities()['features']['evaluation'])
        self.assertEqual(capabilities()['independentModelRequests'], 0)

    def test_reserved_ai_operations_are_unavailable(self):
        for name, value in [('next_task', {'run':'r'}), ('submit', {'run':'r','task':'t','sourceRevision':'s','result':{}}), ('evidence', {'run':'r','task':'t','operation':'read'})]:
            result = invoke(name, value)
            self.assertEqual(result['code'], 'not_implemented')
            self.assertEqual(result['modelCalls'], 0)
            validate(MANIFEST['schemas']['response'], result)

    def test_input_validation(self):
        for name, value in [('status', {}), ('status', {'run':''}), ('start', {'apiKey':'secret'}), ('rules', {'limit':0}), ('report', {'run':'r','format':'html'})]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                invoke(name, value)

    def test_transport(self):
        server = Server()
        def request(method, params=None):
            return server.handle({'jsonrpc':'2.0','id':1,'method':method,'params':params or {}})
        self.assertEqual(request('tools/list')['error']['code'], -32002)
        self.assertIn('serverInfo', request('initialize', {'protocolVersion':'2025-11-25'})['result'])
        self.assertEqual(len(request('tools/list')['result']['tools']), len(MANIFEST['operations']))
        self.assertEqual(request('ping')['result'], {})
        inspected = request('tools/call', {'name':'scanner_capabilities'})['result']
        self.assertFalse(inspected['isError'])
        self.assertEqual(json.loads(inspected['content'][0]['text'])['protocolVersion'], 'bypass-scanner.v2')
        self.assertEqual(request('tools/call', {'name':'scanner_next_task','arguments':{'run':'r'}})['result']['isError'], True)
        self.assertEqual(request('tools/call', {'name':'scanner_status'})['error']['code'], -32602)
        self.assertEqual(request('unknown')['error']['code'], -32601)

    def test_wire_bounds(self):
        for line in (b'not json\n', b'[]\n', b'{"x":NaN}\n', b'\xff\n', b'x'*(MAX_BYTES+1)):
            output = io.StringIO()
            serve(io.BytesIO(line), output)
            self.assertIn('error', json.loads(output.getvalue()))
