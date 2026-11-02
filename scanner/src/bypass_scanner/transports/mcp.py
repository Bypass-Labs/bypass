"""Bounded newline-delimited MCP JSON-RPC; discovery delegates to the service.

The transport has no model client and emits only protocol messages on stdout.
"""
import json
import sys

from bypass_scanner.service import MANIFEST, invoke, close

MAX_BYTES = 1_048_576


class Server:
    def __init__(self):
        self.initialized = False

    def handle(self, message):
        identity = message.get("id") if isinstance(message, dict) else None

        def error(code, text):
            return {"jsonrpc": "2.0", "id": identity, "error": {"code": code, "message": text}}

        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
            return error(-32600, "Invalid Request")
        if not (identity is None or type(identity) in (str, int)):
            identity = None
            return error(-32600, "Invalid request ID")
        if "id" not in message:
            return None
        params = message.get("params", {})
        if not isinstance(params, dict):
            return error(-32602, "Parameters must be an object.")
        method = message["method"]
        if method == "initialize":
            requested = params.get("protocolVersion")
            if self.initialized or requested not in MANIFEST["mcpProtocolVersions"]:
                return error(-32602, "Unsupported protocol version or repeated initialization.")
            self.initialized = True
            result = {"protocolVersion": requested, "capabilities": {"tools": {"listChanged": False}},
                      "serverInfo": {"name": "bypass-scanner", "version": "0.3.0"},
                      "instructions": "SAST/policy discovery and automatic source-only evaluation. Reasoning is supplied by the host or CLI task loop. Python never calls models. Source verdicts are not runtime reproduction."}
        elif not self.initialized:
            return error(-32002, "Initialize the scanner first.")
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": [
                {"name": "scanner_" + name, "description": definition["description"],
                 "inputSchema": definition["inputSchema"],
                 "annotations": {"readOnlyHint": name in ('capabilities', 'rules', 'policies', 'status', 'signals', 'artifact'), "destructiveHint": False}}
                for name, definition in MANIFEST["operations"].items()
            ]}
        elif method == "tools/call":
            name = params.get("name")
            if not isinstance(name, str) or not name.startswith("scanner_") or name[8:] not in MANIFEST["operations"]:
                return error(-32602, "Unknown scanner tool.")
            try:
                value = invoke(name[8:], params.get("arguments", {}))
            except ValueError as exc:
                return error(-32602, str(exc))
            result = {"content": [{"type": "text", "text": json.dumps(value)}],
                      "isError": value.get("status") in ("not_implemented", "error")}
        else:
            return error(-32601, "Method not found")
        return {"jsonrpc": "2.0", "id": identity, "result": result}


def serve(input_stream=None, output_stream=None):
    incoming = input_stream if input_stream is not None else sys.stdin.buffer
    outgoing = output_stream if output_stream is not None else sys.stdout
    server = Server()
    while line := incoming.readline(MAX_BYTES + 1):
        if len(line) > MAX_BYTES:
            # Terminate after an oversized frame; do not parse its remaining bytes.
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Message exceeds 1 MiB."}}
            outgoing.write(json.dumps(response) + "\n")
            outgoing.flush()
            return
        try:
            message = json.loads(line, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid JSON constant")))
            response = server.handle(message)
        except (ValueError, UnicodeError, RecursionError):
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Invalid JSON"}}
        if response is not None:
            outgoing.write(json.dumps(response) + "\n")
            outgoing.flush()
