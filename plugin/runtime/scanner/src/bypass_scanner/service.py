"""Transport-independent contracts and explicit unavailable-operation results."""
import json
from pathlib import Path
import sysconfig

from bypass_scanner.workflow import STAGES


def load_manifest() -> dict:
    root = Path(__file__).resolve().parents[2]
    source = root / "protocol" / "v1.json"
    installed = Path(sysconfig.get_path("data")) / "share/bypass-scanner/protocol/v1.json"
    return json.loads((source if source.is_file() else installed).read_text())


MANIFEST = load_manifest()
PROTOCOL_VERSION = MANIFEST["protocolVersion"]


def validate(schema: dict, value, label: str = "arguments", depth: int = 0) -> None:
    """Validate the small, explicit JSON Schema subset used by protocol v1."""
    if depth >= 24:
        raise ValueError("Structured data exceeds nesting limit.")
    kind = schema.get("type")
    valid = {
        "object": lambda: isinstance(value, dict),
        "array": lambda: isinstance(value, list),
        "string": lambda: isinstance(value, str),
        "integer": lambda: isinstance(value, int) and not isinstance(value, bool),
        "boolean": lambda: isinstance(value, bool),
    }
    if kind not in valid or not valid[kind]():
        raise ValueError(f"Invalid type for {label}.")
    if "enum" in schema and not any(type(value) is type(item) and value == item for item in schema["enum"]):
        raise ValueError(f"Unsupported {label}.")
    if kind == "string" and not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", 64000):
        raise ValueError(f"Invalid length for {label}.")
    if kind == "integer" and not schema.get("minimum", value) <= value <= schema.get("maximum", value):
        raise ValueError(f"Invalid bounds for {label}.")
    if kind == "array":
        if len(value) > schema.get("maxItems", 1000):
            raise ValueError(f"Too many items for {label}.")
        for item in value:
            validate(schema["items"], item, label, depth + 1)
    if kind == "object":
        if any(key not in value for key in schema.get("required", [])):
            raise ValueError(f"Missing required field for {label}.")
        for key, item in value.items():
            if key in ("__proto__", "constructor", "prototype"):
                raise ValueError("Unsafe structured property.")
            child = schema.get("properties", {}).get(key)
            if child:
                validate(child, item, f"{label}.{key}", depth + 1)
            elif schema.get("additionalProperties") is False:
                raise ValueError(f"Unknown field for {label}.")


def capabilities() -> dict:
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "status": "scaffold",
        "analysisImplemented": False,
        "independentModelRequests": 0,
        "implementedOperations": ["capabilities"],
        "operations": list(MANIFEST["operations"]),
        "stages": list(STAGES),
    }


def unavailable(operation: str) -> dict:
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "status": "not_implemented",
        "code": "not_implemented",
        "operation": operation,
        "message": "Scanner analysis is not implemented. No run, finding, source read, or model request was created.",
        "analysisImplemented": False,
        "modelCalls": 0,
        "sourceReads": 0,
    }


def invoke(operation: str, arguments: dict) -> dict:
    if operation not in MANIFEST["operations"]:
        raise ValueError("Unknown scanner operation.")
    validate(MANIFEST["operations"][operation]["inputSchema"], arguments)
    return capabilities() if operation == "capabilities" else unavailable(operation)
