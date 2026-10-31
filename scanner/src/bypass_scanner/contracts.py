"""The shared scanner application contract and its small schema validator."""
import json
from pathlib import Path
import sysconfig


def resolve_manifest(document):
    """Expand local JSON references into self-contained MCP/validator schemas."""
    def expand(value, stack=(), depth=0):
        if depth >= 64:
            raise ValueError('Scanner contract exceeds nesting limit.')
        if isinstance(value, list):
            return [expand(item, stack, depth + 1) for item in value]
        if not isinstance(value, dict):
            return value
        if '$ref' in value:
            reference = value['$ref']
            if len(value) != 1 or not isinstance(reference, str) or not reference.startswith('#/'):
                raise ValueError('Scanner contract supports only local references without siblings.')
            if reference in stack:
                raise ValueError('Cyclic scanner contract reference.')
            target = document
            for token in reference[2:].split('/'):
                key = token.replace('~1', '/').replace('~0', '~')
                if not isinstance(target, dict) or key not in target:
                    raise ValueError('Missing scanner contract reference.')
                target = target[key]
            if not isinstance(target, dict):
                raise ValueError('Scanner contract reference must target an object.')
            return expand(target, stack + (reference,), depth + 1)
        return {key: expand(item, stack, depth + 1) for key, item in value.items()}
    return expand(document)


def load_manifest():
    source = Path(__file__).resolve().parents[2] / 'protocol/v3.json'
    installed = Path(sysconfig.get_path('data')) / 'share/bypass-scanner/protocol/v3.json'
    return resolve_manifest(json.loads((source if source.is_file() else installed).read_text()))


MANIFEST = load_manifest()
PROTOCOL_VERSION = MANIFEST['protocolVersion']


def validate(schema, value, label='arguments', depth=0):
    if depth >= 24:
        raise ValueError('Structured data exceeds nesting limit.')
    if 'anyOf' in schema:
        for child in schema['anyOf']:
            try:
                validate(child, value, label, depth + 1)
                return
            except ValueError:
                pass
        raise ValueError(f'Invalid {label}.')
    kind = schema.get('type')
    matches = {
        'object': isinstance(value, dict), 'array': isinstance(value, list),
        'string': isinstance(value, str), 'boolean': type(value) is bool,
        'integer': type(value) is int, 'number': type(value) in (int, float),
        'null': value is None,
    }
    if not matches.get(kind, False):
        raise ValueError(f'Invalid type for {label}.')
    if 'enum' in schema and not any(type(value) is type(item) and value == item for item in schema['enum']):
        raise ValueError(f'Unsupported {label}.')
    if kind == 'string' and not schema.get('minLength', 0) <= len(value) <= schema.get('maxLength', 64000):
        raise ValueError(f'Invalid length for {label}.')
    if kind in ('integer', 'number') and not schema.get('minimum', value) <= value <= schema.get('maximum', value):
        raise ValueError(f'Invalid bounds for {label}.')
    if kind == 'array':
        if not schema.get('minItems', 0) <= len(value) <= schema.get('maxItems', 1000):
            raise ValueError(f'Invalid item count for {label}.')
        for item in value:
            validate(schema['items'], item, label, depth + 1)
    if kind == 'object':
        if any(key not in value for key in schema.get('required', [])):
            raise ValueError(f'Missing required field for {label}.')
        for key, item in value.items():
            if key in ('__proto__', 'constructor', 'prototype'):
                raise ValueError('Unsafe structured property.')
            child = schema.get('properties', {}).get(key)
            if child is not None:
                validate(child, item, f'{label}.{key}', depth + 1)
            elif schema.get('additionalProperties') is False:
                raise ValueError(f'Unknown field for {label}.')
