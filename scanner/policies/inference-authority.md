# Model output and inference authority

Invariant: model-generated classifications, identifiers, URLs, code, scores, and
recommendations must not become authorization, trusted configuration, executable
content, or consequential action arguments without deterministic validation and
an independently enforced authority decision.

Trace model output through repair or JSON parsing, schema validation, canonical
lookup, persistence, caches, rendering, network calls, tool dispatch, and user or
administrative effects. A syntactically valid object can still select an
unauthorized tenant, destination, field, or action. Inspect truncation recovery,
fallbacks, hallucinated identifiers, confidence handling, and second-model
validation. Closed enums, target-side authorization, provenance checks, and
human approval bound to normalized arguments are counterevidence.

Candidates must identify the inferred value, validation gap, protected decision,
and plausible effect with citations. Do not treat inaccurate prose as a security
issue without an authority boundary. Do not call the model or execute its output.
