# Sensitive field and object binding

Invariant: generic request binding, merge, patch, or update operations must not
let a caller set protected fields or replace trusted object relationships beyond
their granted capability. Trace request keys and nested objects into domain
models, persistence updates, configuration, and downstream commands.

Inspect explicit input schemas, field allowlists, immutable server-derived
values, nested relation updates, spread or merge order, patch semantics, and
ORM or framework mass-assignment protections. Type validation alone does not
authorize a field. Denylists can miss newly added sensitive properties, while
purpose-specific input objects and explicit projections are strong
counterevidence.

Candidates must cite the controllable field set, protected property or relation,
binding operation, and resulting effect. Distinguish unauthorized field changes
from object-access failures and record framework configuration assumptions. Do
not submit mutations or invent model fields absent from source.
