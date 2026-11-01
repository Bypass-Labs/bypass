# Structured data queries

Invariant: attacker-controlled values must remain data rather than query syntax
for SQL, NoSQL, LDAP, XPath, search, graph, or similar query languages. Trace
values and structural operators from entrypoints through query builders and
repository helpers to execution.

Inspect parameterization of values and allowlisting of identifiers, sort fields,
projections, filters, and operators that cannot be parameterized. String
interpolation, partial escaping, and accepting object-shaped filters may preserve
attacker syntax. ORM use alone is not proof: raw fragments, dynamic clauses, and
unsafe operator merging still need review. Fixed queries and typed builders that
separate structure from values are relevant counterevidence.

Candidates must identify the controllable query component, resulting sensitive
read or mutation, and exact execution path with citations. Keep data exposure,
authorization, and availability impacts distinct. Do not connect to a database
or invent schema behavior not established by source.
