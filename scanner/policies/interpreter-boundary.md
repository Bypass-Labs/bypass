# Interpreter boundaries

Invariant: untrusted data must not become executable syntax in an operating
system command, language evaluator, template engine, expression evaluator, or
other interpreter. Trace request, file, database, queue, and integration data
through construction helpers to the actual execution API.

Inspect whether values remain data through argument arrays, parameter binding,
fixed templates, allowlists, and correctly selected escaping for the exact
interpreter context. Escaping for HTML, URLs, or a different shell is not a
control here. Include indirect wrappers, job runners, administrative utilities,
dynamic module loading, and server-side template selection. A constant command
with separated arguments can be strong counterevidence.

Candidates must cite the controllable fragment, syntax-forming operation,
execution sink, and relevant control or counterevidence. Record reachability and
platform assumptions. Do not execute commands, expressions, or templates and do
not provide an operational payload.
