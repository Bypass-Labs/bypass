# Untrusted browser content and navigation

Invariant: attacker-controlled content must not enter an executable browser
context or security-relevant navigation without context-appropriate encoding,
sanitization, or strict destination validation. Trace server-rendered and client-
rendered data into HTML, script, style, URL, DOM, template, and redirect sinks.

Inspect the final context after decoding and transformations. Generic HTML
escaping does not protect script, attribute, CSS, or URL contexts. Review unsafe
DOM APIs, rich-text sanitizers and their configuration, template bypasses,
dangerous URL schemes, response content types, and redirects. Framework
auto-escaping is counterevidence only on the actual rendering path; explicit raw
rendering or post-render DOM construction may bypass it.

Candidates must cite the untrusted source, context transition, sink, and closest
control. Separate stored, reflected, and DOM paths and record browser or policy
assumptions. Do not construct an active payload or load the application.
