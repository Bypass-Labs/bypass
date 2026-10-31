# Path containment

Invariant: untrusted path selections and archive entries must remain within the
authorized filesystem boundary before a read, write, copy, move, or extraction.
Trace decoding, path joins, normalization, link handling, checks, and effects.

Review import/restore, downloads, archive extraction, static serving, and shared
filesystem helpers. Path joining alone does not establish containment. Check the
actual canonicalized path, sibling prefixes, absolute paths, archive link entries,
and check/use ordering. A genuinely restricted selector, trusted-only input, or
correct containment and link protections can rule out a specific hypothesis.

Record the actor-controlled value, effect, closest control, and exact citations.
Do not fabricate an escape payload, execute source, or write any target file.
Preserve unknown platform/link behavior and counterevidence as proof gaps.
