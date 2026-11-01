# Uploaded and generated content

Invariant: uploaded, imported, transformed, and generated files must remain
within their intended type, storage, and delivery boundaries. Trace names,
declared and detected types, content, metadata, and generated derivatives from
ingress through processing to storage and response.

Inspect size and decompression limits, magic-byte or parser validation, archive
entry handling, image/document processors, executable formats, storage location,
name generation, overwrite behavior, response content type and disposition, and
active-content isolation. Extensions and client MIME types are not sufficient.
Random storage names do not neutralize active content if it is later served from
a trusted origin or processed by an unsafe component.

Candidates must identify the attacker-controlled file property, privileged
processor or delivery sink, and relevant validation with citations. Record
external storage and malware-scanning assumptions as proof gaps. Do not create,
upload, decompress, or render a test artifact.
