# Security audit and alert integrity

Invariant: security-relevant actions and denials must produce attributable,
tamper-resistant, privacy-conscious audit events and actionable failure signals;
an actor must not be able to suppress, forge, misattribute, or flood the evidence
needed to detect and investigate abuse.

Trace authentication, authorization, administrative changes, credential and
delegation lifecycle, exports, communications, tool calls, policy changes, and
high-value workflow transitions into logs, metrics, alerts, and retention.
Inspect verified actor and tenant context, target and outcome, correlation IDs,
clock and ordering assumptions, asynchronous loss, error swallowing, redaction,
log injection, access control, integrity, alert thresholds, and failover. Request
logs alone may omit the effective action; secret-rich raw prompts are not safe
telemetry.

Candidates must identify the auditable event, missing or attacker-influenceable
record, and incident-response consequence. Do not report every absent log as a
vulnerability; prioritize events required by an explicit security invariant.
Do not generate events or access external logging systems.
