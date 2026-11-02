# OWASP policy coverage

The bundled policy catalog uses source-trace invariants rather than reproducing
OWASP checklist text. This map records which policies are intended to surface the
root causes described by the current OWASP Web Top 10 (2025), API Security Top 10
(2023), MCP Top 10 (2025 beta), and GenAI/agentic guidance. A mapping is not a
claim of complete coverage, runtime exploitability, or OWASP certification.

Primary references:

- [OWASP Top 10:2025](https://top10.owasp.org/2025/0x00_2025-Introduction/)
- [OWASP API Security Top 10:2023](https://api-security.owasp.org/editions/2023/en/0x11-t10/)
- [OWASP MCP Top 10](https://owasp.org/projects/mcp-top-10)
- [OWASP GenAI prompt injection](https://genai.owasp.org/glossary/prompt-injection/)
- [OWASP Agentic AI Security](https://genai.owasp.org/initiatives/agent-security-initiative/)

## Web Top 10:2025

| Risk | Primary bundled policies |
| --- | --- |
| A01 Broken Access Control | `authz/object-access`, `authz/privileged-action`, `network/destination-boundary` |
| A02 Security Misconfiguration | `deployment/security-mode`, `http/request-integrity`, `browser/cross-origin-action` |
| A03 Software Supply Chain Failures | `supply-chain/execution-integrity`, `surface/inventory-lifecycle` |
| A04 Cryptographic Failures | `crypto/trust-boundary`, `secrets/credential-exposure` |
| A05 Injection | `injection/interpreter-boundary`, `injection/data-query`, `browser/untrusted-content` |
| A06 Insecure Design | `workflow/state-integrity`, `availability/resource-bounds`, `delegation/capability-envelope` |
| A07 Authentication Failures | `authn/session-integrity`, `identity/reserved-principal` |
| A08 Software or Data Integrity Failures | `serialization/untrusted-data`, `data/migration-boundary`, `supply-chain/execution-integrity` |
| A09 Security Logging and Alerting Failures | `security/audit-integrity` |
| A10 Mishandling of Exceptional Conditions | `reliability/exception-boundary`, `workflow/state-integrity` |

## API Security Top 10:2023

| Risk | Primary bundled policies |
| --- | --- |
| API1 Broken Object Level Authorization | `authz/object-access` |
| API2 Broken Authentication | `authn/session-integrity` |
| API3 Broken Object Property Level Authorization | `data/field-binding`, `data/sensitive-exposure` |
| API4 Unrestricted Resource Consumption | `availability/resource-bounds` |
| API5 Broken Function Level Authorization | `authz/privileged-action` |
| API6 Unrestricted Access to Sensitive Business Flows | `workflow/state-integrity`, `delegation/capability-envelope` |
| API7 Server-Side Request Forgery | `network/destination-boundary` |
| API8 Security Misconfiguration | `deployment/security-mode` |
| API9 Improper Inventory Management | `surface/inventory-lifecycle` |
| API10 Unsafe Consumption of APIs | `integration/response-trust` |

## MCP and agentic systems

| Risk family | Primary bundled policies |
| --- | --- |
| Token mismanagement and scope creep | `delegation/capability-envelope`, `secrets/credential-exposure` |
| Tool or contextual prompt poisoning | `ai/instruction-provenance`, `ai/inference-authority` |
| Command execution and downstream injection | `injection/interpreter-boundary`, `injection/data-query` |
| Authentication, authorization, and tenant isolation | `authn/session-integrity`, `authz/object-access`, `identity/derived-state-lineage` |
| Audit and telemetry gaps | `security/audit-integrity` |
| Shadow or stale tool surfaces | `surface/inventory-lifecycle`, `supply-chain/execution-integrity` |
| Context or memory over-sharing | `identity/derived-state-lineage`, `privacy/derivative-lifecycle`, `data/sensitive-exposure` |
| Excessive agency and consequential actions | `delegation/capability-envelope`, `workflow/state-integrity`, `communications/audience-binding` |
| Model output handling | `ai/inference-authority`, `serialization/untrusted-data`, `browser/untrusted-content` |

## Deliberate limits

Policy discovery remains source-only and produces unevaluated hypotheses. It does
not establish deployed API inventory, model behavior, prompt-injection success,
third-party retention, alert delivery, or runtime failure behavior. Those remain
explicit proof gaps until a separate authorized evaluation or runtime workflow
tests them.
