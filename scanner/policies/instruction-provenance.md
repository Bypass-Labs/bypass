# Natural-language instruction provenance

Invariant: text originating from users, documents, websites, messages, tool
results, retrieval stores, and model output must remain untrusted data and must
not silently acquire system, developer, policy, or approval authority when
placed in a model context.

Trace each text source through parsing, retrieval, prompt construction, memory,
tool selection, and consequential sinks. Inspect role assignment, delimiter-only
defenses, instructions embedded into system messages, user-configurable prompts,
tool descriptions, cross-session memory, and whether injected text can choose an
action, target, recipient, credential, or disclosure. Filtering suspicious
phrases is not a complete control. Architectural separation, constrained typed
outputs, least-privilege tools, and authorization outside the model are stronger
counterevidence.

Candidates must show an untrusted instruction path to a security-relevant model
decision and downstream capability; prompt text alone is not a finding. Record
model and tool assumptions. Do not submit prompt payloads to a provider or invoke
an agent action.
