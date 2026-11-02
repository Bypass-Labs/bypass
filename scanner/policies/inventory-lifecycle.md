# Deployed interface and version lifecycle

Invariant: every reachable API, protocol endpoint, debug surface, administrative
interface, legacy version, and alternate transport must have an explicit owner,
supported lifecycle, authentication policy, and retirement path consistent with
the current interface.

Compare route registration, generated clients, schemas, gateways, deployment
manifests, feature flags, documentation, compatibility aliases, health and debug
handlers, protocol discovery, and old version directories. Inspect whether
deprecated or shadow interfaces bypass newer authorization, validation, limits,
or logging. An unlinked route remains reachable. Build-time exclusion, gateway
denial, and an explicit version inventory are relevant counterevidence when the
deployed path is established.

Candidates must cite the reachable interface and the missing or weaker current
control, not merely stale documentation. Record deployment and routing proof
gaps. Do not contact endpoints or assume repository code is deployed.
