# Security scan report

Original detector signals are retained unchanged. Evaluation verdicts are source-based, not runtime reproductions. Unresolved and unevaluated cases are not safety claims. Complete security coverage is not established.

## Contents

- [Analysed project](#analysed-project)
- [Executed analysis](#executed-analysis)
- [Summary](#summary)
- [Confirmed findings](#confirmed-findings)
  - [1. DOM text reinterpreted as HTML - High](#finding-1)
  - [2. Incomplete HTML attribute sanitization - High](#finding-2)
  - [3. Incomplete HTML attribute sanitization - High](#finding-3)
  - [4. Incomplete HTML attribute sanitization - High](#finding-4)
  - [5. Incomplete HTML attribute sanitization - High](#finding-5)
  - [6. Remote property injection - High](#finding-6)
  - [7. Missing rate limiting - High](#finding-7)
  - [8. Missing rate limiting - High](#finding-8)
  - [9. Missing rate limiting - High](#finding-9)
  - [10. Missing rate limiting - High](#finding-10)
  - [11. Missing rate limiting - High](#finding-11)
  - [12. Missing rate limiting - High](#finding-12)
  - [13. Missing rate limiting - High](#finding-13)
  - [14. Missing rate limiting - High](#finding-14)
  - [15. Missing rate limiting - High](#finding-15)
  - [16. Missing rate limiting - High](#finding-16)
  - [17. Missing rate limiting - High](#finding-17)
  - [18. Missing rate limiting - High](#finding-18)
  - [19. Missing rate limiting - High](#finding-19)
  - [20. Missing rate limiting - High](#finding-20)
  - [21. Missing rate limiting - High](#finding-21)
  - [22. Missing regular expression anchor - Medium](#finding-22)
  - [23. Incomplete HTML attribute sanitization - Medium](#finding-23)
  - [24. Incomplete HTML attribute sanitization - Medium](#finding-24)
  - [25. Incomplete HTML attribute sanitization - Medium](#finding-25)
  - [26. Incomplete HTML attribute sanitization - Medium](#finding-26)
  - [27. Incomplete HTML attribute sanitization - Medium](#finding-27)
  - [28. Incomplete HTML attribute sanitization - Medium](#finding-28)
  - [29. Incomplete HTML attribute sanitization - Medium](#finding-29)
  - [30. Incomplete HTML attribute sanitization - Medium](#finding-30)
  - [31. Incomplete HTML attribute sanitization - Medium](#finding-31)
  - [32. Incomplete HTML attribute sanitization - Medium](#finding-32)
  - [33. Incomplete string escaping or encoding - Medium](#finding-33)
  - [34. Remote property injection - Medium](#finding-34)
  - [35. Remote property injection - Medium](#finding-35)
  - [36. Missing rate limiting - Medium](#finding-36)
  - [37. Missing rate limiting - Medium](#finding-37)
  - [38. Missing rate limiting - Medium](#finding-38)
  - [39. Missing rate limiting - Medium](#finding-39)
  - [40. Missing rate limiting - Medium](#finding-40)
  - [41. Missing rate limiting - Medium](#finding-41)
- [Scan details](#scan-details)

## Analysed project

**Project:** job-finder
**Source path:** `~/job-finder`
**Source snapshot digest:** `d9666f6100f4a0e3bb9af8194ba3eafa5e14b2c1c2574e983b700c662862ebe7`
**Snapshot files:** 264
**Detected source languages:** javascript, python

Project name and path describe the current selected connection; they were not recorded when this scan started.

**Source files eligible for analysis:** 253
**Build-context files retained:** 264
**Snapshot files outside analysis scope:** 11
**Include tests / examples / generated files:** False / False / False
Eligible source files are a subset of the retained snapshot, not an additional file count.

## Executed analysis

| Analysis | Count |
| --- | ---: |
| Static rules selected | 149 |
| Static rules in completed query runs | 149 |

| Static-analysis language | Rules selected | Rules in completed query runs |
| --- | ---: | ---: |
| javascript | 101 | 101 |
| python | 48 | 48 |

| Policy analysis | Count |
| --- | ---: |
| Policy rules selected | 32 |
| Distinct policy rules reviewed | 23 |
| Completed policy review tasks | 63 |
| Deferred policy investigations | 71 |

A reviewed policy rule has at least one completed surface review; this is not exhaustive coverage. Mapping tasks and repeated follow-ups are not additional distinct rules.

Rules in completed query runs count successfully completed query batches, not failed or partial query attempts.
Evaluation: incomplete
Independent policy / evaluation API requests: 467 / 540

## Summary

| Outcome | Count |
| --- | ---: |
| Source-confirmed findings | 41 |
| Refuted | 5 |
| Unresolved after analysis | 18 |
| Not analysed | 54 |
| Total candidate signals | 118 |

Not analysed includes candidates marked `needs_review` without an evidence-backed evaluation.
Only confirmed findings are detailed below. Full records for every outcome remain in `report.json` and `evaluation/cases.json`.

## Confirmed findings


---

<a id="finding-1"></a>

### Finding 1: DOM text reinterpreted as HTML

**Severity:** High

**Issue**

OverviewTab in ui/src/components/JobPanel.tsx builds `raw` from `job.description_html || job.description_text` and, after optional entity decoding via `decodeEntities`, assigns it to `html` and renders with `dangerouslySetInnerHTML`. `decodeEntities` uses DOM parsing `document.createElement('textarea'); t.innerHTML = s; return t.value`, and the resulting `html` is passed directly to `dangerouslySetInnerHTML` without sanitization. The JobDetail type includes `description_html: string | null` and `description_text: string | null` which are sourced from external ATS/aggregator feeds. The code flow shows `t.value` → `decodeEntities(raw)` → `raw` → `html` → `dangerouslySetInnerHTML`, matching the detector flow. No sanitization library is used before the innerHTML injection, so attacker-controlled markup can be reinterpreted as HTML in the browser.

**Impact**

Stored or reflected cross-site scripting in the job description panel allowing script execution in the victim's browser session, potential credential theft, UI redress, or actions performed as the logged-in user.

**Recommended next action**

Review trust boundary for job.description_html/text and add output encoding/sanitization before dangerouslySetInnerHTML, e.g., DOMPurify, or avoid innerHTML for untrusted content.

#### Details

**Affected locations**

- `ui/src/components/JobPanel.tsx:224`
- `ui/src/components/JobPanel.tsx:233`
- `ui/src/components/JobPanel.tsx:235`
- `ui/src/components/JobPanel.tsx:236`

**Supporting evidence**

- `ui/src/components/JobPanel.tsx:210-250`
- `ui/src/components/JobPanel.tsx:1-60`

**Severity explanation**

Rendering untrusted job description HTML via dangerouslySetInnerHTML enables stored/reflected XSS with full DOM access in the UI context. Detector severity 7.8 maps to high impact for script execution in a user-facing React panel.

**Counterevidence considered**

No sanitization or safe-listing of description_html/description_text is present in OverviewTab; decodeEntities uses DOM innerHTML parsing and the result is fed directly to dangerouslySetInnerHTML. No evidence of a server-side sanitization step or a client-side DOMPurify/escape guard in the read ranges.

**Prerequisites**

- job.description_html or job.description_text originates from an external/attacker-influenced source, e.g., ATS board feeds or aggregator markdown
- the OverviewTab is rendered for the job panel
- the browser executes the injected markup via dangerouslySetInnerHTML

**Detector:** CodeQL
**Rule:** `js/xss-through-dom`
**Case reference:** `case_da2a8766e79a2cb5d54966f8`

---

<a id="finding-2"></a>

### Finding 2: Incomplete HTML attribute sanitization

**Severity:** High

**Issue**

The source defines esc(s) as String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;") which does not escape double quotes. This esc is used to build HTML via innerHTML and to populate attribute values delimited by double quotes, e.g. href="${esc(j.apply_url)}" and data-id="${esc(j.id)}". Because double quotes are not encoded, a value containing " can break out of the attribute and inject markup/JavaScript. The code flow from the esc definition at line 6-8 to the attribute interpolation around line 48 is present in the file, confirming incomplete HTML attribute sanitization.

**Impact**

An attacker able to influence job data fields can inject a double quote to break out of an HTML attribute and inject arbitrary attributes or event handlers, resulting in cross-site scripting in the context of the web application.

**Recommended next action**

Review and harden esc to encode " as &quot; and ' as &#x27; or replace manual string interpolation with safe DOM construction; audit all uses of esc in attribute contexts.

#### Details

**Affected locations**

- `src/web/assets/app.js:8`
- `src/web/assets/app.js:48`

**Supporting evidence**

- `src/web/assets/app.js:1-120`

**Severity explanation**

Attribute injection via unsanitized double quotes can lead to stored/reflected XSS when job data originates from external sources, allowing script execution in the browser context of the web UI.

**Counterevidence considered**

No source evidence shows additional escaping of double quotes or use of a safe DOM API for attribute assignment; esc is used directly for attribute interpolation.

**Prerequisites**

- Job data fields such as apply_url, id, title, company_name, location_raw, notes are sourced from API responses that may contain attacker-controlled content.
- The rendered HTML is inserted via innerHTML, so attribute values are parsed as markup.

**Detector:** CodeQL
**Rule:** `js/incomplete-html-attribute-sanitization`
**Case reference:** `case_e30038f393cdb89d40a14981`

---

<a id="finding-3"></a>

### Finding 3: Incomplete HTML attribute sanitization

**Severity:** High

**Issue**

The esc helper at src/web/assets/app.js:7-9 only replaces & < > and does not escape double quotes. The same esc output is interpolated into HTML attribute values, e.g., data-id="${esc(j.id)}" and href="${esc(j.apply_url)}" in the template built in renderList. Because double quotes are not encoded, a value containing " can break out of the attribute and inject markup/JavaScript. The code flow from esc definition to attribute interpolation is present in the source, confirming incomplete attribute sanitization.

**Impact**

An attacker-controlled value containing a double quote can break out of the data-id / href attribute and inject arbitrary HTML/JavaScript, leading to cross-site scripting in the job list view.

**Recommended next action**

Replace esc with a full HTML attribute encoder or use DOM-safe construction; ensure " , ' , and > are escaped for attribute contexts.

#### Details

**Affected locations**

- `src/web/assets/app.js:8`
- `src/web/assets/app.js:50`

**Supporting evidence**

- `src/web/assets/app.js:1-100`
- `src/web/assets/app.js:45-60`

**Severity explanation**

Attribute injection via unsanitized double quotes can lead to stored/reflected XSS with script execution in the browser context, a high-impact web injection.

**Counterevidence considered**

No source evidence shows additional escaping for double quotes or use of a safe DOM API; esc is used directly in attribute contexts without further encoding.

**Prerequisites**

- j.id and j.apply_url originate from API response data
- esc is the final sanitizer applied before HTML string interpolation
- template strings are assigned to innerHTML

**Detector:** CodeQL
**Rule:** `js/incomplete-html-attribute-sanitization`
**Case reference:** `case_a3408109676ddac8c3eb27cc`

---

<a id="finding-4"></a>

### Finding 4: Incomplete HTML attribute sanitization

**Severity:** High

**Issue**

The esc helper at line 8 only replaces & < > and does not escape double quotes. The same esc is used to interpolate values into HTML attribute contexts via template literals, e.g. href="${esc(j.apply_url)}" and data-id="${esc(j.id)}" in renderList. Because double quotes are not encoded, a value containing " can break out of the attribute and inject markup/JavaScript. The code flow from the esc definition to the attribute interpolation is present in src/web/assets/app.js.

**Impact**

An attacker who can influence job fields returned by /api/jobs can inject a double quote into an attribute value, breaking out of the attribute and executing arbitrary JavaScript in the context of the web application, leading to cross-site scripting.

**Recommended next action**

Update esc to also encode " and ' e.g. replace(/"/g,'&quot;') and replace(/'/g,'&#x27;'), or use a dedicated attribute encoder / DOM-safe insertion instead of innerHTML.

#### Details

**Affected locations**

- `src/web/assets/app.js:8`
- `src/web/assets/app.js:54`

**Supporting evidence**

- `src/web/assets/app.js:1-120`
- `src/web/assets/app.js:45-65`

**Severity explanation**

Incomplete attribute escaping allows an attacker-controlled value to break out of a quoted HTML attribute and inject script, resulting in stored/reflected XSS with medium-high impact. Detector severity 6.1 aligns with high.

**Counterevidence considered**

No counterevidence was found; esc is defined as String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;") with no quote encoding, and the output is directly embedded in quoted attribute values without additional encoding.

**Prerequisites**

- j.id, j.apply_url, or other fields passed to esc must be attacker-controllable via API response
- renderList or renderJob output is written to DOM via innerHTML

**Detector:** CodeQL
**Rule:** `js/incomplete-html-attribute-sanitization`
**Case reference:** `case_2502021ecdb8033801bd8323`

---

<a id="finding-5"></a>

### Finding 5: Incomplete HTML attribute sanitization

**Severity:** High

**Issue**

The esc helper at src/web/assets/dashboard.js:6-8 only replaces & < > and does not escape double quotes. The sanitized values are interpolated into double-quoted HTML attributes, e.g. data-id="${esc(j.id)}" and href="${esc(j.apply_url)}", and also j.id is interpolated raw into href="/jobs/${j.id}". Because " is not encoded, an attacker-controlled value containing a double quote can break out of the attribute and inject markup/JavaScript. The code flow from esc definition to attribute usage is present in the source, confirming incomplete attribute sanitization.

**Impact**

An attacker-controlled value containing a double quote can break out of the attribute context, enabling injection of arbitrary HTML attributes or event handlers and leading to cross-site scripting in the dashboard page.

**Recommended next action**

Replace esc with a proper HTML attribute encoder that escapes " and ' as well as & < >, or use safe DOM construction instead of innerHTML.

#### Details

**Affected locations**

- `src/web/assets/dashboard.js:8`
- `src/web/assets/dashboard.js:62`

**Supporting evidence**

- `src/web/assets/dashboard.js:1-80`
- `src/web/assets/dashboard.js:55-70`
- `src/web/assets/dashboard.js:48-58`

**Severity explanation**

Attribute injection via unsanitized double quotes can lead to stored/reflected XSS with script execution in the dashboard context, which is a high-impact client-side injection.

**Counterevidence considered**

No counterevidence found; esc is defined without quote encoding and is used directly inside double-quoted attributes and a raw URL interpolation.

**Prerequisites**

- Attacker can influence j.id, j.apply_url, j.title, j.company_name, j.location_raw or state returned from /api/dashboard
- The dashboard renders the jobs list via innerHTML with the described template

**Detector:** CodeQL
**Rule:** `js/incomplete-html-attribute-sanitization`
**Case reference:** `case_d506bfc9a35e3c60b05a68d2`

---

<a id="finding-6"></a>

### Finding 6: Remote property injection

**Severity:** High

**Issue**

The redact helper builds a new object `out` and assigns properties using a key `k` taken directly from `Object.entries(obj)` where `obj` is `req.body` and `req.query` from the request error hook. Source shows `const out = {};` then `for (const [k, v] of Object.entries(obj)) {` and `out[k] = ...` at the same function. The onError hook calls `redact(req.body)` and `redact(req.query)` so user-controlled keys flow into the property write `out[k]`. This is a user-controlled property name write to an object, matching remote property injection.

**Impact**

Prototype pollution or arbitrary property creation on the logging output object, which can lead to denial-of-service, log injection, or unexpected prototype mutation if the object is later used in a context that relies on its prototype.

**Recommended next action**

Review redact to sanitize or allow-list keys, e.g., using Object.create(null) and/or rejecting __proto__ / constructor keys, and consider limiting recursion depth.

#### Details

**Affected locations**

- `src/server.js:97`
- `src/server.js:100`
- `src/server.js:101`
- `src/server.js:120`

**Supporting evidence**

- `src/server.js:95-105`
- `src/server.js:90-130`

**Severity explanation**

User supplied keys can be used to set arbitrary properties on the temporary object, including prototype-polluting keys such as __proto__ or constructor, which can lead to denial-of-service or unexpected behavior in the logging path. Detector severity 7.5 maps to high.

**Counterevidence considered**

No input validation or key allow-list is applied to `k` before using it as a property name on `out`. The object is created fresh per call, so no persistent state mutation of shared objects is evident from the read range, but the property write itself is still driven by remote data.

**Prerequisites**

- Request reaches the onError hook with a body or query object containing attacker-controlled keys
- redact is invoked on req.body / req.query as shown in the error logging hook

**Detector:** CodeQL
**Rule:** `js/remote-property-injection`
**Case reference:** `case_29e6fa33103ea3524f651f37`

---

<a id="finding-7"></a>

### Finding 7: Missing rate limiting

**Severity:** High

**Issue**

The source shows the global API authorization hook at src/server.js lines ~152-171 that verifies Firebase ID tokens for every /api/ request and sets req.uid/req.email. The hook performs authentication and runs on every API request, but no rate-limiting middleware or per-request throttling is applied to this hook or to the protected routes it guards. The file imports no rate-limit plugin and registers no global rate limiting; only isolated manual throttles exist for specific public endpoints (/api/contact per-IP 5/hour, /api/auth/reset per-email 60s). The auth verification path therefore remains without rate limiting, leaving token verification and downstream handlers exposed to brute-force / DoS abuse.

**Impact**

An unauthenticated attacker can flood /api/ endpoints with requests, forcing repeated Firebase token verification and downstream DB / cost attribution work, leading to denial of service, increased compute/cost, and potential brute-force against tokens. Legitimate users may experience degraded availability.

**Recommended next action**

Add a global rate-limiting middleware for /api/ with per-IP and per-user buckets, and apply stricter limits to authentication-sensitive endpoints. Audit other hooks for missing throttling.

#### Details

**Affected locations**

- `src/server.js:152-171`
- `src/server.js:167`

**Supporting evidence**

- `src/server.js:150-180`
- `src/server.js:120-150`
- `src/server.js:1-50`

**Severity explanation**

Unthrottled authentication on all API endpoints allows an attacker to issue unlimited token verification requests, enabling credential stuffing/brute force and resource exhaustion via repeated verifyToken calls and downstream DB work, matching CWE-307/770 impact. Detector severity 7.5 supports high.

**Counterevidence considered**

No global rate-limit plugin is imported or registered; the auth hook at lines 152-171 contains only token extraction and verifyToken with no throttling checks. Manual rate limits are present only for /api/contact and /api/auth/reset, not for the auth hook or general API routes.

**Prerequisites**

- Request targets /api/ path
- Authorization hook executes for protected routes
- verifyToken is invoked per request
- No global rate limiting middleware is configured

**Detector:** CodeQL
**Rule:** `js/missing-rate-limiting`
**Case reference:** `case_c84840bc778908f13ba0b6e3`

---

<a id="finding-8"></a>

### Finding 8: Missing rate limiting

**Severity:** High

**Issue**

The handler app.post('/api/onboarding/complete' performs multiple database operations via getProfile, setProfile and db().query without any per-route rate-limiting guard. Source shows the route definition starting at line 493 with uid extraction and profile load, followed by db().query for welcome_email_sent check and later inserts/updates to job_sources. No rate-limit check, token bucket, or middleware guard is present in the handler body. The existing per-IP rate limit for /api/contact and per-email limit for /api/auth/reset are isolated to those routes and do not apply here.

**Impact**

Repeated unauthenticated or authenticated calls can cause excessive database queries, writes to app_events/job_sources, and spawn background ensureUserFeed and collect runs, leading to CPU/DB exhaustion and denial of service.

**Recommended next action**

Add explicit rate limiting to /api/onboarding/complete, e.g., per-user token bucket or global middleware, and audit other expensive DB-write routes for similar missing limits.

#### Details

**Affected locations**

- `src/server.js:493-587`
- `src/server.js:505-507`
- `src/server.js:517`
- `src/server.js:520-527`
- `src/server.js:541-546`
- `src/server.js:547-552`

**Supporting evidence**

- `src/server.js:490-510`
- `src/server.js:470-520`
- `src/server.js:470-589`

**Severity explanation**

The endpoint performs multiple writes and reads against app_events and job_sources and triggers background feed seeding and rescoring. Unrestricted repeated calls can amplify DB load and background job starts, enabling denial-of-service and resource exhaustion.

**Counterevidence considered**

No source evidence shows a rate-limiting middleware, guard, or check applied to /api/onboarding/complete. The per-IP limit for /api/contact and per-email limit for /api/auth/reset are route-specific and do not cover this handler.

**Prerequisites**

- Authenticated request with req.uid
- User profile exists
- Endpoint reachable via POST /api/onboarding/complete

**Detector:** CodeQL
**Rule:** `js/missing-rate-limiting`
**Case reference:** `case_4a93fc55c95125f02f977a09`

---

<a id="finding-9"></a>

### Finding 9: Missing rate limiting

**Severity:** High

**Issue**

The /api/jobs GET handler at src/server.js performs expensive database access via multiple db().query calls building a complex join/filter query and count query, and it is not wrapped by any rate-limiting middleware or per-IP/user throttle. The handler code shows parameter parsing and direct db().query execution with no rate limit check preceding it. No global rate limiter is registered in server initialization; only isolated per-IP limits exist for /api/contact and a per-email throttle for /api/auth/reset, but the jobs feed endpoint lacks any limiting control, exposing it to DB DoS via repeated requests.

**Impact**

An unauthenticated attacker with valid tokens or many legitimate users can issue repeated /api/jobs requests with varied filters to amplify PostgreSQL work, increasing CPU/IO, connection pool exhaustion, and response latency, leading to denial-of-service for the feed and downstream services.

**Recommended next action**

Add per-user/IP rate limiting to /api/jobs and similar read-heavy endpoints, e.g., Fastify rate-limit plugin or token bucket, and consider query cost caps.

#### Details

**Affected locations**

- `src/server.js:675-779`
- `src/server.js:757`
- `src/server.js:758`
- `src/server.js:770`

**Supporting evidence**

- `src/server.js:670-780`
- `src/server.js:770-850`
- `src/server.js:1-120`

**Severity explanation**

Endpoint performs expensive joins and full-text search against job_postings, user_job_fit and job_states on every request with user-controlled filters, pageSize up to 100. Unrestricted access enables denial-of-service via DB load amplification. Detector severity 7.5 maps to high impact.

**Counterevidence considered**

No rate-limit middleware registration or per-route throttle is present in server initialization. The only rate controls found are isolated to /api/contact per-IP map and password-reset per-email map, not applied to /api/jobs.

**Prerequisites**

- Authenticated request with valid Firebase token
- Endpoint /api/jobs is reachable via GET
- Database contains job_postings/user_job_fit data

**Detector:** CodeQL
**Rule:** `js/missing-rate-limiting`
**Case reference:** `case_70b847334cf7351c53552892`

---

<a id="finding-10"></a>

### Finding 10: Missing rate limiting

**Severity:** High

**Issue**

The POST /api/pipeline/manual handler at src/server.js performs expensive operations including external fetch of the supplied URL with AbortSignal timeout, computeFit with profile load, and three database writes (job_postings insert, user_job_fit upsert, job_states upsert). The handler is registered directly via app.post('/api/pipeline/manual', ...) with no per-route or global rate-limiting middleware applied. No rate-limit plugin is imported or registered, and the only rate-limiting logic in the file is for /api/auth/reset and /api/contact with local in-memory maps. The route therefore can be invoked repeatedly without restriction, enabling denial-of-service via DB load and outbound fetches.

**Impact**

Unlimited submissions can cause DB write amplification, external fetch abuse, increased cost and latency, and potential denial of service for the job pipeline and underlying Postgres.

**Recommended next action**

Add per-user and per-IP rate limiting to /api/pipeline/manual, e.g., fastify-rate-limit or in-memory token bucket, and consider limiting outbound fetch size/timeout and DB write frequency.

#### Details

**Affected locations**

- `src/server.js:805-853`
- `src/server.js:836-839`
- `src/server.js:843-846`
- `src/server.js:847-850`

**Supporting evidence**

- `src/server.js:800-860`
- `src/server.js:750-810`

**Severity explanation**

Handler performs external network fetch and multiple DB writes per request with no throttling, exposing to abuse / DoS; matches CWE-770/307/400 impact assessed as high per detector default.

**Counterevidence considered**

No rate-limit middleware, plugin import, or per-route throttle found in server initialization or around the /api/pipeline/manual handler; the only rate-limit constructs are isolated to password reset and contact endpoints.

**Prerequisites**

- Authenticated request with valid Firebase token
- req.body.title present
- Optional URL triggers outbound fetch

**Detector:** CodeQL
**Rule:** `js/missing-rate-limiting`
**Case reference:** `case_e7418db4f9d4e5c94050bf41`

---

<a id="finding-11"></a>

### Finding 11: Missing rate limiting

**Severity:** High

**Issue**

The handler at src/server.js around line 907 implements GET /api/jobs/:id/insights and performs database accesses before the AI call. The source shows a cached lookup `select result from job_ai_cache where job_id=$1 and user_id=$2 and kind='insights'` and a subsequent `select * from job_postings where id=$1 and (user_id='__system__' or user_id=$2)`, followed by hydrate and an expensive moonshotChat invocation. No per-route or global rate-limiting check is applied to this handler. The same pattern is repeated for GET /api/jobs/:id/interview which also queries `job_ai_cache` and `job_postings` and calls moonshotChat. The file contains ad-hoc rate limits for /api/contact and /api/auth/reset but no rate limiting middleware or guard is registered for the /api/jobs/:id/* endpoints, nor for the broader API. Hence the expensive DB + AI path is exposed without rate limiting, matching the missing-rate-limiting finding.

**Impact**

An unauthenticated or authenticated attacker can repeatedly invoke the insights/interview endpoints to trigger repeated database queries and costly LLM calls, leading to denial of service, increased latency for legitimate users, and unbounded AI API cost exposure.

**Recommended next action**

Add rate limiting for expensive AI endpoints, e.g., per-user token bucket or Fastify rate-limit plugin, and consider stricter limits for AI calls; also enforce caching and cost accounting.

#### Details

**Affected locations**

- `src/server.js:907-968`
- `src/server.js:912-915`
- `src/server.js:918`
- `src/server.js:960-965`

**Supporting evidence**

- `src/server.js:900-980`
- `src/server.js:980-1050`
- `src/server.js:420-500`

**Severity explanation**

The endpoint performs DB reads and an expensive LLM call via moonshotChat with up to 1500 tokens and 40s timeout. Unrestricted calls can be abused for denial-of-service and cost exhaustion, corresponding to CWE-770/307/400. The impact is elevated due to AI cost and DB load.

**Counterevidence considered**

No source evidence shows rate-limiting middleware, plugin registration, or per-route guard applied to /api/jobs/:id/insights or /api/jobs/:id/interview. The only rate limits found are for /api/contact and /api/auth/reset, which are unrelated routes.

**Prerequisites**

- Authenticated request with valid uid
- Valid job id accessible to user
- Cache miss for insights/interview
- Job has description text/html

**Detector:** CodeQL
**Rule:** `js/missing-rate-limiting`
**Case reference:** `case_ab549abefed586f876e83578`

---

<a id="finding-12"></a>

### Finding 12: Missing rate limiting

**Severity:** High

**Issue**

The /api/jobs/:id/insights and /api/jobs/:id/interview handlers perform database reads/writes and expensive AI calls without any rate-limiting guard. The interview handler does: cached select from job_ai_cache, select from job_postings, hydrateJobDescription, moonshotChat, then insert into job_ai_cache. The insights handler does similar DB reads/writes and moonshotChat. No per-route or global rate limiter is applied to these routes; the only rate limits in the file are ad-hoc per-IP maps for /api/contact and /api/auth/reset. The handlers therefore can be invoked repeatedly, causing DB load and costly AI calls, matching missing-rate-limiting.

**Impact**

Unbounded repeated requests can exhaust database connections, increase latency for legitimate users, and incur uncontrolled AI provider costs; enables denial-of-service and cost-based abuse.

**Recommended next action**

Add per-user/per-IP rate limiting or cost-based throttling to AI-expensive routes, e.g., via fastify-rate-limit or in-process token bucket, and verify coverage.

#### Details

**Affected locations**

- `src/server.js:970-1027`
- `src/server.js:974-977`
- `src/server.js:980`
- `src/server.js:1019-1024`

**Supporting evidence**

- `src/server.js:970-1030`
- `src/server.js:920-1030`

**Severity explanation**

Handler performs DB queries and external AI calls on every cache miss; unlimited invocation enables DoS/abuse and cost amplification. Severity aligns with detector 7.5.

**Counterevidence considered**

No rate-limit middleware or per-route throttling is observed for /api/jobs/:id/insights or /api/jobs/:id/interview; the file only contains manual per-IP limits for contact/reset endpoints.

**Prerequisites**

- Authenticated request reaches /api/jobs/:id/insights or /api/jobs/:id/interview
- Cache miss for the job/user/kind
- Job description exists

**Detector:** CodeQL
**Rule:** `js/missing-rate-limiting`
**Case reference:** `case_28755cf94002db6617e70aa3`

---

<a id="finding-13"></a>

### Finding 13: Missing rate limiting

**Severity:** High

**Issue**

The GET /api/candidate-context handler at src/server.js performs multiple database accesses including inserts/selects/updates on candidate_context and user_documents and calls extractResumeText, but no per-route or global rate-limiting middleware is applied to it. The surrounding auth hooks only verify Firebase token and cost accounting; the handler itself contains no rate-limit checks, throttling, or token-bucket logic. The file shows ad-hoc rate limiting only on specific endpoints such as /api/contact and /api/auth/reset, with no evidence of a shared rate-limit guard covering /api/candidate-context. Thus the expensive DB operations are exposed without rate limiting, matching the missing-rate-limiting finding.

**Impact**

An unauthenticated attacker with valid tokens, or a legitimate user abusing the endpoint, can issue repeated GET /api/candidate-context requests causing repeated DB queries and resume extraction work, leading to DB load increase, cost accumulation, and potential denial-of-service for other users.

**Recommended next action**

Add per-route or global rate limiting for /api/candidate-context, e.g., Fastify rate-limit plugin or per-user token bucket, and consider caching the seeded context to reduce DB pressure.

#### Details

**Affected locations**

- `src/server.js:1076-1092`
- `src/server.js:1079-1090`

**Supporting evidence**

- `src/server.js:1000-1080`
- `src/server.js:1070-1100`

**Severity explanation**

The endpoint performs repeated database reads/writes and file extraction per request and is authenticated but unauthenticated rate limited, enabling a denial-of-service via resource exhaustion and increased DB load. Detector severity 7.5 maps to high impact.

**Counterevidence considered**

No counterevidence found; no rate-limit middleware or per-route throttling is present on the candidate-context handler or applied globally via Fastify plugins in the examined source ranges. The only rate-limit patterns in the file are isolated to /api/contact and /api/auth/reset.

**Prerequisites**

- Authenticated request with valid Firebase token via onRequest auth hook
- Handler performs DB queries and optional resume extraction

**Detector:** CodeQL
**Rule:** `js/missing-rate-limiting`
**Case reference:** `case_0f7ad66e9983d5625e9bbcc3`

---

<a id="finding-14"></a>

### Finding 14: Missing rate limiting

**Severity:** High

**Issue**

The POST /api/jobs/:id/tailor handler at src/server.js performs multiple database reads and triggers an expensive fire-and-forget tailoring job via runTailorGeneration, yet no rate-limiting guard is applied to the route or via shared middleware. The handler code shows DB queries for tailored_resumes, job_postings and candidate_context and then sets tailorJobs and calls runTailorGeneration without any per-user/IP throttling, token bucket, or global rate limiter. The GET /api/jobs/:id/tailored handler referenced in the candidate locations also executes a DB query with no rate limiting. No rate-limiting middleware or per-route check is present in the surrounding server setup examined.

**Impact**

An unauthenticated or authenticated attacker can repeatedly invoke POST /api/jobs/:id/tailor to spawn costly DB queries and fire-and-forget AI tailoring jobs, consuming database connections, CPU, and external AI API quota, leading to denial of service and increased cost.

**Recommended next action**

Add per-user rate limiting to the tailor endpoints, e.g., via Fastify rate-limit plugin or in-process token bucket, and consider global rate limits for expensive AI operations.

#### Details

**Affected locations**

- `src/server.js:1308-1322`
- `src/server.js:1311-1315`

**Supporting evidence**

- `src/server.js:1270-1312`
- `src/server.js:1290-1325`
- `src/server.js:1308-1322`

**Severity explanation**

The endpoint kicks off an AI-driven tailoring generation that is expensive and database intensive, and can be invoked repeatedly. Lack of rate limiting enables denial-of-service/abuse via repeated expensive DB and AI work, matching CWE-770/307/400.

**Counterevidence considered**

No source evidence shows a rate limiter, token bucket, or throttling middleware applied to /api/jobs/:id/tailor or /api/jobs/:id/tailored. The only throttling observed in the file is a per-IP map for /api/contact and a per-email map for password reset, which are unrelated to the tailor routes.

**Prerequisites**

- Authenticated request with valid Firebase token via onRequest hook
- Valid job id param and user uid
- Candidate context and job posting exist in DB to trigger generation

**Detector:** CodeQL
**Rule:** `js/missing-rate-limiting`
**Case reference:** `case_50b29e2703ed160e535e3ef8`

---

<a id="finding-15"></a>

### Finding 15: Missing rate limiting

**Severity:** High

**Issue**

The handler at src/server.js lines 1325-1337 is app.put('/api/jobs/:id/tailored', ...) which performs a DB update via db().query with user-supplied resume_md / cover_letter_md and summary. The route definition shows no per-route rate-limit check and the file contains no global rate-limiting middleware or plugin registration for Fastify. Auth and cost hooks are present but no throttling is applied to this endpoint, so repeated writes can be issued without restriction, matching the missing-rate-limiting pattern for an expensive DB write operation.

**Impact**

Potential denial-of-service via DB write amplification and increased operational cost; repeated updates can exhaust DB connections / write capacity and degrade service for other users.

**Recommended next action**

Add per-user / per-route rate limiting, e.g., Fastify rate-limit plugin or in-memory token bucket, for write endpoints that hit the database, and verify coverage via tests.

#### Details

**Affected locations**

- `src/server.js:1325-1337`
- `src/server.js:1327-1334`

**Supporting evidence**

- `src/server.js:1325-1337`

**Severity explanation**

Unauthenticated rate limiting is absent for a state-changing DB write endpoint; an attacker with valid auth can flood the endpoint to cause DB load / DoS and increase cost, consistent with CWE-770/307/400.

**Counterevidence considered**

No source evidence shows a rate-limiting middleware, plugin, or per-request throttle applied to app.put('/api/jobs/:id/tailored') or globally to /api routes. The only rate-limit logic present in the file is a per-IP map for /api/contact and a per-email map for password reset, not applicable to this route.

**Prerequisites**

- Valid Firebase ID token so req.uid is populated by the auth onRequest hook
- Route reachable at PUT /api/jobs/:id/tailored

**Detector:** CodeQL
**Rule:** `js/missing-rate-limiting`
**Case reference:** `case_ae203d9071cad93ae11e70f4`

---

<a id="finding-16"></a>

### Finding 16: Missing rate limiting

**Severity:** High

**Issue**

The handler at src/server.js lines 1485-1495 is app.post('/api/prep/threads') which reads req.body and performs an await db().query insert into prep_threads with user-supplied job_id and title. The code shows no rate-limiting check, middleware, or throttling for this route. Auth is enforced by the global onRequest hook, but no per-route or global rate limit is applied to /api/prep/threads. The route therefore performs a database write without restricting request rate, matching the missing-rate-limiting pattern.

**Impact**

An unauthenticated attacker with valid token or a legitimate user can flood POST /api/prep/threads to generate unlimited prep_threads rows, increasing DB write load, storage consumption, and potentially degrading service for other users.

**Recommended next action**

Add rate limiting to the prep threads endpoints, e.g., per-user token bucket or global Fastify rate-limit plugin, and verify coverage.

#### Details

**Affected locations**

- `src/server.js:1485-1495`
- `src/server.js:1489-1493`

**Supporting evidence**

- `src/server.js:1485-1495`

**Severity explanation**

Unrestricted write endpoint can be abused for denial-of-service via database load and resource exhaustion; detector severity 7.5 maps to high impact.

**Counterevidence considered**

No rate-limiting middleware, plugin registration, or per-route throttling is observed in the server initialization or on the /api/prep/threads handler. The only rate limits found in the file are for /api/contact per-IP and /api/auth/reset per-email, not for prep threads.

**Prerequisites**

- The route app.post('/api/prep/threads') exists and performs db().query insert
- Auth hook sets req.uid but no rate limiting is applied
- Database write is performed synchronously per request

**Detector:** CodeQL
**Rule:** `js/missing-rate-limiting`
**Case reference:** `case_8435257674806f9d93214527`

---

<a id="finding-17"></a>

### Finding 17: Missing rate limiting

**Severity:** High

**Issue**

The handler app.get('/api/prep/threads/:id') at src/server.js performs two database accesses via db().query without any rate-limiting guard. The code shows UUID validation and ownership check but no per-user/IP throttling or global rate-limit middleware applied to this route. The same pattern is repeated for other /api/prep handlers which also call db().query. No rate-limit plugin or per-route limiter is imported or configured in the server bootstrap, and the specific handler lacks checks for request frequency.

**Impact**

Repeated unauthenticated or authenticated requests can trigger repeated database reads, leading to DB load amplification, increased latency, and potential denial-of-service for the prep feature and shared database.

**Recommended next action**

Add per-route or global rate limiting for /api/prep/* handlers, e.g., Fastify rate-limit plugin with user/IP key, and consider caching for read-heavy threads endpoint.

#### Details

**Affected locations**

- `src/server.js:1497-1513`
- `src/server.js:1500-1505`
- `src/server.js:1507-1509`

**Supporting evidence**

- `src/server.js:1450-1520`
- `src/server.js:1495-1515`

**Severity explanation**

Unrestricted DB queries on a per-user resource can be abused for denial-of-service / resource exhaustion. The route is authenticated and performs multiple SELECTs, making it suitable for amplification attacks. Detector severity 7.5 maps to high.

**Counterevidence considered**

No rate-limit middleware, per-route limiter, or per-IP/user throttling is present in the handler or in the server bootstrap for the /api/prep/threads/:id route. The only rate-limiting observed in the file is for /api/contact and /api/auth/reset, not for prep routes.

**Prerequisites**

- Authenticated request with req.uid set by auth hook
- Valid UUID in req.params.id matching UUID_RE
- Thread exists and belongs to user

**Detector:** CodeQL
**Rule:** `js/missing-rate-limiting`
**Case reference:** `case_689e36cb7ef1caff8f0f89e5`

---

<a id="finding-18"></a>

### Finding 18: Missing rate limiting

**Severity:** High

**Issue**

The candidate locations correspond to the prep handlers in src/server.js that perform DB writes/reads for interview prep threads and generation. The source shows app.post("/api/prep/threads/:id/messages"), app.delete("/api/prep/threads/:id"), and app.post("/api/prep/generate") executing db().query inserts/updates/selects and invoking runPrepTurn, with no per-route or global rate-limit middleware applied. The file contains only ad-hoc per-IP limits for /api/contact and a 60s per-email limit for password reset, no rate limiting for the prep routes. Evidence reads confirm DB access without rate limiting controls.

**Impact**

Unbounded calls can cause DB write amplification, prepJobs contention, and excessive AI/LLM invocations via runPrepTurn, leading to denial of service and cost exhaustion.

**Recommended next action**

Add Fastify rate-limit middleware or per-route guard for /api/prep/* handlers, e.g., token bucket per uid/IP, and verify existing contact rate limit does not implicitly protect these routes.

#### Details

**Affected locations**

- `src/server.js:1547-1573`
- `src/server.js:1553`
- `src/server.js:1558`
- `src/server.js:1561-1562`
- `src/server.js:1567-1569`

**Supporting evidence**

- `src/server.js:1540-1580`
- `src/server.js:1500-1600`
- `src/server.js:1525-1555`

**Severity explanation**

Route performs database writes and triggers AI work; unbounded request rate enables DoS / resource exhaustion via DB and downstream AI costs. Detector severity 7.5 maps to high.

**Counterevidence considered**

No global rate-limit middleware or per-route limiter is present in the server bootstrap or in the prep handlers; the only rate controls observed are for /api/contact per-IP and password-reset per-email, not covering the prep endpoints.

**Prerequisites**

- Authenticated request with valid Firebase token
- Valid UUID thread id and body content
- DB connectivity to prep_threads/prep_messages

**Detector:** CodeQL
**Rule:** `js/missing-rate-limiting`
**Case reference:** `case_897ed76278da7d8c25ec5639`

---

<a id="finding-19"></a>

### Finding 19: Missing rate limiting

**Severity:** High

**Issue**

The POST /api/prep/notes handler at src/server.js 1613-1624 performs an authenticated database INSERT via db().query with no per-route or global rate-limit check. The handler is defined as app.post("/api/prep/notes", async (req) => { ... const r = await db().query(`insert into prep_notes...` ... }) and returns the inserted row. The surrounding code shows normNoteInput and the insert, confirming an expensive DB write. No rate-limit middleware, plugin registration, or per-IP/user throttling is applied to this route. The file contains ad-hoc rate limits only for /api/contact and /api/auth/reset, and no Fastify rate-limit plugin or shared guard is registered for the API. Therefore the route can be called repeatedly by an authenticated user without restriction, enabling denial-of-service via DB load.

**Impact**

Repeated unauthenticated-rate-limited inserts can exhaust DB write capacity, increase storage, and degrade latency for all users; effectively a denial-of-service vector for the prep notes feature.

**Recommended next action**

Add a Fastify rate-limit plugin or per-route middleware for /api/prep/notes and related prep endpoints, e.g., per-user limits such as 10-30 writes/minute, and verify no other write-heavy routes lack limits.

#### Details

**Affected locations**

- `src/server.js:1613-1624`
- `src/server.js:1618-1622`

**Supporting evidence**

- `src/server.js:1613-1624`
- `src/server.js:1590-1650`

**Severity explanation**

An unauthenticated-rate-limited write endpoint that performs DB inserts can be abused to exhaust database connections/CPU and storage, leading to denial-of-service for the service. The operation is state-changing and expensive, matching CWE-770/307/400 impact, consistent with detector severity 7.5.

**Counterevidence considered**

No source evidence shows a rate-limit plugin registration, global onRequest/onPreHandler throttling, or per-route rate limiting applied to /api/prep/notes. The only rate limits found are a per-IP Map for /api/contact and a per-email Map for /api/auth/reset, which are unrelated to the notes endpoint.

**Prerequisites**

- Authenticated request with valid Firebase token so req.uid is set by onRequest auth hook
- Endpoint is exposed under /api/prep/notes via Fastify app.post

**Detector:** CodeQL
**Rule:** `js/missing-rate-limiting`
**Case reference:** `case_26c915c8a01e22a0c8a0ff6c`

---

<a id="finding-20"></a>

### Finding 20: Missing rate limiting

**Severity:** High

**Issue**

The handler at src/server.js around line 1681 is app.post('/api/workflows') which normalises input, validates it and performs an INSERT into workflows via db().query. The code shows no per-route or global rate-limiting check before the database write, and the surrounding server setup contains no Fastify rate-limit plugin registration or middleware that applies to /api routes. The file contains explicit per-IP rate limiting only for /api/contact and a per-email throttle for /api/auth/reset, but the workflows endpoints lack any rate limiting guard, leaving the DB write exposed to abuse/DoS.

**Impact**

Repeated POST /api/workflows can exhaust database connections / write capacity, increase cost, and enable DoS against the service. Validation is cheap but the DB insert and subsequent writes can be amplified by an attacker.

**Recommended next action**

Add rate limiting to workflow mutation endpoints, e.g., per-user token bucket, and consider global Fastify rate-limit plugin for all /api/* routes.

#### Details

**Affected locations**

- `src/server.js:1681-1692`
- `src/server.js:1685-1690`

**Supporting evidence**

- `src/server.js:1665-1705`
- `src/server.js:1705-1750`

**Severity explanation**

An unauthenticated or authenticated user can repeatedly POST to /api/workflows triggering expensive DB inserts and validation, enabling denial-of-service and resource exhaustion. The rule maps to CWE-770/307/400 with default severity 7.5, which aligns with high impact.

**Counterevidence considered**

No source evidence shows a rate-limit plugin registration, global onRequest/onPreHandler rate limiter, or per-route rate limiting applied to /api/workflows. The only rate-limiting present in the file is the manual per-IP map for /api/contact and the per-email map for password reset, which does not cover the workflows routes.

**Prerequisites**

- Authenticated request with valid Firebase token is required by onRequest auth hook, but rate limiting is independent of auth.
- Handler performs DB write via db().query INSERT into workflows.
- No middleware or plugin enforces request rate caps for this route.

**Detector:** CodeQL
**Rule:** `js/missing-rate-limiting`
**Case reference:** `case_f3aefaf949dac15d01d87fff`

---

<a id="finding-21"></a>

### Finding 21: Missing rate limiting

**Severity:** High

**Issue**

The /api/workflows/preview handler at src/server.js performs expensive database work via compileRule and two db().query calls with Promise.all, and the handler code shows no per-route or global rate limiting applied. The surrounding source shows only ad-hoc rate limits for /api/contact and password reset, with no rate-limit middleware or guard on the workflows preview route. Thus the handler can be called repeatedly without restriction, matching the missing-rate-limiting finding.

**Impact**

Unrestricted calls to the preview endpoint can amplify database load via compiled dynamic queries with joins, enabling DoS/abuse and increased cost.

**Recommended next action**

Add rate limiting to the workflows preview and run endpoints, e.g., per-user token bucket, and consider query cost caps.

#### Details

**Affected locations**

- `src/server.js:1694-1706`
- `src/server.js:1698-1703`

**Supporting evidence**

- `src/server.js:1700-1750`

**Severity explanation**

The preview endpoint executes compiled dynamic SQL with joins against job_postings, user_job_fit and job_states and returns a count plus a sample set. Unrestricted repeated calls can exhaust DB connections/CPU and constitute a denial-of-service vector, consistent with CWE-770/307/400. Severity aligns with detector rating ~7.5.

**Counterevidence considered**

No rate-limit middleware or per-route guard is present on /api/workflows/preview; the only rate limits in the file are the per-IP contact limit and the 60s password-reset limit. No global Fastify rate-limit plugin is registered in the examined server bootstrap and auth hooks.

**Prerequisites**

- Authenticated request reaches /api/workflows/preview
- Handler compiles user-supplied rule and runs two DB queries
- No rate-limiting middleware is configured globally or on this route

**Detector:** CodeQL
**Rule:** `js/missing-rate-limiting`
**Case reference:** `case_d050e369cd9a306940ddc082`

---

<a id="finding-22"></a>

### Finding 22: Missing regular expression anchor

**Severity:** Medium

**Issue**

The source shows xProfileUrl normalises URLs with a regex that is anchored at the start but not at the end. Line 140 contains `if (/^https?:\/\//i.test(s)) return s.replace(/^https?:\/\/(www\.)?twitter\.com/i, 'https://x.com');`. The replacement pattern `/^https?:\/\/(www\.)?twitter\.com/i` lacks a trailing anchor or path delimiter, so strings such as `https://twitter.com.evil.com` match the prefix and are rewritten to `https://x.com.evil.com`. This is the missing-regexp-anchor condition reported by the detector.

**Impact**

Maliciously crafted URLs can bypass the intended twitter.com → x.com normalisation, producing a rewritten URL that points to an attacker-controlled domain suffix. This can lead to incorrect profile resolution, potential SSRF-like data fetch from unintended host, and loss of integrity of downstream Bright Data requests.

**Recommended next action**

Anchor the hostname regex with a word boundary or trailing `/$` and consider validating the full hostname with URL parsing before replacement.

#### Details

**Affected locations**

- `src/signals/brightdata.js:140`

**Supporting evidence**

- `src/signals/brightdata.js:135-145`

**Severity explanation**

The bug can cause incorrect canonicalisation of X profile URLs, allowing a crafted host suffix to survive the rewrite. This is not direct remote code execution but enables URL spoofing / data fetching from an unintended host, which warrants medium severity.

**Counterevidence considered**

No countervailing guard was found in the read range; the regex is used directly for replacement without a trailing `$` or `/` check.

**Prerequisites**

- Input is a string beginning with http/https that contains the twitter.com prefix
- xProfileUrl is invoked for user-supplied handles/URLs
- No additional validation of the host after replacement

**Detector:** CodeQL
**Rule:** `js/regex/missing-regexp-anchor`
**Case reference:** `case_314a4a4833626ac943124b68`

---

<a id="finding-23"></a>

### Finding 23: Incomplete HTML attribute sanitization

**Severity:** Medium

**Issue**

The esc helper defined at lines 10-13 only replaces &, < and > and does not escape double quotes. The HTML string built for the report uses esc on user-controlled apply_url inside a double-quoted href attribute at line 72: <a href="${esc(j.apply_url)}". Because double quotes are not encoded, a value containing " can break out of the attribute and inject HTML/JavaScript. The code flow from the esc function to the attribute interpolation is present in src/notify/digest.js, confirming incomplete attribute sanitization for HTML output stored in reports.html and used in the digest.

**Impact**

Stored cross-site scripting via crafted apply_url breaking out of href attribute in the generated report HTML, potentially leading to script execution in viewers of the digest report.

**Recommended next action**

Review apply_url validation at ingestion and replace esc with a proper HTML attribute encoder or use DOM-safe construction; also audit other uses of esc for attribute contexts.

#### Details

**Affected locations**

- `src/notify/digest.js:10-13`
- `src/notify/digest.js:72`

**Supporting evidence**

- `src/notify/digest.js:1-109`

**Severity explanation**

Attribute injection can lead to stored XSS when the generated HTML is rendered to users. The impact is limited to the digest report page and depends on attacker control of apply_url in job_postings, giving medium severity.

**Counterevidence considered**

No counterevidence found; esc does not encode double quotes and the href attribute is constructed with double quotes around the interpolated value.

**Prerequisites**

- apply_url value from job_postings contains a double quote or other characters that break the attribute
- the generated html is rendered to an end user without further encoding
- reports.html is served or displayed in a context that interprets HTML

**Detector:** CodeQL
**Rule:** `js/incomplete-html-attribute-sanitization`
**Case reference:** `case_522a56d893b9e184c8e945cc`

---

<a id="finding-24"></a>

### Finding 24: Incomplete HTML attribute sanitization

**Severity:** Medium

**Issue**

The esc helper at src/notify/workflows.js replaces only &, < and > and leaves " unescaped. renderAlertEmail builds HTML with attribute values interpolated as href="${esc(j.apply_url)}" and href="${esc(baseUrl)}/alerts". Because esc does not encode double quotes, a crafted apply_url containing " can break out of the href attribute and inject arbitrary HTML/JS into the email body. The code flow from the esc definition to its use in the href attribute is present in source, confirming incomplete attribute sanitization leading to XSS in generated email HTML.

**Impact**

An attacker who can influence a job posting apply_url can inject HTML/JavaScript into the alert email, leading to cross-site scripting when the email is rendered by a vulnerable client, potentially stealing credentials or performing actions on behalf of the recipient.

**Recommended next action**

Review and replace esc with a proper HTML attribute encoder or use a templating library that auto-escapes attributes, and ensure URLs are validated/encoded before insertion.

#### Details

**Affected locations**

- `src/notify/workflows.js:19`
- `src/notify/workflows.js:69`

**Supporting evidence**

- `src/notify/workflows.js:1-120`
- `src/notify/workflows.js:40-90`

**Severity explanation**

XSS in email HTML can execute in vulnerable email clients and the payload is injected via user-influenced job data. Impact is limited to email rendering context and requires attacker-controlled apply_url, so medium severity is appropriate.

**Counterevidence considered**

No counterevidence found; esc is defined without quote encoding and is directly used in double-quoted href attributes without additional encoding.

**Prerequisites**

- apply_url or baseUrl contains a double quote or other characters that break attribute context
- renderAlertEmail output is delivered as HTML email to a client that renders HTML
- no additional encoding layer is applied after esc

**Detector:** CodeQL
**Rule:** `js/incomplete-html-attribute-sanitization`
**Case reference:** `case_e363fced629d1cee1ae7e02a`

---

<a id="finding-25"></a>

### Finding 25: Incomplete HTML attribute sanitization

**Severity:** Medium

**Issue**

The `esc` helper at src/notify/workflows.js replaces only `&`, `<`, `>` and is used to build HTML attribute values delimited by double quotes. In `renderAlertEmail` the helper is applied to `baseUrl` and `j.apply_url` inside `href="${esc(... )}"`. Because `esc` does not encode `"`, a double quote in the input can close the attribute and inject markup. The definition shows the limited replacements and the usages show insertion into double-quoted attributes, confirming incomplete attribute sanitization.

**Impact**

Potential cross-site scripting in email HTML via attribute breakout when unescaped double quotes reach href attributes, allowing injection of additional attributes or JavaScript URIs.

**Recommended next action**

Replace esc with an attribute-safe encoder that escapes " and ' , or use a dedicated HTML serializer for attribute contexts, and audit other interpolations in renderAlertEmail.

#### Details

**Affected locations**

- `src/notify/workflows.js:19`
- `src/notify/workflows.js:79`

**Supporting evidence**

- `src/notify/workflows.js:1-120`
- `src/notify/workflows.js:70-90`
- `src/notify/workflows.js:55-70`

**Severity explanation**

Attribute injection via unescaped double quotes can break out of href attributes in the generated email HTML, enabling script execution in vulnerable email clients. Impact is limited to email rendering context and requires attacker-controlled URL input.

**Counterevidence considered**

No counterevidence found; the esc function does not escape double quotes and is directly interpolated into double-quoted HTML attributes.

**Prerequisites**

- baseUrl or apply_url contains a double quote character
- renderAlertEmail is executed with untrusted URL input
- email HTML is rendered by a client that processes injected markup

**Detector:** CodeQL
**Rule:** `js/incomplete-html-attribute-sanitization`
**Case reference:** `case_224d2b025f5eeb59042e2283`

---

<a id="finding-26"></a>

### Finding 26: Incomplete HTML attribute sanitization

**Severity:** Medium

**Issue**

The source defines esc at src/web/assets/app.js line 8 as String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;") which does not escape double quotes. The same esc is used to interpolate values into HTML attribute strings built via template literals and assigned to innerHTML. For example in renderList the template contains data-id="${esc(j.id)}" and href="${esc(j.apply_url)}" where esc(j.id) is inserted directly into an attribute value delimited by double quotes. Because double quotes are not escaped, a value containing " can break out of the attribute and inject markup/JavaScript. The code flow from the esc definition to the attribute interpolation is present in the file, confirming incomplete HTML attribute sanitization.

**Impact**

An attacker able to influence job fields returned by /api/jobs can inject a double quote into an attribute value, breaking out of the attribute and injecting arbitrary HTML/JavaScript executed in the user's browser session, leading to session hijacking or actions performed as the user.

**Recommended next action**

Replace innerHTML string building with DOM APIs or a complete HTML entity encoder that escapes &, <, >, ", and ' for attribute contexts, and validate/sanitize server-side data.

#### Details

**Affected locations**

- `src/web/assets/app.js:8`
- `src/web/assets/app.js:52`

**Supporting evidence**

- `src/web/assets/app.js:1-120`

**Severity explanation**

Attribute injection leading to XSS is possible when untrusted data contains a double quote. Impact is script execution in the victim's origin with user interaction; no evidence of additional server-side encoding. Severity aligns with medium for reflected/stored XSS via DOM innerHTML.

**Counterevidence considered**

No counterevidence found in the read range; esc is defined without double-quote escaping and is used directly in double-quoted attribute contexts via innerHTML.

**Prerequisites**

- j.id, j.apply_url, j.title, j.company_name, j.location_raw, j.salary_max, notes, or fit reasons contain a double quote character
- renderList or renderJob is executed with data from the API
- the generated markup is inserted via innerHTML as shown

**Detector:** CodeQL
**Rule:** `js/incomplete-html-attribute-sanitization`
**Case reference:** `case_7314e2a7601b32822cdafdb1`

---

<a id="finding-27"></a>

### Finding 27: Incomplete HTML attribute sanitization

**Severity:** Medium

**Issue**

The `esc` helper only replaces `&`, `<`, `>` and does not encode quotes or other attribute-breaking characters. Both renderList and renderJob embed user-controlled `j.apply_url` into an HTML attribute via `href="${esc(j.apply_url)}"`. Because `esc` leaves double quotes intact, a crafted apply_url containing `"` can break out of the attribute and inject markup/JavaScript. The sanitizer is therefore incomplete for attribute contexts.

**Impact**

An attacker-controlled `apply_url` containing a double quote can break the `href` attribute and inject arbitrary HTML/JavaScript, leading to cross-site scripting in the job list and job detail pages.

**Recommended next action**

Update `esc` to also encode quotes and `'` or switch to DOM-based attribute assignment; review all uses of `esc` in attribute contexts.

#### Details

**Affected locations**

- `src/web/assets/app.js:8`
- `src/web/assets/app.js:102`

**Supporting evidence**

- `src/web/assets/app.js:5-9`
- `src/web/assets/app.js:40-60`
- `src/web/assets/app.js:85-105`

**Severity explanation**

Attribute injection via unsanitized quotes enables stored/reflected XSS with medium impact; severity aligns with detector 6.1 and typical XSS exposure.

**Counterevidence considered**

No source evidence shows additional encoding of `apply_url` before insertion into `href` attributes, nor use of safe DOM APIs such as `setAttribute` with proper encoding. The `esc` function is used directly in both locations.

**Prerequisites**

- `j.apply_url` originates from API data and is attacker controllable or influenced
- `esc` is used for HTML attribute interpolation
- Output is written via `innerHTML`

**Detector:** CodeQL
**Rule:** `js/incomplete-html-attribute-sanitization`
**Case reference:** `case_471ac32da1a2cb1aa985ef2c`

---

<a id="finding-28"></a>

### Finding 28: Incomplete HTML attribute sanitization

**Severity:** Medium

**Issue**

The esc helper at line 8 only replaces &, < and > and does not escape double quotes. The function is used to build HTML attribute values delimited by double quotes, e.g., href="${esc(j.apply_url)}" in renderList and href="${esc(s.url)}" in the referral signals rendering. Because double quotes are not encoded, an attacker-controlled URL containing a double quote can break out of the attribute and inject markup/JavaScript. The code flow from line 8 definition to line 164 usage shows the incomplete sanitizer is applied to attribute context, confirming incomplete HTML attribute sanitization.

**Impact**

An attacker who can influence apply_url or signal url can inject a double quote to break out of the href attribute and inject arbitrary HTML/JavaScript, leading to cross-site scripting in the context of the web app.

**Recommended next action**

Review and strengthen esc to encode quotes and other attribute-relevant characters, or use DOM APIs / safe templating for attribute insertion.

#### Details

**Affected locations**

- `src/web/assets/app.js:8`
- `src/web/assets/app.js:164`

**Supporting evidence**

- `src/web/assets/app.js:1-120`
- `src/web/assets/app.js:150-180`

**Severity explanation**

Attribute injection via unsanitized double quotes enables stored/reflected XSS in the job listing and signals pages. Impact is script execution in user context; no evidence of additional output encoding or CSP mitigation in the read source, so medium severity is appropriate.

**Counterevidence considered**

No counterevidence found in the read ranges; esc is defined without quote encoding and is directly interpolated into double-quoted HTML attributes.

**Prerequisites**

- User-controllable job apply_url, signal url, or other fields flow into esc()
- esc() output is interpolated into HTML attribute values delimited by double quotes
- No additional attribute encoding or DOM-safe insertion is applied downstream

**Detector:** CodeQL
**Rule:** `js/incomplete-html-attribute-sanitization`
**Case reference:** `case_bb5fed3f77ac1ecdd0b9f613`

---

<a id="finding-29"></a>

### Finding 29: Incomplete HTML attribute sanitization

**Severity:** Medium

**Issue**

The esc helper defined at line 8 only replaces &, < and > and does not encode double quotes or other attribute-breaking characters. The generated markup on line 56 interpolates user-controlled data via esc(j.apply_url) inside a double-quoted href attribute and also uses esc for data-id attributes, e.g. data-id="${esc(j.id)}". Because " is not escaped, a value containing a double quote can close the attribute prematurely and inject additional attributes or script, constituting incomplete HTML attribute sanitization leading to XSS. The code flow from the esc definition to the attribute interpolation is visible in the source.

**Impact**

An attacker able to influence job fields returned by /api/dashboard can inject a double quote into apply_url or other fields, breaking the href/data-id attribute and injecting arbitrary HTML/JS executed in the dashboard page context.

**Recommended next action**

Replace innerHTML construction with DOM APIs or ensure attribute values are encoded for HTML attributes, e.g., encode " and ' and use proper escaping or a dedicated HTML attribute encoder.

#### Details

**Affected locations**

- `src/web/assets/dashboard.js:8`
- `src/web/assets/dashboard.js:56`

**Supporting evidence**

- `src/web/assets/dashboard.js:1-98`

**Severity explanation**

Attribute injection can lead to stored/reflected XSS depending on API data provenance; the sanitizer omits quote encoding, giving a medium severity per detector baseline and typical XSS impact.

**Counterevidence considered**

No source evidence shows additional encoding, quote escaping, or DOM-safe construction for the interpolated attributes; the esc function is used directly in attribute contexts without further sanitization.

**Prerequisites**

- apply_url, id, title, company_name, location_raw, state values originate from API response data.jobs
- generated markup is inserted via innerHTML
- esc is the only transformation applied before interpolation

**Detector:** CodeQL
**Rule:** `js/incomplete-html-attribute-sanitization`
**Case reference:** `case_bb06a998273f6699f7216c17`

---

<a id="finding-30"></a>

### Finding 30: Incomplete HTML attribute sanitization

**Severity:** Medium

**Issue**

The esc helper at src/web/assets/dashboard.js defines sanitization as String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;") and does not escape double quotes or other attribute-breaking characters. The function is used to build HTML via innerHTML in load(), e.g. data-id="${esc(j.id)}" and href="${esc(j.apply_url)}". Because the attribute values are delimited by double quotes, an input containing " can terminate the attribute and inject arbitrary HTML/JS. The code flow from the esc definition to the attribute interpolation is present in the same file, confirming incomplete attribute sanitization.

**Impact**

An attacker who can influence job fields can inject a double quote into an attribute value, breaking out of the attribute and injecting additional attributes or event handlers, leading to cross-site scripting in the dashboard page.

**Recommended next action**

Review esc to add comprehensive HTML attribute escaping, e.g., also replace " with &quot; and ' with &#x27;, or use DOM APIs instead of innerHTML concatenation.

#### Details

**Affected locations**

- `src/web/assets/dashboard.js:8`
- `src/web/assets/dashboard.js:58`

**Supporting evidence**

- `src/web/assets/dashboard.js:1-98`

**Severity explanation**

Escaping of &, <, > only leaves double quotes unescaped in attribute contexts, enabling attribute injection and potential script execution via crafted job data. Detector severity 6.1 aligns with medium impact XSS.

**Counterevidence considered**

No counterevidence found; esc is defined without quote escaping and is used directly inside double-quoted attribute values in the innerHTML template.

**Prerequisites**

- j.id, j.apply_url, j.title, j.company_name, j.location_raw, j.state contain a double quote or other attribute-breaking sequence
- data.jobs is rendered via el.innerHTML with the template shown
- user-controlled or attacker-influenced job fields are passed to the template without additional encoding

**Detector:** CodeQL
**Rule:** `js/incomplete-html-attribute-sanitization`
**Case reference:** `case_6c1da666c0b980a53f9ce7b8`

---

<a id="finding-31"></a>

### Finding 31: Incomplete HTML attribute sanitization

**Severity:** Medium

**Issue**

The source defines esc(s) as String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;") which does not encode double quotes. The function is used to build HTML that is injected via innerHTML. In refresh(), the template literal includes `<a href="${esc(s.url)}" target="_blank" rel="noreferrer">` where s.url originates from api('/api/signals') and is therefore attacker-controllable. Because esc does not escape ", an attacker-supplied URL containing a double quote can break out of the href attribute and inject arbitrary attributes or script, leading to XSS. The same esc is defined at the location cited and used in the attribute construction cited, confirming the incomplete attribute sanitization path described by the candidate.

**Impact**

An attacker-controlled URL can break out of the href attribute, enabling injection of additional attributes or JavaScript execution via XSS when the signals list is rendered.

**Recommended next action**

Replace esc with a complete HTML attribute encoder or use DOM APIs to set attributes safely, e.g., encode " and ' and also use textContent for content, and consider a Content Security Policy.

#### Details

**Affected locations**

- `src/web/assets/signals.js:8`
- `src/web/assets/signals.js:22`

**Supporting evidence**

- `src/web/assets/signals.js:1-61`

**Severity explanation**

Attribute injection via innerHTML with unescaped double quotes enables stored/reflected XSS in the signals list view. Impact is script execution in the context of the web app, which is a typical medium severity XSS with no evidence of additional sandboxing or CSP mitigation in the read range.

**Counterevidence considered**

No counterevidence found in the read range. The esc implementation is confirmed to lack double-quote encoding and is directly used in an HTML attribute interpolated into innerHTML.

**Prerequisites**

- s.url is supplied by the backend API /api/signals and can be influenced by an attacker
- the signals list is rendered via element.innerHTML with template literals
- esc is the only sanitization applied before insertion

**Detector:** CodeQL
**Rule:** `js/incomplete-html-attribute-sanitization`
**Case reference:** `case_72adecf43060f02dcc52fa52`

---

<a id="finding-32"></a>

### Finding 32: Incomplete HTML attribute sanitization

**Severity:** Medium

**Issue**

The source defines esc as String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;") which does not escape double quotes or single quotes. The sanitized value is then interpolated into an HTML attribute delimited by double quotes via innerHTML: \<button data-key="${esc(s.key)}" data-enabled="${s.enabled}">. Because esc leaves " intact, a source-controlled s.key containing a double quote can break out of the attribute value and inject additional attributes or event handlers. The code flow from esc definition to its use in the attribute construction is present in the file, confirming incomplete attribute sanitization as alleged.

**Impact**

An attacker who can influence s.key, s.name, s.type or last_success_at can inject a double quote to break out of the data-key attribute and inject arbitrary HTML/attributes, leading to cross-site scripting in the sources page context.

**Recommended next action**

Replace innerHTML construction with safe DOM APIs or extend esc to encode " and ' and use proper attribute escaping, e.g., replace /"/g with &quot; and avoid innerHTML for user data.

#### Details

**Affected locations**

- `src/web/assets/sources.js:8`
- `src/web/assets/sources.js:20`

**Supporting evidence**

- `src/web/assets/sources.js:1-42`

**Severity explanation**

Attribute injection via innerHTML can lead to stored/reflected XSS with user-controlled source data, enabling script execution in the context of the application. This matches a medium severity XSS exposure.

**Counterevidence considered**

No counter-evidence found; esc is used directly for attribute interpolation without quote escaping, and innerHTML is used to insert the constructed markup.

**Prerequisites**

- s.key or other source fields originate from user-controlled / API data
- load() renders the sources list via innerHTML
- esc is the only sanitization applied before interpolation into HTML attributes

**Detector:** CodeQL
**Rule:** `js/incomplete-html-attribute-sanitization`
**Case reference:** `case_2b6963e3031f32e934f4ecee`

---

<a id="finding-33"></a>

### Finding 33: Incomplete string escaping or encoding

**Severity:** Medium

**Issue**

The DSL generator for text conditions builds a quoted string with only double-quote escaping. In ui/src/components/RuleBuilder.tsx condToDsl constructs the output as `${c.field} ${c.op} "${v.replace(/"/g, '\\"')}"`; the replace handles " but does not escape backslash characters. Therefore a backslash in the user-supplied value remains unescaped in the generated DSL, which is an incomplete sanitization of a meta-character for the DSL string literal.

**Impact**

Generated DSL may contain unescaped backslashes, leading to malformed quoting, potential parser misinterpretation, and incomplete sanitization of the DSL string literal.

**Recommended next action**

Review condToDsl to add comprehensive escaping for backslash and other DSL meta-characters, or use a proper encoder for DSL string literals.

#### Details

**Affected locations**

- `ui/src/components/RuleBuilder.tsx:33`

**Supporting evidence**

- `ui/src/components/RuleBuilder.tsx:25-45`
- `ui/src/components/RuleBuilder.tsx:1-100`

**Severity explanation**

The incomplete escaping can produce malformed DSL strings and enable parser confusion or injection via backslash sequences in text field values. Impact is limited to the builder-generated DSL and does not directly reach remote execution, warranting medium severity.

**Counterevidence considered**

No source evidence shows backslash escaping or a downstream canonicalization step that normalizes backslashes before the DSL string is emitted or consumed. The condToDsl implementation only replaces double quotes.

**Prerequisites**

- A text-type field condition is present
- condToDsl is invoked via buildDsl for that condition
- User-supplied value contains a backslash character

**Detector:** CodeQL
**Rule:** `js/incomplete-sanitization`
**Case reference:** `case_3273c7173dfcb7ab29e6b971`

---

<a id="finding-34"></a>

### Finding 34: Remote property injection

**Severity:** Medium

**Issue**

The redact function iterates over user-supplied objects from req.body and req.query and writes properties using a user-controlled key k: for (const [k, v] of Object.entries(obj)) { ... out[k] = ... }. The onError hook passes redact(req.body) and redact(req.query) into logging, so req.body and req.query flow into redact. This is a direct write to an object with a property name derived from untrusted input, matching remote property injection. No sanitization of property names such as __proto__ / constructor is performed before the out[k] assignments, so arbitrary property names can be written, including prototype pollution vectors, which can lead to denial-of-service.

**Impact**

Attacker can supply crafted object keys, e.g., __proto__, constructor, prototype, to cause prototype pollution or force creation of many properties. In logging context this can lead to denial-of-service via excessive object growth, prototype pollution side effects, or log poisoning. The write uses user-controlled property names without validation.

**Recommended next action**

Consider hardening redact to use a safe property assignment such as Object.create(null) and/or an allowlist/blocklist for keys like __proto__, constructor, prototype, and avoid recursive copying of attacker-controlled objects for logging.

#### Details

**Affected locations**

- `src/server.js:97`
- `src/server.js:100`
- `src/server.js:102`
- `src/server.js:120`

**Supporting evidence**

- `src/server.js:98-104`
- `src/server.js:118-122`
- `src/server.js:95-110`

**Severity explanation**

Property name is controlled by remote request data and is used to write into a newly created object used for logging. While the object is short-lived, the write path is unsanitized and enables prototype pollution / arbitrary property injection, which is the classic denial-of-service exposure described for this rule. Severity is medium rather than critical/high because the object is not long-lived application state, but the injection path is present and exploitable in principle.

**Counterevidence considered**

No sanitization or allowlist of property names is applied before out[k] assignments; the code deliberately copies all enumerable keys from req.body / req.query into a new object. The function is invoked in the onError hook with req.body and req.query, confirming user-controlled source reaches the sink.

**Prerequisites**

- Request error path is triggered, req.body and/or req.query contain an object with attacker-controlled keys
- redact is executed with those objects, which it is in app.addHook('onError')

**Detector:** CodeQL
**Rule:** `js/remote-property-injection`
**Case reference:** `case_58977995fe450806e20a4292`

---

<a id="finding-35"></a>

### Finding 35: Remote property injection

**Severity:** Medium

**Issue**

The `redact` function iterates over user-controlled objects via `Object.entries(obj)` and writes to a newly created object using a user-controlled property name `k` with `out[k] = ...`. The function is invoked with request data `redact(req.body)` and `redact(req.query)` in the `onError` hook, so property names originate from `req.body` and `req.query`. This is a write to an object with a property name derived from remote input, enabling prototype pollution / remote property injection as flagged by the detector. No filtering of dangerous keys such as `__proto__`/`constructor` is performed before the assignment.

**Impact**

Prototype pollution via user-controlled property names in the `redact` helper can corrupt the object prototype chain, leading to denial-of-service, unexpected property values in logs, or downstream logic manipulation when the redacted object is processed.

**Recommended next action**

Review and harden `redact` to use a safe object creation method, e.g., `Object.create(null)` and explicitly block `__proto__`, `constructor`, `prototype` keys, or use a library for safe cloning before logging.

#### Details

**Affected locations**

- `src/server.js:97`
- `src/server.js:100`
- `src/server.js:104`
- `src/server.js:120`

**Supporting evidence**

- `src/server.js:85-110`
- `src/server.js:115-125`

**Severity explanation**

User-controlled property names are used to write into an object that is later logged. This enables prototype pollution which can lead to denial-of-service or logic manipulation; impact is limited to the logging path but no explicit sanitization is present, matching medium severity.

**Counterevidence considered**

No counterevidence found; the source shows direct use of user-supplied keys `k` from `Object.entries(obj)` to assign `out[k]` and calls `redact(req.body)` / `redact(req.query)` without validation.

**Prerequisites**

- Request reaches the `onError` hook, e.g., an error is thrown during request handling.
- Attacker can supply request body or query parameters with specially crafted property names such as `__proto__` or `constructor`.
- The `redact` function is executed with that user input.

**Detector:** CodeQL
**Rule:** `js/remote-property-injection`
**Case reference:** `case_91cf808d14a72fb89e60a550`

---

<a id="finding-36"></a>

### Finding 36: Missing rate limiting

**Severity:** Medium

**Issue**

The GET '/' handler at src/server.js lines 254-264 performs file system checks via fs.existsSync(landingPath) and serves files via reply.sendFile(file) / reply.sendFile('beta.html'). The handler is registered without any rate-limiting middleware or guard. No fastify-rate-limit or equivalent limiter is registered globally or on this route in the read source, and the route performs file-system access on each request.

**Impact**

An unauthenticated client can issue unlimited GET '/' requests causing repeated file-system checks and static file reads, enabling a low-cost denial-of-service / resource exhaustion against the server.

**Recommended next action**

No further source reads required for this verdict; if deployment-level rate limiting is desired, verify reverse-proxy configuration out of band.

#### Details

**Affected locations**

- `src/server.js:254-264`
- `src/server.js:262`

**Supporting evidence**

- `src/server.js:254-270`
- `src/server.js:250-270`

**Severity explanation**

Static file serving with a cheap exists check is not a high-cost operation, but unbounded serving of the root path can be abused for DoS; detector severity 7.5 is high, source shows no limiting, so medium is a supported conservative rating.

**Counterevidence considered**

No rate-limit plugin registration or per-route rate limiter observed in the inspected portions of src/server.js; no global limiter covering the '/' handler was found in the read ranges.

**Prerequisites**

- The route is reachable at GET '/'
- No rate-limit middleware is applied to the app or the route
- File system access via fs.existsSync and reply.sendFile is performed per request

**Detector:** CodeQL
**Rule:** `js/missing-rate-limiting`
**Case reference:** `case_df744e0b3a8de9e0f193109c`

---

<a id="finding-37"></a>

### Finding 37: Missing rate limiting

**Severity:** Medium

**Issue**

The POST /api/profile handler at src/server.js performs database writes via db().query for job_sources inserts and calls setProfile which accesses the database, and the handler code shown contains no rate-limiting checks. The route is authenticated but lacks per-IP or per-user throttling, matching the missing-rate-limiting pattern for an expensive DB operation. The contact endpoint nearby demonstrates the codebase uses explicit in-memory rate limiting, showing rate limiting is intentionally applied where present, and its absence here is therefore a control gap.

**Impact**

Repeated unauthenticated or authenticated requests can trigger multiple DB writes and JSONB config updates per request, enabling denial-of-service via database load and increased cost, and potential abuse of job source configuration churn.

**Recommended next action**

Add per-user/per-IP rate limiting to /api/profile POST, e.g., using an in-memory token bucket or Fastify rate-limit plugin, and consider applying consistent rate limiting to other write-heavy routes.

#### Details

**Affected locations**

- `src/server.js:389-409`
- `src/server.js:402`

**Supporting evidence**

- `src/server.js:320-380`
- `src/server.js:350-390`
- `src/server.js:410-470`

**Severity explanation**

The endpoint writes to persistent storage and updates job source configs; abuse could cause DB load / DoS and data churn. No authentication bypass, but lack of throttling enables amplified writes. Severity is medium given user authentication requirement and limited blast radius versus unauthenticated public endpoint.

**Counterevidence considered**

No rate-limit middleware or per-route throttle is observed on the /api/profile POST handler in the inspected range; the handler contains only validation, profile persistence, and job_sources upserts with no hits map, token bucket, or Fastify rate-limit plugin usage.

**Prerequisites**

- Authenticated request with valid Firebase token
- req.uid present
- req.body.profile object supplied
- roles array non-empty to trigger job_sources upserts

**Detector:** CodeQL
**Rule:** `js/missing-rate-limiting`
**Case reference:** `case_bc9bf79fd2e5bcce4fc1d153`

---

<a id="finding-38"></a>

### Finding 38: Missing rate limiting

**Severity:** Medium

**Issue**

The handler at src/server.js lines 1340-1351 implements GET /api/tailored which performs a database query via db().query with user-specific filtering and returns rows. The surrounding source shows no rate-limiting middleware, plugin, or per-route guard applied to this handler. Auth is enforced via onRequest hook, but no rate-limit check is present for this endpoint. The route therefore performs a DB access operation without restricting request rate, matching the missing rate limiting pattern.

**Impact**

Repeated unauthenticated/authenticated calls can cause excessive database load, increased latency for legitimate users, and potential denial-of-service via resource exhaustion.

**Recommended next action**

Review whether a global rate-limit plugin should be added to Fastify and apply stricter per-user limits to read-heavy endpoints like /api/tailored.

#### Details

**Affected locations**

- `src/server.js:1340-1351`
- `src/server.js:1341-1349`

**Supporting evidence**

- `src/server.js:1340-1355`

**Severity explanation**

Endpoint performs authenticated database read with limit 100; unauthenticated abuse is prevented by auth, but authenticated users or token compromise could drive repeated DB queries leading to DoS / resource exhaustion. Impact is moderate denial-of-service potential, not critical data exposure.

**Counterevidence considered**

No rate-limit middleware or per-route guard is registered in the server bootstrap or on this handler; imports contain no rate-limit plugin and the onRequest hooks only perform auth and cost tracking, not rate limiting. The handler directly calls db().query without throttling.

**Prerequisites**

- Authenticated request with valid Firebase token or E2E mode
- Route /api/tailored is reachable via Fastify GET registration

**Detector:** CodeQL
**Rule:** `js/missing-rate-limiting`
**Case reference:** `case_9716eae2354c474c22e1a755`

---

<a id="finding-39"></a>

### Finding 39: Missing rate limiting

**Severity:** Medium

**Issue**

The handler at src/server.js lines 1472-1483 implements GET /api/prep/threads and performs a database query with user-scoped SELECT including a correlated subquery for message count. Source shows the route definition and the db().query call with no rate-limiting middleware, guard, or per-IP/user throttling applied to this handler. No global rate-limit plugin is registered in the server bootstrap, and no per-route limit is present in the handler body. The route is therefore exposed to unbounded request rates that can amplify DB load, matching the missing-rate-limiting finding.

**Impact**

An unauthenticated attacker with valid credentials or a compromised account could issue rapid GET /api/prep/threads requests, causing repeated correlated DB queries and increased database load, potentially degrading service for other users via DoS amplification.

**Recommended next action**

Add per-route or global rate limiting for /api/prep/* endpoints, e.g., fastify-rate-limit with user-scoped keys, and review other read-heavy prep routes for similar exposure.

#### Details

**Affected locations**

- `src/server.js:1472-1483`
- `src/server.js:1473-1481`

**Supporting evidence**

- `src/server.js:1470-1490`
- `src/server.js:1470-1520`
- `src/server.js:1460-1510`

**Severity explanation**

The endpoint performs a DB read with joins and a correlated subquery per thread; repeated calls can amplify DB load and constitute a denial-of-service vector. Impact is limited to read amplification and no direct data modification, so severity is medium rather than critical/high.

**Counterevidence considered**

No rate-limiting middleware, per-IP map, or per-user throttle is attached to the /api/prep/threads GET handler or to the /api/prep/* routes in the examined source. The server bootstrap shows no fastify-rate-limit registration and the handler body contains only auth via onRequest hook and a direct db().query call.

**Prerequisites**

- Authenticated request with valid Firebase token or E2E mode, resulting in req.uid set by onRequest auth hook
- Endpoint reachable at GET /api/prep/threads

**Detector:** CodeQL
**Rule:** `js/missing-rate-limiting`
**Case reference:** `case_62f902540ef1ca3482f0d8d8`

---

<a id="finding-40"></a>

### Finding 40: Missing rate limiting

**Severity:** Medium

**Issue**

The prep thread handlers at src/server.js perform database queries without any rate-limiting control. The GET /api/prep/threads/:id handler reads prep_threads and prep_messages with db().query, the POST /api/prep/threads/:id/messages handler validates ownership then executes an insert into prep_messages and an update of prep_threads, and the DELETE /api/prep/threads/:id handler deletes from prep_threads. No per-route or global rate-limit middleware is applied to these endpoints and no in-handler throttling is present. The only rate-limiting observed in the file is for /api/contact, /api/auth/reset and similar public endpoints. Thus the expensive DB operations are exposed to unrestricted request rates.

**Impact**

An attacker with valid credentials can issue rapid GET/POST/DELETE requests to /api/prep/threads/:id and /api/prep/threads/:id/messages, causing repeated database queries, inserts/updates, and triggering fire-and-forget prep jobs. This can exhaust DB connections / CPU, increase AI cost attribution, and degrade availability for other users.

**Recommended next action**

Add per-user / per-IP rate limiting for /api/prep/* endpoints or apply a global Fastify rate-limit plugin, and consider a generating-state guard plus backoff for POST messages.

#### Details

**Affected locations**

- `src/server.js:1515-1534`
- `src/server.js:1520`
- `src/server.js:1524-1526`
- `src/server.js:1528-1530`

**Supporting evidence**

- `src/server.js:1510-1540`
- `src/server.js:1500-1525`

**Severity explanation**

Unrestricted DB reads/writes on authenticated prep endpoints enable amplification / DoS against the database and downstream AI work; impact is availability degradation rather than direct data breach. Severity is medium given authentication requirement and DB cost but no compensating rate control.

**Counterevidence considered**

No rate-limit middleware, plugin, or in-handler throttling was found for the /api/prep/* routes in the inspected server.js scope. The file contains explicit per-IP rate limiting only for /api/contact and per-email throttling for /api/auth/reset, with no similar controls for prep endpoints.

**Prerequisites**

- Authenticated request with valid Firebase token resulting in req.uid
- Valid UUID for thread id matching UUID_RE
- Thread ownership verified via DB lookup for write/delete operations

**Detector:** CodeQL
**Rule:** `js/missing-rate-limiting`
**Case reference:** `case_62186aefe0fdaac43633c978`

---

<a id="finding-41"></a>

### Finding 41: Missing rate limiting

**Severity:** Medium

**Issue**

The handler at src/server.js implements GET /api/prep/notes/:id which performs a database query via db().query to fetch a prep note for the authenticated user. The source shows the route definition with UUID validation followed by an await db().query with a SELECT joining prep_notes and job_postings, and returns the note. No rate-limiting middleware, per-route limiter, or in-handler throttling is applied to this handler. Auth is enforced by the global onRequest hook but no request-rate control is present for this expensive DB access path.

**Impact**

Repeated unauthenticated-rate-limited requests can amplify database load and connection usage, leading to increased latency or denial of service for legitimate users. An attacker with valid credentials could exhaust DB resources or trigger cost attribution via runWithCost.

**Recommended next action**

Consider adding per-user or per-IP rate limiting for /api/prep/* read endpoints, e.g., via fastify-rate-limit or an in-memory token bucket, and verify existing infrastructure rate limiting.

#### Details

**Affected locations**

- `src/server.js:1592-1603`
- `src/server.js:1595-1600`

**Supporting evidence**

- `src/server.js:1550-1600`
- `src/server.js:1600-1650`

**Severity explanation**

An unauthenticated-rate-limited read endpoint that hits the database on every request can be abused by an authenticated user or token holder to generate repeated DB load, enabling denial-of-service / resource exhaustion. The query is selective and limited to a single row by UUID, so impact is moderate rather than critical, aligning with medium severity for missing rate limiting on a DB-backed API.

**Counterevidence considered**

No source evidence shows a global Fastify rate-limit plugin, per-route rate limiter, or in-handler throttling applied to /api/prep/notes/:id or /api/prep/notes. The only rate-limiting constructs found in the file are local in-memory maps for password reset and contact form, not applied to prep notes routes.

**Prerequisites**

- Authenticated request with valid Firebase ID token so req.uid is set by onRequest auth hook
- Route is reachable under /api/prep/notes/:id with a valid UUID parameter
- Database is reachable via db() client

**Detector:** CodeQL
**Rule:** `js/missing-rate-limiting`
**Case reference:** `case_61c46172ea0b1eeeb733cb51`

---

## Scan details

Run: `scan_7b78cb1a2cb642c8a62da086`
Status: **incomplete**
Source revision: `d9666f6100f4a0e3bb9af8194ba3eafa5e14b2c1c2574e983b700c662862ebe7`
Independent API request attempts: 1007
Muse host reasoning: not used

Policy tasks completed: 64/64. Deferred policy investigations: 71. See `policy/coverage.json` for coverage gaps.
- javascript: completed; Queries executed; full extraction coverage is not established.
- python: completed; Queries executed; full extraction coverage is not established.

Filtered detector alerts: 0. See `analysis-scope.json` for source selection.
File counts do not establish extraction or complete security coverage.

**Run note**

Source-only evaluation finished. See confirmed, refuted and unresolved cases; runtime reproduction was not performed.
