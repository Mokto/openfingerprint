# Experimental Rust check API

A self-hosted, MIT-licensed backend companion to the browser SDK. The next release
provides stateless `POST /v1/check` with independent browser, automation, domain
and IP sections, plus a Redis-backed collection flow for single-use server-owned
events. `POST /v1/verify` remains a compatibility adapter.

Domain intelligence runs locally against openly licensed, versioned snapshots:

| Requested check | Available behavior |
| --- | --- |
| `signals` | Canonical schema-4/5 verification and bounded evidence counts. |
| `automation` | Versioned rules for client-reported observations, now included automatically inside SDK `signals`. |
| `domain` | Disposable-domain, free-subdomain and source-scoped referrer-spam evidence, with provenance and expiry. |
| `ip` | IPv4/IPv6 literal validation; otherwise `unknown/not_configured`. |

The domain snapshot is bundled and can be overridden with a refreshed local file.
A valid input does not mean a domain is legitimate or an IP is clean. Unlisted or
uncovered domains remain null, not false. The API looks up MX hosts to detect
mail routed to a listed disposable provider.
IP intelligence, RDAP and domain authority are not implemented. The spam scope is specifically **referrer spam**,
not email-sending reputation. See [sources, licenses and refresh](data/README.md). Older API releases, including 0.4.0, have a different
`/v1/check` contract; this guide describes the next release, not a live upgrade.

The API does not execute browser probes, recognize physical devices, execute
signup decisions or provide Fingerprint Pro feature parity. Probe values can be
forged, and matching hashes can collide or change with settings and updates.

## Data minimization and networking

Stateless checks have no visitor database, observation cache, email processing or
account history. Their evidence, domains and IPs are dropped after processing.
With collection enabled, Redis temporarily holds random action bindings, origins,
challenges and evaluated events, subject to TTL and capacity limits below. Raw
collection user agents/platforms are discarded after evaluation; request evidence
and credentials are not logged. Outbound traffic consists of MX DNS queries and,
when configured, Redis commands.
Responses have `Cache-Control: no-store` and set no cookies. Domain/IP inputs are
not echoed in responses. No browser/server IP is inferred from the connection or
forwarded headers. Signals-only calls do not run domain/IP checks.

The process retains configured credential tags and a read-only domain snapshot;
collection state is shared in Redis, not an in-memory fallback. There is no
visitor-history or domain cache. Collection capacity limits are not rate limiting:
apply quotas and request limits at your edge/gateway, including the public collector.

A separate operator updater refreshes public snapshots without rebuilding the
image; the API re-reads an override file every minute and swaps in a changed
snapshot only if it is valid.

A domain check whose result MX hosts could still change (a fresh `not_listed`
domain) sends one UDP MX query to one nameserver: a random transaction ID, a
one-second limit, no retries, no TCP fallback and no cache in the API.
Already-decided domains are never sent to DNS. The nameserver sees the domains you
check; use a resolver you trust, such as the cluster DNS, and allow only it on UDP
53. Without DNS access, lookups report `unavailable` and everything else works.
RDAP and other live lookups are not implemented.
There are no lookup retries, remote-provider waits or visitor-history fallbacks.

The SDK hashes identity signals locally and automatically includes bounded
automation evidence outside those hashes. `collect()` has no networking;
`identify()` posts evidence plus bounded browser context to a configured same-origin
collection proxy. Neither writes storage unless `collect()` opts into `storageKey`. Leave that option
unset when sending results here. Hashes are pseudonymous, not anonymous. Your
application and hosting proxy have their own logging, retention, disclosure and
access-control responsibilities.

## Configuration

Provide secrets privately at runtime. Never put them in Git, browser code, image
build arguments, command-line arguments or logs.

| Variable | Meaning |
| --- | --- |
| `OPENFINGERPRINT_SITES` | JSON array of 1–16 site configurations, each with `id` and `secret_key`. |
| `OPENFINGERPRINT_LISTEN_ADDR` | Optional listener, default `127.0.0.1:8180`. |
| `OPENFINGERPRINT_REDIS_URL` | Optional private Redis/Valkey connection URL; enables collection. Supports `rediss://` with certificate validation. Missing/unreachable Redis yields HTTP 503 on collection routes; no memory fallback. |
| `OPENFINGERPRINT_COLLECTION_TTL_SECONDS` | Lifetime of each challenge and, separately, each published event: 1–300 seconds, default 120. Use identical settings on every replica. |
| `OPENFINGERPRINT_COLLECTION_CAPACITY` | Maximum outstanding challenges plus events per server credential: 1–100000, default 1024. Issuance at capacity returns 429. |
| `OPENFINGERPRINT_DOMAIN_DATA` | Optional read-only snapshot path; otherwise uses the bundled snapshot. Missing/invalid overrides yield unknown domain facts without disabling browser verification. |
| `OPENFINGERPRINT_DOMAIN_DATA_RELOAD_SECONDS` | Seconds between checks of the override file, 1–86400, default 60. A changed file that fails to read or parse is rejected and the last valid snapshot stays until its sources expire. |
| `OPENFINGERPRINT_DNS` | Nameserver for MX lookups, default `system` (the first `nameserver` in `/etc/resolv.conf`). Also accepts an IP, `IP:port` or `host:port` (resolved once at startup). Startup fails without a usable nameserver. |
| `OPENFINGERPRINT_METRICS_ADDR` | Optional listener for Prometheus `GET /metrics`, for example `0.0.0.0:9180`. Keep it off the API port so network policy can expose it separately. |

IDs are 1–64 ASCII characters, start with a letter and otherwise contain letters,
digits, underscores or dots. Server keys are 32–128 URL-safe ASCII characters;
generate them randomly. IDs and credentials must be unique. Startup rejects
invalid configuration without echoing its values.

`OPENFINGERPRINT_SIGNING_KEY` is no longer read or required by this source.
Existing configurations containing `site_key` and `origins` remain readable for
rollout; those fields enable no browser endpoint or CORS. Legacy public keys must
remain distinct from server keys and are never authentication. New configurations
need only `id` and `secret_key`. Do not remove configuration required by an older
running image before deploying the compatible release.

The process does not terminate TLS. Protect credential transport with TLS or an
equivalent protected boundary; cluster-local HTTP and NetworkPolicy do not encrypt
traffic. Restrict the deployment to its intended backend callers and do not forward
browser Origin/cookies to private routes. Only the public collection proxy forwards
Origin and the relevant browser headers; it must strip cookies and Authorization.
No dashboard, SDK hosting, billing or tenant-management
endpoint is provided.

## Endpoints

Private POST routes require `Authorization: Bearer <server secret>` and
`Content-Type: application/json`, with no `Origin` header. Authentication runs
before JSON parsing. Only `POST /v1/collect` accepts browser-origin requests,
authorized by a single-use challenge. No route enables cross-origin CORS.

### `GET /health`

No authentication or body. Returns HTTP 200 with plain text `ok`. This is process
liveness, not evidence quality, dataset coverage or identification accuracy.

### `POST /v1/check`

The JSON object accepts only these fields:

| Field | Shape |
| --- | --- |
| `signals` | Optional SDK result object, as described below. |
| `automation` | Optional version-1 SDK automation evidence, as described below. |
| `domain` | Optional ASCII hostname, not a URL or complete email address. |
| `ip` | Optional visitor IPv4/IPv6 literal supplied by your trusted backend. |

At least one non-null field is required. Null is equivalent to omission. Results
contain only requested non-null sections. Inputs can be combined in any order;
there is no cross-input identity merging, and automation/domain/IP never change the browser ID.

For example:

```json
{"domain":"example.test","ip":"192.0.2.1"}
```

The IP section returns `{"status":"unknown","reason":"not_configured"}`.
With fresh domain data, `domain` contains `disposable`, `free_subdomain` and `spam`
facts. Disposable evidence combines the community list with recently monitored
provider domains from an openly licensed feed; no vendor API results are imported. Each has a nullable `value`, evidence `status`, `scope` and `sources` with
license, revision, source-commit/retrieval/expiry times. For example, a confirmed
list match yields `value: true, status: listed`; an ordinary non-match yields
`value: null, status: not_listed`, not a clean verdict.

An otherwise `not_listed` domain whose external MX host is on a fresh
disposable source yields `value: true, status: mx_listed`, with that host's source
statuses. Mail routed to a known disposable provider is strong evidence, but
it is inferred, so you can treat it separately from a direct listing. MX hosts
inside the queried domain are ignored. A disputed, allowlisted or conflicting
MX host or parent domain blocks the inference; direct listings, allowlists and
disputes always take precedence. MX hosts are never echoed. They describe mail
routing at check time, not mailbox validation.

Every valid domain section has `mx_lookup`:

| `mx_lookup` | Meaning |
| --- | --- |
| `resolved` | The API found MX hosts (up to 10, by preference). |
| `no_records` | The domain exists but publishes no usable MX, including null MX. |
| `no_domain` | NXDOMAIN. Undeliverable now, which is not proof of abuse. |
| `unavailable` | Timeout, SERVFAIL, truncated or malformed answer. Unknown, not clean. |
| `not_needed` | MX hosts could not change the result (already listed, allowlisted, disputed, or no fresh data), so nothing was sent to DNS. |

Free-subdomain operator apexes yield false with `provider_domain`; strict children
can match. Reviewed allowlist overrides yield false with `allowlisted`. Conflicting
fresh sources yield null with `conflict`. Exact domains under an independently
reviewed dispute also yield null with `conflict/review_required`; an overdue review
does not restore a positive accusation. This is not an allowlist or a clean verdict.
Stale, future-dated, missing or invalid data stays unknown. The overall domain status is `ok` when all scoped checks ran
against fresh sources, `partial` for incomplete/conflicting coverage, or `unknown`
when no fresh data is available. `ok` never means the domain is safe.

`spam.scope` is always `referrer_spam` in this release. The open Matomo feed does
not establish mailbox spam or comprehensive abuse coverage. Neither disposable
nor free-subdomain classifications set this fact. [Data details](data/README.md)
include exact matching/expiry semantics and the bounded provider coverage.

With valid full SDK evidence, the `signals` section is:

```json
{
  "status":"ok",
  "schema_version":5,
  "fingerprint":"<full fingerprint>",
  "evidence":{
    "included_components":2,
    "included_hints":1,
    "unavailable_probes":3,
    "excluded_probes":3
  }
}
```

Counts describe the submitted, validated evidence, not entropy, probability,
confidence, a risk score or honest probe execution. Included counts omit excluded
probes. Unavailable and excluded counts are separate and may overlap.

Valid evidence without a full ID has `status: insufficient_signals`, null schema
and fingerprint, and evidence counts. A core ID never substitutes for a full ID.
Invalid evidence has `status: invalid_input`, `reason: invalid_signals`, and null
schema, fingerprint and evidence. That does not discard another section's result.

Domain/IP sections return `invalid_input` with `invalid_domain` or `invalid_ip`
for invalid values, including wrong field types. The same field-level handling
applies to malformed signal objects. HTTP 200 means the envelope was processed,
not that every check succeeded: inspect each requested section. Valid sections
survive failures in other sections; there is no combined clean/fraud verdict.

Malformed JSON, non-object envelopes, empty/all-null requests and unknown top-level
fields return HTTP 400. Full email addresses, visitor tokens, account metadata and
raw browser context are not additional inputs. All request bodies are limited to
64 KiB, including nested evidence, before evaluation.

#### Automation indicators

`collect()` includes observations automatically as `signals.automation`, and
`/v1/check` returns their evaluation as `signals.automation`. No additional SDK
option or forwarding step is needed. Existing callers may still send standalone
`automation` (including without a fingerprint):

```json
{"automation":{"version":1,"webdriver":true,"headlessUserAgent":false,"seleniumArtifacts":false,"phantomArtifacts":null}}
```

The response contains:

```json
{
  "automation": {
    "status": "detected",
    "rule_version": 1,
    "source": "client_reported",
    "indicators": ["webdriver"],
    "unavailable_probes": ["phantom_artifacts"]
  }
}
```

Evidence accepts only `version: 1` and four optional booleans:
`webdriver`, `headlessUserAgent`, `seleniumArtifacts`, `phantomArtifacts`.
Null or omitted observations remain unknown. Names in `indicators` and
`unavailable_probes` are respectively `webdriver`, `headless_user_agent`,
`selenium_artifacts`, `phantom_artifacts`, in that order.

Rule version 1 reports `detected` if any observation is true, `unknown` if none
is true and any is unavailable, or `not_detected` only if all four are false.
Malformed evidence, unknown keys, unsupported versions and non-boolean/non-null
observations produce `invalid_input` with `reason: invalid_automation` and empty
indicator/unavailable arrays. Other sections still run. Top-level
`automation: null` omits the section, like other optional inputs.

These rules interpret client reports, not attested browser execution. Evidence
can be forged or hidden. `not_detected` is not proof of a human, and automation
may be legitimate testing or assistive tooling, not malicious traffic. No
good/bad bot classification, confidence, fraud score, retention or new outbound
traffic is introduced. Deploy the compatible API before sending this field;
older servers reject it. `/v1/verify` accepts embedded automation but ignores it,
retaining its status/schema/fingerprint-only response.

#### Domain and IP boundaries

Domains have at least two labels, each 1–63 ASCII letters/digits/hyphens, without
leading/trailing hyphens. Maximum length is 253 characters excluding an optional
single trailing dot; the final label must contain a letter. Case is accepted.
Internationalized names must be supplied as ASCII A-labels; no Unicode conversion,
IDNA decoding, address resolution or registrability check is performed. Dataset
matching does use Mozilla's Public Suffix List to protect registry/private-suffix
boundaries; this does not turn lexical input acceptance into domain validation. Lexical acceptance is not domain existence or mailbox validation.

IPs must be literals, without ports, CIDR prefixes, brackets, zone IDs or surrounding
whitespace. IPv4-mapped IPv6 and private/loopback literals are syntactically
accepted, but receive no clean/public-network verdict. Use trusted proxy
configuration to obtain the actual visitor IP; do not trust a browser-provided
value or accidentally supply the application server's address.

### Challenge-bound collection

Enable these routes with `OPENFINGERPRINT_REDIS_URL`. Every API replica must
use the same authoritative Redis database, credentials and collection settings.
There is no local-state fallback. A single Redis/Valkey primary is supported,
not Redis Cluster (the atomic scripts operate on multiple keys).

#### 1. Your backend issues a challenge

`POST /v1/challenges` requires the server credential and accepts only:

```json
{"binding":"<64 lowercase hexadecimal characters>","origin":"https://your-app.example"}
```

Generate a random 32-byte binding in your backend and retain it against the
authenticated session and specific action. Never accept the expected binding from
the browser, reuse one across unrelated actions, or send account/session data
instead. Apply your application's authentication, CSRF and issuance limits.
Origin must be an exact canonical HTTPS origin without path, credentials, query
or fragment (HTTP loopback is allowed for development).

The response is `{"challenge":"<random token>","expires_in_ms":120000}`.
Give only the challenge to the browser; do not expose the binding or server key.

#### 2. The SDK submits evidence to your same-origin proxy

Call `identify({ endpoint: '/fingerprint/collect', challenge })`. Automation is
included automatically. Expose only a bounded POST proxy to `POST /v1/collect`:
preserve the browser's Origin, User-Agent and Sec-CH-UA-Platform; strip cookies,
Authorization and other forwarded headers. Do not replace the browser's UA with
the proxy's UA. Require HTTPS and appropriate CSP `connect-src`; cross-origin
CORS and preflight are deliberately unsupported.

The collection body accepts only `challenge`, a full SDK `signals` object with
valid embedded `automation`, and `context`:
`{"userAgent": "<up to 512 UTF-8 bytes or null>", "platform": "<up to 128 bytes or null>"}`.
Context properties may be omitted; other metadata is rejected. The global 64 KiB
body limit applies. Non-null `storageId` is still rejected. Origin must match
the backend-issued challenge; cookies and Authorization are forbidden.

The server validates evidence, compares submitted UA against the request header,
checks reported headless status against the submitted UA, and compares recognized
Windows/macOS platform observations against Client Hints when present. Missing
or unrecognized evidence stays unknown. A HeadlessChrome token observed in the
request UA adds a headless indicator even if the submitted boolean denies it.
Raw UA/platform values are discarded, not stored in the event.

Publishing the evaluated event and consuming the challenge is one atomic Redis
operation. Only one concurrent request can succeed, across API replicas.
The browser gets only `{"event_id":"<random token>"}`; it cannot overwrite the
stored verdict. The SDK returns `{ eventId }`.

#### 3. Your backend consumes the event with the protected action

`POST /v1/events/consume` requires the server credential and accepts only:

```json
{"event_id":"<ID from the browser>","binding":"<expected server-stored action binding>"}
```

Consumption checks the credential scope, expected action binding and expiry,
and atomically deletes the event before returning it. Concurrent consumption
succeeds once. A wrong binding or credential does not destroy the rightful event.
The response contains `event_id`, `created_at_unix_ms`, `expires_at_unix_ms`,
evaluated `signals` (including `automation`), `consistency` and `request`.
The latter contains the matched `origin` and nullable request-UA
`headless_user_agent` observation, never raw UA/platform strings or an inferred IP.

`consistency` has `rule_version: 1`, `status`, `indicators` and
`unavailable_checks`. Check names are `user_agent_mismatch`,
`headless_evidence_mismatch`, `platform_mismatch`. Status is `detected` for
any mismatch, `unknown` for incomplete checks without mismatches, otherwise
`not_detected`. This is not a calibrated browser-tampering classifier.

Use this server-owned response for protected decisions, not the browser's raw
`signals`, fingerprint or boolean claims. Missing, mismatched, expired or used
records return 409 `expired_used_or_mismatched`. Redis errors/timeouts return
503 `collection_unavailable`; unavailable collection must not become a trusted
or clean result. Do not retry ambiguous submissions/consumption automatically:
a lost response may follow successful consumption. Restart with a new challenge
and apply application-level action idempotency.

#### Security and retention limits

Challenges and events each expire after the configured TTL, independently.
The per-credential capacity counts both, and expired entries are pruned during
issuance. Redis time controls expiry timestamps, avoiding API-replica clock drift.
No raw browser context, accounts, domains, IPs or visitor history are retained.
Retained data is still pseudonymous and sensitive: configure Redis authentication,
private access, `rediss://` where needed, memory limits and `noeviction`.
Allow the scripting and key/sorted-set commands used by the collector.
Disable persistence/backups when not needed; TTL is not backup erasure.

Atomic single-use guarantees assume one authoritative Redis history. A rollback,
restored backup or asynchronous failover can resurrect consumed state. After
such a rollback, stop old API replicas and rotate affected server credentials
before accepting protected actions; old records are then outside the new scope.
Redis deletion/eviction instead loses pending flows and fails closed.

This flow protects evaluated-result integrity and reuse, not honest execution of
JavaScript. Attackers can still fabricate observations, forge HTTP headers outside
a normal browser, or run fresh automated sessions. Origin checks are browser
constraints, not bot authentication. Transport uses HTTPS, not a browser-held
signing secret, custom encrypted SDK protocol, obfuscation or device attestation.
Combine evidence with application controls; `not_detected` never means trusted.

### SDK evidence

| Field | Shape |
| --- | --- |
| `version` | Integer `4` or `5`. |
| `fingerprint` | Full lowercase SHA-256 string, or null/omitted. |
| `coreFingerprint` | Core lowercase SHA-256 string, or null/omitted. |
| `components`, `hints` | Objects mapping bounded probe names to lowercase SHA-256 strings. |
| `unavailable` | Object mapping probe names to `unsupported`, `unstable`, `timeout` or `error`. |
| `excluded` | Unique subset of `audio`, `canvas`, `screen`. |
| `durationMs` | Finite number from 0 to 60000. |
| `timings` | Optional object of `{ "durationMs": number, "blockingMs": number }` per probe, same numeric bounds. |
| `storageId` | Omitted or null only. |

Each map has at most 32 entries. Names are 1–64 ASCII characters, start with a
letter and otherwise contain letters, digits, underscores or dots. `automation` is the only additional SDK field accepted and is evaluated separately
from identity; it may be omitted by older SDKs. Unknown fields and unsolicited
visitor metadata are rejected. Non-null IDs must match the
canonical hash for the reported schema; changing only the version does not
translate an identity between schemas.

### `POST /v1/verify` (compatibility)

Accepts the original, unwrapped SDK evidence object and retains the exact response:

```json
{"status":"ok","schema_version":5,"fingerprint":"<full fingerprint>"}
```

Without a full ID:

```json
{"status":"insufficient_signals","schema_version":null,"fingerprint":null}
```

Invalid evidence still returns HTTP 400 here, unlike field-level failures inside
`/v1/check`. No evidence counts or additional keys are added to this legacy response.
Both routes use the same canonical verifier and server authentication.

Deploy the compatible API first. Then update callers to wrap evidence in `signals`
and read `response.signals` (which also contains evidence counts), not merely change
the URL. Keep strict schema/ID matching and fail-closed identity writes. Retire
`/v1/verify` only in a later coordinated release once all callers have migrated.
This source change does not migrate or deploy any existing caller.

### HTTP errors and application use

Errors return
`{"error":"<reason>"}`: 400 invalid envelope/evidence, 401 unauthorized, 403 browser
Origin, or 413 oversized body. Unsupported methods return
405. Collection preflight returns 405; collection is same-origin only.

Use a background flow where missing/failed verification leaves the ID unknown,
not blocked authentication. Applications may save a full ID and schema alongside
their own authenticated session/account after privacy review. Compare only within
the same customer and schema; never use a core-only or network-based fallback.

## Metrics

`/metrics` on `OPENFINGERPRINT_METRICS_ADDR` reports dataset health only, never
requests, domains or credentials:

| Metric | Meaning |
| --- | --- |
| `openfingerprint_domain_data_loaded` | 1 when a valid snapshot is loaded. |
| `openfingerprint_domain_data_source_expiry_timestamp_seconds{source}` | When each source stops being used. |
| `openfingerprint_domain_data_source_fetched_timestamp_seconds{source}` | When each source was fetched or reviewed. |
| `openfingerprint_domain_data_source_entries{source}` | Listed domains per source. |
| `openfingerprint_domain_data_loaded_timestamp_seconds` | When the current snapshot was loaded. |
| `openfingerprint_domain_data_reload_failures_total` | Changed snapshot files that were rejected. |
| `openfingerprint_mx_lookups_total{result}` | MX lookups by `mx_lookup` outcome. |

Alert on source expiry, not on `/health`: an expired source silently degrades
domain checks to unknown while the process stays healthy.

## Kubernetes

The [Helm chart](chart/README.md), published to `oci://ghcr.io/mokto/charts/openfingerprint`
with each API release, runs the API with egress only to cluster DNS, refreshes the open snapshot
into a ConfigMap with a CronJob and ships optional Prometheus alerts.

## Checks and containers

Requires current stable Rust (tested with 1.99.1) and Node 24+:

```sh
pnpm api:check
```

This runs formatting, Clippy, unit tests and a real loopback HTTP self-check. It
generates credentials in RAM, boots without a signing key, checks both schemas,
all 15 input combinations, automatic/nested automation rules, partial failures, scoped domain matches, public-suffix
boundaries, fresh/stale/invalid/missing snapshots, strict metadata/body boundaries,
compatibility and no request logging, then stops the
server. Updater checks use local fixtures and verify license-change rejection and
atomic failure preservation; CI does not download feeds. It prints no credentials or visitor payloads.

With a disposable Redis database, run the cross-replica collection checks too:

```sh
OPENFINGERPRINT_TEST_REDIS_URL=redis://127.0.0.1:6379/15 node api/test-collection.mjs
```

They check racing publication/consumption, binding/tenant isolation, expiry,
capacity, unknowns, input limits and Redis failures. Without that variable this
suite explicitly skips; CI runs it against a Redis service.

After release, images are published as `ghcr.io/mokto/openfingerprint-api:<version>`
for linux/amd64 and linux/arm64. Pin a released manifest digest; publishing does
not deploy an API. SDK and API releases are independent (`sdk-v*` and `api-v*`).
Release Please opens the API release PR; merging it dispatches multi-architecture
image publishing. New personal GHCR packages need the owner to set visibility to
Public before anonymous checks can pass.

```sh
docker buildx build --load --provenance=false -f api/Dockerfile -t openfingerprint-api:check .
node api/test.mjs --image openfingerprint-api:check
```

For another architecture, add `--platform linux/amd64` or `--platform linux/arm64`
to both commands. The image runs as UID/GID 65532, supports read-only operation,
retains application/dependency/Rust licenses, and handles SIGTERM/SIGINT gracefully.
Pull-request CI runs SDK/browser and Rust/HTTP checks, without building Docker
images or duplicating runs on branch pushes. Release Please explicitly dispatches
the same checks for its bot-created release PRs. After an API release, the image
workflow builds and smoke-tests AMD64/ARM64 natively before publishing and creating
the multi-architecture manifest. No visitor-store migration is needed; a refreshed
public snapshot can be mounted read-only without rebuilding the image. The API remains experimental: add deployment-wide abuse protection,
credential lifecycle controls and operational/privacy review before relying on it.
