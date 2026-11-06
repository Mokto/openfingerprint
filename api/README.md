# Experimental Rust check API

A self-hosted, MIT-licensed backend companion to the browser SDK. The next release
provides `GET /health` and one primary business endpoint, `POST /v1/check`, with
independent browser, domain and IP sections. `POST /v1/verify` is retained as a
compatibility adapter while existing callers migrate.

This is the checker foundation, not an intelligence-feed release:

| Requested check | Available behavior |
| --- | --- |
| `signals` | Canonical schema-4/5 verification and bounded evidence counts. |
| `domain` | Hostname syntax validation; otherwise `unknown/not_configured`. |
| `ip` | IPv4/IPv6 literal validation; otherwise `unknown/not_configured`. |

No domain/network source is bundled or configurable yet. A valid input does not
mean a domain is legitimate or an IP is clean. Dataset ingestion, provenance,
freshness and lookups are separate work. Do not infer missing boolean verdicts
from these responses. Older API releases, including 0.4.0, have a different
`/v1/check` contract; this guide describes the next release, not a live upgrade.

The API does not collect browser signals, recognize physical devices, execute
signup decisions or provide Fingerprint Pro feature parity. Probe values can be
forged, and matching hashes can collide or change with settings and updates.

## Data minimization and networking

There is no visitor database, observation cache, email processing, visitor token,
account history, DNS lookup or outgoing provider request. Request evidence,
domains and IPs are dropped after processing and are not logged or persisted.
Responses have `Cache-Control: no-store` and set no cookies. Domain/IP inputs are
not echoed in responses. No browser/server IP is inferred from the connection or
forwarded headers. Signals-only calls do not run domain/IP checks.

The only retained runtime state is configured server credential tags and one
quota counter/window per site. These are not keyed by visitor, IP, domain or
profile. Restart resets the quota windows. Multiple replicas have independent
quotas; use an edge/shared limiter for a deployment-wide quota. Both business
routes share the same per-site quota, so the compatibility route cannot double it.

The service works with outgoing traffic denied. Future public datasets can be
supplied as snapshots; live DNS/RDAP would need a separately scoped lookup worker
and an explicit network-policy decision, not silently reopened Internet access.
There are no lookup retries, remote-provider waits or visitor-history fallbacks.

The SDK is unchanged: it hashes signals locally, makes no network requests and
writes no storage unless the caller opts into `storageKey`. Leave that option
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
browser Origin/cookies. No dashboard, SDK hosting, billing or tenant-management
endpoint is provided.

## Endpoints

Both POST routes require `Authorization: Bearer <server secret>` and
`Content-Type: application/json`, with no `Origin` header. Authentication runs
before JSON parsing. Browser-origin requests are forbidden; no CORS is enabled.

### `GET /health`

No authentication or body. Returns HTTP 200 with plain text `ok`. This is process
liveness, not evidence quality, dataset coverage or identification accuracy.

### `POST /v1/check`

The JSON object accepts only these fields:

| Field | Shape |
| --- | --- |
| `signals` | Optional SDK result object, as described below. |
| `domain` | Optional ASCII hostname, not a URL or complete email address. |
| `ip` | Optional visitor IPv4/IPv6 literal supplied by your trusted backend. |

At least one non-null field is required. Null is equivalent to omission. Results
contain only requested non-null sections. Inputs can be combined in any order;
there is no cross-input identity merging, and domain/IP never change the browser ID.

For example:

```json
{"domain":"example.test","ip":"192.0.2.1"}
```

Currently returns HTTP 200:

```json
{
  "domain":{"status":"unknown","reason":"not_configured"},
  "ip":{"status":"unknown","reason":"not_configured"}
}
```

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

#### Domain and IP boundaries

Domains have at least two labels, each 1–63 ASCII letters/digits/hyphens, without
leading/trailing hyphens. Maximum length is 253 characters excluding an optional
single trailing dot; the final label must contain a letter. Case is accepted.
Internationalized names must be supplied as ASCII A-labels; no Unicode conversion,
IDNA decoding, public-suffix validation, DNS resolution or registrability check is
performed. Lexical acceptance is not domain existence or mailbox validation.

IPs must be literals, without ports, CIDR prefixes, brackets, zone IDs or surrounding
whitespace. IPv4-mapped IPv6 and private/loopback literals are syntactically
accepted, but receive no clean/public-network verdict. Use trusted proxy
configuration to obtain the actual visitor IP; do not trust a browser-provided
value or accidentally supply the application server's address.

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
letter and otherwise contain letters, digits, underscores or dots. Unknown fields
and unsolicited visitor metadata are rejected. Non-null IDs must match the
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

Both routes share 60 authenticated attempts per site per minute, including malformed
requests. Browser-origin rejections happen before quota consumption. Errors return
`{"error":"<reason>"}`: 400 invalid envelope/evidence, 401 unauthorized, 403 browser
Origin, 413 oversized body, 429 quota or 503 unavailable. Unsupported methods return
405. The retired `/v1/collect` endpoint and collection preflight return 404.

Use a background flow where missing/failed verification leaves the ID unknown,
not blocked authentication. Applications may save a full ID and schema alongside
their own authenticated session/account after privacy review. Compare only within
the same customer and schema; never use a core-only or network-based fallback.

## Checks and containers

Requires current stable Rust (tested with 1.99.1) and Node 24+:

```sh
pnpm api:check
```

This runs formatting, Clippy, unit tests and a real loopback HTTP self-check. It
generates credentials in RAM, boots without a signing key, checks both schemas,
all seven input combinations, partial failures, unknown intelligence, strict
metadata/body boundaries, compatibility, shared/independent quotas and no request
logging, then stops the server. It prints no credentials or visitor payloads.

After release, images are published as `ghcr.io/mokto/openfingerprint-api:<version>`
for linux/amd64 and linux/arm64. Pin a released manifest digest; publishing does
not deploy an API. SDK and API releases are independent (`sdk-v*` and `api-v*`).
Release Please opens the API release PR; merging it dispatches multi-architecture
image publishing. New personal GHCR packages need the owner to set visibility to
Public before anonymous checks can pass.

```sh
docker buildx build --load --provenance=false -f api/Dockerfile -t openfingerprint-api:check .
node scripts/test-api.mjs --image openfingerprint-api:check
```

For another architecture, add `--platform linux/amd64` or `--platform linux/arm64`
to both commands. The image runs as UID/GID 65532, supports read-only operation,
retains application/dependency/Rust licenses, and handles SIGTERM/SIGINT gracefully.
Pull-request CI runs SDK/browser and Rust/HTTP checks, without building Docker
images or duplicating runs on branch pushes. Release Please explicitly dispatches
the same checks for its bot-created release PRs. After an API release, the image
workflow builds and smoke-tests AMD64/ARM64 natively before publishing and creating
the multi-architecture manifest. No data volume or visitor-store migration is
needed. The API remains experimental: add deployment-wide abuse protection,
credential lifecycle controls and operational/privacy review before relying on it.
