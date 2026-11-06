# Experimental Rust profile-verification API

A self-hosted, MIT-licensed companion to the browser SDK. The verifier-only source
exposes two endpoints: `GET /health` and `POST /v1/verify`. Older API releases still
include the retired signup-check endpoints; this guide describes the next release.

The API checks schema-4/5 SDK evidence and canonical hashes. It does not collect
browser signals, recognize physical devices, execute signup decisions or provide
Fingerprint Pro feature parity. Probe values can be forged, and matching hashes
can collide or change with browser settings and updates.

## Data minimization

There is no visitor database, observation cache, email processing, visitor token,
account history, network intelligence, DNS lookup or outgoing provider request.
Verification receives bounded hashed evidence, validates it and drops it after the
request. It does not persist or log request bodies, hashes, IP addresses, user
agents, account IDs or cookies. Responses have `Cache-Control: no-store`.

The only retained runtime state is configured server credential tags and one
quota counter/window per site. These are not keyed by visitor, IP or profile.
Restart resets the quota windows. Multiple replicas have independent quotas;
use an edge/shared limiter if you require a deployment-wide quota.

The SDK is unchanged: it hashes signals locally, has no telemetry or network
requests and writes no browser storage unless its caller explicitly opts into
`storageKey`. Leave that option unset when sending results to this API. Hashes are
pseudonymous, not anonymous. Your application and hosting proxy have their own
logging, retention, disclosure and access-control responsibilities.

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

`OPENFINGERPRINT_SIGNING_KEY` is no longer read or required. Existing site
configurations containing `site_key` and `origins` remain readable for rollout;
those fields enable no browser endpoint or CORS. Legacy public keys must remain
distinct from server keys and are never accepted as authentication. New
configurations need only `id` and `secret_key`.

The process does not terminate TLS. Use TLS before transmitting server credentials
over a non-loopback network, and do not forward browser Origin/cookies to the API.
No dashboard, SDK hosting, billing or tenant-management endpoint is provided.

## Endpoints

### `GET /health`

No authentication or request body. Returns HTTP 200 with plain text `ok`. This is
process liveness, not proof of identification quality or upstream infrastructure.

### `POST /v1/verify`

Send `Authorization: Bearer <server secret>` and `Content-Type: application/json`
from your backend, with no `Origin` header. The JSON body is an SDK result:

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
and unsolicited visitor metadata are rejected. All JSON bodies are limited to
64 KiB. Non-null IDs must match the canonical hash for the reported schema;
changing only the version does not translate an identity between schemas.

A valid full profile returns HTTP 200:

```json
{"status":"ok","schema_version":5,"fingerprint":"<full fingerprint>"}
```

Valid evidence without a full ID returns HTTP 200:

```json
{"status":"insufficient_signals","schema_version":null,"fingerprint":null}
```

A core-only result is not a full identity. The API does not invent a fallback,
look up past visits or turn missing evidence into a zero-match claim. The response
verifies canonical consistency, not honest probe execution or device attestation.

Authentication happens before JSON parsing. Browser-origin requests are forbidden;
no browser CORS is enabled. The per-site quota is 60 authenticated attempts per
minute, including malformed requests. API errors return `{"error":"<reason>"}`:
400 invalid evidence/JSON, 401 unauthorized, 403 browser Origin, 413 oversized body,
429 quota or 503 unavailable. Retired `/v1/collect` and `/v1/check` routes, including
the collection preflight, return 404. There is no email-only check endpoint.

Verify in a background flow where failure leaves the ID unknown rather than
blocking authentication. Applications may save a returned full ID and schema
alongside their own authenticated session/account after applicable privacy review.
Compare only within the same customer and schema; never substitute the core ID.

## Checks and containers

Requires current stable Rust (tested with 1.99.1) and Node 24+:

```sh
pnpm api:check
```

This runs formatting, Clippy, unit tests and a real loopback HTTP self-check. The
self-check generates credentials in RAM, boots without a signing key, checks
legacy/minimal configuration, canonical hashes, strict metadata/body boundaries,
retired routes, no request logging and independent quotas, then stops the server.
It prints no credentials, visitor evidence or response payloads.

After the verifier-only API release, its image is published as
`ghcr.io/mokto/openfingerprint-api:<version>` for linux/amd64 and linux/arm64. Pin a
released manifest digest; publishing does not deploy an API. SDK and API releases
are independent (`sdk-v*` and `api-v*`). Release Please opens the API release PR;
merging it dispatches multi-architecture image publishing. New personal GHCR
packages require the owner to set visibility to Public before anonymous checks
can pass. Existing public-package visibility does not need changing.

Build and check a local native image:

```sh
docker buildx build --load --provenance=false -f api/Dockerfile -t openfingerprint-api:check .
node scripts/test-api.mjs --image openfingerprint-api:check
```

For another architecture, add `--platform linux/amd64` or `--platform linux/arm64`
to both commands. The image runs as UID/GID 65532, supports read-only operation,
retains application/dependency/Rust licenses, and handles SIGTERM/SIGINT gracefully.
CI checks both architectures natively. No data volume or visitor-store migration
is needed. The API remains experimental: add deployment-wide abuse protection,
credential lifecycle controls and operational/privacy review before relying on it.
