# Experimental Rust signup-check API

The browser SDK and this API are separate components in one repository. Both are
MIT licensed under the [repository license](../LICENSE). The disposable-domain
snapshot is CC0; see [data attribution](data/README.md). Rust dependencies retain
their own licenses.

This is a bounded, single-process proof of concept, not a production service.
Restart loses all observations, links, quotas and outstanding tokens. Do not run
multiple replicas as one service. There is no hosted service, billing, confirmed
account counter or physical-device attestation.

## Run the checks

Requires current stable Rust (tested with 1.99.1) and Node 24+:

```sh
pnpm api:check
```

Alternatively, run the Cargo checks and HTTP self-check directly:

```sh
cargo fmt --manifest-path api/Cargo.toml --check
cargo clippy --manifest-path api/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path api/Cargo.toml --locked
cargo build --manifest-path api/Cargo.toml --locked
node scripts/test-api.mjs
```

The HTTP self-check starts its own loopback server on a free port. It generates
three customer configurations in memory, exercises real HTTP requests, prints
only check results, then stops the server. No credentials, emails, tokens, hashes
or report files are printed or saved. No database or cloud account is needed.
For a custom Cargo target directory, pass `--binary /path/to/openfingerprint-api`.

## Run manually

Supply these environment variables privately, then run
`cargo run --manifest-path api/Cargo.toml --locked`:

| Variable | Meaning |
| --- | --- |
| `OPENFINGERPRINT_SIGNING_KEY` | 32 cryptographically random bytes encoded as 64 lowercase hexadecimal characters. |
| `OPENFINGERPRINT_SITES` | JSON array of 1–16 site configurations. |
| `OPENFINGERPRINT_LISTEN_ADDR` | Optional listener, default `127.0.0.1:8180`. |

Each site configuration has `id`, `site_key`, `secret_key` and `origins`.
IDs are 1–64 ASCII characters, start with a letter and otherwise contain
letters/digits/underscore/dot. Public site keys and server-only secret keys are
32–128 URL-safe ASCII characters. Generate random credentials; length validation
cannot establish randomness. IDs and keys must be unique across sites and roles.

`origins` contains 1–16 exact browser origins, without a path, trailing slash,
credentials, query or wildcard. HTTPS is allowed; HTTP is restricted to localhost
and loopback. Include non-default ports. Startup fails closed for invalid or
missing configuration without printing its values.

The API does not serve the SDK or a web dashboard. Serve the built browser SDK
from your application. Do not embed either signing or server secret keys in it.
TLS is required before sending credentials over a non-loopback network; this
process does not terminate TLS.

## Docker images

After an API release, the image is available at
`ghcr.io/mokto/openfingerprint-api:<version>` for **linux/amd64** and **linux/arm64**.
Docker selects the architecture automatically. Images are not published from PRs.
No image has been released merely by adding this build configuration.

With the signing key and site configuration already set privately in your shell:

```sh
docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  -p 127.0.0.1:8180:8180 \
  --env OPENFINGERPRINT_SIGNING_KEY --env OPENFINGERPRINT_SITES \
  ghcr.io/mokto/openfingerprint-api:0.1.0
```

The image runs as UID/GID 65532 and listens on port 8180 inside the container.
The host port above is loopback-only; use an appropriate TLS proxy for external
access. No secrets are accepted as build arguments or copied into the image.
SIGTERM/SIGINT initiate graceful shutdown. The filesystem can remain read-only;
a volume does not make the in-memory state durable. Restart still loses all state.

Build and check a local native-architecture image from the repository root:

```sh
docker buildx build --load --provenance=false -f api/Dockerfile -t openfingerprint-api:check .
node scripts/test-api.mjs --image openfingerprint-api:check
```

To test another architecture with local emulation, add `--platform linux/amd64`
or `--platform linux/arm64` to both commands. CI builds and runs the same HTTP
checks on native AMD64 and ARM64 GitHub runners. Container checks also verify
non-root execution, read-only operation, license retention and clean SIGTERM exit.
The runtime includes application/data attribution, locked dependency licenses and
Rust license notices under `/usr/share/licenses/openfingerprint-api/`. The build
fails if a selected dependency has no recognized license/notice files. Base-image
OS notices remain in their original locations. Update pinned base-image digests
when applying security updates.

### Publishing a release

Release Please maintains an API release PR from conventional commits on `main`.
Review and merge that PR to update `api/Cargo.toml`, its lockfile, changelog and
release manifest, then create an `api-v<version>` GitHub release. The SDK's root
package version is independent and is not managed by this configuration.

The automation uses the short-lived `GITHUB_TOKEN`, not a stored PAT. Because its
PR/tag events do not start other workflows automatically, it explicitly dispatches
CI for release PRs and image publishing for released tags. Repository Actions
settings must allow GitHub Actions to create pull requests.

The image workflow checks that the tag matches `api/Cargo.toml` and its commit is
already on `main`. It builds and checks both architectures before combining their
manifests, publishing the version tag and a `sha-<commit>` tag. Prefer a manifest digest when
an immutable deployment pin is required. There is no `latest` production-readiness
promise, and publishing an image does not deploy a hosted API.

GitHub initially makes new personal-account packages private, even from a public
repository. On the first release, the owner must open the `openfingerprint-api`
package's **Package settings → Change visibility → Public**. This is irreversible.
The workflow deliberately fails anonymous verification until that is done; rerun
its failed manifest job afterward. Verification checks both manifest architectures
and pulls both images with a fresh, unauthenticated Docker configuration. Do not
advertise a public image until that verification succeeds.

## Collection and signup checks

1. After applicable disclosure/consent, collect browser evidence ahead of signup.
   The unchanged SDK has a two-second cooperative default budget; it can return
   null IDs and native calls can exceed the budget.
2. Send the schema-4 result directly to `POST /v1/collect` with `X-Site-Key` and an
   allowed browser Origin. Do not set the SDK's `storageKey`: unsolicited storage
   markers are rejected. The response has `visitor_token` and Unix `expires_at`.
3. Pass the token to your own signup backend. From that trusted backend, call
   `POST /v1/check` with `Authorization: Bearer <server secret>` and JSON
   `{ "email": ..., "visitor_token": ... }`. The token is optional for email-only
   checks. Never forward the browser Origin to this server-only endpoint.

Authentication is checked before parsing the signup-check body or doing DNS work.
`/v1/check` rejects browser-origin requests and does not enable browser CORS.
Collection has exact-origin preflight handling; public site keys and Origin/CORS
are not authentication against a client that can forge requests.

The server validates bounded signal maps, statuses, exclusions and timings, and
recomputes non-null full/core IDs from the canonical schema-4 inputs. These checks
catch accidental corruption, not dishonest clients. A signed token binds a random
observation to one customer and expiry; it does not prove a real browser, person
or physical device. Excluded diagnostic evidence alone cannot create an identity.

## Response semantics

`/v1/check` returns `verdict`, email `reasons`, email signals and a `linking` object.
Email heuristics may recommend `allow`, `review` or `block`; the API does not
execute a signup action. Browser-link evidence never changes that email verdict.
MX presence does not prove deliverability, ownership or abuse. Absence of MX is
not a complete SMTP deliverability test, and the bundled domain list can be stale.
Do not treat these experimental heuristics as safe automatic blocking policy.

`linking` contains:

- `status`: `ok` when exact-profile evidence was read and recorded, otherwise an
  explanatory status such as `not_collected`, `invalid_token`, `expired_token`,
  `observation_unavailable`, `insufficient_signals` or `linking_unavailable`.
- `other_emails_seen`: distinct other normalized emails previously checked against
  that customer's exact full profile and schema. **Not confirmed accounts.**
- `recorded`: whether this check recorded the email/profile link.

Missing, expired, tampered, wrong-customer, unavailable or insufficient browser
identity returns `other_emails_seen: null` and `recorded: false`, never a fabricated
zero-match claim. Authentication, rate and transport failures remain HTTP errors;
customers must explicitly choose their signup fail-open policy.

The parser accepts unquoted ASCII dot-atom addresses with DNS-style domain
labels. Quoted local parts, address literals and SMTPUTF8 are not supported;
ASCII punycode domains are accepted. Normalization lowercases addresses, strips
plus tags and folds Gmail dots and `googlemail.com`. This is an experimental
alias policy, not universal mailbox semantics. One observation token binds to one
normalized email. A different email needs a fresh token. Alias/retry recording is idempotent and does not extend link
retention. Comparison and recording are atomic.

Matching uses only customer, schema and the exact full profile. It never merges
by core-only similarity, network, account ID, storage marker or fuzzy threshold.
Profiles can collide or change with settings and browser updates.

## Limits and privacy

- 256 live observations and 512 live links per site. Capacity does not evict valid
  records to admit new ones; it produces an explicit capacity/unknown result.
- Separate fixed monotonic windows allow 60 collections and 60 authenticated
  checks per minute per site. Authenticated malformed requests consume quota.
- Strict JSON, 64 KiB bodies, bounded names/email/token inputs and no-store replies.
- Tokens and observations expire after 15 minutes. A monotonic deadline prevents
  backward wall-clock changes from extending observation lifetime.
- Links expire 30 days after first recording. Access and a 60-second background
  sweep remove expired data. Retry checks do not reset that expiry.
- Observations retain hashes and bounded availability/exclusion/timing metadata.
  Links retain customer-scoped email HMACs, not plaintext addresses. Responses
  return normalized caller-supplied email data, but it is not saved or logged.
- No IP, network, raw UA or request-log collection is added. Treat hashes, tokens
  and link history as pseudonymous data, not anonymous data.

Before production, add durable indexed transactions and expiry, distributed quotas,
key rotation/revocation, tenant management, deletion controls, operational safeguards,
TLS/proxy policy and privacy review. Define confirmed signup/credit-issuance events
before advertising account counts. Calibrate false merges and missed returns on
independently labelled devices before using device evidence to restrict users.
