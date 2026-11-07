# OpenFingerprint agent guide

## What this repository is

OpenFingerprint is an experimental browser-signal SDK and a self-hosted check API. It collects pseudonymous browser evidence for application security; it does not prove physical-device identity, attest browser execution or establish Fingerprint Pro accuracy.

- `sdk/` is the TypeScript browser package, published as `@openfingerprint/sdk`. It collects rendering probes and environment hints, hashes identity locally with Web Crypto, and reports automation observations separately.
- `api/` is a Rust service using Axum and Tokio. It verifies SDK profiles, evaluates automation evidence, provides domain intelligence and manages challenge-bound collection. Redis holds shared single-use collection state and cached RDAP registry answers, not a visitor-history database.
- The repository root is a private pnpm workspace for development, CI and release orchestration, not another published package. The SDK can be used without the API.

## Code map

| Location | Responsibility |
| --- | --- |
| [sdk/src/index.ts](sdk/src/index.ts) | Public `collect()`/`identify()` entry points, rendering probes, scheduling, result assembly and identity hashing. |
| [sdk/src/environment.ts](sdk/src/environment.ts), [sdk/src/policy.ts](sdk/src/policy.ts) | Environment hints and browser-specific exclusions from identity. Excluded probes can remain available as diagnostics. |
| [sdk/src/automation.ts](sdk/src/automation.ts), [api/src/automation.rs](api/src/automation.rs) | Browser automation observations and their independent server-side evaluation rules. |
| [api/src/main.rs](api/src/main.rs) | HTTP routes, process startup, snapshot reload scheduling, metrics listener and graceful shutdown. |
| [api/src/check.rs](api/src/check.rs) | Server authentication, request validation, canonical profile/hash verification, `/v1/check` and compatibility `/v1/verify`. |
| [api/src/collection.rs](api/src/collection.rs) | Challenges, browser/header consistency, Redis-backed single-use publication and backend event consumption. |
| [api/src/domains.rs](api/src/domains.rs), [api/src/mx.rs](api/src/mx.rs) | Licensed domain-snapshot matching, provenance/expiry and bounded DNS MX lookup/provider inference. |
| [api/src/rdap.rs](api/src/rdap.rs), [api/src/cache.rs](api/src/cache.rs) | Registered-domain RDAP lookup and Redis cache/connection handling. |
| [api/data/](api/data/), [api/update-domain-data.mjs](api/update-domain-data.mjs) | Bundled source/review metadata, RDAP bootstrap data and the validated domain-snapshot updater. Dataset licenses are separate from the code's MIT license. |
| [sdk/test.mjs](sdk/test.mjs), [sdk/test-collection.mjs](sdk/test-collection.mjs) | Playwright browser/reference checks and SDK submission/transport checks. |
| [api/test.mjs](api/test.mjs), [api/test-collection.mjs](api/test-collection.mjs), [api/test-domain-updater.mjs](api/test-domain-updater.mjs) | HTTP/container, Redis collection and dataset-updater integration checks. Rust unit tests live alongside their modules. |
| [api/chart/](api/chart/), [api/Dockerfile](api/Dockerfile), [api/updater.Dockerfile](api/updater.Dockerfile) | Helm deployment, network policy, refresh/monitoring resources and runtime/updater images. |
| [.github/workflows/](.github/workflows/), [scripts/test-release.mjs](scripts/test-release.mjs) | CI, component publishing, dataset refresh automation and release-configuration regression checks. |

## How the pieces connect

- Local collection: `collect()` runs bounded browser probes and returns identity hashes, availability/timing diagnostics and separate automation evidence. Collection failures and browser-policy exclusions are not evidence of malicious behavior.
- Protected-action collection: the application backend issues `/v1/challenges` with a server-owned action binding; `identify()` submits through a same-origin proxy to `/v1/collect` and receives only an event ID. The backend consumes that event through `/v1/events/consume` using its stored binding before deciding the action. The browser does not supply the expected binding or the authoritative verdict.
- Direct checks: authenticated backends call `/v1/check` for independent requested sections. `/v1/verify` preserves the fingerprint-only compatibility response. Neither endpoint executes browser probes.
- Domain intelligence: the API matches versioned local snapshots, uses DNS MX evidence where applicable and obtains registered-domain registration dates through RDAP. The separate updater refreshes public datasets; source provenance, licensing and expiry travel with the data.

## Finish with a pull request

- After completing changes and the applicable checks, create or update a pull request before handing off; do not leave completed work only in a local worktree.
- Open the PR for large and UI-affecting changes too; do not wait for the user to test locally first. Skip PR creation only for read-only tasks or when the user explicitly declines one.
- Include the change summary, checks run, skipped checks and remaining limitations in the PR. Return its link to the user.
- Reference roadmap issues without closing them while their other milestones remain unfinished.
- Keep each task on its own branch. Preserve unrelated changes and other worktrees; do not merge or deploy without the user's request.

## Read the relevant guide

- For browser collection, identity schemas or SDK transport, read the [SDK guide](sdk/README.md).
- For API contracts, authentication, collection state or security signals, read the [API guide](api/README.md).
- For dataset sources, matching, licensing or refresh, read the [data guide](api/data/README.md).
- For deployment, network policy or monitoring, read the [Helm guide](api/chart/README.md).
- For publishing changes, read [Releases](README.md#releases). The SDK and API release independently through Release Please.

## Preserve the boundaries

- Keep the SDK free of runtime dependencies and import-time collection. Keep `collect()` network-free; use `identify()` for explicit submission.
- Preserve existing fingerprint hashes and verification compatibility unless the task explicitly calls for a versioned migration. Keep diagnostic evidence outside identity hashes.
- Preserve unknown results for missing, failed or stale evidence. Do not present browser observations as attestation or a negative detection as proof of trust.
- Keep server credentials and protected decisions on the backend. Preserve challenge/action binding, single-use consumption and failure behavior when changing collection.

## Verification

Use the Node and pnpm versions declared in [package.json](package.json). Install JavaScript dependencies with `pnpm install --frozen-lockfile`.

| Changed area | Checks |
| --- | --- |
| SDK or shared build/release wiring | `pnpm check`, `pnpm build`, `pnpm test` |
| Rust API or API data logic | `pnpm api:check` |
| Helm chart | `bash api/chart/test.sh` |
| Documentation or agent instructions only | Verify referenced paths, headings and commands; run `git diff --check`. |

- For browser tests, install engines with `pnpm --dir sdk exec playwright-core install chromium firefox webkit`; use `--with-deps` when the host needs system libraries.
- For collection changes, set `OPENFINGERPRINT_TEST_REDIS_URL` to a dedicated disposable Redis database when running `pnpm api:check`, so the collection integration suite runs rather than skips. Follow the [API checks guide](api/README.md#checks-and-containers) for prerequisites.
- Report unavailable infrastructure or browser coverage as untested, not passed. Passing automated browser tests does not establish real-device identification accuracy.
