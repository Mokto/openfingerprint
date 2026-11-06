# OpenFingerprint

A browser-signal SDK and an optional, experimental Rust check API. The code is MIT
licensed and released independently; [datasets](api/data/README.md) retain their
own licenses.

| Component | Purpose | Documentation |
| --- | --- | --- |
| [`sdk/`](sdk/) | Standalone TypeScript browser collector, published as `@openfingerprint/sdk`. | [SDK guide](sdk/README.md) |
| [`api/`](api/) | Self-hosted Rust backend for server-only signal, domain and IP checks. | [API guide](api/README.md) |

The SDK has zero runtime dependencies. It hashes signals locally, makes no network
requests and has no telemetry, remote code, WASM or import-time collection. You
choose whether and where to send results.

The API verifies submitted evidence without visitor storage or history. Open
domain snapshots provide independent disposable, free-subdomain and scoped
referrer-spam evidence, including recently monitored provider domains, provenance,
expiry and exact reviewed disputes. Optional caller-resolved MX hosts detect new
domains whose mail is routed to a listed disposable provider. Unlisted data stays
unknown, not clean. IP
intelligence is not implemented yet. The API does not collect browser signals,
and the SDK does not depend on it. See the [data guide](api/data/README.md) for
sources, licensing and refresh without image rebuilds.

**Experimental:** a profile hash is not proof of physical-device identity. Devices
can collide; settings, updates and missing signals can split repeat visits.
Identification accuracy comparable to FingerprintJS has not been established.
Hashes are pseudonymous, not anonymous. Review each component's privacy and
security boundaries before use.

## Install the SDK

```sh
npm install @openfingerprint/sdk
```

```js
import { collect } from '@openfingerprint/sdk';

const result = await collect();
```

Collect only after your application's fraud-prevention disclosure/consent
requirements are satisfied. See the [SDK guide](sdk/README.md) for options,
result schemas, browser limits and test methodology.

## Development

Requires Node 24+, pnpm 12.11.2 and current stable Rust for API development.

```sh
git clone https://github.com/Mokto/openfingerprint.git
cd openfingerprint
pnpm install --frozen-lockfile
pnpm check
pnpm build
pnpm --dir sdk exec playwright-core install chromium firefox webkit
pnpm test
pnpm api:check
```

The root package is private and provides convenience commands. SDK source,
build configuration, browser tests and generated `dist/` live in `sdk/`.
The API owns its Cargo package, Dockerfile, HTTP self-check and data updater in `api/`, plus a Helm chart in `api/chart/`.
API checks require Rust and Node but no JavaScript dependencies, database or cloud
account. See the [API guide](api/README.md) for configuration and containers.

## Releases

Release Please tracks each component separately:

- SDK: `sdk/package.json`, `sdk/CHANGELOG.md`, `sdk-v*` tags, npm.
- API: `api/Cargo.toml`, `api/CHANGELOG.md`, `api-v*` tags, GHCR images and the
  `oci://ghcr.io/mokto/charts/openfingerprint` Helm chart.

Merging a release PR dispatches the corresponding publishing workflow. SDK
publishing checks the tag against `sdk/package.json`, builds and tests the SDK,
verifies package contents and uses npm trusted publishing with provenance.
API publishing builds and smoke-tests Linux AMD64/ARM64 API and domain-updater
images, then publishes the Helm chart pinned to their digests. When the
`DISPATCH_TARGET` and `DISPATCH_TOKEN` secrets are set, it then dispatches a
deployment workflow; it never migrates callers. An SDK release does not release the API,
and an API release does not release the SDK.

`pnpm check` includes a release-wiring regression check. The shared workflow and
release configuration remain at the repository root.

## License

[MIT](LICENSE), copyright 2026 Théo Mathieu. The SDK retains its adapted
FingerprintJS font-preference notices in
[`sdk/THIRD-PARTY-NOTICES`](sdk/THIRD-PARTY-NOTICES) and both emitted bundles.
