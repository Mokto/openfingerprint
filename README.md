# OpenFingerprint

A browser-signal SDK and an optional, experimental Rust check API. The code is MIT
licensed and released independently; [datasets](api/data/README.md) retain their
own licenses. Documentation: [openfingerprint.com/docs](https://openfingerprint.com/docs).

| Component | Purpose | Documentation |
| --- | --- | --- |
| [`sdk/`](sdk/) | Standalone TypeScript browser collector, published as `@openfingerprint/sdk`. | [SDK guide](sdk/README.md) |
| [`api/`](api/) | Rust backend: a public identify listener for browsers and an internal check API for identifications, domains and IPs. | [API guide](api/README.md) |

The SDK has zero runtime dependencies, no telemetry, remote code, WASM or
import-time collection. It hashes identity locally and adds bounded automation,
tampering and spoofing observations. `identify()` posts that evidence over TLS to the
API's public `/v1/identify` listener, which observes the request itself, including the
browser's TLS handshake (JA4), and returns an `identificationId`. Your backend sends that
ID to the API's internal `/v1/check`, which reports an optional reconciled `visitorId`,
automation, tampering and spoofing verdicts, whether the identification was looked up before
(`replayed`) and its age by the API's clock. A script that posts a browser's evidence
from Python, Go, curl or Node shows up as `tls_mismatch`; a real browser driven by
automation does not, which the automation probes cover.

The API's internal listener has no authentication: run it on a private network behind
your backend (see the [security notes](api/README.md#security)); only the identify
listener faces the Internet. Redis holds cached registry answers and hour-long
identifications. Optional PostgreSQL-backed [visitor reconciliation](api/README.md#visitor-reconciliation)
retains server-issued visitor IDs, exact fingerprint aliases and reference hashes until
explicit deletion. These are pseudonymous browser groupings, not person or physical-device identities. Open
domain snapshots provide independent disposable, free-subdomain, public-mailbox,
email-relay and scoped referrer-spam evidence, including recently monitored provider
domains, provenance, expiry and exact reviewed disputes, plus typo suggestions for
public mailbox domains. The API looks up each domain's MX hosts to name its mail
provider and detect new domains whose mail is routed to a listed disposable
provider, and the registration date of its registered domain over RDAP. Unlisted data stays
unknown, not clean. IP country estimates use an optional local DB-IP Country Lite
database, with provenance, expiry and automatic refresh in the Helm chart; they
do not establish a person's location. Optional local network snapshots add
Tor-exit, ASN and published cloud-range evidence with independent source expiry.
Only an IP your backend passes is evaluated, and it is not retained. VPN/proxy
classification remains unknown. The API does not run browser probes; the SDK collects
them and posts them to it. See the [data guide](api/data/README.md) for
sources, licensing and refresh without image rebuilds.

**Experimental:** a profile hash is not proof of physical-device identity. Devices
can collide; settings, updates and missing signals can split repeat visits.
Identification accuracy comparable to FingerprintJS has not been established.
Hashes are pseudonymous, not anonymous. Review each component's privacy and
security boundaries before use. The [identification study tools](evaluation/README.md)
provide consented, externally labelled capture and offline evaluation; automated
smoke tests do not establish real-device accuracy.

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

Requires Node 24+, pnpm 12.17.0 and current stable Rust for API development.

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
API checks require Rust and Node but no JavaScript dependencies or cloud account.
Visitor integration checks additionally require a disposable PostgreSQL database; CI supplies one.
See the [API guide](api/README.md) for configuration and containers.

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
`DISPATCH_TARGET`/`DISPATCH_TOKEN` and `DISPATCH_TARGET_K3S`/`DISPATCH_TOKEN_K3S` secret
pairs are set, it then dispatches a deployment workflow for each pair; it never migrates callers. An SDK release does not release the API,
and an API release does not release the SDK.

`pnpm check` includes a release-wiring regression check. The shared workflow and
release configuration remain at the repository root.

## License

[MIT](LICENSE), copyright 2026 Théo Mathieu. The SDK retains its adapted
FingerprintJS font-preference notices in
[`sdk/THIRD-PARTY-NOTICES`](sdk/THIRD-PARTY-NOTICES) and both emitted bundles.
