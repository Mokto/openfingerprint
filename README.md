# OpenFingerprint

A small, standalone TypeScript browser-signal collector for fraud-prevention
experiments. **MIT licensed. Zero runtime dependencies.**

No network requests, telemetry, remote code, WASM or import-time collection.
Signals are hashed locally with Web Crypto. You choose whether and where to send
results. This repository contains the browser client, not a hosted API or matcher.

**Experimental:** a profile hash is not proof of physical-device identity. Different
devices can collide; settings, updates and missing signals can split repeat visits.
Identification accuracy comparable to FingerprintJS has not been established.

## Build from source

This package is not published to npm. Clone and build it locally:

```sh
git clone https://github.com/Mokto/openfingerprint.git
cd openfingerprint
pnpm install --frozen-lockfile
pnpm check
pnpm build
```

Node 24+ and pnpm 12.11.2 are used for development. Build outputs:

- `dist/index.js`: standalone ES module.
- `dist/index.iife.js`: script exposing `OpenFingerprint.collect`.
- `dist/types/`: TypeScript declarations.

The package exports resolve to the built ES module and declarations when used as
a local dependency. Only development/build/test dependencies are installed; none
are required by the emitted collector.

## Use

Call after your application's fraud-prevention disclosure/consent requirements
are satisfied. Collect ahead of signup rather than making authentication wait.

```js
import { collect } from './dist/index.js';

const result = await collect();
```

For a regular script tag, serve `dist/index.iife.js` from your own origin, then
call `OpenFingerprint.collect()` under the same consent/security conditions.
Neither import nor loading the script starts collection automatically.

Options:

| Option       | Default | Meaning                                                                                |
| ------------ | ------- | -------------------------------------------------------------------------------------- |
| `timeoutMs`  | `2000`  | Cooperative budget, from 1 to 5000 ms. Native browser calls can overrun it.            |
| `storageKey` | omitted | Optional namespaced random UUID in localStorage, separate from all fingerprint hashes. |

No persistence is used by default. Explicitly enabling `storageKey` reads/writes
only that marker, not arbitrary localStorage data. Blocked storage returns `null`.

## Result and schema

Version **0.4.0**, result **schema 4**:

- `fingerprint`: full SHA-256 over selected component and environment-hint hashes.
- `coreFingerprint`: separately domain-separated hash of selected rendering probes;
  it is not sufficient to merge devices or accounts.
- `components`: canvas, installed-font metrics, canvas fallback metrics
  (`fontFallbacks`), calibrated DOM font preferences (`fontPreferences`), GPU and
  offline audio, retained as full SHA-256 hashes.
- `hints`: hashed platform, hardware, locale, browser, display/screen, feature,
  media, math and architecture observations.
- `excluded`: diagnostic-only groups omitted from both aggregate IDs by policy.
- `unavailable`: explicit `unsupported`, `unstable`, `timeout` or `error` per probe.
- `storageId`: optional random UUID, otherwise `null`.
- `durationMs` and `timings`: collection diagnostics, not a hard CPU-time limit.

Missing probes do not receive a common success-like placeholder. Aggregate IDs
may be null; excluded diagnostic evidence alone cannot produce an identity.
Never interpret missing IDs as matches. Preserve the schema, availability and
exclusion metadata when comparing observations.

### Safari policy

Reported Safari 17+ excludes canvas, audio and screen geometry/pixel ratio from
both IDs in regular and private browsing. Their hashes/failures remain diagnostics;
color depth is retained. Diagnostic timeouts cannot erase an already-completed ID.
This is not private-mode detection. The reported UA/vendor gate does not cover all
WebViews, spoofed browsers or every browser's privacy behavior.

DOM font preferences measure default, Apple body, generic, minimum-size and system
font widths in an isolated, laid-out document. Zoom/DPR calibration follows the
pinned reference behavior; Chromium calibration depends on the reported UA major
version, so spoofed/frozen versions can select the wrong path. Existing canvas
fallback metrics remain separate. Temporary frames are removed on failure/abort.

### Compatibility

Schema-4 hash domains (`stealth-agent:4`, `stealth-core:4`) and optional marker
namespace (`stealth:`) intentionally retain their original spellings. Renaming the
project must not silently change existing IDs or markers. Compare IDs only within
the same schema; any future change to identity inputs requires versioning.

## Tests and reference comparison

```sh
pnpm exec playwright-core install chromium firefox webkit
pnpm test
```

Tests use isolated browser contexts and block external page requests. They cover
canonical hashes, optional storage, availability, deadlines/cleanup, Safari-policy
fixtures, retained signal detail and calibrated font-preference parity with
FingerprintJS 5.3.0 at DPR 1, 1.25, 2 and 3. Reference collectors are development
fixtures, not part of the standalone client. Monitoring/beacons are disabled.

Optional commands:

```sh
pnpm test --chrome
pnpm test --headed --out .test-results/visible.json
pnpm test --no-references
```

`--chrome` additionally requires an installed Google Chrome. Linux runners may
need `pnpm exec playwright-core install --with-deps chromium firefox webkit`.
Reports under `.test-results/` are ignored by git. Benchmarks rotate collectors in
fresh documents, measuring collection rather than download/parse. Automation and
Playwright WebKit are not physical-device ground truth or shipping Safari.

## Privacy and limits

Hashes are **pseudonymous, not anonymous**; low-entropy values can be guessed.
Browser values can be forged. Signing collected results on a server would not
turn them into hardware attestation. Use only for legitimate security/fraud
prevention, with appropriate disclosure, consent/legal basis, customer isolation
and retention controls. Do not log raw probes, hashes or persistent identifiers.

The client provides no cross-browser identity guarantee, server-side account
linking, disposable-email checks, network intelligence, signed tokens or automatic
blocking. It should not be used for cross-site advertising or covert tracking.
More probes and repeated matching samples do not establish population accuracy;
measure false merges, missed returns and missingness on independently labelled
physical devices before making decisions.

## License and provenance

[MIT](LICENSE), copyright 2026 Théo Mathieu.

The DOM font-preference presets/calibration adapt
[FingerprintJS 5.3.0](https://github.com/fingerprintjs/fingerprintjs/blob/v5.3.0/src/sources/font_preferences.ts),
also MIT. Its full copyright/license notice is retained in
[THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES) and both emitted bundles. Other probes and
the policy gate are standalone implementations. The full FingerprintJS and
ThumbmarkJS collectors are used only by development tests.
