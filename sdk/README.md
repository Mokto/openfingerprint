# OpenFingerprint browser SDK

A standalone, MIT-licensed TypeScript browser-signal collector with **zero runtime dependencies**.

The SDK has no telemetry, remote code, WASM or import-time collection. `collect()`
hashes identity signals locally and always includes automation observations as
unhashed booleans/nulls, with no network requests. `identify()` submits that evidence
to your same-origin collection proxy and returns an opaque event ID. The optional
self-hosted API provides stateless checks and a Redis-backed single-use event flow;
it does not provide managed identification or visitor history.

**Experimental:** a profile hash is not proof of physical-device identity. Different
devices can collide; settings, updates and missing signals can split repeat visits.
Identification accuracy comparable to FingerprintJS has not been established.

## Install

```sh
npm install @openfingerprint/sdk
```

Releases are published from GitHub Actions with npm trusted publishing, so each
version carries a provenance attestation linking it to this repository, the release
tag and the workflow run. The package ships only the built bundles, type
declarations, license and notices; it has no runtime dependencies.

## Build from source

Clone and build it locally:

```sh
git clone https://github.com/Mokto/openfingerprint.git
cd openfingerprint
pnpm install --frozen-lockfile
cd sdk
pnpm check
pnpm build
```

Node 24+ and pnpm 12.11.2 are used for development. Build outputs:

- `dist/index.js`: standalone ES module.
- `dist/index.iife.js`: script exposing `OpenFingerprint.collect`, `OpenFingerprint.identify` and `OpenFingerprint.collectAutomation`.
- `dist/types/`: TypeScript declarations.

The package exports resolve to the built ES module and declarations. Only
development/build/test dependencies are installed; none are required by the
emitted collector.

### Releases

Release Please versions the SDK (`sdk-v*` tags, `sdk/CHANGELOG.md`) and the API
(`api-v*` tags, `api/CHANGELOG.md`) independently. Merging an SDK release PR
dispatches `.github/workflows/sdk-publish.yml`, which checks that the tag matches
`sdk/package.json` and is on `main`, runs the type check, build and browser tests, verifies
the package contents and publishes to npm. A version already on npm is skipped.

## Optional Rust API

The independent [Rust API](../api/README.md) verifies SDK evidence and accepts
optional domain/IP inputs. It is self-hosted and experimental. `collect()` does
not call it; `identify()` uses its collection endpoint via your same-origin proxy.
See the [project overview](../README.md) for backend checks and releases.

## Use

Call after your application's fraud-prevention disclosure/consent requirements
are satisfied. Collect ahead of signup rather than making authentication wait.

```js
import { collect } from '@openfingerprint/sdk';

const result = await collect();
```

For a regular script tag, serve `dist/index.iife.js` from your own origin, then
call `OpenFingerprint.collect()` under the same consent/security conditions.
Neither import nor loading the script starts collection automatically.

Options:

| Option       | Default | Meaning                                                                                      |
| ------------ | ------- | -------------------------------------------------------------------------------------------- |
| `timeoutMs`  | `2000`  | Cooperative budget, from 1 to 5000 ms. Native browser calls can overrun it.                  |
| `storageKey` | omitted | Optional namespaced random UUID in localStorage, separate from all fingerprint hashes.       |
| `onIdentity` | omitted | Receives a detached result snapshot after identity calculation, before excluded diagnostics. |

No persistence is used by default. Explicitly enabling `storageKey` reads/writes
only that marker, not arbitrary localStorage data. Blocked storage returns `null`.

### Automatic automation observations

Every `collect()` result and `onIdentity` snapshot includes `automation`.
Forward `{ signals: result }` to a compatible `/v1/check` to receive the evaluation
inside `response.signals.automation`. No opt-in or separate call is needed.
Automation remains outside fingerprint hashes, so identity schema 5 is unchanged.
Deploy the compatible API first: older versions reject this additional SDK field.
`collectAutomation()` remains available as a synchronous browser-only helper.

| Field | Observation |
| --- | --- |
| `version` | Always `1`, independent of fingerprint schema 5. |
| `webdriver` | The boolean `navigator.webdriver` value. |
| `headlessUserAgent` | A `HeadlessChrome/` token in the user-agent string. |
| `seleniumArtifacts` | Presence of `__webdriver_evaluate`, `__selenium_evaluate`, `__webdriver_script_fn` or `__selenium_unwrapped` on `document`. |
| `phantomArtifacts` | Presence of `callPhantom` or `_phantom` on `window`. |

Each observation is `boolean | null`. Missing/non-boolean WebDriver values,
empty/non-string user agents and throwing reads return null independently.
Artifact checks inspect property presence without invoking getters or functions.
The collector makes no network requests, writes no storage and returns no raw UA
or artifact values.

These are client-reported, forgeable indicators, not a malicious-bot verdict.
Hidden automation can evade them; applications can also define matching names.
An observed false means only that this specific marker was absent. It does not
prove human activity. The [API](../api/README.md#automation-indicators) evaluates
the observations with versioned rules and preserves unknowns.

### Challenge-bound identification

Your backend first obtains a challenge from `POST /v1/challenges`, binding it to
a random, server-stored session/action token and your exact browser origin.
It gives only the challenge to the browser:

```js
import { identify } from '@openfingerprint/sdk';

const { eventId } = await identify({
	endpoint: '/fingerprint/collect',
	challenge
});
```

`identify()` collects identity and automation automatically, then makes one JSON
POST to the same-origin endpoint. Your proxy forwards it to the API's
`POST /v1/collect`, preserving Origin, User-Agent and Sec-CH-UA-Platform, but no
cookies or Authorization. The browser receives only an opaque event ID, not a
server verdict. With network data configured, the API also derives Tor/ASN/cloud
range evidence from the request, not from browser IP claims. Your proxy must
sanitize forwarding headers and the API must trust only its actual proxy CIDRs;
raw IPs are not retained. No extra SDK option is needed. Send that ID with the business action; your backend consumes it
using `POST /v1/events/consume` and the expected server-stored binding.

The endpoint must be same-origin HTTPS (HTTP is allowed on localhost/loopback).
Requests omit credentials and referrers, disable caching, refuse redirects and do
not retry. Allow the endpoint in your CSP `connect-src 'self'`.
`timeoutMs` controls collection as for `collect()`; `networkTimeoutMs` is a
separate 1–30000 ms network budget, default 5000. A failed/ambiguous submission
requires a fresh challenge; do not retry the same one.

Only this flow additionally sends bounded raw user-agent (512 UTF-8 bytes) and
platform (128 bytes) observations for server consistency checks. Unavailable or
over-limit values become null. They are not included in identity hashes, returned
to the browser or retained in the event. `identify()` does not use storage and
does not expose an `onIdentity` callback.

Challenge/event binding prevents replacement and reuse of evaluated results; it
does not attest honest browser execution. Unknown results stay unknown. Missing,
expired or already-used events must never authorize a protected action. See the
[collection API](../api/README.md#challenge-bound-collection) for deployment,
retention, Redis and integration requirements.

### Identity readiness and cooperative batching

`collect()` still resolves only after diagnostic collection finishes or times out.
An optional `onIdentity(snapshot)` callback exposes the earlier identity phase:

```js
const finalResult = await collect({
	onIdentity(snapshot) {
		handleIdentity(snapshot);
	}
});
```

`handleIdentity` is your application handler; the SDK sends nothing. The callback
runs once before excluded diagnostic work, including when no identity could be
computed (`fingerprint`/`coreFingerprint` can be null). Invalid options or a missing
secure browser context still reject without calling it. Check the IDs before use.

The snapshot has the normal result shape, with elapsed duration, independent
copies of maps/arrays/timing entries, and the optional storage marker. It contains
only results available at that point; excluded diagnostics may be absent until
the final result. When no diagnostics are excluded, the callback may run only
shortly before the final promise; it is not an earlier, weaker identity. Callback
mutations cannot alter the final result. Callback
throws/rejections are contained, and returned promises are not awaited. Keep the
handler's synchronous work short: a blocking caller can still delay diagnostics.
No callback is installed or invoked unless explicitly supplied.

Font catalogue and fallback measurements now use approximately four-millisecond
work slices, checked between native reads, rather than yielding every eight fonts.
All candidates, texts, metrics, ordering and hashes are retained. A MessageChannel
task gives other event-loop work an opportunity to run; it guarantees neither a
paint nor an input-latency bound. A single native call, GPU initialization or other
browser work can still block longer than a slice. This targets responsiveness,
not a guaranteed reduction in total collection time. The default budget remains
two seconds.

Version 0.5.1 checks the monotonic deadline before reads and after font-work yields,
and aborts other pending probes whenever a deadline check observes expiry. This
avoids continued work when the timeout callback is delayed. It still cannot
interrupt an active native call or resume a suspended page; it is not a hard
wall-time guarantee or a recovery mechanism for missing identities.

## Result and schema

Version **0.6.0**, result **schema 5**:

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
  `blockingMs` covers only the initial synchronous portion of a probe call, not
  cumulative CPU work or the longest later task.

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

Hash domains (`stealth-agent:5`, `stealth-core:5`) and the optional marker
namespace (`stealth:`) intentionally retain their original `stealth` spelling.
Renaming the project must not silently change existing IDs or markers. Compare IDs
only within the same schema; any change to identity inputs requires versioning.

Schema 5 (version 0.6.0) changes only the locale hint: it uses the primary
`navigator.language`, time-zone name and resolved `Intl` locale. It no longer
includes the full `navigator.languages` list, which Chrome incognito and Safari
reduce to one entry, or the current UTC offset, which changes at daylight-saving
transitions. Probes, canvas/font/GPU/audio inputs and the core ID inputs are
unchanged, but every full and core ID differs from schema 4 because the hash domain
changes. Schema-4 history does not match schema-5 IDs.

## Tests and reference comparison

```sh
pnpm exec playwright-core install chromium firefox webkit
pnpm test
```

Tests use isolated browser contexts and block external page requests. They cover
canonical hashes, optional storage, availability, deadlines/cleanup, all 96 font
candidates, time-budgeted yields, aborting a paused slice, port/frame cleanup,
identity-before-diagnostics delivery, detached snapshots, callback failure isolation,
delayed-timeout cancellation before reads/after yields with concurrent pending audio,
Safari-policy fixtures, retained signal detail and calibrated font-preference parity with
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

For a consented, externally labelled repeat-visit study, use the repository's
[offline identification measurement tools](../evaluation/README.md). They compare
full/core identities separately and report collisions, missed returns and missing
evidence without modifying the published SDK or uploading samples.

## Reference scheduling comparison

Pinned development references are FingerprintJS 5.3.0 and ThumbmarkJS 1.12.0.
They use different signals, stabilization and hashing, so timings alone do not
establish equivalent quality.

| Library         | Scheduling and latency considerations                                                                                                                                                                                                                                                                                                                                         |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| OpenFingerprint | Native audio overlaps; canvas/font/hint probes finish before GPU initialization. Font work yields by time budget. Optional early identity precedes excluded diagnostics; the final promise still includes them.                                                                                                                                                               |
| FingerprintJS   | `load()` waits for idle, with a 50 ms timer fallback and a 100 ms idle-callback timeout. Source dispatch yields roughly every 16 ms between sources, not inside an individual source. Async work overlaps across its load/get phases. Font DOM writes are batched, but font measurement itself is synchronous. Each `get()` waits for all components before producing the ID. |
| ThumbmarkJS     | Eagerly dispatches components and overlaps their promises, but synchronous font/canvas/GPU work still blocks dispatch. Per-component timeouts default to five seconds and do not interrupt native work or cap the entire pipeline. Empty speech voices can add an 800 ms wait.                                                                                                |

FingerprintJS reuses source-load state per agent and caches a WebGL context.
Thumbmark reuses WebGL state where supported and exposes component/pipeline
diagnostics with `performance: true`; its API-response cache does not skip local
collection. Thumbmark's component elapsed timers start after eager dispatch, so
include `_dispatch.*` and `_pipeline.dispatch` when examining synchronous cost. Our SDK deliberately recollects probe evidence per call.

The comparison test includes FingerprintJS `load()` in elapsed time; idle waiting
is not necessarily a fixed 50 ms delay. Thumbmark uses its default stabilization
rules in this lab; integrations using `stabilize: []` are not configuration-equivalent.
Reference monitoring/logging is disabled and no API keys are configured. Timeout
races do not guarantee cancellation of underlying browser work in any library.
Reference IDs can still be produced from component sets containing errors or
timeouts; ID presence alone does not establish equivalent evidence or accuracy.

## Privacy and limits

Hashes are **pseudonymous, not anonymous**; low-entropy values can be guessed.
Browser values can be forged. Signing collected results on a server would not
turn them into hardware attestation. Use only for legitimate security/fraud
prevention, with appropriate disclosure, consent/legal basis, customer isolation
and retention controls. Do not put raw probes, hashes or persistent identifiers
in application logs. Approved identification studies require separate restricted
storage, consent, retention and withdrawal handling as described in the study guide.

The client provides no cross-browser identity guarantee, server-side account
linking, disposable-email checks, network intelligence, signed tokens or automatic
blocking. It should not be used for cross-site advertising or covert tracking.
More probes and repeated matching samples do not establish population accuracy;
measure false merges, missed returns and missingness on independently labelled
physical devices before making decisions.

## License and provenance

[MIT](LICENSE), copyright 2026 Théo Mathieu. Both emitted bundles start with this
notice as a preserved `/*!` comment, so bundlers that keep legal comments carry it
into application builds.

The DOM font-preference presets/calibration adapt
[FingerprintJS 5.3.0](https://github.com/fingerprintjs/fingerprintjs/blob/v5.3.0/src/sources/font_preferences.ts),
also MIT. Its full copyright/license notice is retained in
[THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES) and both emitted bundles. Other probes and
the policy gate are standalone implementations. The full FingerprintJS and
ThumbmarkJS collectors are used only by development tests.
