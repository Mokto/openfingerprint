# OpenFingerprint browser SDK

Documentation: [openfingerprint.com/docs/sdk](https://openfingerprint.com/docs/sdk)

A standalone, MIT-licensed TypeScript browser-signal collector with **zero runtime dependencies**.

The SDK has no telemetry, remote code, WASM or import-time collection. It hashes identity
signals locally and adds automation, tampering and spoofing observations outside those
hashes. `identify({ endpoint })` posts that evidence to the API's public listener, which
observes the request itself (headers and TLS handshake), and returns an
`identificationId` for your backend to check. The API is self-hosted or hosted; it keeps
identifications for an hour and no visitor history.

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

Node 24+ and pnpm 12.17.0 are used for development. Build outputs:

- `dist/index.js`: standalone ES module.
- `dist/index.iife.js`: script exposing `OpenFingerprint.identify`, `OpenFingerprint.watch`, `OpenFingerprint.collect`, `OpenFingerprint.collectAutomation` and `OpenFingerprint.collectSpoofing`.
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

## Rust API

The [Rust API](../api/README.md) receives the evidence on its public `/v1/identify`
listener and verifies it when your backend calls its internal `/v1/check`, optionally
with domain, email and IP inputs. See the [project overview](../README.md) for releases.

## Use

Call after your application's fraud-prevention disclosure/consent requirements
are satisfied. Identify ahead of signup rather than making authentication wait.

```js
import { identify } from '@openfingerprint/sdk';

const { identificationId } = await identify({ endpoint: 'https://identify.example.com/v1/identify' });
await fetch('/signup', { method: 'POST', body: JSON.stringify({ ...form, identificationId }) });
```

Your backend sends `identificationId` to the API's internal `POST /v1/check` (or the gRPC
`Check`) and acts on the verdicts. For a regular script tag, serve `dist/index.iife.js`
from your own origin, then call `OpenFingerprint.identify(…)` under the same consent and
security conditions. Neither import nor loading the script starts collection.

Options:

| Option      | Default  | Meaning                                                                     |
| ----------- | -------- | --------------------------------------------------------------------------- |
| `endpoint`  | required | The API's public `/v1/identify` URL, on your own domain or the hosted one.   |
| `timeoutMs` | `2000`   | Cooperative collection budget, from 1 to 5000 ms. Native calls can overrun it. |

`identify()` collects, then posts the evidence as JSON in a `text/plain` request without
cookies, so there is no CORS preflight. Posting gives up after 3 seconds, so `identify()`
can take up to 3 seconds longer than `timeoutMs`. It resolves with
`identificationId: null` when posting fails (network, ad blocker, rate limit or an
unavailable API) and rejects only for invalid options. Add the endpoint's origin to your
page's `connect-src` Content Security Policy. Nothing is written to storage.

`collect({ timeoutMs })` is the local building block: it returns the evidence described
below without any network request, for tests and diagnostics. The API only accepts
evidence posted to its listener.

### Automatic automation observations

The evidence always includes `automation`. `/v1/check` returns its evaluation as
`automation` (`identification.automation` with `detail: true`). Automation remains
outside fingerprint hashes, so the identity schema is unchanged. Deploy the API first:
it accepts only the automation evidence version it defines, currently 7.
`collectAutomation()` remains available as a synchronous browser-only helper.

| Field | Observation |
| --- | --- |
| `version` | Always `7`, independent of the fingerprint schema. |
| `webdriver` | The boolean `navigator.webdriver` value. |
| `headlessUserAgent` | A `HeadlessChrome/` token in the user-agent string, or a `HeadlessChrome` brand in `navigator.userAgentData`, which survives a replaced user-agent string. |
| `seleniumArtifacts` | Presence of `__webdriver_evaluate`, `__selenium_evaluate`, `__webdriver_script_fn` or `__selenium_unwrapped` on `document`. |
| `phantomArtifacts` | Presence of `callPhantom` or `_phantom` on `window`. |
| `platformMismatch` | UA OS family differs from `navigator.platform` or `userAgentData.platform`. |
| `missingChromeObject` | Chromium UA (not WebView) without `window.chrome`. |
| `notificationPermissionQuirk` | `Notification.permission` is `denied` while `permissions.query` reports `prompt`. `collect()` only. |
| `emptyPlugins` | Desktop Chromium with an empty `navigator.plugins`. |
| `emptyLanguages` | Empty `navigator.languages`. |
| `softwareRenderer` | Unmasked WebGL renderer matches SwiftShader, llvmpipe, softpipe, software rasterizer or Mesa offscreen. Taken from the GPU probe, so `collect()` only. |
| `zeroDimensions` | Screen or outer-window width or height of 0. Unknown when only the outer window is 0 in a hidden document, as in a tab opened in the background. |
| `cdpDetected` | An error passed to `console.debug` in a fresh same-origin frame had its stack formatted (V8 called that frame's `Error.prepareStackTrace`), which happens only while a CDP client has `Runtime.enable` on: Puppeteer, Playwright, ChromeDriver or open DevTools. Always false outside V8. Clients that avoid `Runtime.enable` are not seen. Unknown when no frame can be created. |
| `nativeFunctionTampering` | The `navigator.webdriver` getter or `Permissions.prototype.query` is not native code when read with the `toString` of a fresh same-origin frame, or is a `Proxy` (which `toString` reports as native); `navigator` has its own `webdriver` property, or the getter is gone from a browser that defines it; a detached `srcdoc` frame has a window, as puppeteer-extra-plugin-stealth fakes; or `Function.prototype.toString` accepts a non-function. A `toString` wrapper that still answers correctly, as error monitors install, is not reported. Unknown when no frame can be created. |
| `workerUserAgentMismatch` | A blob dedicated worker reports a different UA or platform than the main thread. `collect()` only. |
| `driverArtifacts` | A global left by ChromeDriver (`cdc_…_Array` and similar, `$cdc_…`), other WebDriver and Watir bindings, Playwright's exposed-function binding, NightmareJS or Chrome's `domAutomation`, or a `selenium`, `webdriver` or `driver` attribute on `<html>`. |
| `engineMismatch` | The JavaScript engine, told apart by its `RangeError` wording, is not the one the user agent claims: V8 for `Chrome/`, SpiderMonkey for `Firefox/`, JavaScriptCore for `Version/… Safari/`. iOS user agents and unrecognized engines are unknown. |
| `userAgentDataMismatch` | The `Chromium` brand major version in `navigator.userAgentData` differs from the `Chrome/` major version in the user-agent string, as when a script or flag replaces only the string. |
| `proportionalMonospace` | The generic `monospace` font measures `m` more than 1.5 times wider than `i` in a 2D canvas, so it is not fixed-width. Every platform maps `monospace` to a fixed-width font; Camoufox doesn't when it claims another operating system than its host. Unknown without a 2D canvas. |
| `engineApiMismatch` | `navigator.userAgentData` exists but is not a `NavigatorUAData`, as when script builds it; or the user agent claims Chrome 120 or later and `CompressionStream`, `Navigation` or `Highlight` is missing, though Chrome shipped all three by version 105. Engines that imitate Chrome, such as Obscura, do this. |
| `protocolScript` | Only after [`watch()`](#watching-the-page). Code compiled by a debugging protocol called one of the trapped DOM methods: CDP `Runtime.evaluate` in Chromium (nodriver, zendriver, pydoll, Playwright and Selenium in the page's own world), Puppeteer's named scripts, ChromeDriver's helper, or Firefox's Debugger API (Playwright, Camoufox and WebDriver BiDi in the page's world). Typing in the DevTools console counts too. Code in an isolated world, Patchright's and Camoufox's default, is not seen. Null without `watch()` and in WebKit. |

The standalone `collectAutomation()` returns `null` for the three `collect()`-only
observations, which need async or GPU-probe results. The worker probe needs
`worker-src blob:` in a strict CSP; a blocked worker is `null` (unknown) and logs
a CSP violation. `cdpDetected` also fires with DevTools open, and real users with
user-agent switchers, in-app browsers that rewrite the user agent or unusual setups
can trip several probes, including `engineMismatch` and `userAgentDataMismatch`.
Treat each as an indicator, not proof.

Each observation is `boolean | null`. Missing/non-boolean WebDriver values,
empty/non-string user agents and throwing reads return null independently.
Artifact checks inspect property presence without invoking getters or functions.
The automation collector makes no network requests, writes no storage and returns no
raw UA or artifact values.

These are client-reported, forgeable indicators, not a malicious-bot verdict.
Hidden automation can evade them; applications can also define matching names.
An observed false means only that this specific marker was absent. It does not
prove human activity. The [API](../api/README.md#automation-indicators) evaluates
the observations with versioned rules and preserves unknowns.

### Tampering observations

`collect()` also returns `tampering`: `{ version: 1, canvasReadbackAltered,
audioRenderAltered }`, each `boolean | null`. It draws a fixed 16x16 canvas of flat
colors and renders a constant 0.5 audio signal offline, and flags a result that does
not read back exactly. Clean browsers read both exactly, while noise injection and
resist-fingerprinting modes do not. This is common among privacy-conscious people:
it is not an automation signal and the SDK adds no verdict. The probes never affect
the identity hashes, make no network requests and return no pixel or sample data. The
[API](../api/README.md#tampering-indicators) evaluates it.

### Spoofing evidence

`collect()` also returns `spoofing`: `{ version: 1, userAgent, language, clientHints }`,
read from `navigator.userAgent`, `navigator.language` and the low-entropy
`navigator.userAgentData` (`{ brands, mobile, platform }`, null outside Chromium).
These are the values the browser already sends as `User-Agent`, `Accept-Language` and
`Sec-CH-UA*` headers, so they are kept as read, not hashed, and never affect the
identity hashes. Unreadable or oversized values are null. The API compares them with
the headers and TLS handshake of the request that posted them and reports
[`spoofing`](../api/README.md#spoofing-indicators). `collectSpoofing()` returns the same
object synchronously.

### Watching the page

`collect()` sees one moment. `watch()` keeps observing until the page unloads, and
every later `identify()` (or `collect()`) reports what it saw. Call it as early as possible, ideally from
a script in `<head>`, and collect at the protected action (signup or login submit):

```js
import { identify, watch } from '@openfingerprint/sdk';

watch();
form.addEventListener('submit', async () => {
	const { identificationId } = await identify({ endpoint });
	// send identificationId with the form
});
```

It does two things, both network-free:

- **Traps** (`automation.protocolScript`). In Chromium and Firefox it wraps a few DOM
  methods scrapers use (`querySelector`, `querySelectorAll`, `getElementById`,
  `getElementsByClassName`, `getElementsByTagName`, `document.evaluate`, the
  `document.title`, `outerHTML` and `innerText` getters, and `HTMLElement.click`) and
  inspects the call stack of each call for code a debugging protocol compiled. The
  first hit removes every trap. Until then each trapped call costs a stack capture of
  about 2.5 µs. Page scripts without a URL (inserted inline scripts, `setTimeout`
  strings, `javascript:` links, `eval`), cross-origin scripts and extension scripts
  in the page's world are not flagged. Other scripts on the page can see that these
  methods are wrapped, and a fingerprinting or anti-tampering library running there
  may report it.
- **Input counts** (`result.behavior`, `null` without `watch()`), all since `watch()`:

| Field | Counts |
| --- | --- |
| `version` | Always `2`; deploy an API accepting behavior versions 1 and 2 first. |
| `watchedMs` | Milliseconds since `watch()`. |
| `pointerMoves` | Trusted mouse `pointermove` events. |
| `mouseClicks` | Trusted clicks with nonzero `detail`, a preceding mouse `pointerdown`, and no contradictory click pointer type. Keyboard activation, touch and pen are excluded. |
| `clicksWithoutMovement` | Mouse clicks whose press saved at most one trusted mouse `pointermove` since the previous trusted press (or watcher start). This counts events, not distance. |
| `centeredClicks` | Mouse clicks within ±1 CSS px on each axis of the clicked element's bounding-box centre, measured at click time; both box dimensions must exceed 4 px. |
| `keys` | Trusted key presses (repeats, IME composition and `keyCode` 229 excluded). |
| `instantKeys` | Keys released less than 5 ms after being pressed. |
| `insertedTexts` | `insertText` input with no key press before it, as CDP `Input.insertText` (Playwright's `fill`) produces. Dictation and some autofill do too. |
| `touches` | Trusted `touchstart` events. |
| `wheels` | Trusted `wheel` events. |
| `untrustedEvents` | Clicks, key, mouse and input events dispatched by script. Pages do this themselves, so this is context only. |

Every count is something real users can produce: keyboard-only use, autofill,
dictation, on-screen keyboards, or an identification at page load before any input.
The [API](../api/README.md#behavior-patterns) turns them into patterns, never into a
detection. Browser-marked `isTrusted` is not proof of human input: browser drivers
produce trusted events too. No pointer paths, raw coordinates, typed text or event
streams are retained or transmitted. Key-down timestamps are transiently held until
release to calculate `instantKeys`; only aggregates are reported.

Totals last for this module's page lifetime; another `watch()` does nothing, and neither
`collect()` nor `identify()` resets them. Each trusted `pointerdown` saves and resets only
the local movement interval, even for touch or pen. Movement after that press belongs to
the next interval, not the current click. Before the first press, the interval starts at
`watch()`. Evidence is copied at the end of asynchronous collection, just before
`identify()` posts it; input during collection is included, input during posting is not.

Version 2 fixes WebKit touch compatibility clicks labelled `mouse`: the preceding press
must also be mouse input. Version 1 could include those taps. The fields and behavior
rule meaning are unchanged; fingerprint hashes are unaffected. A watcher started
between press and click conservatively excludes that click without an observed mouse
press. No watcher means null evidence, not a zero-input observation.

Stationary repeats, double-clicks and starting `watch()` over a button can match the same
patterns as automation. Assistive tools that generate mouse input are indistinguishable
from other mouse input here; do not use these patterns to block signup/login. See the
[controlled click study](../evaluation/behavior.md) for checks, sample-size guidance and
known false positives/evasions.

### What the API reports about an identification

Besides the verdicts, `/v1/check` returns `replayed` (this identification was looked up
before) and `ageMs` (time since the listener stored it, by the API's clock). An
identification lives for an hour. Your backend can also compare the connection's IP
address with what it expects, rate-limit by IP and fingerprint, and treat the same
fingerprint across many new accounts as a signal. See the
[API guide](../api/README.md) for the full response.

### Cooperative batching

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

Result **schema 1**:

`identify()` resolves with `{ identificationId }`. `collect()` resolves with the
evidence it posts:

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
- `behavior`: input counts since [`watch()`](#watching-the-page), or `null`.
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

Hash domains (`stealth-agent:1`, `stealth-core:1`) and the optional marker
namespace (`stealth:`) intentionally retain their original `stealth` spelling.
Renaming the project must not silently change existing IDs or markers. Compare IDs
only within the same schema; any change to identity inputs requires versioning.

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
linking, disposable-email checks, network intelligence, signed evidence or automatic
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
