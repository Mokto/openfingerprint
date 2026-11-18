# GPU-drift investigation — on hold

`gpu-v1` remains an experimental proposal. Do not merge, migrate or deploy it on
this evidence. A unique stored candidate is not proof of the same browser or
physical device. The independently labelled synthetic visitor fixture deliberately
shows additional false merges when GPU differences are ignored; those fabricated
pairs are not measurements from this lab.

## Reproduce the local measurement

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --dir sdk exec playwright-core install chromium firefox webkit
node evaluation/test-gpu-drift.mjs
```

The script uses the built SDK, not a replacement collector. It binds to loopback,
blocks external browser requests and never calls `identify()` or the API. No
production rule, evidence, timeout or browser integration changes. The aggregate
report goes to Git-ignored `.test-results/identification/gpu-drift.json`; component
and hint hashes stay in process memory. No renderer strings, participant labels or
visitor IDs are written or uploaded.

All attempts use one automated host and are classified as **synthetic**. Each case
launches a fresh browser process and collects three times in fresh documents.
Viewport 1440×900, DPR 1, `en-US`, timezone `Europe/Copenhagen` and the origin stay
fixed. Collection uses the SDK's default two-second cooperative budget.

The first baseline attempt per engine is the fixed reference, even if it fails.
The reference itself is not a return comparison. Failures and null identities stay
in the attempt count; no successful retry replaces them. The comparison requires
schema 1, a full fingerprint, all six components and ten hints, no exclusions and
no unavailable identity probe. It is a counterfactual equality check, not API
replay or a reimplementation of canonical evidence verification.

The native fault uses `WEBGL_lose_context` immediately after obtaining the GPU
probe's context. Instrumented cases count lost-context/null reads without changing
read results. Normal context disposal after the probe is not a lost-context read.
The baseline is uninstrumented. Fresh-process cases compare instrumented collection
with it; this is not an isolated instrumentation control. Chromium additionally runs
with explicit SwiftShader, Metal on macOS, and 6× CPU throttling. Launch flags are
controlled interventions, not evidence of a production browser's configuration.

## Recorded run: 2026-11-18

Locally built SDK **0.13.1**, with SDK source unchanged from `sdk-v0.13.1`.
Bundle SHA-256:
`2ab78a2884ca2a0bd89ceb15aa9e130d5ab09740fc0ffa6321eb9b77bacbc736`.
One macOS host; Chromium 158.0.8127.18, Firefox 159.0 and Playwright WebKit 27.2.
Playwright WebKit is not shipping Safari.

| Intervention | Attempts | Observation |
| --- | ---: | --- |
| Baseline and fresh process, all three engines | 18 | All fingerprints present. Chromium/Firefox's ten eligible return comparisons kept all 16 hashes unchanged. WebKit's exclusion policy is outside `gpu-v1`. |
| Chromium at 6× CPU | 3 | All 16 hashes unchanged from its fixed baseline. This is not a deadline guarantee. |
| Chromium explicit SwiftShader and Metal | 6 | Only the GPU hash changed; all other 15 hashes matched the fixed baseline. No lost-context or null GPU reads were observed. |
| Native context loss, all three engines | 9 | Every attempt still included a GPU hash and a full fingerprint despite reading a lost context. Six Chromium/Firefox attempts would satisfy the proposed non-GPU equality predicate; WebKit remains ineligible. |

All **36** attempts returned a fingerprint in this run; the nine invalid GPU reads
are a collector defect, not successful collection. There were **zero external
requests**. GPU hashes were stable within each three-attempt case.

This adds evidence that a controlled backend change on one host can produce
GPU-only variation. It does **not** identify the cause of a production split.
It also reproduces why validating GPU reads is separate from, and should precede,
relaxing identity matching. This branch does not implement that collector fix.

There are **zero independent different-device pairs**. The false-merge rate is
therefore **unknown (`null`)**, not zero. Neither 36 attempts nor multiple engines
turn one host into a physical-device collision cohort.

## What data is still needed

A consented, independently inventoried cohort must include actual separate
physical devices with similar configurations: same model where possible, OS,
browser version, fonts, screen settings and locale. Keep device labels separate
from browser/profile labels, following the [study guide](README.md). Pro IDs,
accounts, IPs and sessions cannot supply ground truth.

Pre-register unchanged returns, fresh processes and controlled graphics/settings
changes. Compare against immutable baselines, retain failed attempts, and evaluate
both cross-device collisions and within-browser missed returns. Include conflicts
between the locale and GPU rules, not only GPU-only matches. A two-device pilot can
find a counterexample; it cannot establish population accuracy.

The existing study recorder retains exact full/core identities, not the fifteen
probe hashes or a GPU-excluded signature. Its report alone cannot evaluate this
proposal. Any additional study datum or transfer process needs an explicit,
private, consented design; do not repurpose the core identity, add automatic
production logging or publish participant samples. More raw production fields
would not supply the missing independent labels.
