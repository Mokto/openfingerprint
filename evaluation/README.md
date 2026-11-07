# Identification measurement

Offline tools for a **consented, independently labelled study**, not a visitor database,
tracking endpoint or population-accuracy claim. SDK hashes and collection behavior are
unchanged. The tools have no runtime dependencies beyond Node 24; the browser recorder
uses an explicitly supplied SDK collector and never uploads, persists or collects on import.

## Establish ground truth first

- Enrol actual physical devices, including multiple devices of the same model. Include
  shipping Safari on iPhones, Android browsers and desktops; Playwright WebKit is not Safari.
- Assign a random device UUID per physical device and a separate random browser UUID per
  browser installation/profile. Reuse the device label across browsers on the same device.
  Private visits retain their parent browser label; a different regular profile gets a new
  browser label. Labels come from the operator, **never** an account ID, fingerprint, cookie, IP or SDK
  `storageId`. This measures same-browser returns, not cross-browser recognition.
- Record consent and the physical inventory independently. A `consent: true` flag and a
  `real_device` label are assertions, not proof of consent, hardware or honest execution.
- Pre-register devices, visit rounds, conditions and exclusions before inspecting results.
  Keep the SDK bundle/build, collection defaults and origin fixed across the study. Record
  the SDK version and Git revision in the private lab notes. Use a separate study for a
  different bundle/schema; browser/OS updates do not require changing the SDK build.
- Keep the participant-to-label inventory separately with restricted access. Set a retention
  deadline and withdrawal process before collection. Remove withdrawn participants and their
  samples together, documenting the exclusion rather than silently hiding failed returns.

A pilot can reveal defects; it cannot establish a population accuracy percentage. Recruit
beyond one household, workplace or hardware model before generalizing.

## Create a study

From the repository root:

```sh
pnpm install --frozen-lockfile
pnpm build
umask 077
node --input-type=module <<'JS'
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
const directory = '.test-results/identification';
await mkdir(directory, { recursive: true });
const plan = {
  format: 1, study: randomUUID(), schema: 1,
  build: createHash('sha256').update(await readFile('sdk/dist/index.js')).digest('hex'),
  targets: [
    { browser: randomUUID(), device: randomUUID(), cohort: 'real_device', platform: 'ios', family: 'safari', deviceClass: 'phone' },
    { browser: randomUUID(), device: randomUUID(), cohort: 'real_device', platform: 'android', family: 'chrome', deviceClass: 'phone' }
  ],
  rounds: [
    { id: 1, day: 0, condition: 'baseline' },
    { id: 2, day: 0, condition: 'reload' },
    { id: 3, day: 0, condition: 'restart' },
    { id: 4, day: 0, condition: 'private' },
    { id: 5, day: 1, condition: 'return' },
    { id: 6, day: 7, condition: 'return' },
    { id: 7, day: 30, condition: 'return' }
  ]
};
await writeFile(`${directory}/plan.json`, JSON.stringify(plan, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
await writeFile(`${directory}/samples.jsonl`, '', { flag: 'wx', mode: 0o600 });
JS
```

**Edit the target list to match your enrolled devices before running this example.** These
example targets are not measurements. To add another browser on the same device, reuse
that device UUID. Do not regenerate labels on return visits or overwrite an existing plan.
`day` describes the schedule, not evidence that a visit happened on time. Plan dedicated
`browser_update`, `os_update` or `settings_change` rounds/subcohorts if investigating those
changes. Do not label unchanged environments as updated.

Use an encrypted, access-controlled, non-public directory for real study data. The example
`.test-results/` location is Git-ignored, not encrypted or exempt from backups. Never put
samples, the inventory or IDs in Git, issue attachments, application logs or public CI artifacts.
Hashes and labels remain pseudonymous data. These tools do not enforce deletion or provide
an upload service; approve any transfer/hosting infrastructure separately.

## Record one scheduled attempt

Serve **only** the pinned `sdk/dist/index.js` and `evaluation/record.mjs` as `sdk.js` and
`record.mjs` on your approved HTTPS study origin. Never publish the repository, `.git`,
private plan or sample files. Desktop loopback is also a secure context; plain HTTP on a
LAN address is not sufficient for phone collection. Do not change production integration.

After consent, use that device's browser console/Web Inspector, substituting the operator's
study, build, browser label and round from the private plan:

```js
const { collect } = await import('/study/sdk.js');
const { capture } = await import('/study/record.mjs');
const sample = await capture({
  study: '<study UUID>', build: '<SDK bundle SHA-256>',
  browser: '<externally assigned browser UUID>', round: 1, consent: true
}, collect);
const line = JSON.stringify(sample);
```

Transfer `line` through the approved study process and append the JSON object, one per line,
to `samples.jsonl`. Do not include console quote wrappers. No submission happens automatically.
The operator must verify the served bundle against the plan; a browser-supplied build label
is not an integrity check. No `storageKey` is used, and the recorder does not retain raw probes,
component/hint hashes, user agents, automation observations or storage identifiers.

Record **failed attempts and null IDs**; do not retry until successful or replace a bad sample.
Extra trials require pre-planned rounds. Duplicate browser/round records are rejected rather
than cherry-picked. Client timestamps are descriptive, not attested time or ordering: rounds
come from the external schedule. Capture exceptions/invalid SDK results produce a `failed`
record with null identities and no exception details.

## Analyze completed rounds

```sh
umask 077
pnpm --silent accuracy --plan .test-results/identification/plan.json \
  --samples .test-results/identification/samples.jsonl --through-round 1 \
  > .test-results/identification/report.json
```

Advance `--through-round` only after that wave closes; future rounds are not counted as
missing. `client_elapsed_days` shows the observed client-reported follow-up span
and clock regressions separately from the planned `day`; it is not attested time.
Output contains aggregate counts only, partitioned by `real_device`/`synthetic`
and platform/browser/device-class strata. It never combines synthetic observations into
real-device metrics or prints device/browser labels or fingerprint values.

Full and core identities are evaluated **separately**, without fallback, learned aliases or
account merging:

| Metric | Definition |
| --- | --- |
| False merges | Distinct pairs of physical devices sharing at least one non-null exact ID anywhere in the included history, divided by device pairs with IDs. Each device pair counts once, even after many repeated collisions. Same-device browser collisions are not false physical-device merges. This is potential exact-lookup confusion, not traffic-weighted classifier precision. |
| Pair coverage | Device pairs with IDs divided by all enrolled physical-device pairs. Missing devices cannot appear clean. |
| Missed returns | Recorded follow-up attempts not matching that browser's **round-1 baseline**, divided by recorded follow-ups. Null/missing baseline IDs, null current IDs and failed captures are misses, never null-to-null matches. |
| Hash churn | Different IDs divided by return comparisons where both IDs exist. Missingness is excluded here but remains visible in missed returns. |
| Planned match coverage | Matched returns divided by planned follow-ups. This exposes attendance/collection gaps; it is not identification accuracy. |
| Missing evidence | Unrecorded/failed samples and missing IDs, plus probe unavailability split into identity evidence and excluded diagnostics. |

Zero denominators produce `null`, not perfect accuracy. An empty file produces no measured
rates. Global collision pairs consider history, not just simultaneous visits. Strata may
share physical devices and are not additive. Counts from repeated visits/device pairs are
correlated: no binomial confidence interval or population guarantee is emitted. Composition,
privacy settings, mode changes, browser versions and non-returning participants can bias rates.
A real result needs an audited cohort, actual follow-up time and an appropriate sampling plan.

Plans are bounded to 500 browser targets and 32 rounds, with consecutive round IDs, random
UUID labels, schema 1 and one bundle digest. CLI files are limited to 1 MiB for the plan and
32 MiB for JSONL, with 8 KiB records. Mixed builds/studies, unknown labels, invalid fields and
duplicates fail the report without echoing private values.

## Runnable checks

```sh
node evaluation/test.mjs
pnpm build
node evaluation/test-browser.mjs
```

The unit check uses fabricated identities to verify metric arithmetic and privacy boundaries.
The browser check runs real SDK collection in Chromium, Firefox and WebKit on **one automated
host**, two visits each, blocks external requests and writes only an aggregate synthetic
report to `.test-results/identification/smoke-report.json`. It tests the measurement pipeline,
not physical-device accuracy; it reports **zero real-device observations**. Both run in CI.
