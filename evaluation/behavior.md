# Stationary mouse-click study

## Findings and smallest change

The existing `watch()` → `collect()`/`identify()` → stored identification → behavior
rules pipeline already collects both patterns. No duplicate detector is needed.
Controlled checks exposed one correctness defect: WebKit's touch compatibility click
reports `pointerType: "mouse"` after a touch press. Behavior evidence v2 requires the
preceding press to be mouse too. The API accepts v1 and v2; deploy that API before the
v2 SDK. That collection correction added no fields or identity inputs and changed no
automation verdicts or production settings. The pattern meanings remain unchanged;
behavior ruleVersion 2 later adds the separate context flag described below.

The other missing pieces were regression coverage and aggregate observability. Pattern
frequency is useful operational context, but is not detection accuracy.

## Exact collection and snapshot semantics

Source: [`sdk/src/watch.ts`](../sdk/src/watch.ts),
[`sdk/src/index.ts`](../sdk/src/index.ts),
[`api/src/identify.rs`](../api/src/identify.rs),
[`api/src/behavior.rs`](../api/src/behavior.rs).

- `pointerMoves` counts trusted mouse `pointermove` events, not pixels, path length,
  speed or distinct cursor positions. Browser drivers can generate trusted events.
- Every trusted `pointerdown` saves the number of mouse moves since the previous
  trusted press (or watcher start), resets that local interval to zero, and saves its
  pointer type. This applies to mouse, touch and pen presses.
- A trusted click with nonzero `detail`, a saved mouse press and no contradictory click
  pointer type increments `mouseClicks`. Keyboard activation (`detail: 0`), touch, pen
  and script-dispatched clicks are excluded. V1 let the click's type override the saved
  press type; v2 corrects that. Untrusted qualifying event types have their own count.
- `clicksWithoutMovement` increments when the saved pre-press interval contained 0 or 1
  move events. Movement between press and click does not change this click's saved
  count; it contributes to the next press's interval. One large jump qualifies;
  several tiny events do not.
- `centeredClicks` compares the click with the clicked element's bounding rectangle at
  click time: both dimensions must exceed 4 CSS px and each axis must be within 1 CSS px
  of the centre. It is not the ancestor button's centre when a child was clicked.
- These totals and `watchedMs` are cumulative for the module's page lifetime. Calling
  `watch()` again does nothing. Collecting or identifying never resets them. A reload
  starts a new module instance; no observations before `watch()` can be recovered.
- `collect()` copies the aggregates after its asynchronous probes and hashes finish.
  `identify()` then serializes that copy and posts it. Input during collection is
  included; input during posting is not. Later snapshots overlap earlier ones.
- Without a running watcher, evidence is null/omitted and `/v1/check` omits behavior.
  Missing evidence stays unknown. An observed snapshot with no input instead matches
  `no_input`. Malformed/unsupported evidence is rejected, not treated as clean.
- Both click patterns currently mean **at least one mouse click, all qualifying**.
  They do not change the independent automation verdict or the fingerprint.

## Reproduce

Use the repository's declared Node/pnpm versions and existing development dependencies:

```sh
pnpm install --frozen-lockfile
pnpm build
node sdk/test-behavior.mjs
pnpm api:check
```

`pnpm test` also runs the controlled browser checks. The test-only bundle exposes the
existing aggregate snapshot function; it does not add an SDK export or detector.
Local results, including browser versions and aggregates only, are written to
`.test-results/behavior.json`. No pointer paths or event streams are saved.

The initial controlled run used Chromium 158.0.8127.18, Firefox 159.0 and WebKit 27.2
on one host, headless. All ordinary-interaction controls are scripted reproductions,
**not a measured human cohort**. Browser input events were trusted. Actual Selenium
sessions, headed/real-device input and physical assistive technologies were not tested.
Chromium protocol dispatch exercises a no-movement driver-style press/release sequence,
not the Selenium client or ChromeDriver implementation.

| Controlled case | Mouse clicks / low-movement / centred | Interpretation |
| --- | --- | --- |
| Playwright element clicks, all three engines | 10 / 10 / 10 | Both patterns match. |
| Direct Chromium protocol press/release, no pointer moves | 10 / 10 / 10 | Both patterns match with trusted input. |
| Automation with multi-event movement, still centred | 10 / 0 / 10 | Movement alone evades only the low-movement pattern. |
| Automation with multi-event movement and off-centre clicks | 10 / 0 / 0 | Known evasion of both patterns. |
| Ordinary multi-event movement then off-centre click | 1 / 0 / 0 | Neither pattern matches. |
| Same interaction followed by nine stationary repeats | 10 / 9 / 0 | Existing all-click rule does not match despite 90% stationary. |
| Watcher starts with cursor over button centre | 1 / 1 / 1 | Both match an ordinary first click. |
| Same cursor, followed by a double-click | 3 / 3 / 3 | Ordinary double-click adds two, not one. |
| Stationary ordinary-interaction control, centred | 10 / 10 / 10 | Identical click aggregates to automation. |
| One large jump, off-centre click | 1 / 1 / 0 | Event count is not distance. |
| Eight subpixel move steps, off-centre click | 1 / 0 / 0 | Tiny distance still avoids the low-movement pattern. |
| Keyboard Enter/Space; script activation | 0 / 0 / 0 | No mouse-pattern evidence. |
| Touch tap | 0 / 0 / 0 in v2 | V1 miscounted this as 1 / 1 / 1 in WebKit. |
| Keyboard and touch after a mouse click | No added mouse clicks | Stale mouse state must not classify these activations. |
| Identification before interaction | 0 / 0 / 0 | Observed `no_input`, not an automation finding. |
| Identification without a watcher | Missing | Unknown, not zero-input or a negative detection. |

Regression checks also pin interval resets, repeated `watch()` calls, collection-end
snapshot timing, frozen posted evidence and both API evidence versions.

## Threshold and minimum-sample recommendation

**No automation decision threshold is supported by these results.** Even 10/10
low-movement and centred clicks overlap perfectly between the driver and the stationary
ordinary-interaction control. Raising the count cannot resolve that ambiguity; lowering
the ratio from 100% to 90% admits the normal movement-then-repeat control too.

Keep the existing 100%, n≥1 rules as descriptive observations for compatibility, never
proof of automation. For an aggregate **repeated-click review slice**, use **n≥3 and
100% qualifying clicks**, separately for each existing pattern: n=1 is an isolated
click and n=2 can be a double-click. This is a sample-size filter for context, not a
calibrated detector. Inspect 3–4, 5–9 and 10+ separately rather than claiming higher
counts make the pattern accurate. The original patterns retain their thresholds; the
new context flag below requires at least three clicks and both patterns.

A production accuracy claim requires consented, independently labelled human and
automation cohorts, varied pages/devices and assistive input, with per-cohort false
positives and evasions measured. These deterministic fixtures cannot estimate a
population false-positive rate, precision or recall. Assistive tools producing mouse
press/click sequences remain indistinguishable from other mouse input. Never turn
these observations into automatic bot verdicts or signup/login blocking rules.

## Separate suspicious-click context flag

After this study, the API adds `suspiciousClickPattern` as **context, not an automation
verdict**, under behavior `ruleVersion: 2`. It reuses both existing patterns: v2 evidence,
at least 3 mouse clicks, all low-movement and all centred means true. A sufficient v2
sample not matching both means false. Missing evidence, fewer than 3 mouse clicks and
legacy v1 evidence mean unknown; v1 is not reliable enough because of the touch bug.

This is a minimum-sample convention, not a detection threshold justified by human
accuracy measurements. It deliberately still describes ordinary stationary controls as
suspicious; it must not be read as proof of automation. The existing patterns, automation
verdict, collector, evidence schema and fingerprint inputs do not change.

Compact REST/RPC responses expose the flag only when known; REST detail includes a
nullable `identification.behavior.suspiciousClickPattern` when behavior is present.
See the [API contract](../api/README.md#suspicious-click-pattern) for presence rules and
RPC compatibility. Runnable API checks cover the sample boundary, both patterns,
non-mouse input, legacy/missing evidence, true/false/unknown transport parity, unchanged
automation/identity and once-per-store metrics.

## Aggregate observability

Three bounded-label counter families use only existing evidence:

- `openfingerprint_behavior_observations_total{evidence,mouse_clicks}` is the denominator:
  one increment after each successful identification store. Evidence is `missing`,
  `v1` or `v2`. Sample buckets are `unknown` for missing, otherwise `0`, `1`, `2`, `3_4`,
  `5_9`, `10_plus`. Unknown is deliberately separate from zero.
- `openfingerprint_behavior_patterns_total{evidence,mouse_clicks,pattern}` increments
  for each of the five existing descriptive patterns in that stored snapshot.
  Multiple patterns can match one snapshot. Keep v1 separate because of the touch bug.
- `openfingerprint_suspicious_click_patterns_total{result}` counts the new context flag
  as `true`, `false` or `unknown`, once per successful store. The eligible denominator
  is true plus false snapshots; unknown is not a negative. This is not an accuracy
  metric, and repeated check evaluations do not increment it.

Repeated REST/Connect/gRPC checks never increment these counters. Rejected evidence and
failed stores do not count as observations. Multiple posts from one page still count
separately and can contain overlapping cumulative events: these are snapshots, not
unique visitors or independent click samples. No visitor IDs, IPs or arbitrary strings
are labels. No new transmitted counters, raw coordinates, paths, text or streams.

For example, the fraction of v2 snapshots with at least three mouse clicks that match
`clicks_without_movement`, over an hour:

```promql
sum(increase(openfingerprint_behavior_patterns_total{evidence="v2",mouse_clicks=~"3_4|5_9|10_plus",pattern="clicks_without_movement"}[1h]))
/
sum(increase(openfingerprint_behavior_observations_total{evidence="v2",mouse_clicks=~"3_4|5_9|10_plus"}[1h]))
```

A zero denominator means no eligible observations, not a 0% match rate. This ratio is
pattern prevalence within submitted snapshots, **not bot prevalence or accuracy**.
