---
name: stealth-detection-review
description: Review open-source bot-detection projects (CreepJS, BotD, rebrowser-bot-detector), anti-detect browsers (Camoufox and its competitors such as Clearcote, CloakBrowser and Obscura) and stealth drivers (Patchright, nodriver, zendriver, puppeteer-extra-plugin-stealth, SeleniumBase UC) for techniques the SDK automation probes miss, run the built SDK against those stealth tools, and open a PR with precise new probes. Use for the weekly stealth review, or when asked to compare OpenFingerprint's automation detection with other projects or test it against stealth browsers.
---

# Stealth detection review

The goal is a PR that makes `sdk/src/automation.ts` (and its API rules in
`api/src/automation.rs`) detect more automation without flagging real visitors,
backed by a before/after run of the stealth harness. When nothing passes the bar
below, skip the PR and only report.

## Steps

1. Work on a fresh branch from `origin/main`. When the checkout has another branch
   or uncommitted changes, create a worktree for the new branch instead of
   switching.
2. Run `pnpm install --frozen-lockfile` and `pnpm build`.
3. Run the harness from the repo root, once as is and once with `--headed`, and keep
   both outputs for the PR:
   `node .agents/skills/stealth-detection-review/scripts/harness.mjs`.
   It updates each tool to its latest release and opens a local page that calls
   `watch()`. Each tool then reads `document.title` through its default evaluate
   API, as a scraper would. The harness prints which automation and tampering
   fields the page's `collect()` returned as `true` or `null`. Headed runs matter most: headless leaks hide every other gap.
   A full run takes about 15 minutes; `--only camoufox,clearcote` limits it. Compare
   with the newest earlier files in `~/.cache/openfingerprint-stealth/results/`: a
   tool that was detected last time and is not now is the most important finding.
   A tool detected by nothing is the next target.
4. Look for anti-detect browsers and stealth drivers that aren't in
   [references/sources.md](references/sources.md) yet: search the web and GitHub for
   Camoufox alternatives and new or fast-rising stealth automation projects. Add
   each one you find to `sources.md`, and add a driver to `scripts/harness.mjs` when
   it can be installed and launched from a script. Commit those changes in the PR.
5. Review the projects in [references/sources.md](references/sources.md). Clone or
   fetch each into `~/.cache/openfingerprint-stealth/repos/`, and read what changed
   since the commit recorded in `~/.cache/openfingerprint-stealth/reviewed.json`
   (`{"owner/repo": "sha"}`); for a repo with no entry, read its detection or
   evasion code. For an evasion tool, look for what it patches and how that patch
   could show. For a detector, look for checks the SDK lacks.
6. For each candidate check, decide with the bar in [Precision bar](#precision-bar),
   then prototype it in the page of a Playwright Chromium, Firefox and WebKit run
   before writing SDK code.
7. Implement the checks that pass. New fields, and changed meanings of existing
   fields, need a new automation evidence version in both the SDK and
   `api/src/automation.rs` (follow how `V5` was added). Add assertions in
   `sdk/test.mjs` (clean page false, simulated patch true, unreadable input null)
   and Rust unit tests, and update the field tables in `sdk/README.md` and
   `api/README.md`.
8. Run the checks for the areas you changed from the
   [Verification](../../../AGENTS.md#verification) table, then rerun the harness
   with the new build.
9. Open the PR with `create_pr`, giving it the before/after harness lines, the
   sources each check came from and the checks you rejected with the reason.
10. Write the head commit SHA of every repo you reviewed to `reviewed.json`, even
   when no PR came out of it, and end with a short report: harness lines, PR link
   or "no change", and rejected ideas.

## Precision bar

- One `true` automation observation makes the API verdict `detected`, so a check
  must never fire in a real browser on a real device: not with DevTools closed, an
  error monitor installed, a privacy extension, a user-agent switcher or a
  background tab. Return `null` when the check can't tell.
- Put signals that privacy tools also produce (canvas, audio or WebGL noise) in
  `sdk/src/tampering.ts`, not in automation.
- Prefer checks on behavior the tool must change (a native function that is a
  `Proxy`, an engine that contradicts the user agent) over name lists a tool can
  rename.
- Keep existing probes even when a tool evades them: they still catch the tools
  that don't.
- Reimplement ideas; don't copy code. Several sources are GPL or AGPL, and the
  SDK is MIT.

## Harness rules

- Point the tools only at the harness's local page: the run must not send
  automation traffic to third-party sites.
- When a tool fails to start or never reports, spend at most one attempt fixing
  its driver code in `scripts/harness.mjs` (check the tool's open issues for the
  current Chrome or Firefox), then report it as broken this week.
- Before proposing a check aimed at a tool, add or keep that tool in the harness
  so the PR shows it firing.
