# Agent instructions

## Finish with a pull request

- After completing changes and the applicable checks, create or update a pull request before handing off; do not leave completed work only in a local worktree.
- For large or UI-affecting changes, let the user test locally and wait for their request before opening the PR. Skip PR creation for read-only tasks or when the user explicitly declines one.
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
