# Open domain data

`domains.json` is a versioned public-data snapshot, not visitor history. It includes
source revisions, retrieval/expiry times, license texts and license SHA-256 values.
It contains no email addresses, browser profiles, account associations or IP history.

## Sources and scope

| Source | License | Meaning |
| --- | --- | --- |
| [disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains) | CC0-1.0 | Community-listed disposable email domains. The upstream warns that entries can become outdated; a match is evidence, not device/user fraud proof. |
| [FakeFilter](https://github.com/7c/fakefilter) | BSD-3-Clause | Domains observed by monitored temporary-mail providers within the last 14 days. Older observations are not imported. |
| [is-a.dev](https://github.com/is-a-dev/register) | MIT | User registrations beneath `is-a.dev`; the apex is not a user subdomain. |
| [is-a.bot](https://github.com/free-domains/is-a.bot) | MIT | User registrations beneath `is-a.bot`; the apex is not a user subdomain. |
| `reviewed-free-subdomains.json` | CC0-1.0 | First-party factual curation, currently DuckDNS, with primary-provider evidence and an explicit review expiry. No vendor API results are used. |
| `reviewed-domain-disputes.json` | CC0-1.0 | Exact domains requiring review because first-party operator evidence conflicts with a blanket disposable classification. These return unknown/conflict, not clean or false. |
| [IANA RDAP bootstrap](https://data.iana.org/rdap/dns.json) (`rdap-dns.json`) | IANA registry data | Which registry answers RDAP queries for each TLD. Not a domain list: the API uses it only to route registration-date lookups. Refreshed by the weekly data workflow. |
| [Matomo referrer-spam-list](https://github.com/matomo-org/referrer-spam-list) | Public Domain declaration | Referrer-spam hostnames only. This is not an email-sending reputation database. |

The `spam` result always carries `scope: referrer_spam`. It must not be advertised
as comprehensive email spam, phishing or malware detection. Disposable and free
subdomain matches do not set spam. A free subdomain is not evidence of abuse.

Coverage is deliberately bounded: the free-subdomain data currently covers three
namespaces, not all DDNS/free-hosting services. MISP's dynamic-DNS list is not used:
it mixes provider types and deliberately retains retired domains. The Public
Suffix List establishes boundaries, not whether a provider is free.

StopForumSpam, Spamhaus and UserCheck data are not imported. Their access or
redistribution restrictions do not meet this snapshot's open-data requirement.
No scraping, API-key enrichment or bulk vendor-result copying is performed.

## Matching and corrections

The runtime uses complete DNS-label suffixes, never substring matching or naive
last-two-label extraction. A listed tenant is not promoted to its parent. Mozilla
PSL wildcard/exception and private-suffix boundaries protect registries/shared
hosting from broad disposable/spam matches. In particular, a public-suffix rule in
an upstream spam list cannot classify every domain below that suffix. That source
reports `public_suffix_excluded` rather than hiding the safety exclusion.

Free-subdomain namespaces match strict children only; their operator apex gets
`value: false, status: provider_domain`. A most-specific allowlist entry suppresses
broader matches from the same source. Operators may add reviewed `allowlist`
entries to a local snapshot; the current upstream disposable source does not
publish an allowlist. Conflicting fresh sources return null with `conflict`.

Reviewed disputes use a separate `disposable_review` source, primary-evidence links
and a content revision. Only the exact named domains are withheld; this is not a
suffix-wide exemption or a trusted-mailbox assertion. The source reports
`disputed`; the disposable fact becomes null with `conflict/review_required`.
An expired review remains pending with stale provenance instead of restoring a
potentially false accusation. Remove a pending record only after resolving the
evidence. An operator-maintained allowlist is a different, explicit policy choice.

Report upstream mistakes through the linked projects; do not turn unreviewed user
submissions into permanent global accusations.

An unlisted domain has `value: null, status: not_listed`, not `false` or a clean
verdict. Expired/future-dated evidence stays unknown. Source timestamps describe
retrieval and the source commit, not the last observation of every individual
entry. Refreshing a list does not prove that all its domains remain unchanged.

## Refresh without rebuilding an image

From a checkout, with Node 24+ and outgoing HTTPS access:

```sh
node api/update-domain-data.mjs --output /srv/openfingerprint/domains.json
```

The updater uses only fixed public GitHub sources. It resolves immutable revisions,
checks reviewed license hashes, bounds response sizes/timeouts, normalizes IDNs
with Node's IDNA implementation and rejects URLs/invalid hostnames. It replaces the
output atomically only after all inputs pass. A failed fetch or license change
keeps the previous file. Review license changes before updating the expected hash.

Fetched feeds expire after seven days. Run the updater daily from a separate
operator job or host; do not give the API Internet egress. FakeFilter additionally
requires a feed generated within three days, valid observation timestamps and
records last seen within 14 days at snapshot creation. Its seven-day snapshot
expiry bounds included observations to at most 21 days old while fresh. This is
provider-observation freshness, not proof of mailbox ownership or human identity.
A stale/malformed feed aborts the update without replacing the previous file.

First-party namespace curation and dispute reviews expire after 30 days. Their
review dates are **not** advanced by an automatic refresh. Re-review the primary
evidence before advancing them. Pending disputes continue to require review when
overdue; stale namespace curation cannot produce a positive free-subdomain verdict.

Mount the output read-only into the API and set `OPENFINGERPRINT_DOMAIN_DATA` to
its in-container path. The API checks the file every minute and swaps in a changed
snapshot only after it parses; a broken file is rejected and counted in metrics
while the last valid snapshot keeps serving until it expires. No restart or image
rebuild is needed. Do not replace this public cache with visitor storage, put
secrets in it, or grant the API Kubernetes access. Without an override, the API
uses its bundled snapshot, which has the same expiry policy and must also be
refreshed when stale.

In Kubernetes, `node api/update-domain-data.mjs --configmap <name>` publishes the
snapshot to a ConfigMap through the in-cluster API instead (the
`ghcr.io/mokto/openfingerprint-domain-updater` image runs exactly this). The
[chart](../chart/README.md) schedules it every six hours and mounts the ConfigMap
into the API. ConfigMaps hold at most 1 MiB; today's snapshot is about 230 KB.

The updater ignores any listing of a protected major mailbox or mail-infrastructure
domain (for example `gmail.com` or `google.com`), its subdomains and its parents,
and logs what it ignored. With MX inference, one such upstream mistake would accuse
every domain whose mail those providers route.

A weekly GitHub workflow proposes the refreshed bundled snapshot as a
`chore(data)` pull request with per-source changes, so release images and
self-hosters start from current data.

A missing/malformed override produces unknown domain results, never a silent
fallback to the bundled data. Browser verification remains available. `/health`
is still process liveness, not a guarantee of dataset freshness. The API has no
domain-authority score. MX hosts from its DNS lookup are matched against the same fresh disposable sources (`mx_listed`);
this covers new domains routed to listed providers, not providers absent from
every source.

## Checks

```sh
node api/test-domain-updater.mjs
pnpm api:check
```

These use local fixtures, with no feed download in CI. The HTTP check exercises
fresh, stale, invalid and missing snapshots and verifies that browser verification
and legacy `/v1/verify` still work. License texts stay in the source snapshot and
in the release image at `/usr/share/licenses/openfingerprint-api/domain-data.json`.
The application's MIT license does not override any source's terms. The BSD
copyright, redistribution conditions and no-endorsement clause are retained in
the snapshot and release image.

## Evaluating quality

Monitor-derived samples test ingestion coverage, not independent accuracy once the
same monitored source is integrated. Do not present a re-run of those examples as
a held-out benchmark. Mailbox/ISP catalogue labels are also proxies: an operator
may offer temporary inboxes or both persistent accounts and disposable aliases.
Confirm disagreements with first-party service documentation; neither anonymous
signup nor optional alias deletion establishes temporary mailbox lifetime. Keep
source-labelled, independently reviewed and unresolved cases separate.
