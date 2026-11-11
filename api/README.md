# Experimental Rust check API

Documentation: [openfingerprint.com/docs/api](https://openfingerprint.com/docs/api)

A self-hosted, MIT-licensed backend companion to the browser SDK. The next release
provides stateless `POST /v1/check` with independent browser, automation, domain
and IP sections.

**The API has no authentication.** It is meant to sit on a private network behind
your own backend, gateway or NetworkPolicy; see [Security](#security) before exposing it.

Domain and country intelligence run locally against openly licensed datasets:

| Requested check | Available behavior |
| --- | --- |
| `signals` | Schema-1 verification of the SDK's opaque `token`, with a 21-character fingerprint, whether the same evidence was checked before (`replayed`) and the token's age. |
| `automation` | Versioned rules for client-reported observations, now included automatically inside SDK `signals`. |
| `domain` | Disposable, free-subdomain, public-mailbox, email-relay and source-scoped referrer-spam evidence with provenance and expiry, typo suggestions, MX providers, registration dates and SPF/DMARC status. |
| `email` | Role-account detection for a full address, plus every `domain` check for the address's domain. |
| `ip` | Local country estimate plus independent Tor-exit, ASN and published cloud-range evidence under `network`, with source provenance and expiry. Missing facts remain unknown. |

The domain snapshot is bundled and can be overridden with a refreshed local file.
A valid input does not mean a domain is legitimate or an IP is clean. Unlisted or
uncovered domains remain null, not false. The API looks up MX hosts to detect
mail routed to a listed disposable provider, and reports when the registered
domain was created, from its registry over RDAP.
VPN/proxy classification and domain authority are not implemented. The spam scope is specifically **referrer spam**,
not email-sending reputation. See [sources, licenses and refresh](data/README.md). Older API releases, including 0.4.0, have a different
`/v1/check` contract; this guide describes the next release, not a live upgrade.

The API does not execute browser probes, recognize physical devices, execute
signup decisions or provide Fingerprint Pro feature parity. Probe values can be
forged, and matching hashes can collide or change with settings and updates.

## Data minimization and networking

Stateless checks have no visitor database, observation cache or account history.
Their evidence, email addresses, domains and IPs are dropped after processing; an
email address is never logged, cached, echoed or used as a metric label.
Redis holds three kinds of key, all with a TTL: cached RDAP answers keyed by SHA-256
hashes of registered domains, token replay markers keyed by a SHA-256 hash of the
token's content (see [Replayed tokens](#replayed-tokens-and-token-age)), and
[nonces](#post-v1nonce) keyed by a SHA-256 hash of the nonce, holding only `issued` or
`used`. None stores a fingerprint, account, address or IP. Request evidence is not logged.
Outbound traffic consists of MX DNS queries, at most one RDAP
request to the domain's registry per uncached check, Redis commands and, only when
`SENTRY_DSN` is set, error reports to Sentry.
Country and network lookups use local datasets only. Their separate updaters
download public datasets without receiving checked IPs or application credentials.
Responses have `Cache-Control: no-store` and set no cookies. Domain/IP inputs are
not echoed in responses. Checks never infer an IP from the connection or forwarded headers:
only an `ip` your backend passes is evaluated. Signals-only calls do not run domain/IP checks.

The process retains read-only domain/country/network datasets; the RDAP cache and
replay markers are shared in Redis, not an in-memory fallback. There is no visitor
history. The API does no rate limiting: apply quotas and request limits at your
edge/gateway.

A separate operator updater refreshes public snapshots without rebuilding the
image; the API re-reads an override file every minute and swaps in a changed
snapshot only if it is valid.

Every domain check except a bare public suffix (`co.uk`) sends one UDP MX query and
up to three TXT queries (SPF at the domain, DMARC at `_dmarc.<domain>` and, for
subdomains, at `_dmarc.<organisational domain>`) to one nameserver, all at once: a
random transaction ID, resent once after a second without an answer, a two-second
limit (the registry lookup that runs alongside has the same budget) and no cache in
the API. A truncated answer is asked again over TCP; about a fifth of large
organisations publish more TXT data than fits in UDP. The nameserver sees the
domains you check; use a resolver you trust, such as the cluster DNS, and allow only
it on UDP and TCP 53. Without DNS access, lookups report `unavailable` and everything
else works.

Every valid domain check also asks the registry for the creation date of the
registered domain under its ICANN public suffix (`mail.example.co.uk` queries
`example.co.uk`). The registry comes from the IANA RDAP bootstrap bundled in the
image (`data/rdap-dns.json`, refreshed weekly): one HTTPS GET, a two-second limit,
a 256 KiB response cap and no retries. A redirect is followed once, only to HTTPS on
a host name with the same `/domain/<name>` path (registries such as `.ua` refer to a
sub-registry). For TLDs without RDAP (`.io`, `.me`, `.us`, `.it`, `.ru` and about 150
more), the API sends one plain WHOIS query on TCP 43 to the TLD's WHOIS server from
IANA (`data/whois-servers.json`, refreshed weekly), with the same time limit and a
64 KiB cap. WHOIS is free text: a date counts only from a known creation field in an
unambiguous format, recorded at day precision, and an answer it cannot classify
(including rate-limit notices) is `unavailable`. Some registries publish no
creation date (DENIC for `.de`, EURid for `.eu`): those answer `no_date`. At most
four RDAP and two WHOIS requests run at once per server; others wait inside the
same two-second budget, because bursts get throttled. The registry sees the
registered domains you check, and its terms of use apply. Answers are cached in Redis for a day (an hour for `not_found`)
under `openfingerprint:rdap:v2:<SHA-256 of the registered domain>`; unavailable
answers are not cached. Version 2 ignores older cached dates that may have been
normalized from invalid calendar dates or timezone offsets; old keys expire
without flushing Redis. A slow or failing Redis (250 ms limit) only means asking the
registry. The cache holds public registry dates, not who asked. Tenants of private namespaces (`name.github.io`, a
listed free-subdomain service) are not looked up: their registered domain belongs
to the namespace operator. The API needs HTTPS and TCP 43 to public addresses for
this; without them, results report `unavailable`.
There are no lookup retries, remote-provider waits or visitor-history fallbacks.

The SDK hashes identity signals locally and automatically includes bounded
automation evidence outside those hashes. `collect()` has no networking: your
backend sends the token. It writes no storage unless `collect()` opts into
`storageKey`. Leave that option unset when sending results here. Hashes are pseudonymous, not anonymous. Your
application and hosting proxy have their own logging, retention, disclosure and
access-control responsibilities.

## Configuration

Provide secrets privately at runtime. Never put them in Git, browser code, image
build arguments, command-line arguments or logs.

| Variable | Meaning |
| --- | --- |
| `OPENFINGERPRINT_SITES` | No longer used. The API has no credentials; if the variable is set it is ignored and the API logs one warning at startup, so old deployments keep starting. |
| `OPENFINGERPRINT_LISTEN_ADDR` | Optional listener, default `127.0.0.1:8180`. |
| `OPENFINGERPRINT_NETWORK_DATA` | Optional network manifest path. Keep its content-addressed ASN files in the same directory. No bundled/live fallback; absent/invalid data is unknown. Checked every 60 seconds; invalid replacements retain last-good data without extending expiry. |
| `OPENFINGERPRINT_REDIS_URL` | Required private Redis/Valkey connection URL (Redis 7 or later for nonces) for the RDAP cache, token replay markers and nonces; the API does not start without it. Supports `rediss://` with certificate validation. An unreachable Redis means uncached RDAP lookups, no `replayed` or `nonce` answer and HTTP 503 from `/v1/nonce`; checks keep working and there is no memory fallback. Each pod keeps one multiplexed connection each for the RDAP cache, replay markers and nonces, replaced after any error, timeout or 60 s of idleness; commands are never retried. RDAP cache writes happen after the response (at most 64 in flight; extra writes are dropped and counted as cache errors). |
| `OPENFINGERPRINT_REDIS_PASSWORD` | Optional Redis password, overriding one in the URL, so the URL can live outside a Secret. |
| `OPENFINGERPRINT_REQUIRE_NONCE` | `true` or `false` (default). With `true`, a checked token without a [nonce](#post-v1nonce) counts as `spoofing` (`nonce_invalid`, nonce status `missing`). Enable it only once every page that collects a token gets a nonce. Any other value stops startup. |
| `OPENFINGERPRINT_REPLAY_WINDOW_SECONDS` | How long a checked token is remembered: 1–604800 seconds, default 3600. Use identical settings on every replica. |
| `OPENFINGERPRINT_DOMAIN_DATA` | Optional read-only snapshot path; otherwise uses the bundled snapshot. Missing/invalid overrides yield unknown domain facts without disabling browser verification. |
| `OPENFINGERPRINT_DOMAIN_DATA_RELOAD_SECONDS` | Seconds between checks of the override file, 1–86400, default 60. A changed file that fails to read or parse is rejected and the last valid snapshot stays until its sources expire. |
| `OPENFINGERPRINT_COUNTRY_DATA` | Optional read-only DB-IP Country Lite MMDB path. Without it, IP checks return `unknown/not_configured`. Missing/invalid files yield unknown country results without disabling other checks. |
| `OPENFINGERPRINT_COUNTRY_DATA_RELOAD_SECONDS` | Seconds between country file checks, 1–86400, default 60. Invalid files or older database builds are rejected; the last valid database remains until it expires. |
| `OPENFINGERPRINT_DNS` | Nameserver for MX lookups, default `system` (the first `nameserver` in `/etc/resolv.conf`). Also accepts an IP, `IP:port` or `host:port` (resolved once at startup). Startup fails without a usable nameserver. |
| `OPENFINGERPRINT_WHOIS_SERVERS` | Optional path to a `{"servers": {"tld": "host"}}` file replacing the bundled WHOIS server list; `host:port` is allowed, for local test servers. |
| `OPENFINGERPRINT_RDAP_BOOTSTRAP` | Optional path to an IANA RDAP bootstrap file replacing the bundled one; read at startup. It may contain `http://` servers, for local test registries. |
| `OPENFINGERPRINT_METRICS_ADDR` | Optional listener for Prometheus `GET /metrics`, for example `0.0.0.0:9180`. Keep it off the API port so network policy can expose it separately. |
| `SENTRY_DSN` | Optional. Enables error reporting to Sentry: panics, HTTP 5xx responses and rejected snapshot reloads, as static messages with release (`CARGO_PKG_VERSION`) and stack traces. Request data, headers, IPs, users and breadcrumbs are removed before sending, so signals, hashes, credentials and event IDs are never reported. `SENTRY_ENVIRONMENT` optionally sets the environment. With `networkPolicy.enabled`, `networkPolicy.rdapTo` must allow HTTPS to your Sentry ingest host; the default allows all public addresses. |

## Security

The API has no authentication, no keys and no tenants. Whoever can reach it can use
it, and each check makes DNS, RDAP and WHOIS requests from your server's addresses.
Deploy it so that only your backend can connect:

- Keep the Service private: no Ingress, no public load balancer. With the
  [Helm chart](chart/README.md), enable `networkPolicy` and list your backend's pods
  in `networkPolicy.apiFrom`; the chart's default allows any pod in the cluster.
- If a gateway exposes it, put your own authentication, quotas and request limits there.
- A request that carries an `Origin` header is refused (HTTP 403), so a web page cannot
  call the API from a visitor's browser. There is no CORS and no preflight.
- Every route requires `Content-Type: application/json`; bodies are limited to 64 KiB.

The process does not terminate TLS. Terminate it in front if traffic leaves a trusted
network; cluster-local HTTP and NetworkPolicy do not encrypt traffic. No dashboard,
SDK hosting, billing or tenant-management endpoint is provided.

Earlier releases required `Authorization: Bearer <secret>` and `OPENFINGERPRINT_SITES`.
Both are ignored now, so callers may keep sending the header while they roll over.

## Endpoints

Routes require `Content-Type: application/json` and refuse any request with an `Origin`
header. There is no authentication ([Security](#security)) and no CORS.

### `GET /health`

No body. Returns HTTP 200 with plain text `ok`. This is process
liveness, not evidence quality, dataset coverage or identification accuracy.

### `POST /v1/check`

The JSON object accepts only these fields:

| Field | Shape |
| --- | --- |
| `signals` | Optional `token` string from the SDK result (`result.token`). Objects are rejected as `invalid_signals`. |
| `automation` | Optional version-1, -2 or -3 SDK automation evidence, as described below. |
| `domain` | Optional ASCII hostname, not a URL or complete email address. |
| `email` | Optional full email address. Its domain gets the `domain` checks, so it cannot be combined with `domain`. |
| `ip` | Optional visitor IPv4/IPv6 literal supplied by your trusted backend. |
| `headers` | Optional object with the raw `userAgent`, `acceptLanguage`, `secChUa`, `secChUaMobile` and `secChUaPlatform` headers of the browser request that carried `signals`. Used only with `signals`, for [spoofing](#spoofing-indicators). |
| `detail` | Optional boolean, default false. `true` returns the full response described in this guide, with evidence counts, rule metadata and per-source provenance. |

By default the response is one flat object of verdicts:

```json
{"fingerprint":"_AJUXF4ttBmXt1N1es89S",
 "replayed":false,
 "tokenAgeMs":1830,
 "automation":true,
 "tampering":false,
 "spoofing":false,
 "disposable":false,
 "free":true,
 "mx":true,
 "country":"us",
 "vpn":false,
 "tor":false}
```

A key that is missing means unknown, so there are no `null` facts. Only the
`fingerprint` can be `null`.

| Key | Meaning |
| --- | --- |
| `fingerprint` | From `signals`; `null` when the token is invalid or has no full ID. |
| `replayed`, `tokenAgeMs` | From a valid `signals` token: whether the same evidence was checked before, and milliseconds since the browser sealed it. See [Replayed tokens](#replayed-tokens-and-token-age). |
| `automation`, `tampering` | The browser reported automation tooling, or altered canvas/audio readback. |
| `spoofing` | The token does not belong to the request that carried it: the browser's own report contradicts `headers`, or its [nonce](#post-v1nonce) is reused, expired, not issued here or missing when required. Only when one of these is in use. |
| `disposable`, `free`, `spam`, `relay`, `cheapTld`, `mx` | From `domain` or the domain of `email`. `free` is a public mailbox; `cheapTld` says the TLD is one registrars sell at teaser prices; `mx` says the domain has mail servers. |
| `country`, `vpn`, `tor`, `datacenter`, `proxy` | From `ip`. `country` is a lowercase ISO 3166-1 alpha-2 code. |
| `invalid` | Only present when an input was rejected: a list of `signals`, `automation`, `tampering`, `spoofing`, `headers`, `domain`, `email` and/or `ip`. |

`email` and `domain` give the same keys. Everything else (evidence counts, indicator
lists, rule versions, role account, ASN and hosting provider, MX providers,
SPF/DMARC, registration date, suggested domain, `mx_listed` provenance, uppercase
`countryCode`, sources, and rejection reasons) is only in the `detail: true` response.

The rest of this guide describes the `detail: true` shape.

Response keys are camelCase; enumerated values such as `not_listed` or
`invalid_input` stay snake_case. At least one non-null field is required. Null is equivalent to omission. Results
contain only requested non-null sections. Inputs can be combined in any order;
there is no cross-input identity merging, and automation/domain/IP never change the browser ID.

For example:

```json
{"domain":"example.test","ip":"192.0.2.1"}
```

Without a configured country database, the IP section returns
`{"status":"unknown","reason":"not_configured"}`. With a fresh database and a
covered public IP, it returns `status: ok`, `countryCode` (for example `DK`) and
`source`: dataset ID, license, attribution URL/text, database build/expiry timestamps
and file SHA-256. No IP is echoed. The example documentation address above is
reserved and therefore stays unknown even with a database.

Country is an estimate of the network endpoint, not a person's physical location,
nationality or a fraud verdict. VPNs, carrier routing and anycast can produce
misleading countries. It never changes browser identity. IPv4-mapped IPv6 is
normalized to IPv4; private, shared, loopback, documentation, multicast and other
special-purpose addresses remain `unknown/non_public_ip`. Missing coverage or an
unknown country code yields `unknown/not_found`. Missing/invalid configured data
yields `unknown/unavailable`; a database older than 62 days yields
`unknown/stale_data`. Unknown/error results omit `countryCode`; results against a
loaded database retain its provenance even when stale. `ok` means a country was
found, not that the IP is safe. The API never infers IPs from connections or headers.

See [country licensing and refresh](data/README.md#ip-country-data) before using
these results: DB-IP requires attribution, including a link on web pages that use them.
With fresh domain data, `domain` contains `disposable`, `freeSubdomain`, `spam`,
`publicMailbox` and `relay` facts. Disposable evidence combines the community list with recently monitored
provider domains and domains read directly from live temporary-mail services, each from an openly licensed feed; no vendor API results are imported. Each has a nullable `value`, evidence `status`, `scope` and `sources` with
license, revision, source-commit/retrieval/expiry times. For example, a confirmed
list match yields `value: true, status: listed`; an ordinary non-match yields
`value: null, status: not_listed`, not a clean verdict.

An otherwise `not_listed` domain whose external MX host is on a fresh
disposable source yields `value: true, status: mx_listed`, with that host's source
statuses. Mail routed to a known disposable provider is strong evidence, but
it is inferred, so you can treat it separately from a direct listing. MX hosts
inside the queried domain are ignored. A disputed, allowlisted or conflicting
MX host or parent domain blocks the inference; direct listings, allowlists and
disputes always take precedence. MX hosts are never echoed. They describe mail
routing at check time, not mailbox validation.

The same `mx_listed` result applies when every MX host is under infrastructure that
public disposable lists cluster on and popular sites do not use
([`disposable-infrastructure.json`](data/disposable-infrastructure.json)): a service that
rotates through thousands of throwaway domains, such as the ones temporary-mail sites
register, brings fresh and even years-old domains onto the same mail servers faster than any
list notices them. An entry needs at least 50 listed domains, at most 3 of the Tranco top
300,000, no overlap with a known mail provider, and either an independent check that at least
90% of a sample of at least 8 such domains is disposable or the operator's own site advertising
a temporary inbox. [`api/mine-disposable-infra.mjs`](mine-disposable-infra.mjs) lists the
candidates. A domain with any other MX host is not matched.

Every valid domain section has `mxLookup`:

| `mxLookup` | Meaning |
| --- | --- |
| `resolved` | The API found MX hosts (up to 10, by preference). |
| `no_records` | The domain exists but publishes no usable MX, including null MX. |
| `no_domain` | NXDOMAIN. Undeliverable now, which is not proof of abuse. |
| `unavailable` | Timeout, SERVFAIL, truncated or malformed answer. Unknown, not clean. |
| `not_needed` | The domain is a public suffix such as `co.uk`, so nothing was sent to DNS. |

With `mxLookup: resolved`, `mxProviders` lists the services that run those MX
hosts, in MX preference order, as `{"slug": "google", "type": "mailbox"}`. Types are
`mailbox` (hosted mailboxes), `gateway` (filtering in front of another mailbox),
`forwarding` (mail is passed on to another address) and `inbound` (delivered to an
application). An empty list means self-hosted or unrecognised routing, not a missing
provider. The table (`data/mx-providers.json`) holds only host suffixes that the
provider documents or owns, with evidence, and ships with each release. Ownership
without public documentation means the provider's own domain or its own mail routes
there and the MX servers present an organisation-validated certificate issued to the
provider (Proofpoint, Fortinet); the entry's `ownership` note records the check. Broad
cloud domains are never used: Amazon SES is matched by its documented regional
`inbound-smtp` hosts only, not by self-hosted mail on `amazonaws.com`. In the Tranco
top 20,000, the table names a provider for 72% of domains with MX.

`publicMailbox` is true when the exact domain is a reviewed shared mailbox service
(Gmail, Outlook.com, Yahoo, iCloud, GMX, regional providers and large ISPs): its
addresses belong to unrelated people, not to one organisation. Subdomains do not
match. An otherwise unlisted domain whose MX hosts all belong to one provider's
consumer-only infrastructure yields `value: true, status: mx_listed`: Microsoft's
consumer Outlook.com servers (`*.olc.protection.outlook.com`, not the
`*.mail.protection.outlook.com` organisation tenants), Yahoo's servers for itself,
AOL and partner ISPs (`yahoodns.net` except Yahoo Small Business `mx-biz`), GMX,
WEB.DE and mail.com, whose vanity catalogue (`email.com`, `usa.com`...) is covered this way, and
Mail2World's public hosts (`publicms1/2/3.mail2world.com`) for its roughly 2,000 `@mail2...` domains.
In the Tranco top 20,000 this matched 25 domains, all shared consumer or ISP mail.
Patterns that also serve organisations (Microsoft `mx.microsoft`, Yandex, Mail.ru)
are deliberately not used. `relay` is true for reviewed forwarding-alias domains (Apple Hide My Email,
DuckDuckGo, Firefox Relay, SimpleLogin, Proton Pass, addy.io, StartMail, AliasVault, ManyMe, Bump,
33mail, erine.email) and their subdomains: a real mailbox hides behind the address. An otherwise
unlisted domain whose MX hosts all belong to one alias service's forwarding servers (SimpleLogin
and Proton Pass `mx1/mx2.simplelogin.co`, addy.io `mail/mail2.anonaddy.me`) yields
`value: true, status: mx_listed`: its own alias domains and its users' custom domains, whose
every address is an alias. Generic forwarders that organisations use for their own domains
(Cloudflare Email Routing, ImprovMX, Forward Email) are not relays; they appear in
`mxProviders` with `type: forwarding`. Neither fact is a risk verdict.

`suggestedDomain` suggests the public mailbox domain a registered domain was probably
meant to be (`gmial.com` and `gmail.con` suggest `gmail.com`), or is null. It needs a
fresh public-mailbox list, accepts one edit after the first letter of a provider
name of five letters or more, or one edit in its suffix (not one two-letter country
code for another: `posteo.dk` is Posteo's, not a typo of `posteo.de`), and stays null
when two domains are equally close. Across the Tranco top 20,000 sites it suggested
nothing.

Every valid domain section also has `registration`:

| `registration.status` | Meaning |
| --- | --- |
| `found` | `registeredAtUnix` is the registry's `registration` event for the registered domain. |
| `no_date` | The registry answered without a usable registration date (some redact it). |
| `not_found` | The registry does not know the domain: unregistered or recently deleted. |
| `unsupported_tld` | The TLD has neither an RDAP service nor a reachable WHOIS server that accepts automated queries (for example `.ch`). |
| `not_applicable` | A public suffix, or a tenant of a private namespace. |
| `unavailable` | Timeout, error status, redirect, oversized or inconsistent answer. Unknown, not clean. |

A young registration is evidence, not a verdict: new businesses register domains
too, and the date says nothing about when a mailbox was created. A domain that
expired and was registered again shows the new date.

`cheapTld` says what the domain cost to create. It is true when the last label is a
generic TLD that a public registrar price list sells for 3 USD or less in the first
year (`.xyz`, `.top`, `.online`, `.site`, about 90 of them), false for other priced TLDs
including country codes such as `.de`, whose registries are cheap at every price level, and
absent when the TLD has no price. `status` is `cheap`, `not_cheap` or `unknown_tld`. It
describes the TLD, not the site: many real businesses use these TLDs, and a spam
domain on `.com` is false. Use it as context next to registration age, never as a block.
The list comes from `data/tld-prices.json` and is refreshed weekly with the other bundled data.

`spf` and `dmarc` describe the domain's published sender authentication. Only the
outcome is returned, never the record text:

| `spf.status` | Meaning |
| --- | --- |
| `found` | Exactly one `v=spf1` TXT record. `policy` is how it treats senders it does not list, from its first `all` term: `fail` (`-all`), `softfail` (`~all`), `neutral` (`?all`, bare `all`) or `pass` (`+all`, anyone may send). Absent when the record has no `all` term, such as one that only redirects. |
| `multiple` | More than one, which receivers treat as an error (RFC 7208). |
| `none` | No SPF record. |
| `no_domain` | The domain does not exist in DNS. |
| `not_needed` / `unavailable` | A public suffix / timeout or DNS error. |

| `dmarc.status` | Meaning |
| --- | --- |
| `found` | One `v=DMARC1` record with `policy` `none`, `quarantine` or `reject`. `inherited: true` means it came from the organisational domain, whose `sp` (or `p`) applies. |
| `invalid` | A DMARC record without a valid `p`. |
| `none` | No DMARC record at the domain or its organisational domain (several records count as none). |
| `not_needed` / `unavailable` | A public suffix / timeout or DNS error. |

In a sample with live MX, 49% of listed disposable domains published neither SPF nor
DMARC, against 4% of Tranco top-20,000 sites (DMARC found: 25% against 78%). Absence is
still not a verdict: small businesses and personal domains often skip both, receiving
mail does not need them, and large disposable services publish both.

Free-subdomain operator apexes yield false with `provider_domain`; strict children
can match. Reviewed allowlist overrides yield false with `allowlisted`. Conflicting
fresh sources yield null with `conflict`. Exact domains under an independently
reviewed dispute also yield null with `conflict/review_required`; an overdue review
does not restore a positive accusation. This is not an allowlist or a clean verdict.
Stale, future-dated, missing or invalid data stays unknown. The overall domain status is `ok` when all scoped checks ran
against fresh sources, `partial` for incomplete/conflicting coverage, or `unknown`
when no fresh data is available. `ok` never means the domain is safe.

`spam.scope` is always `referrer_spam` in this release. The open Matomo feed does
not establish mailbox spam or comprehensive abuse coverage. Neither disposable
nor free-subdomain classifications set this fact. [Data details](data/README.md)
include exact matching/expiry semantics and the bounded provider coverage.

With valid full SDK evidence, the `signals` section is:

```json
{
  "status":"ok",
  "schema_version":1,
  "fingerprint":"<21-character ID>",
  "evidence":{
    "includedComponents":2,
    "includedHints":1,
    "unavailableProbes":3,
    "excludedProbes":3
  }
}
```

`evidence.identityGroups` (omitted when empty) holds partial identity hashes
for repeat-visit matching: `fonts`, `hardware`, `rendering` and `software`. Each
is a domain-separated SHA-256 (`stealth-group:<name>:<schema>`) over the
verified hashes of that group's probes, and appears only when every probe in
the group is present and not excluded, so a missing probe never changes a
group's value. Compare them when `fingerprint` differs: a browser update changes
`software` but not `hardware` or `fonts`. Matching is the caller's decision; the
API stores nothing, and agreement on one group is not proof of the same device.
Groups are derived from the same inputs as the fingerprint, with no new SDK data.

Counts describe the submitted, validated evidence, not entropy, probability,
confidence, a risk score or honest probe execution. Included counts omit excluded
probes. Unavailable and excluded counts are separate and may overlap.

The returned fingerprint is the first 126 bits of the full SHA-256, as 21
base64url characters (`A-Za-z0-9_-`, case-sensitive; do not lowercase it). The API
verifies the full hash inside the token.

Valid evidence without a full ID has `status: insufficient_signals`, null schema
and fingerprint, and evidence counts. A core ID never substitutes for a full ID.
Invalid evidence has `status: invalid_input`, `reason: invalid_signals`, and null
schema, fingerprint and evidence. That does not discard another section's result.

Domain/email/IP sections return `invalid_input` with `invalid_domain`, `invalid_email` or `invalid_ip`
for invalid values, including wrong field types. The same field-level handling
applies to malformed signal objects. HTTP 200 means the envelope was processed,
not that every check succeeded: inspect each requested section. Valid sections
survive failures in other sections; there is no combined clean/fraud verdict.

Malformed JSON, non-object envelopes, empty/all-null requests and unknown top-level
fields, and `domain` together with `email`, return HTTP 400. Visitor tokens, account
metadata and raw browser context are not additional inputs. All request bodies are limited to
64 KiB, including nested evidence, before evaluation.

#### Automation indicators

`collect()` includes observations automatically as `signals.automation`, and
`/v1/check` returns their evaluation as `signals.automation`. No additional SDK
option or forwarding step is needed. Existing callers may still send standalone
`automation` (including without a fingerprint):

```json
{"automation":{"version":2,"webdriver":true,"headlessUserAgent":false,"seleniumArtifacts":false,"phantomArtifacts":null,"cdpDetected":false}}
```

The response contains:

```json
{
  "automation": {
    "status": "detected",
    "ruleVersion": 2,
    "source": "client_reported",
    "indicators": ["webdriver"],
    "unavailableProbes": ["phantom_artifacts", "platform_mismatch"]
  }
}
```

Evidence accepts `version: 1` with four optional booleans, `version: 2`, `3` or `4`
with those four plus ten more, or `version: 5` with three more after those. Versions 3
and 4 have the same fields as version 2; they only change how the SDK observes
`nativeFunctionTampering` (3) and `cdpDetected` (4), as the table describes. Version 5
also widens how the SDK observes `headlessUserAgent`, `zeroDimensions` and
`nativeFunctionTampering`. Each version
rejects any field it does not define, so a version-1 document cannot carry
version-2 probes. `ruleVersion` echoes the
evidence version. Null or omitted observations remain unknown. `indicators` and
`unavailableProbes` list snake_case names in this order:

| Evidence field | Name | Since | `true` means |
| --- | --- | --- | --- |
| `webdriver` | `webdriver` | 1 | `navigator.webdriver` is true. |
| `headlessUserAgent` | `headless_user_agent` | 1 | UA contains `HeadlessChrome/`. Version 5: or a `userAgentData` brand is `HeadlessChrome`. |
| `seleniumArtifacts` | `selenium_artifacts` | 1 | A Selenium global exists on `document`. |
| `phantomArtifacts` | `phantom_artifacts` | 1 | A Phantom global exists on `window`. |
| `platformMismatch` | `platform_mismatch` | 2 | UA OS family contradicts `navigator.platform` or `userAgentData.platform`. |
| `missingChromeObject` | `missing_chrome_object` | 2 | A Chromium UA (not WebView) without `window.chrome`. |
| `notificationPermissionQuirk` | `notification_permission_quirk` | 2 | `Notification.permission` is `denied` while the Permissions API reports `prompt`. |
| `emptyPlugins` | `empty_plugins` | 2 | Desktop Chromium with no `navigator.plugins`. |
| `emptyLanguages` | `empty_languages` | 2 | `navigator.languages` is empty. |
| `softwareRenderer` | `software_renderer` | 2 | Unmasked WebGL renderer is SwiftShader, llvmpipe, softpipe or similar. |
| `zeroDimensions` | `zero_dimensions` | 2 | Screen or outer-window width/height is 0. Version 5: a 0x0 outer window in a hidden (background) tab is unknown instead. |
| `cdpDetected` | `cdp_detected` | 2 | Version 4: logging an error formatted its stack (V8 called `Error.prepareStackTrace`), which happens only while a CDP client has `Runtime.enable` on, as Puppeteer, Playwright, ChromeDriver and open DevTools do. Clients that avoid `Runtime.enable`, such as nodriver or rebrowser-patches, are not seen. Versions 2 and 3: a getter on the logged error's `stack` was read, which Chrome 137 and later never do, so their reports from current Chrome are false whether or not a client is attached. |
| `nativeFunctionTampering` | `native_function_tampering` | 2 | Version 5: also a `Proxy` around either native, an own `webdriver` on `navigator`, a deleted `webdriver` getter, or a detached `srcdoc` frame with a window (puppeteer-extra-plugin-stealth). Version 3: the `navigator.webdriver` getter or `Permissions.prototype.query` is not native when read with an untouched `toString`, or `Function.prototype.toString.call({})` does not throw. Version 2: also true when `Function.prototype.toString` itself is replaced, which error monitors such as Sentry do by default, so version-2 reports from such pages are positive on every visit; do not rely on it. |
| `workerUserAgentMismatch` | `worker_user_agent_mismatch` | 2 | A dedicated worker reports a different UA or platform than the main thread. |
| `driverArtifacts` | `driver_artifacts` | 5 | A ChromeDriver, WebDriver, Watir, Playwright-binding, NightmareJS or `domAutomation` global, or a driver attribute on `<html>`. |
| `engineMismatch` | `engine_mismatch` | 5 | The JavaScript engine is not the one the UA claims (V8, SpiderMonkey or JavaScriptCore). |
| `userAgentDataMismatch` | `user_agent_data_mismatch` | 5 | The `Chromium` brand major version differs from the UA's `Chrome/` major version. |

Rules for every version report `detected` if any observation is true, `unknown`
if none is true and any is unavailable, or `not_detected` only if every
observation the version defines is false.
Malformed evidence, unknown keys, unsupported versions and non-boolean/non-null
observations produce `invalid_input` with `reason: invalid_automation` and empty
indicator/unavailable arrays. Other sections still run. Top-level
`automation: null` omits the section, like other optional inputs.

These rules interpret client reports, not attested browser execution. Evidence
can be forged or hidden. `not_detected` is not proof of a human, and automation
may be legitimate testing or assistive tooling, not malicious traffic. No
good/bad bot classification, confidence, fraud score, retention or new outbound
traffic is introduced. Deploy the compatible API before upgrading the SDK;
older servers reject evidence versions they do not define.

#### Tampering indicators

`collect()` also reports `signals.tampering`, and `/v1/check` returns its evaluation as
`signals.tampering`, separate from `signals.automation` on purpose: privacy browsers
and anti-fingerprinting extensions trigger it for ordinary people, so it must never
read as automation. The response has the automation shape (`status`, `rule_version: 1`,
`source: "client_reported"`, `indicators`, `unavailable_probes`) with these names:

| Evidence field | Name | `true` means |
| --- | --- | --- |
| `canvasReadbackAltered` | `canvas_readback_altered` | A 16x16 canvas of opaque flat colors did not read back exactly. Clean engines always read it exactly; noise injection (Brave farbling, canvas-noise extensions) or Firefox resistFingerprinting changes it. |
| `audioRenderAltered` | `audio_render_altered` | An offline render of a constant 0.5 signal returned any other sample. |

Evidence accepts only `version: 1` and these two optional booleans; anything else is
`invalid_input` with `reason: invalid_tampering`. Missing or throwing probes stay null
(unknown), and null or omitted `signals.tampering` omits the section. The probes use
fixed content, add no identity hash input and never change the fingerprint. A result
shows that something altered readback in this browser, not who or why; a clean result
does not rule out tampering that spares these two reads, such as a spoofed value.
Deploy the API before upgrading the SDK: older servers reject the new `tampering`
field in `signals`.

#### Spoofing indicators

`collect()` also puts the browser's own `navigator.userAgent`, `navigator.language` and
low-entropy client hints (`navigator.userAgentData` brands, mobile, platform) in the
token, as read, under `spoofing`. When your backend also sends `headers`, copied from
the browser request that carried the token, `/v1/check` compares the two and returns
`signals.spoofing` (compact: `spoofing`). The section has the automation shape
(`status`, `ruleVersion: 1`, `source: "client_reported_vs_request_headers"`,
`indicators`, `unavailableProbes`):

| Name | `true` means | Unknown when |
| --- | --- | --- |
| `user_agent_mismatch` | The reported user agent differs from `User-Agent`. | Either side is missing. |
| `client_hints_mismatch` | The reported brands (in any order), mobile flag or platform differ from `Sec-CH-UA`, `Sec-CH-UA-Mobile` and `Sec-CH-UA-Platform`. | Only one side has client hints, or a header does not parse. Neither side having them (Firefox, Safari) counts as agreement. |
| `language_mismatch` | The primary subtag of the reported language differs from the first `Accept-Language` tag (`en-US` and `en` agree, as WebKit reports `ja` while sending `ja-JP`). | Either side is missing or `*`. |
| `nonce_invalid` | The token's [nonce](#post-v1nonce) is reused, expired or not issued here, or missing while `OPENFINGERPRINT_REQUIRE_NONCE` is set. `signals.nonce.status` gives which. | Redis cannot answer. |

The three header probes run only when you send `headers`, and `nonce_invalid` only when
the token has a nonce or one is required; a probe not in use is left out, not listed as
unavailable. Without either, there is no `spoofing` result.

Both sides come from the same browser, so they agree for ordinary visitors in
Chromium, Firefox and WebKit. A mismatch means the token and the request did not come
from the same unmodified browser: a user-agent switcher that changes one side only, a
token captured in one browser and sent from another client, or a forged token sent
with a script's headers. It is not proof of intent. Anyone who reads this code can
send matching headers, so `not_detected` does not show the browser is genuine.
Headless Chromium sends no `Accept-Language` by default; that leaves the language
probe unknown rather than positive. A time zone or IP comparison is deliberately not
part of this check, since VPN users and travellers would fail it.

Unlike `tampering`, which reports altered canvas or audio readback in the browser
(often a privacy tool), `spoofing` compares the token with the request around it.
Without `headers`, or for a token without `spoofing` evidence from an older SDK, the
check is `unknown` or omitted. Malformed `headers` (unknown keys, non-strings, values
over 1024 bytes) are `invalid_input` with `reason: invalid_headers`; malformed
evidence is `invalid_input` with `reason: invalid_spoofing`. The user agent,
language and client hints travel in the token readable by your backend, as they
already do in the request headers; the API never logs or stores them. Deploy the API
before upgrading the SDK: older servers reject a token with the `spoofing` field.

#### Domain and IP boundaries

Domains have at least two labels, each 1–63 ASCII letters/digits/hyphens, without
leading/trailing hyphens. Maximum length is 253 characters excluding an optional
single trailing dot; the final label must contain a letter. Case is accepted.
Internationalized names must be supplied as ASCII A-labels; no Unicode conversion,
IDNA decoding, address resolution or registrability check is performed. Dataset
matching does use Mozilla's Public Suffix List to protect registry/private-suffix
boundaries; this does not turn lexical input acceptance into domain validation. Lexical acceptance is not domain existence or mailbox validation.

Email addresses are `local@domain` with an unquoted dot-atom local part of at most 64
characters, a domain as above and at most 254 characters in total; quoted local parts,
comments and address literals are rejected rather than interpreted. An invalid address
returns only `email` with `invalid_email` and runs no domain check. A valid one returns
`email: {"status": "checked", "roleAccount": true|false}` and the `domain` section.
`roleAccount` is true when the local part, lowercased, without a `+tag` and without
`.`, `-` and `_`, is a shared mailbox name: the RFC 2142 names (`postmaster`, `abuse`,
`info`, `sales`, `support`...) or a common business or system mailbox (`admin`,
`billing`, `hello`, `noreply`, `office`, `team`...). It describes the address, not the
person: a role mailbox can belong to a real customer, so treat it as context, not a block.

IPs must be literals, without ports, CIDR prefixes, brackets, zone IDs or surrounding
whitespace. IPv4-mapped IPv6 is normalized to IPv4. Private, loopback, multicast,
documentation and other excluded special-use ranges return network `unknown` with
`non_global_ip` under `ip.network`. Classification conservatively excludes special-purpose IPv6
blocks rather than handling every IANA global exception.

#### Local network intelligence

`/v1/check` accepts `{"ip":"8.8.8.8"}` from your backend. Existing
country fields (`ip.status`, `ip.reason`, `ip.countryCode`, `ip.source`) retain
their country-only meaning. Independent network evidence is returned under
`ip.network`, with `source: "backend_supplied"`: the API cannot tell where the address came from.
Pass the visitor's address as your own trusted edge saw it, never a browser-provided IP or
the application's own IP.

For public addresses, the independent `tor`, `hosting`, `asn`, `vpn`, `datacenter` and `proxy` facts contain
`value`, `status` and `source` provenance. A Tor match is `true`; a hosting
match is `{"providers":["AWS"],"scope":"published_cloud_range"}`; an ASN match
is `{"number":15169,"organization":"Google LLC"}` (illustrative values).
`ip.network.status: "ok"` means at least one network fact is known, not that the
visitor is safe; it does not change `ip.status` or the country estimate.
A `vpn` match is `{"scope":"listed_vpn_range"}`, a `datacenter` match is
`{"scope":"listed_datacenter_range"}` and a `proxy` match is
`{"protocols":["http","socks5"],"scope":"listed_open_proxy"}`. These objects are in the
`detail: true` response; the default response and the RPC message carry `true` for a
listed `vpn`, `tor`, `datacenter` or `proxy` and leave the key out otherwise.
No match yields null, never false or a residential/human verdict. Facts for a source
that is not loaded report `not_configured`. Residential proxies and VPNs missing from the
lists are not detected, and datacenter ranges include VPN ranges as the upstream defines them.

Fact statuses include `matched`, `not_listed`, `not_in_database`,
`not_configured`, `invalid_data`, `stale_data`, `clock_skew` and
`lookup_failed` and `observation_time_unavailable`. Each loaded source includes its license, attribution, immutable
revision/URL and updated/fetched/expiry timestamps. Failed refreshes never
relabel old data as newly updated.

| Source | Evidence and limitations | License | Maximum age |
| --- | --- | --- | --- |
| [Tor CollecTor exit lists](https://collector.torproject.org/recent/exit-lists/) | Recently measured exit addresses only, not relay listening addresses or proof of abuse. Each observation expires at 24 hours, even while its snapshot is fresh. Incomplete coverage, including IPv6; absence stays unknown. | [CC0](https://metrics.torproject.org/about.html) | 3 hours from the collected list timestamp. |
| [Published cloud ranges](https://github.com/tobilg/public-cloud-provider-ip-ranges) | Source-labelled provider ranges, not a physical datacenter/device classifier. Includes shared/CDN infrastructure; not all hosting providers are covered. No organization-name or whole-ASN heuristics. | MIT; exact license pinned and retained in the manifest. | 7 days from the last commit changing the source data file. |
| [X4BNet lists_vpn](https://github.com/X4BNet/lists_vpn) `output/vpn` | Netblocks of common VPN providers, built by the project from ASN data. A match shows the address belongs to a listed VPN network, not that this visitor is hiding anything. Incomplete; unlisted VPNs stay unknown. | MIT (the project's statement; its ASN input, IPLocate, is CC BY-SA 4.0 and is credited in the manifest). The license text is pinned and retained. | 7 days from the last commit changing the lists. |
| X4BNet lists_vpn `output/datacenter` | Networks that are "not an eyeball network": VPN and datacenter/hosting ASNs, selected partly by name keywords. Overlaps `hosting` and `vpn`; shared or CDN space is included. | Same as above. | 7 days. |
| [monosans/proxy-list](https://github.com/monosans/proxy-list) | Public HTTP, SOCKS4 and SOCKS5 proxy addresses that the upstream tested as working. Only the listening address is matched, without port. A proxy can exit through another address, and these lists change by the hour. | MIT; exact license pinned and retained in the manifest. | 6 hours from the last commit changing the list. |
| [DB-IP ASN Lite](https://db-ip.com/db/download/ip-to-asn-lite) | Monthly IPv4/IPv6 ASN number and organization, with reduced coverage/accuracy. ASN is not visitor identity, geolocation or hosting proof. | CC BY 4.0. | 45 days from the earlier of the release month and actual MMDB build time. |

**DB-IP attribution:** pages that display or use its results must link to
[DB-IP.com](https://db-ip.com/), for example `IP Geolocation by DB-IP`, and
preserve the license/source attribution when redistributing data. Keep the cloud
source's full MIT notice with redistributed manifests. Source licenses do not
change this project's MIT license.

**IPLocate and X4B attribution:** the VPN and datacenter lists come from
[X4BNet lists_vpn](https://github.com/X4BNet/lists_vpn), which builds them from the
IPLocate IP-to-ASN database ([CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)).
Where these results are used, credit the data, for example
`IP address data powered by <a href="https://www.iplocate.io">IPLocate.io</a>`, and
keep the manifest's license and attribution text with any redistributed copy. ShareAlike
applies if you redistribute the ranges themselves, so do not publish `network.json`:
this project's repository and images contain no ranges, and the API returns only a scope
label.

Build the native validator, then refresh a directory outside the repository:

```sh
cargo build --manifest-path api/Cargo.toml --locked
node api/update-network-data.mjs --output /var/lib/openfingerprint/network.json
OPENFINGERPRINT_NETWORK_DATA=/var/lib/openfingerprint/network.json \
  ./api/target/debug/openfingerprint-api
```

Run the updater hourly; ASN downloads are limited to daily when the existing
artifact is valid. It uses HTTPS, bounded downloads/decompression and strict
input validation. The native validator checks CIDRs, schema, source lifetime,
ASN hash/type/tree and record semantics before atomic manifest publication.
Failed sources retain their original evidence and expiry; partial failure exits
nonzero so the job is observable. Invalid baselines are not silently discarded.
An OS lock serializes writers and releases on process death; the empty `.lock`
file remains intentionally. **Do not delete it while a writer may be running.**
SIGTERM aborts downloads/validation and preserves the prior manifest.

`--loop` keeps the updater running instead of exiting: it refreshes hourly, retries hourly after
a failure (after one minute while no manifest exists yet), and removes ASN files older than an
hour that the manifest no longer references. The Helm chart's per-pod sidecar uses it; one-shot
runs (CI, the CronJob) are unchanged. A manifest that does not exist yet is unknown
(`data_unavailable`), not a rejected snapshot, so it does not count as a reload failure.

Tor snapshot entries are `{"ip":"8.8.8.8","observed_at_unix":<Unix seconds>}`;
duplicate addresses keep their latest observation. Positive Tor facts carry
`expiresAtUnix`, bounded by both that observation's 24-hour window and the
snapshot expiry. The API rechecks both limits on lookup and event consumption,
without retaining the checked address in the event.

Upgrade API readers before the network updater. Old bare-address Tor entries
remain readable alongside other sources, but their matches are unknown with
`observation_time_unavailable` until a refresh supplies timestamps. Already-stored
Tor matches without a per-fact expiry likewise become unknown when consumed;
other facts remain independent. Old API readers reject the new entry format and
retain their last-good snapshot with its original expiry.

The manifest and immutable `asn-<sha256>.mmdb` files must travel together.
Old ASN versions are retained for safe readers/rollback; prune unreferenced
versions when needed. No visitor addresses are written to this directory.
Override `OPENFINGERPRINT_API_BINARY` when the validator is not at the default
debug-build path. The API image also accepts `--validate-network-data <path>`
without server credentials or networking.

### SDK evidence

`/v1/check` takes the SDK's opaque `token`, not the readable
fields. The token is obfuscated, not encrypted: the scheme is public, so it hides
evidence from casual inspection and makes repeat visits look different on the wire,
nothing more. The decoded object is validated as follows:

| Field | Shape |
| --- | --- |
| `version` | Integer `1`. |
| `fingerprint` | Full lowercase SHA-256 string, or null/omitted. |
| `coreFingerprint` | Core lowercase SHA-256 string, or null/omitted. |
| `components`, `hints` | Objects mapping bounded probe names to lowercase SHA-256 strings. |
| `unavailable` | Object mapping probe names to `unsupported`, `unstable`, `timeout` or `error`. |
| `excluded` | Unique subset of `audio`, `canvas`, `screen`. |
| `durationMs` | Finite number from 0 to 60000. |
| `timings` | Optional object of `{ "durationMs": number, "blockingMs": number }` per probe, same numeric bounds. |
| `storageId` | Omitted or null only. |
| `collectedAt` | Optional finite number from 0 to 1e15: milliseconds since the Unix epoch on the browser's clock when the token was sealed. Older SDKs omit it. |

Each map has at most 32 entries. Names are 1–64 ASCII characters, start with a
letter and otherwise contain letters, digits, underscores or dots. `automation`, `tampering` and `spoofing` are the only additional SDK fields accepted and are evaluated separately
from identity; older SDKs may omit them. Unknown fields and unsolicited
visitor metadata are rejected. Non-null IDs must match the
canonical hash for the reported schema; changing only the version does not
translate an identity between schemas.

#### Replayed tokens and token age

The token is client-supplied and unsigned, so a script can build one. Two fields help
your backend judge a token that arrives:

- `replayed` (`signals.replayed` with `detail: true`): `true` when the same evidence was
  already checked within `OPENFINGERPRINT_REPLAY_WINDOW_SECONDS` (default one hour). The
  API stores one marker per token in Redis, keyed by a SHA-256 hash of the decoded
  content, with a TTL: nothing identifies a device, account or address. The first check
  of a token returns `false` and marks it; later ones return `true`. Hashing the
  content, not the sealed string, means re-sealing a captured token under a new random
  prefix still counts as a replay. Invalid tokens leave no marker. When Redis cannot answer, the field is absent, never `false`.
- `tokenAgeMs` (`signals.tokenAgeMs`): milliseconds from the browser's `collectedAt` to
  now. It uses the browser's clock, which is often wrong: expect negative values and use
  a generous limit. Absent for tokens without `collectedAt`.

A legitimate token can be checked more than once (a form re-submitted after a
validation error, a signup validated twice), so treat `replayed` as a signal for your
own rules, not as a block. Neither field stops a forger who builds a fresh token for
every request: both are cheap protection against reusing a captured one.

### `POST /v1/nonce`

Optional. Mints a single-use nonce for one page. Your backend calls it (the API is
private), hands the nonce to the page, and the page passes it to the SDK:
`collect({ nonce })`, which also takes a promise so collection can start before the
nonce arrives. The SDK seals it into the token if it has resolved by then; otherwise
the token has none. `/v1/check` then reports the outcome as `signals.nonce` and, when
the nonce is not valid, as `spoofing` (indicator `nonce_invalid`).

Request body `{}`, or `{"ttlSeconds": n}` for a lifetime of 60 to 86400 seconds
(default 1800). Response:

```json
{"nonce":"AAAAAGry_3BMz1q5kFTo3RkVhBbsbN8c","expiresAt":1794310000}
```

The nonce is 32 base64url characters: its expiry and 128 random bits. Redis stores a
SHA-256 hash of it with the same lifetime. The first `/v1/check` of a token with that
nonce marks it used, atomically, and reports:

| `signals.nonce.status` | `nonce_invalid` | Meaning |
| --- | --- | --- |
| `valid` | `false` | Issued here, unexpired, not seen before. |
| `reused` | `true` | Already seen in an earlier token, even if the rest of the token changed. |
| `expired` | `true` | Past its expiry. |
| `not_issued` | `true` | Not minted by this API, or not a nonce at all. |
| `missing` | `true` | The token has none while `OPENFINGERPRINT_REQUIRE_NONCE` is set. |
| `unavailable` | unknown | Redis could not answer. |

A token without a nonce has no nonce result unless one is required. Without
`OPENFINGERPRINT_REQUIRE_NONCE`, a forger can simply leave the nonce out, so require it
once your pages always mint one (chart value `nonce.required`). A nonce makes stockpiled or edited
tokens fail, which `replayed` alone cannot (it keys on content, so changing one field
of a captured token makes it look new), and every token needs a round trip to your
backend, which you can rate-limit per IP or session. It does not show that the rest
of the token is genuine: a script can fetch a nonce and forge everything else. Give
each page its own nonce: a second tab or a re-submitted form reuses one, which flags an
honest visitor too, so treat `spoofing` as a signal, not a block. Redis must be
version 7 or later (`SET … XX KEEPTTL GET`). Failures to store a nonce return HTTP 503
`nonce_unavailable`; checks keep working without one.

### Removed: `POST /v1/verify`

Earlier releases had `POST /v1/verify`, which took the unwrapped evidence object and
returned `{"status","schema_version","fingerprint"}`. It was removed after 0.14.0 and now
answers 404. Send `result.token` as `signals` to `POST /v1/check` and read
`response.fingerprint`, or `response.signals` with `detail: true` (`status`,
`schema_version`, `fingerprint`, `evidence`). Keep strict schema/ID matching and
fail-closed identity writes: a missing `fingerprint` means unknown.

### Connect, gRPC and gRPC-Web (`openfingerprint.v1.OpenFingerprint/Check`)

The compact `/v1/check` verdicts are also an RPC, on the same listener, without
authentication and refusing any `Origin` header. It speaks the [Connect](https://connectrpc.com/) protocol, gRPC and gRPC-Web, so any of
these work:

```sh
# Connect: a plain POST, JSON or protobuf, over HTTP/1.1 or HTTP/2
curl -H 'Content-Type: application/json' \
  -d '{"email":"john@gmail.com","ip":"8.8.8.8"}' \
  http://localhost:8180/openfingerprint.v1.OpenFingerprint/Check

# gRPC, with the schema from server reflection (HTTP/2 without TLS)
grpcurl -plaintext localhost:8180 list
buf curl --reflect -d '{"domain":"gmail.com"}' \
  http://localhost:8180/openfingerprint.v1.OpenFingerprint/Check
```

[`proto/openfingerprint.proto`](proto/openfingerprint.proto) is the contract.
`CheckRequest` has `signals` (the SDK `token`), `domain`, `email`, `ip` and `headers`;
`CheckResponse` has the same fields as the compact JSON, with an unset optional
field meaning unknown. `CreateNonce` is `POST /v1/nonce` (`ttl_seconds` in,
`nonce` and `expires_at` out); an unavailable Redis is `UNAVAILABLE`. `detail` and standalone `automation` evidence are JSON-only.
Reflection (`grpc.reflection.v1` and `v1alpha`) is open like the rest.

The listener speaks HTTP/2 without TLS (as it does HTTP/1.1), so terminate TLS in
front of it and, for gRPC, route with your ingress's gRPC backend setting (for
example `nginx.ingress.kubernetes.io/backend-protocol: "GRPC"`). Connect needs no
special setting. Browsers cannot call it: there is no CORS, and `Origin` is refused.

| Connect HTTP status | gRPC status | Cause |
| --- | --- | --- |
| 400 | `INVALID_ARGUMENT` | No field set, both `domain` and `email`, or a malformed message. |
| 403 | `PERMISSION_DENIED` | Browser `Origin` header present. |
| 429 | `RESOURCE_EXHAUSTED` | Message over 64 KiB. |

A rejected field (such as an invalid `ip`) is not an error: it comes back in `invalid`.

### HTTP errors and application use

Errors return
`{"error":"<reason>"}`: 400 invalid envelope/evidence, 403 browser
Origin, or 413 oversized body. Unsupported methods return 405.

Use a background flow where missing/failed verification leaves the ID unknown,
not blocked authentication. Applications may save a full ID and schema alongside
their own session/account after privacy review. Compare only within
the same customer and schema; never use a core-only or network-based fallback.

## Metrics

`/metrics` on `OPENFINGERPRINT_METRICS_ADDR` reports dataset health, lookup outcomes and
aggregate latency. Labels are fixed names (route, status class, step), never request
contents, domains, addresses or credentials:

| Metric | Meaning |
| --- | --- |
| `openfingerprint_domain_data_loaded` | 1 when a valid snapshot is loaded. |
| `openfingerprint_domain_data_source_expiry_timestamp_seconds{source}` | When each source stops being used. |
| `openfingerprint_domain_data_source_fetched_timestamp_seconds{source}` | When each source was fetched or reviewed. |
| `openfingerprint_domain_data_source_entries{source}` | Listed domains per source. |
| `openfingerprint_domain_data_loaded_timestamp_seconds` | When the current snapshot was loaded. |
| `openfingerprint_domain_data_reload_failures_total` | Changed snapshot files that were rejected. |
| `openfingerprint_network_data_source_fresh{source}` | Whether each network source is loaded, not future-dated and unexpired. |
| `openfingerprint_network_data_source_expiry_timestamp_seconds{source}` | When each network source expires; 0 when absent. |
| `openfingerprint_network_data_reload_failures_total` | Rejected reload attempts, retried so repaired sidecars can recover without editing the manifest. |
| `openfingerprint_mx_lookups_total{result}` | MX lookups by `mxLookup` outcome. |
| `openfingerprint_txt_lookups_total{result}` | SPF and DMARC TXT lookups by outcome (`resolved`, `no_records`, `no_domain`, `unavailable`). |
| `openfingerprint_dns_tcp_queries_total` | Truncated answers repeated over TCP. |
| `openfingerprint_rdap_lookups_total{result}` | RDAP lookups by `registration.status` (not cache hits or `not_applicable`); `unsupported_tld` counts TLDs with neither RDAP nor WHOIS. |
| `openfingerprint_whois_lookups_total{result}` | WHOIS lookups for TLDs without RDAP, by `registration.status`. |
| `openfingerprint_rdap_cache_total{result}` | RDAP cache hits, misses and errors. Errors mean checks are reaching the registry directly. |
| `openfingerprint_spoofing_checks_total{status}`, `openfingerprint_spoofing_indicators_total{indicator}` | Tokens compared with their request `headers`, by verdict, and how often each comparison found a mismatch. They count evaluated tokens, not visitors. |
| `openfingerprint_automation_checks_total{status}`, `openfingerprint_automation_indicators_total{indicator}` | Valid automation reports evaluated, by verdict (`detected`, `unknown`, `not_detected`), and how often each probe was positive. One positive probe is enough for `detected`, so the indicator counts show which probes fire in practice. They count evaluated reports, not visitors. |
| `openfingerprint_nonces_total{result}` | Nonces `issued`, and nonces found in checked tokens by outcome: `valid`, `reused`, `expired`, `not_issued`, `missing` (none while required), and `error` (Redis could not store or answer). |
| `openfingerprint_replay_checks_total{result}` | Token replay checks: `new` (first sighting), `replayed` (seen before) and `error` (Redis could not answer, so `replayed` was left out). |
| `openfingerprint_http_request_duration_seconds{route,status}` | Histogram of time to produce a response. `route` is `check`, `nonce`, `rpc` or `other`; `status` is `2xx`, `4xx`, `5xx` or `other`. `rpc` covers the Connect/gRPC/gRPC-Web endpoint and reflection; gRPC failures are HTTP 200, so only Connect shows `4xx`. Buckets run from 1 ms to 5 s. |
| `openfingerprint_check_step_duration_seconds{step}` | Histogram of where a `/v1/check` spends time. Sections: `automation`, `signals`, `domain`, `ip_country`, `ip_network`. The `domain` section runs `domain_mx`, `domain_registration` and `domain_mail_auth` concurrently, so it lasts as long as the slowest, not their sum. Beneath them: `dns_lookup` (each MX or TXT query), `redis_get` and `redis_set` (RDAP cache), `replay` (the token replay marker), `nonce` (marking the token's nonce used), `rdap_fetch` and `whois_fetch` (registry calls on a cache miss, including the wait for a per-registry slot). A step cut short by its timeout is recorded at the time it was cut. |
| `openfingerprint_country_data_loaded` | 1 when a valid country database is loaded (not necessarily fresh). |
| `openfingerprint_country_data_expiry_timestamp_seconds` | When the country database stops being used, or 0 when unavailable. |
| `openfingerprint_country_data_reload_failures_total` | Changed country files rejected, including rollbacks to older builds. |

Alert on source expiry, not on `/health`: an expired source silently degrades
domain checks to unknown while the process stays healthy.

Useful queries: p95 of the endpoint,
`histogram_quantile(0.95, sum by (le) (rate(openfingerprint_http_request_duration_seconds_bucket{route="check"}[5m])))`;
and where the time goes, the same expression with
`openfingerprint_check_step_duration_seconds_bucket` and `sum by (le, step)`. Lookups
bounded by a 2 s timeout (DNS, registries) put slow checks in the 2 s bucket; a high
`redis_get` p95 near its 250 ms timeout means the cache is hurting, not helping.

## Kubernetes

The [Helm chart](chart/README.md), published to `oci://ghcr.io/mokto/charts/openfingerprint`
with each API release, runs the API with optional NetworkPolicies, a bundled
`redis-ha` or your own Redis, a domain-data ConfigMap CronJob, a daily country-data
sidecar and optional Prometheus alerts. Policies permit DNS, Redis, registry HTTPS
and public HTTPS for country downloads. Kubernetes cannot isolate sidecar egress
from the API. Set `countryData.enabled=false` to remove the country sidecar, volume
and its HTTPS rule; the separate RDAP HTTPS allowance remains.

## Checks and containers

Requires current stable Rust (tested with 1.99.1) and Node 24+:

```sh
pnpm api:check
```

This runs formatting, Clippy, unit tests and a real loopback HTTP self-check. It
boots with an old `OPENFINGERPRINT_SITES` value to prove it is ignored, checks both schemas,
token replay and age, all 15 input combinations, automatic/nested automation rules, partial failures, scoped domain matches, public-suffix
boundaries, fresh/stale/invalid/missing snapshots, strict metadata/body boundaries,
compatibility and no request logging, then stops the
server. Updater checks use local fixtures and verify license-change rejection and
atomic failure preservation. Country checks exercise IPv4/IPv6, special-use ranges,
provenance, expiry, invalid files and live reloads; CI does not download feeds. It prints no credentials or visitor payloads.

`node api/test-network.mjs` checks local facts, IPv4/IPv6, source failure,
license guards, exclusive/crash-recoverable refresh and explicit unknowns.
Optionally set `OPENFINGERPRINT_TEST_NETWORK_DATA` to a freshly updated manifest
to check real DB-IP IPv4/IPv6 lookups. Normal CI does not depend on live sources;
release image smoke tests do.

After release, images are published as `ghcr.io/mokto/openfingerprint-api:<version>`
for linux/amd64 and linux/arm64. Pin a released manifest digest; publishing does
not deploy an API. SDK and API releases are independent (`sdk-v*` and `api-v*`).
Release Please opens the API release PR; merging it dispatches multi-architecture
image publishing. New personal GHCR packages need the owner to set visibility to
Public before anonymous checks can pass.

```sh
docker buildx build --load --provenance=false -f api/Dockerfile -t openfingerprint-api:check .
node api/test.mjs --image openfingerprint-api:check
```

For another architecture, add `--platform linux/amd64` or `--platform linux/arm64`
to both commands. To build the updater from a checkout, build the API image first
and pass its same-architecture tag; the updater copies its native MMDB validator:

```sh
docker buildx build --load --provenance=false -f api/updater.Dockerfile \
  --build-arg API_IMAGE=openfingerprint-api:check -t openfingerprint-updater:check .
```

The image runs as UID/GID 65532, supports read-only operation,
retains application/dependency/Rust licenses, and handles SIGTERM/SIGINT gracefully.
Pull-request CI runs SDK/browser and Rust/HTTP checks, without building Docker
images or duplicating runs on branch pushes. Release Please explicitly dispatches
the same checks for its bot-created release PRs. After an API release, the image
workflow builds and smoke-tests AMD64/ARM64 natively before publishing and creating
the multi-architecture manifest. No visitor-store migration is needed; a refreshed
public snapshot can be mounted read-only without rebuilding the image. The API remains experimental: add deployment-wide abuse protection,
access control and operational/privacy review before relying on it.
