# Experimental Rust check API

A self-hosted, MIT-licensed backend companion to the browser SDK. The next release
provides stateless `POST /v1/check` with independent browser, automation, domain
and IP sections, plus a Redis-backed collection flow for single-use server-owned
events. `POST /v1/verify` remains a compatibility adapter.

Domain and country intelligence run locally against openly licensed datasets:

| Requested check | Available behavior |
| --- | --- |
| `signals` | Canonical schema-4/5 verification and bounded evidence counts. |
| `automation` | Versioned rules for client-reported observations, now included automatically inside SDK `signals`. |
| `domain` | Disposable, free-subdomain, public-mailbox, email-relay and source-scoped referrer-spam evidence with provenance and expiry, typo suggestions, MX providers, registration dates and SPF/DMARC status. |
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

Stateless checks have no visitor database, observation cache, email processing or
account history. Their evidence, domains and IPs are dropped after processing.
Redis temporarily holds random action bindings, origins, challenges and evaluated
events for collection, subject to TTL and capacity limits below, and cached RDAP
answers keyed by SHA-256 hashes of registered domains. Raw collection user
agents/platforms are discarded after evaluation; request evidence and credentials
are not logged. Outbound traffic consists of MX DNS queries, at most one RDAP
request to the domain's registry per uncached check, and Redis commands.
Country and network lookups use local datasets only. Their separate updaters
download public datasets without receiving checked IPs or application credentials.
Responses have `Cache-Control: no-store` and set no cookies. Domain/IP inputs are
not echoed in responses. Stateless checks never infer an IP from the connection or forwarded headers;
collection derives it through the trusted-peer rules below. Signals-only calls do not run domain/IP checks.

The process retains configured credential tags and read-only domain/country/network datasets;
collection state and the RDAP cache are shared in Redis, not an in-memory fallback.
There is no visitor history. Collection capacity limits are not rate limiting:
apply quotas and request limits at your edge/gateway, including the public collector.

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
without flushing Redis or touching collection state. A slow or failing Redis (250 ms limit) only means asking the
registry. The cache holds public registry dates, not who asked. Tenants of private namespaces (`name.github.io`, a
listed free-subdomain service) are not looked up: their registered domain belongs
to the namespace operator. The API needs HTTPS and TCP 43 to public addresses for
this; without them, results report `unavailable`.
There are no lookup retries, remote-provider waits or visitor-history fallbacks.

The SDK hashes identity signals locally and automatically includes bounded
automation evidence outside those hashes. `collect()` has no networking;
`identify()` posts evidence plus bounded browser context to a configured same-origin
collection proxy. Neither writes storage unless `collect()` opts into `storageKey`. Leave that option
unset when sending results here. Hashes are pseudonymous, not anonymous. Your
application and hosting proxy have their own logging, retention, disclosure and
access-control responsibilities.

## Configuration

Provide secrets privately at runtime. Never put them in Git, browser code, image
build arguments, command-line arguments or logs.

| Variable | Meaning |
| --- | --- |
| `OPENFINGERPRINT_SITES` | JSON array of 1–16 site configurations, each with `id` and `secret_key`. |
| `OPENFINGERPRINT_LISTEN_ADDR` | Optional listener, default `127.0.0.1:8180`. |
| `OPENFINGERPRINT_NETWORK_DATA` | Optional network manifest path. Keep its content-addressed ASN files in the same directory. No bundled/live fallback; absent/invalid data is unknown. Checked every 60 seconds; invalid replacements retain last-good data without extending expiry. |
| `OPENFINGERPRINT_TRUSTED_PROXIES` | Optional JSON array of canonical proxy CIDRs (maximum 128), default `[]`. Only these socket peers may supply `X-Forwarded-For` to collection. Do not trust entire networks unnecessarily; `/0` is rejected. |
| `OPENFINGERPRINT_REDIS_URL` | Required private Redis/Valkey connection URL for collection state and the RDAP cache; the API does not start without it. Supports `rediss://` with certificate validation. Unreachable Redis yields HTTP 503 on collection routes and uncached RDAP lookups; checks keep working and there is no memory fallback. |
| `OPENFINGERPRINT_REDIS_PASSWORD` | Optional Redis password, overriding one in the URL, so the URL can live outside a Secret. |
| `OPENFINGERPRINT_COLLECTION_TTL_SECONDS` | Lifetime of each challenge and, separately, each published event: 1–300 seconds, default 120. Use identical settings on every replica. |
| `OPENFINGERPRINT_COLLECTION_CAPACITY` | Maximum outstanding challenges plus events per server credential: 1–100000, default 1024. Issuance at capacity returns 429. |
| `OPENFINGERPRINT_DOMAIN_DATA` | Optional read-only snapshot path; otherwise uses the bundled snapshot. Missing/invalid overrides yield unknown domain facts without disabling browser verification. |
| `OPENFINGERPRINT_DOMAIN_DATA_RELOAD_SECONDS` | Seconds between checks of the override file, 1–86400, default 60. A changed file that fails to read or parse is rejected and the last valid snapshot stays until its sources expire. |
| `OPENFINGERPRINT_COUNTRY_DATA` | Optional read-only DB-IP Country Lite MMDB path. Without it, IP checks return `unknown/not_configured`. Missing/invalid files yield unknown country results without disabling other checks. |
| `OPENFINGERPRINT_COUNTRY_DATA_RELOAD_SECONDS` | Seconds between country file checks, 1–86400, default 60. Invalid files or older database builds are rejected; the last valid database remains until it expires. |
| `OPENFINGERPRINT_DNS` | Nameserver for MX lookups, default `system` (the first `nameserver` in `/etc/resolv.conf`). Also accepts an IP, `IP:port` or `host:port` (resolved once at startup). Startup fails without a usable nameserver. |
| `OPENFINGERPRINT_WHOIS_SERVERS` | Optional path to a `{"servers": {"tld": "host"}}` file replacing the bundled WHOIS server list; `host:port` is allowed, for local test servers. |
| `OPENFINGERPRINT_RDAP_BOOTSTRAP` | Optional path to an IANA RDAP bootstrap file replacing the bundled one; read at startup. It may contain `http://` servers, for local test registries. |
| `OPENFINGERPRINT_METRICS_ADDR` | Optional listener for Prometheus `GET /metrics`, for example `0.0.0.0:9180`. Keep it off the API port so network policy can expose it separately. |

IDs are 1–64 ASCII characters, start with a letter and otherwise contain letters,
digits, underscores or dots. Server keys are 32–128 URL-safe ASCII characters;
generate them randomly. IDs and credentials must be unique. Startup rejects
invalid configuration without echoing its values.

`OPENFINGERPRINT_SIGNING_KEY` is no longer read or required by this source.
Existing configurations containing `site_key` and `origins` remain readable for
rollout; those fields enable no browser endpoint or CORS. Legacy public keys must
remain distinct from server keys and are never authentication. New configurations
need only `id` and `secret_key`. Do not remove configuration required by an older
running image before deploying the compatible release.

The process does not terminate TLS. Protect credential transport with TLS or an
equivalent protected boundary; cluster-local HTTP and NetworkPolicy do not encrypt
traffic. Restrict the deployment to its intended backend callers and do not forward
browser Origin/cookies to private routes. Only the public collection proxy forwards
Origin and the relevant browser headers; it must strip cookies and Authorization.
No dashboard, SDK hosting, billing or tenant-management
endpoint is provided.

## Endpoints

Private POST routes require `Authorization: Bearer <server secret>` and
`Content-Type: application/json`, with no `Origin` header. Authentication runs
before JSON parsing. Only `POST /v1/collect` accepts browser-origin requests,
authorized by a single-use challenge. No route enables cross-origin CORS.

### `GET /health`

No authentication or body. Returns HTTP 200 with plain text `ok`. This is process
liveness, not evidence quality, dataset coverage or identification accuracy.

### `POST /v1/check`

The JSON object accepts only these fields:

| Field | Shape |
| --- | --- |
| `signals` | Optional SDK result object, as described below. |
| `automation` | Optional version-1 or version-2 SDK automation evidence, as described below. |
| `domain` | Optional ASCII hostname, not a URL or complete email address. |
| `ip` | Optional visitor IPv4/IPv6 literal supplied by your trusted backend. |

At least one non-null field is required. Null is equivalent to omission. Results
contain only requested non-null sections. Inputs can be combined in any order;
there is no cross-input identity merging, and automation/domain/IP never change the browser ID.

For example:

```json
{"domain":"example.test","ip":"192.0.2.1"}
```

Without a configured country database, the IP section returns
`{"status":"unknown","reason":"not_configured"}`. With a fresh database and a
covered public IP, it returns `status: ok`, `country_code` (for example `DK`) and
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
`unknown/stale_data`. Unknown/error results omit `country_code`; results against a
loaded database retain its provenance even when stale. `ok` means a country was
found, not that the IP is safe. The API never infers IPs from connections or headers.

See [country licensing and refresh](data/README.md#ip-country-data) before using
these results: DB-IP requires attribution, including a link on web pages that use them.
With fresh domain data, `domain` contains `disposable`, `free_subdomain`, `spam`,
`public_mailbox` and `relay` facts. Disposable evidence combines the community list with recently monitored
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

Every valid domain section has `mx_lookup`:

| `mx_lookup` | Meaning |
| --- | --- |
| `resolved` | The API found MX hosts (up to 10, by preference). |
| `no_records` | The domain exists but publishes no usable MX, including null MX. |
| `no_domain` | NXDOMAIN. Undeliverable now, which is not proof of abuse. |
| `unavailable` | Timeout, SERVFAIL, truncated or malformed answer. Unknown, not clean. |
| `not_needed` | The domain is a public suffix such as `co.uk`, so nothing was sent to DNS. |

With `mx_lookup: resolved`, `mx_providers` lists the services that run those MX
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

`public_mailbox` is true when the exact domain is a reviewed shared mailbox service
(Gmail, Outlook.com, Yahoo, iCloud, GMX, regional providers and large ISPs): its
addresses belong to unrelated people, not to one organisation. Subdomains do not
match. An otherwise unlisted domain whose MX hosts all belong to one provider's
consumer-only infrastructure yields `value: true, status: mx_listed`: Microsoft's
consumer Outlook.com servers (`*.olc.protection.outlook.com`, not the
`*.mail.protection.outlook.com` organisation tenants), Yahoo's servers for itself,
AOL and partner ISPs (`yahoodns.net` except Yahoo Small Business `mx-biz`), GMX,
WEB.DE and mail.com, whose vanity catalogue (`email.com`, `usa.com`...) is covered this way.
In the Tranco top 20,000 this matched 25 domains, all shared consumer or ISP mail.
Patterns that also serve organisations (Microsoft `mx.microsoft`, Yandex, Mail.ru)
are deliberately not used. `relay` is true for reviewed forwarding-alias domains (Apple Hide My Email,
DuckDuckGo, Firefox Relay, SimpleLogin, Proton Pass, addy.io, StartMail, AliasVault) and their subdomains: a real mailbox
hides behind the address. Neither is a risk verdict.

`did_you_mean` suggests the public mailbox domain a registered domain was probably
meant to be (`gmial.com` and `gmail.con` suggest `gmail.com`), or is null. It needs a
fresh public-mailbox list, accepts one edit after the first letter of a provider
name of five letters or more, or one edit in its suffix (not one two-letter country
code for another: `posteo.dk` is Posteo's, not a typo of `posteo.de`), and stays null
when two domains are equally close. Across the Tranco top 20,000 sites it suggested
nothing.

Every valid domain section also has `registration`:

| `registration.status` | Meaning |
| --- | --- |
| `found` | `registered_at_unix` is the registry's `registration` event for the registered domain. |
| `no_date` | The registry answered without a usable registration date (some redact it). |
| `not_found` | The registry does not know the domain: unregistered or recently deleted. |
| `unsupported_tld` | The TLD has neither an RDAP service nor a reachable WHOIS server that accepts automated queries (for example `.ch`). |
| `not_applicable` | A public suffix, or a tenant of a private namespace. |
| `unavailable` | Timeout, error status, redirect, oversized or inconsistent answer. Unknown, not clean. |

A young registration is evidence, not a verdict: new businesses register domains
too, and the date says nothing about when a mailbox was created. A domain that
expired and was registered again shows the new date.

`spf` and `dmarc` describe the domain's published sender authentication. Only the
outcome is returned, never the record text:

| `spf.status` | Meaning |
| --- | --- |
| `found` | Exactly one `v=spf1` TXT record. |
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
  "schema_version":5,
  "fingerprint":"<full fingerprint>",
  "evidence":{
    "included_components":2,
    "included_hints":1,
    "unavailable_probes":3,
    "excluded_probes":3
  }
}
```

`evidence.identity_groups` (omitted when empty) holds partial identity hashes
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

Valid evidence without a full ID has `status: insufficient_signals`, null schema
and fingerprint, and evidence counts. A core ID never substitutes for a full ID.
Invalid evidence has `status: invalid_input`, `reason: invalid_signals`, and null
schema, fingerprint and evidence. That does not discard another section's result.

Domain/IP sections return `invalid_input` with `invalid_domain` or `invalid_ip`
for invalid values, including wrong field types. The same field-level handling
applies to malformed signal objects. HTTP 200 means the envelope was processed,
not that every check succeeded: inspect each requested section. Valid sections
survive failures in other sections; there is no combined clean/fraud verdict.

Malformed JSON, non-object envelopes, empty/all-null requests and unknown top-level
fields return HTTP 400. Full email addresses, visitor tokens, account metadata and
raw browser context are not additional inputs. All request bodies are limited to
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
    "rule_version": 2,
    "source": "client_reported",
    "indicators": ["webdriver"],
    "unavailable_probes": ["phantom_artifacts", "platform_mismatch"]
  }
}
```

Evidence accepts `version: 1` with four optional booleans, or `version: 2` with
those four plus ten more. Each version rejects any field it does not define, so a
version-1 document cannot carry version-2 probes. `rule_version` echoes the
evidence version. Null or omitted observations remain unknown. `indicators` and
`unavailable_probes` list snake_case names in this order:

| Evidence field | Name | Since | `true` means |
| --- | --- | --- | --- |
| `webdriver` | `webdriver` | 1 | `navigator.webdriver` is true. |
| `headlessUserAgent` | `headless_user_agent` | 1 | UA contains `HeadlessChrome/`. |
| `seleniumArtifacts` | `selenium_artifacts` | 1 | A Selenium global exists on `document`. |
| `phantomArtifacts` | `phantom_artifacts` | 1 | A Phantom global exists on `window`. |
| `platformMismatch` | `platform_mismatch` | 2 | UA OS family contradicts `navigator.platform` or `userAgentData.platform`. |
| `missingChromeObject` | `missing_chrome_object` | 2 | A Chromium UA (not WebView) without `window.chrome`. |
| `notificationPermissionQuirk` | `notification_permission_quirk` | 2 | `Notification.permission` is `denied` while the Permissions API reports `prompt`. |
| `emptyPlugins` | `empty_plugins` | 2 | Desktop Chromium with no `navigator.plugins`. |
| `emptyLanguages` | `empty_languages` | 2 | `navigator.languages` is empty. |
| `softwareRenderer` | `software_renderer` | 2 | Unmasked WebGL renderer is SwiftShader, llvmpipe, softpipe or similar. |
| `zeroDimensions` | `zero_dimensions` | 2 | Screen or outer-window width/height is 0. |
| `cdpDetected` | `cdp_detected` | 2 | A console-logged object's `stack` getter was read, as a CDP client or open DevTools does. |
| `nativeFunctionTampering` | `native_function_tampering` | 2 | `Function.prototype.toString`, the `navigator.webdriver` getter or `Permissions.prototype.query` is not native. |
| `workerUserAgentMismatch` | `worker_user_agent_mismatch` | 2 | A dedicated worker reports a different UA or platform than the main thread. |

Rules for either version report `detected` if any observation is true, `unknown`
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
older servers reject version-2 evidence. `/v1/verify` accepts embedded automation but ignores it,
retaining its status/schema/fingerprint-only response.

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

#### Domain and IP boundaries

Domains have at least two labels, each 1–63 ASCII letters/digits/hyphens, without
leading/trailing hyphens. Maximum length is 253 characters excluding an optional
single trailing dot; the final label must contain a letter. Case is accepted.
Internationalized names must be supplied as ASCII A-labels; no Unicode conversion,
IDNA decoding, address resolution or registrability check is performed. Dataset
matching does use Mozilla's Public Suffix List to protect registry/private-suffix
boundaries; this does not turn lexical input acceptance into domain validation. Lexical acceptance is not domain existence or mailbox validation.

IPs must be literals, without ports, CIDR prefixes, brackets, zone IDs or surrounding
whitespace. IPv4-mapped IPv6 is normalized to IPv4. Private, loopback, multicast,
documentation and other excluded special-use ranges return network `unknown` with
`non_global_ip` under `ip.network`. Classification conservatively excludes special-purpose IPv6
blocks rather than handling every IANA global exception.

#### Local network intelligence

`/v1/check` accepts `{"ip":"8.8.8.8"}` from an authenticated backend. Existing
country fields (`ip.status`, `ip.reason`, `ip.country_code`, `ip.source`) retain
their country-only meaning. Independent network evidence is returned under
`ip.network`, with `source: "backend_supplied"`: the server credential authenticates the caller,
not the IP's origin. Never pass a browser-provided IP or the application's own IP.

For public addresses, the independent `tor`, `hosting`, `asn`, `vpn`, `datacenter` and `proxy` facts contain
`value`, `status` and `source` provenance. A Tor match is `true`; a hosting
match is `{"providers":["AWS"],"scope":"published_cloud_range"}`; an ASN match
is `{"number":15169,"organization":"Google LLC"}` (illustrative values).
`ip.network.status: "ok"` means at least one network fact is known, not that the
visitor is safe; it does not change `ip.status` or the country estimate.
A `vpn` match is `{"scope":"listed_vpn_range"}`, a `datacenter` match is
`{"scope":"listed_datacenter_range"}` and a `proxy` match is
`{"protocols":["http","socks5"],"scope":"listed_open_proxy"}`.
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
`expires_at_unix`, bounded by both that observation's 24-hour window and the
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

#### Trusted request IPs in collection

Collection automatically evaluates the socket peer, returning
`source: "peer"`. It ignores all forwarding claims unless that peer matches
`OPENFINGERPRINT_TRUSTED_PROXIES`. For a trusted peer, it walks
`X-Forwarded-For` **right to left**, stopping at the first untrusted hop;
untrusted prefixes are not parsed. It accepts at most 16 trusted hops and only
bare IP literals. Missing, duplicate or invalid relevant headers return unknown,
not the proxy's hosting verdict. `Forwarded` and `X-Real-IP` are ignored.

Your public edge must overwrite untrusted forwarding headers, or append its
observed peer through a fully configured trusted chain. Never copy an arbitrary
browser header into an authoritative single-IP field. Configure the CIDRs the API
actually sees, accounting for source NAT, and keep `networkPolicy.apiFrom`
restricted to the intended callers/proxy.

For example, with Nginx directly receiving browser connections:

```nginx
location = /fingerprint/collect {
    access_log off;
    limit_except POST { deny all; }
    client_max_body_size 64k;
    proxy_pass http://openfingerprint.openfingerprint.svc.cluster.local/v1/collect;
    proxy_pass_request_headers off;
    proxy_set_header Content-Type application/json;
    proxy_set_header Origin $http_origin;
    proxy_set_header User-Agent $http_user_agent;
    proxy_set_header Sec-CH-UA-Platform $http_sec_ch_ua_platform;
    proxy_set_header X-Forwarded-For $remote_addr;
}
```

Trust only this proxy's address/CIDR in the API configuration. If Nginx is behind
another proxy, configure its real-IP handling explicitly; this example does not
authenticate upstream forwarding claims. Do not expose the private challenge or
consume routes. Browser credentials are not forwarded. Review proxy/application
error and access logs separately: the API's no-raw-IP retention does not control
other infrastructure's logging.

The browser still receives only an event ID. Its backend-consumed event includes
`ip` network evidence (the same shape as `/v1/check`'s `ip.network`), without
the raw address or forwarding chain; country estimates are not included in the
collected event. Network facts are
evaluated at collection and expired/future-dated matches are nulled again on
consumption. Roll out all API replicas before relying on this behavior. Neither
network facts nor missing evidence alone should authorize or automatically block
a protected action.

### Challenge-bound collection

These routes use the Redis at `OPENFINGERPRINT_REDIS_URL`. Every API replica must
use the same authoritative Redis database, credentials and collection settings.
There is no local-state fallback. A single Redis/Valkey primary is supported,
not Redis Cluster (the atomic scripts operate on multiple keys).

#### 1. Your backend issues a challenge

`POST /v1/challenges` requires the server credential and accepts only:

```json
{"binding":"<64 lowercase hexadecimal characters>","origin":"https://your-app.example"}
```

Generate a random 32-byte binding in your backend and retain it against the
authenticated session and specific action. Never accept the expected binding from
the browser, reuse one across unrelated actions, or send account/session data
instead. Apply your application's authentication, CSRF and issuance limits.
Origin must be an exact canonical HTTPS origin without path, credentials, query
or fragment (HTTP loopback is allowed for development).

The response is `{"challenge":"<random token>","expires_in_ms":120000}`.
Give only the challenge to the browser; do not expose the binding or server key.

#### 2. The SDK submits evidence to your same-origin proxy

Call `identify({ endpoint: '/fingerprint/collect', challenge })`. Automation is
included automatically. Expose only a bounded POST proxy to `POST /v1/collect`:
preserve the browser's Origin, User-Agent and Sec-CH-UA-Platform; strip cookies,
Authorization and other forwarded headers. Do not replace the browser's UA with
the proxy's UA. Require HTTPS and appropriate CSP `connect-src`; cross-origin
CORS and preflight are deliberately unsupported.

The collection body accepts only `challenge`, a full SDK `signals` object with
valid embedded `automation`, and `context`:
`{"userAgent": "<up to 512 UTF-8 bytes or null>", "platform": "<up to 128 bytes or null>", "webrtc": {"addresses": ["<up to 8 IP literals>"]}}`.
Context properties may be omitted; other metadata is rejected. The global 64 KiB
body limit applies. Non-null `storageId` is still rejected. Origin must match
the backend-issued challenge; cookies and Authorization are forbidden.

The server validates evidence, compares submitted UA against the request header,
checks reported headless status against the submitted UA, and compares recognized
Windows/macOS platform observations against Client Hints when present. Missing
or unrecognized evidence stays unknown. A HeadlessChrome token observed in the
request UA adds a headless indicator even if the submitted boolean denies it.
Raw UA/platform values are discarded, not stored in the event. The request IP is
evaluated locally and discarded too; only derived network evidence is stored.

Publishing the evaluated event and consuming the challenge is one atomic Redis
operation. Only one concurrent request can succeed, across API replicas.
The browser gets only `{"event_id":"<random token>"}`; it cannot overwrite the
stored verdict. The SDK returns `{ eventId }`.

#### 3. Your backend consumes the event with the protected action

`POST /v1/events/consume` requires the server credential and accepts only:

```json
{"event_id":"<ID from the browser>","binding":"<expected server-stored action binding>"}
```

Consumption checks the credential scope, expected action binding and expiry,
and atomically deletes the event before returning it. Concurrent consumption
succeeds once. A wrong binding or credential does not destroy the rightful event.
The response contains `event_id`, `created_at_unix_ms`, `expires_at_unix_ms`,
evaluated `signals` (including `automation`), `consistency`, `ip` network evidence
and `request`.
The latter contains the matched `origin` and nullable request-UA
`headless_user_agent` observation, never raw UA/platform strings or an inferred IP.

`consistency` has `rule_version`, `status`, `indicators` and
`unavailable_checks`. Check names are `user_agent_mismatch`,
`headless_evidence_mismatch`, `platform_mismatch`. When the SDK sent
`context.webrtc` (opt-in `webrtcStun`), `rule_version` is 2 and
`webrtc_ip_mismatch` is added: the submitted public WebRTC addresses are compared
with the request IP, on its address family only. A mismatch means none of the
same-family addresses equals the request IP. The check is unknown when the request IP
is not public or trusted, or no same-family address was submitted. Submitted
addresses must be at most 8 IP literals, are never stored or returned, and a
mismatch also occurs behind multi-egress NAT, so treat it as an indicator. Status is `detected` for
any mismatch, `unknown` for incomplete checks without mismatches, otherwise
`not_detected`. This is not a calibrated browser-tampering classifier.

Use this server-owned response for protected decisions, not the browser's raw
`signals`, fingerprint or boolean claims. Missing, mismatched, expired or used
records return 409 `expired_used_or_mismatched`. Redis errors/timeouts return
503 `collection_unavailable`; unavailable collection must not become a trusted
or clean result. Do not retry ambiguous submissions/consumption automatically:
a lost response may follow successful consumption. Restart with a new challenge
and apply application-level action idempotency.

#### Security and retention limits

Challenges and events each expire after the configured TTL, independently.
The per-credential capacity counts both, and expired entries are pruned during
issuance. Redis time controls expiry timestamps, avoiding API-replica clock drift.
No raw browser context, accounts, domains, IPs or visitor history are retained.
Retained data is still pseudonymous and sensitive: configure Redis authentication,
private access, `rediss://` where needed, memory limits and `noeviction`.
Allow the scripting and key/sorted-set commands used by the collector.
Disable persistence/backups when not needed; TTL is not backup erasure.

Atomic single-use guarantees assume one authoritative Redis history. A rollback,
restored backup or asynchronous failover can resurrect consumed state. After
such a rollback, stop old API replicas and rotate affected server credentials
before accepting protected actions; old records are then outside the new scope.
Redis deletion/eviction instead loses pending flows and fails closed.

This flow protects evaluated-result integrity and reuse, not honest execution of
JavaScript. Attackers can still fabricate observations, forge HTTP headers outside
a normal browser, or run fresh automated sessions. Origin checks are browser
constraints, not bot authentication. Transport uses HTTPS, not a browser-held
signing secret, custom encrypted SDK protocol, obfuscation or device attestation.
Combine evidence with application controls; `not_detected` never means trusted.

### SDK evidence

| Field | Shape |
| --- | --- |
| `version` | Integer `4` or `5`. |
| `fingerprint` | Full lowercase SHA-256 string, or null/omitted. |
| `coreFingerprint` | Core lowercase SHA-256 string, or null/omitted. |
| `components`, `hints` | Objects mapping bounded probe names to lowercase SHA-256 strings. |
| `unavailable` | Object mapping probe names to `unsupported`, `unstable`, `timeout` or `error`. |
| `excluded` | Unique subset of `audio`, `canvas`, `screen`. |
| `durationMs` | Finite number from 0 to 60000. |
| `timings` | Optional object of `{ "durationMs": number, "blockingMs": number }` per probe, same numeric bounds. |
| `storageId` | Omitted or null only. |

Each map has at most 32 entries. Names are 1–64 ASCII characters, start with a
letter and otherwise contain letters, digits, underscores or dots. `automation` is the only additional SDK field accepted and is evaluated separately
from identity; it may be omitted by older SDKs. Unknown fields and unsolicited
visitor metadata are rejected. Non-null IDs must match the
canonical hash for the reported schema; changing only the version does not
translate an identity between schemas.

### `POST /v1/verify` (compatibility)

Accepts the original, unwrapped SDK evidence object and retains the exact response:

```json
{"status":"ok","schema_version":5,"fingerprint":"<full fingerprint>"}
```

Without a full ID:

```json
{"status":"insufficient_signals","schema_version":null,"fingerprint":null}
```

Invalid evidence still returns HTTP 400 here, unlike field-level failures inside
`/v1/check`. No evidence counts or additional keys are added to this legacy response.
Both routes use the same canonical verifier and server authentication.

Deploy the compatible API first. Then update callers to wrap evidence in `signals`
and read `response.signals` (which also contains evidence counts), not merely change
the URL. Keep strict schema/ID matching and fail-closed identity writes. Retire
`/v1/verify` only in a later coordinated release once all callers have migrated.
This source change does not migrate or deploy any existing caller.

### HTTP errors and application use

Errors return
`{"error":"<reason>"}`: 400 invalid envelope/evidence, 401 unauthorized, 403 browser
Origin, or 413 oversized body. Unsupported methods return
405. Collection preflight returns 405; collection is same-origin only.

Use a background flow where missing/failed verification leaves the ID unknown,
not blocked authentication. Applications may save a full ID and schema alongside
their own authenticated session/account after privacy review. Compare only within
the same customer and schema; never use a core-only or network-based fallback.

## Metrics

`/metrics` on `OPENFINGERPRINT_METRICS_ADDR` reports dataset health only, never
requests, domains or credentials:

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
| `openfingerprint_mx_lookups_total{result}` | MX lookups by `mx_lookup` outcome. |
| `openfingerprint_txt_lookups_total{result}` | SPF and DMARC TXT lookups by outcome (`resolved`, `no_records`, `no_domain`, `unavailable`). |
| `openfingerprint_dns_tcp_queries_total` | Truncated answers repeated over TCP. |
| `openfingerprint_rdap_lookups_total{result}` | RDAP lookups by `registration.status` (not cache hits or `not_applicable`); `unsupported_tld` counts TLDs with neither RDAP nor WHOIS. |
| `openfingerprint_whois_lookups_total{result}` | WHOIS lookups for TLDs without RDAP, by `registration.status`. |
| `openfingerprint_rdap_cache_total{result}` | RDAP cache hits, misses and errors. Errors mean checks are reaching the registry directly. |
| `openfingerprint_country_data_loaded` | 1 when a valid country database is loaded (not necessarily fresh). |
| `openfingerprint_country_data_expiry_timestamp_seconds` | When the country database stops being used, or 0 when unavailable. |
| `openfingerprint_country_data_reload_failures_total` | Changed country files rejected, including rollbacks to older builds. |

Alert on source expiry, not on `/health`: an expired source silently degrades
domain checks to unknown while the process stays healthy.

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
generates credentials in RAM, boots without a signing key, checks both schemas,
all 15 input combinations, automatic/nested automation rules, partial failures, scoped domain matches, public-suffix
boundaries, fresh/stale/invalid/missing snapshots, strict metadata/body boundaries,
compatibility and no request logging, then stops the
server. Updater checks use local fixtures and verify license-change rejection and
atomic failure preservation. Country checks exercise IPv4/IPv6, special-use ranges,
provenance, expiry, invalid files and live reloads; CI does not download feeds. It prints no credentials or visitor payloads.

With a disposable Redis database, run the cross-replica collection checks too:

```sh
OPENFINGERPRINT_TEST_REDIS_URL=redis://127.0.0.1:6379/15 node api/test-collection.mjs
```

They check racing publication/consumption, binding/tenant isolation, expiry,
capacity, unknowns, input limits and Redis failures. Without that variable this
suite explicitly skips; CI runs it against a Redis service.

`node api/test-network.mjs` checks local facts, IPv4/IPv6, source failure,
license guards, exclusive/crash-recoverable refresh and explicit unknowns. The
Redis environment above additionally enables trusted-proxy, browser-IP rejection,
single-use event and expiry-between-collection-and-consumption checks; CI sets it.
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
credential lifecycle controls and operational/privacy review before relying on it.
