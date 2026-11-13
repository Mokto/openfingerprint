# Experimental Rust check API

Documentation: [openfingerprint.com/docs/api](https://openfingerprint.com/docs/api)

A self-hosted, MIT-licensed backend companion to the browser SDK. It has two listeners:

- **Public, `POST /v1/identify`:** browsers post the SDK's evidence here over TLS. The API
  reads the request's headers and TLS handshake itself, stores them with the evidence for
  an hour, and answers with an `identificationId`.
- **Internal, `POST /v1/check` (and the same check over Connect/gRPC):** your backend sends
  the `identificationId` with any email, domain or IP and gets independent verdicts.

**The internal listener has no authentication.** Keep it on a private network behind
your own backend, gateway or NetworkPolicy; see [Security](#security).

Domain and country intelligence run locally against openly licensed datasets:

| Requested check | Available behavior |
| --- | --- |
| `identificationId` | Schema-1 verification of the browser's evidence, with an optional reconciled `visitorId`, automation, tampering and spoofing verdicts, whether this identification was looked up before (`replayed`) and its age. Profile hashes are not returned. |
| `domain` | Disposable, free-subdomain, public-mailbox, email-relay and source-scoped referrer-spam evidence with provenance and expiry, typo suggestions, MX providers, registration dates and SPF/DMARC status. |
| `email` | Role-account detection for a full address, plus every `domain` check for the address's domain. |
| `ip` | Local country estimate plus independent Tor, ASN, hosting, VPN and open-proxy list evidence under `network`, with source provenance and expiry. Missing facts remain unknown. |

The domain snapshot is bundled and can be overridden with a refreshed local file.
A valid input does not mean a domain is legitimate or an IP is clean. Unlisted or
uncovered domains remain null, not false. The API looks up MX hosts to detect
mail routed to a listed disposable provider, and reports when the registered
domain was created, from its registry over RDAP.
VPN/proxy evidence is list-based and incomplete; domain authority is not implemented. The spam scope is specifically **referrer spam**,
not email-sending reputation. See [sources, licenses and refresh](data/README.md).

The API does not execute browser probes, recognize physical devices, execute
signup decisions or provide Fingerprint Pro feature parity. Probe values can be
forged, and matching hashes can collide or change with settings and updates.

## Data minimization and networking

Domain, email and IP checks have no account history. Their inputs are dropped after processing; an
email address is never logged, cached, echoed or used as a metric label.
Redis holds three kinds of key, all with a TTL: cached RDAP answers keyed by SHA-256
hashes of registered domains, identifications keyed by a SHA-256 hash of their ID for one
hour, and lookup markers for `replayed`, also hashed and expiring with the
identification. None stores an account, address or IP; an identification holds the
browser's evidence, its `User-Agent`, `Accept-Language` and `Sec-CH-UA*` headers, its JA4
TLS fingerprint and the page origin. Request evidence is not logged.
Outbound traffic consists of MX DNS queries, at most one RDAP
request to the domain's registry per uncached check, Redis commands and, only when
`SENTRY_DSN` is set, error reports to Sentry.
Country and network lookups use local datasets only. Their separate updaters
download public datasets without receiving checked IPs or application credentials.
Responses have `Cache-Control: no-store` and set no cookies. Domain/IP inputs are
not echoed in responses. Checks never infer an IP from the connection or forwarded headers:
only an `ip` your backend passes is evaluated. Identification-only calls do not run domain/IP checks.

The process retains read-only domain/country/network datasets; the RDAP cache and
identifications are shared in Redis, not an in-memory fallback. There is no visitor
history unless PostgreSQL-backed [visitor reconciliation](#visitor-reconciliation) is configured.
Its canonical IDs, exact aliases and reference hashes have no automatic expiry. The internal listener does no rate limiting: apply quotas at your gateway. The
public listener limits each client network.

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
There are no registry lookup retries, remote-provider waits or network-based visitor fallbacks.

The SDK hashes identity signals locally and includes bounded automation, tampering and
spoofing evidence outside those hashes. `identify()` posts it to the public listener;
the SDK writes no storage. Hashes are pseudonymous, not anonymous. Your application and
hosting proxy have their own logging, retention, disclosure and access-control
responsibilities.

## Configuration

Provide secrets privately at runtime. Never put them in Git, browser code, image
build arguments, command-line arguments or logs.

| Variable | Meaning |
| --- | --- |
| `OPENFINGERPRINT_LISTEN_ADDR` | Internal listener, default `127.0.0.1:8180`. |
| `OPENFINGERPRINT_IDENTIFY_ADDR` | Required public TLS listener for [`POST /v1/identify`](#post-v1identify-public), for example `0.0.0.0:8443`. |
| `OPENFINGERPRINT_IDENTIFY_CERTS` | Required directory of PEM certificates: `tls.crt` and `tls.key` at its root serve any hostname, and a subdirectory named after a hostname serves that name by SNI, which is how mounted Kubernetes TLS Secrets look. Reread every 5 minutes, so renewed and added certificates are picked up; a broken reload keeps the previous ones. |
| `OPENFINGERPRINT_IDENTIFY_ORIGINS` | Required page origins allowed to post, comma-separated (`https://app.example.com,https://www.example.com`), or `*` for any. Other origins get HTTP 403. |
| `OPENFINGERPRINT_IDENTIFY_LIMIT_PER_MINUTE` | Identifications per client network (an IPv4 address or IPv6 /64) per minute, per replica: 1–1000000, default 60. |
| `OPENFINGERPRINT_IDENTIFY_PROXY_PROTOCOL` | `true` when a load balancer in front sends the PROXY protocol (v1 or v2), so the limit sees client addresses; connections without the header are then dropped. Default `false`. |
| `OPENFINGERPRINT_NETWORK_DATA` | Optional network manifest path. Keep its content-addressed ASN files in the same directory. No bundled/live fallback; absent/invalid data is unknown. Checked every 60 seconds; invalid replacements retain last-good data without extending expiry. |
| `OPENFINGERPRINT_REDIS_URL` | Required private Redis/Valkey connection URL for the RDAP cache, identifications and lookup markers; the API does not start without it. Supports `rediss://` with certificate validation. An unreachable Redis means uncached RDAP lookups, HTTP 503 from `/v1/identify` and unknown identifications; domain and IP checks keep working and there is no memory fallback. Each pod keeps one multiplexed connection for each of these, replaced after any error, timeout or 60 s of idleness; commands are never retried. RDAP cache writes happen after the response (at most 64 in flight; extra writes are dropped and counted as cache errors). |
| `OPENFINGERPRINT_REDIS_PASSWORD` | Optional Redis password, overriding one in the URL, so the URL can live outside a Secret. |
| `OPENFINGERPRINT_POSTGRES_URL` | Optional dedicated PostgreSQL database connection string for visitor reconciliation. Without it, checks return verdicts but no browser identity. TLS is required by default, with certificate and hostname verification; only explicit `sslmode=disable` permits plaintext for trusted local tests. Credentials belong in a Secret. |
| `OPENFINGERPRINT_POSTGRES_PASSWORD` | Optional password override for a URL without credentials. |
| `OPENFINGERPRINT_POSTGRES_CA` | Optional PEM file adding a private PostgreSQL CA to the system roots. No insecure certificate-verification mode exists. |
| `OPENFINGERPRINT_VISITOR_NAMESPACE` | Required with PostgreSQL: 1–64 ASCII letters, digits, underscores or hyphens. Stable deployment boundary, stamped on identifications. Do not change it during rule upgrades. |
| `OPENFINGERPRINT_VISITOR_SCOPE` | Requires PostgreSQL. Optional stable default customer scope for checks without `visitorScope`: 1–128 ASCII letters, digits, underscores or hyphens. Unset preserves the existing unscoped partition and its IDs. Changing it starts a separate identity partition. |
| `OPENFINGERPRINT_VISITOR_REQUIRE_SCOPE` | `true` requires an explicit `visitorScope` on every identification check, rejecting a missing scope with HTTP 400 / RPC `INVALID_ARGUMENT`. Default `false`. Cannot be combined with a default scope. Use this for shared hosted deployments with PostgreSQL. |
| `OPENFINGERPRINT_DOMAIN_DATA` | Optional read-only snapshot path; otherwise uses the bundled snapshot. Missing/invalid overrides yield unknown domain facts without disabling browser verification. |
| `OPENFINGERPRINT_DOMAIN_DATA_RELOAD_SECONDS` | Seconds between checks of the override file, 1–86400, default 60. A changed file that fails to read or parse is rejected and the last valid snapshot stays until its sources expire. |
| `OPENFINGERPRINT_COUNTRY_DATA` | Optional read-only DB-IP Country Lite MMDB path. Without it, IP checks return `unknown/not_configured`. Missing/invalid files yield unknown country results without disabling other checks. |
| `OPENFINGERPRINT_COUNTRY_DATA_RELOAD_SECONDS` | Seconds between country file checks, 1–86400, default 60. Invalid files or older database builds are rejected; the last valid database remains until it expires. |
| `OPENFINGERPRINT_DNS` | Nameserver for MX lookups, default `system` (the first `nameserver` in `/etc/resolv.conf`). Also accepts an IP, `IP:port` or `host:port` (resolved once at startup). Startup fails without a usable nameserver. |
| `OPENFINGERPRINT_WHOIS_SERVERS` | Optional path to a `{"servers": {"tld": "host"}}` file replacing the bundled WHOIS server list; `host:port` is allowed, for local test servers. |
| `OPENFINGERPRINT_RDAP_BOOTSTRAP` | Optional path to an IANA RDAP bootstrap file replacing the bundled one; read at startup. It may contain `http://` servers, for local test registries. |
| `OPENFINGERPRINT_METRICS_ADDR` | Optional listener for Prometheus `GET /metrics`, for example `0.0.0.0:9180`. Keep it off the API port so network policy can expose it separately. |
| `SENTRY_DSN` | Optional. Enables error reporting to Sentry: panics, HTTP 5xx responses and rejected snapshot reloads, as static messages with release (`CARGO_PKG_VERSION`) and stack traces. Request data, headers, IPs, users and breadcrumbs are removed before sending, so evidence, hashes, credentials and identification IDs are never reported. `SENTRY_ENVIRONMENT` optionally sets the environment. With `networkPolicy.enabled`, `networkPolicy.rdapTo` must allow HTTPS to your Sentry ingest host; the default allows all public addresses. |

## Security

The internal listener has no authentication or keys. `visitorScope` partitions identity
data but does not authenticate or authorize a tenant. Whoever can reach the listener
can select any scope, and domain checks can make DNS, RDAP and WHOIS requests from your server's
addresses. Deploy it so that only your backend can connect:

- Keep its Service private: no Ingress, no public load balancer. With the
  [Helm chart](chart/README.md), enable `networkPolicy` and list your backend's pods
  in `networkPolicy.apiFrom`; the chart's default allows any pod in the cluster.
- If a gateway exposes it, put your own authentication, quotas and request limits there.
- A request that carries an `Origin` header is refused (HTTP 403), so a web page cannot
  call it from a visitor's browser. There is no CORS and no preflight.
- Every route requires `Content-Type: application/json`; bodies are limited to 64 KiB.

The public listener is meant to face the Internet. It terminates TLS itself, accepts only
`POST /v1/identify` from the configured origins, limits each client network, and takes
nothing but SDK evidence, so a page cannot make your server run domain or IP lookups
through it.

The internal listener does not terminate TLS. Terminate it in front if traffic leaves a
trusted network; cluster-local HTTP and NetworkPolicy do not encrypt traffic. No
dashboard, SDK hosting, billing or tenant-management endpoint is provided.

## Endpoints

The internal routes require `Content-Type: application/json` and refuse any request with
an `Origin` header; there is no authentication ([Security](#security)) and no CORS.
`POST /v1/identify` on the public listener is the only browser-facing route.

### `GET /health`

Internal listener. No body. Returns HTTP 200 with plain text `ok`. This is process
liveness, not evidence quality, dataset coverage or identification accuracy.

### `POST /v1/identify` (public)

The SDK's `identify({ endpoint })` posts its evidence here as JSON in a `text/plain` body
(a simple CORS request, no preflight). The listener:

1. checks the `Origin` against `OPENFINGERPRINT_IDENTIFY_ORIGINS`, the per-network limit
   and the evidence's validity;
2. reads the JA4 fingerprint of the TLS ClientHello and the `User-Agent`,
   `Accept-Language` and `Sec-CH-UA*` headers of the request;
3. stores them with the evidence and the page origin for one hour under a random
   128-bit ID, and answers `{"identificationId":"<22 characters>"}` with
   `Access-Control-Allow-Origin`.

Errors are `{"error":"<reason>"}`: 403 `origin_not_allowed`, 400 `invalid_evidence`,
429 `rate_limited` and 503 `identify_unavailable` (Redis could not store it); the SDK
then resolves with `identificationId: null`.

The listener terminates TLS itself, because a proxy that terminates TLS hides the
handshake. Route its port with TCP passthrough (a Kubernetes `LoadBalancer` Service,
Traefik `IngressRouteTCP` with `passthrough`, nginx `stream` or HAProxy `mode tcp`) and set
`OPENFINGERPRINT_IDENTIFY_PROXY_PROTOCOL=true` if the load balancer sends the PROXY
protocol. It serves HTTP/1.1 and HTTP/2 with ALPN. To serve customers' own subdomains
(`fp.customer.example` as a CNAME to the listener, which ad-block lists do not catch),
add a certificate directory per hostname.

What this proves and what it does not: a script must connect with its own TLS stack, and
a library's handshake under a browser user agent is reported as
[`tls_mismatch`](#spoofing-indicators). Unlisted handshakes (other browser versions,
company TLS inspection) stay unknown rather than flagged. A real browser driven by
automation has a real browser handshake, and libraries built to imitate Chrome's handshake
exist, so `tls_mismatch: false` does not show a human; the automation probes cover the
first case. The reference fingerprints in [src/tls.rs](src/tls.rs) were measured in
November 2026 and need updating as browsers and libraries change. JA4 is the
[FoxIO](https://github.com/FoxIO-LLC/ja4) TLS client fingerprint (BSD 3-Clause).

### `POST /v1/check` (internal)

The JSON object accepts only these fields:

| Field | Shape |
| --- | --- |
| `identificationId` | Optional ID from `/v1/identify`, which your page passes to your backend. |
| `visitorScope` | Optional stable customer/account scope selected by your trusted backend: 1–128 ASCII letters, digits, underscores or hyphens. Requires `identificationId`. Does not identify the browser or authorize access. See [Customer scopes](#customer-scopes). |
| `domain` | Optional ASCII hostname, not a URL or complete email address. |
| `email` | Optional full email address. Its domain gets the `domain` checks, so it cannot be combined with `domain`. |
| `ip` | Optional visitor IPv4/IPv6 literal supplied by your trusted backend. |
| `detail` | Optional boolean, default false. `true` returns the full response described in this guide, with evidence counts, rule metadata and per-source provenance. |

By default the response is one flat object of verdicts:

```json
{"visitorId":"<resolved visitor ID, when available>",
 "replayed":false,
 "ageMs":1830,
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

A key that is missing means unknown, so there are no `null` facts.

| Key | Meaning |
| --- | --- |
| `visitorId` | Server-issued browser grouping from [visitor reconciliation](#visitor-reconciliation). Absent without PostgreSQL or when resolution is unknown. Never falls back to a fingerprint. |
| `replayed`, `ageMs` | Whether this identification was looked up before, and milliseconds since it was stored, by the API's clock. See [Replays and age](#replays-and-age). |
| `automation`, `tampering` | The browser reported automation tooling, or altered canvas/audio readback. |
| `spoofing` | The browser's own report contradicts the request the public listener received: its headers or its TLS handshake. |
| `behavior` | [Input patterns](#behavior-patterns) since the page called the SDK's `watch()`, as a list. Context, not a verdict. Only for pages that call `watch()`. |
| `suspiciousClickPattern` | Repeated mouse clicks match both click patterns below. Context only, separate from `automation`; omitted when evidence is missing, legacy or insufficient. |
| `disposable`, `free`, `spam`, `relay`, `cheapTld`, `mx` | From `domain` or the domain of `email`. `free` is a public mailbox; `cheapTld` says the TLD is one registrars sell at teaser prices; `mx` says the domain has mail servers. |
| `country`, `vpn`, `tor`, `datacenter`, `proxy` | From `ip`. `country` is a lowercase ISO 3166-1 alpha-2 code. |
| `invalid` | Only present when an input was rejected: a list of `identificationId` (malformed, unknown or expired), `domain`, `email` and/or `ip`. |

`email` and `domain` give the same keys. Everything else (evidence counts, indicator
lists, rule versions, role account, ASN and hosting provider, MX providers,
SPF/DMARC, registration date, suggested domain, `mx_listed` provenance, uppercase
`countryCode`, sources, and rejection reasons) is only in the `detail: true` response.

**Breaking change:** checks no longer return `fingerprint` or `evidence.identityGroups`,
including with `detail: true`. Use `visitorId` for application identity. Without
PostgreSQL, checks return verdicts but no browser identity. Internal hash verification,
visitor matching and the SDK's `identify()` response are unchanged.

The rest of this guide describes the `detail: true` shape.

Response keys are camelCase; enumerated values such as `not_listed` or
`invalid_input` stay snake_case. At least one non-null field is required. Null is equivalent to omission. Results
contain only requested non-null sections. Inputs can be combined in any order;
there is no cross-input identity merging, and domain/IP never change the browser ID.

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

With valid full SDK evidence, the `identification` section is:

```json
{
  "status":"ok",
  "schema_version":1,
  "evidence":{
    "includedComponents":2,
    "includedHints":1,
    "unavailableProbes":3,
    "excludedProbes":3
  },
  "automation":{"status":"not_detected","ruleVersion":7,"source":"client_reported","indicators":[],"unavailableProbes":[]},
  "tampering":{"status":"not_detected","rule_version":1,"source":"client_reported","indicators":[],"unavailable_probes":[]},
  "spoofing":{"status":"not_detected","ruleVersion":1,"source":"client_reported_vs_request_headers","indicators":[],"unavailableProbes":[]},
  "replayed":false,
  "ageMs":1830,
  "origin":"https://app.example.com",
  "ja4":"t13d1517h2_8daaf6152771_cb7bf5808d99",
  "tlsClient":"chromium"
}
```

`tlsClient` is the client the JA4 matched in the reference table (`chromium`, `firefox`,
`apple`, `curl`, `python`, `go` or `node`), omitted when it matched none.

Counts describe the submitted, validated evidence, not entropy, probability,
confidence, a risk score or honest probe execution. Included counts omit excluded
probes. Unavailable and excluded counts are separate and may overlap.

The API verifies full profile hashes inside the submitted evidence but never returns
them or the partial identity-group hashes. Those hashes remain internal matching inputs.
Removing them from responses does not add customer isolation: deployments still need a
trusted tenant boundary. Browser-side `collect()` still returns its local evidence;
this change does not prevent independent fingerprint collection or correlation.

Valid evidence without a full ID has `status: insufficient_signals`, null schema
and evidence counts. A core ID never substitutes for a full ID.
An unknown or expired identification has `status: invalid_input` with `reason:
unknown_identification` (or `invalid_identification_id` for a malformed ID) and null
schema and evidence; when Redis cannot answer it has `status: unavailable`
and `reason: identification_unavailable`. Neither discards another section's result.

Domain/email/IP sections return `invalid_input` with `invalid_domain`, `invalid_email` or `invalid_ip`
for invalid values, including wrong field types. HTTP 200 means the envelope was processed,
not that every check succeeded: inspect each requested section. Valid sections
survive failures in other sections; there is no combined clean/fraud verdict.

Malformed JSON, non-object envelopes, empty/all-null requests and unknown top-level
fields, and `domain` together with `email`, return HTTP 400. Apart from the explicit
`visitorScope`, account metadata and raw browser context are not additional inputs. All request bodies are limited to
64 KiB, including nested evidence, before evaluation.

#### Automation indicators

The SDK reports automation observations in its evidence, and `/v1/check` returns their
evaluation as `identification.automation`:

```json
{
  "automation": {
    "status": "detected",
    "ruleVersion": 7,
    "source": "client_reported",
    "indicators": ["webdriver"],
    "unavailableProbes": ["phantom_artifacts", "platform_mismatch"]
  }
}
```

The evidence must be `version: 7` with these optional booleans and nothing else; the
listener rejects other versions and unknown fields with `invalid_evidence`. Null or
omitted observations remain unknown. `indicators` and `unavailableProbes` list
snake_case names in this order:

| Evidence field | Name | `true` means |
| --- | --- | --- |
| `webdriver` | `webdriver` | `navigator.webdriver` is true. |
| `headlessUserAgent` | `headless_user_agent` | UA contains `HeadlessChrome/`, or a `userAgentData` brand is `HeadlessChrome`. |
| `seleniumArtifacts` | `selenium_artifacts` | A Selenium global exists on `document`. |
| `phantomArtifacts` | `phantom_artifacts` | A Phantom global exists on `window`. |
| `platformMismatch` | `platform_mismatch` | UA OS family contradicts `navigator.platform` or `userAgentData.platform`. |
| `missingChromeObject` | `missing_chrome_object` | A Chromium UA (not WebView) without `window.chrome`. |
| `notificationPermissionQuirk` | `notification_permission_quirk` | `Notification.permission` is `denied` while the Permissions API reports `prompt`. |
| `emptyPlugins` | `empty_plugins` | Desktop Chromium with no `navigator.plugins`. |
| `emptyLanguages` | `empty_languages` | `navigator.languages` is empty. |
| `softwareRenderer` | `software_renderer` | Unmasked WebGL renderer is SwiftShader, llvmpipe, softpipe or similar. |
| `zeroDimensions` | `zero_dimensions` | Screen or outer-window width/height is 0 (a 0x0 outer window in a hidden, background tab is unknown instead). |
| `cdpDetected` | `cdp_detected` | Logging an error formatted its stack (V8 called `Error.prepareStackTrace`), which happens only while a CDP client has `Runtime.enable` on, as Puppeteer, Playwright, ChromeDriver and open DevTools do. Clients that avoid `Runtime.enable`, such as nodriver or rebrowser-patches, are not seen. |
| `nativeFunctionTampering` | `native_function_tampering` | The `navigator.webdriver` getter or `Permissions.prototype.query` is not native when read with an untouched `toString`, `Function.prototype.toString.call({})` does not throw, a `Proxy` wraps either native, `navigator` has an own `webdriver`, the `webdriver` getter was deleted, or a detached `srcdoc` frame has a window (puppeteer-extra-plugin-stealth). |
| `workerUserAgentMismatch` | `worker_user_agent_mismatch` | A dedicated worker reports a different UA or platform than the main thread. |
| `driverArtifacts` | `driver_artifacts` | A ChromeDriver, WebDriver, Watir, Playwright-binding, NightmareJS or `domAutomation` global, or a driver attribute on `<html>`. |
| `engineMismatch` | `engine_mismatch` | The JavaScript engine is not the one the UA claims (V8, SpiderMonkey or JavaScriptCore). |
| `userAgentDataMismatch` | `user_agent_data_mismatch` | The `Chromium` brand major version differs from the UA's `Chrome/` major version. |
| `proportionalMonospace` | `proportional_monospace` | The generic `monospace` font is not fixed-width (Camoufox claiming another OS than its host). |
| `engineApiMismatch` | `engine_api_mismatch` | `userAgentData` is not a `NavigatorUAData`, or a Chrome 120+ UA lacks APIs Chrome shipped by version 105 (engines imitating Chrome, such as Obscura). |
| `protocolScript` | `protocol_script` | After the SDK's `watch()`, code compiled by a debugging protocol (CDP `Runtime.evaluate`, Puppeteer, ChromeDriver, Firefox's Debugger API) called a trapped DOM method in the page's own world. Also set by typing in the DevTools console. |


The rule reports `detected` if any observation is true, `unknown` if none is true and
any is unavailable, or `not_detected` only if every observation is false. The exception is
`protocol_script`: it is null whenever the page did not call `watch()`, and in WebKit, so it
is listed in `unavailableProbes` then but does not make the verdict `unknown`.

These rules interpret client reports, not attested browser execution. Evidence
can be forged or hidden. `not_detected` is not proof of a human, and automation
may be legitimate testing or assistive tooling, not malicious traffic. No
good/bad bot classification, confidence, fraud score, retention or new outbound
traffic is introduced. Deploy the API before upgrading the SDK: the listener accepts
only the evidence version it defines.

#### Tampering indicators

The evidence also carries tampering observations, and `/v1/check` returns their
evaluation as `identification.tampering`, separate from `automation` on purpose: privacy browsers
and anti-fingerprinting extensions trigger it for ordinary people, so it must never
read as automation. The response has the automation shape (`status`, `rule_version: 1`,
`source: "client_reported"`, `indicators`, `unavailable_probes`) with these names:

| Evidence field | Name | `true` means |
| --- | --- | --- |
| `canvasReadbackAltered` | `canvas_readback_altered` | A 16x16 canvas of opaque flat colors did not read back exactly. Clean engines always read it exactly; noise injection (Brave farbling, canvas-noise extensions) or Firefox resistFingerprinting changes it. |
| `audioRenderAltered` | `audio_render_altered` | An offline render of a constant 0.5 signal returned any other sample. |

Evidence accepts only `version: 1` and these two optional booleans; anything else is
rejected by the listener. Missing or throwing probes stay null (unknown). The probes use
fixed content, add no identity hash input and never change the fingerprint. A result
shows that something altered readback in this browser, not who or why; a clean result
does not rule out tampering that spares these two reads, such as a spoofed value.

#### Behavior patterns

After the SDK's `watch()`, the evidence carries `behavior`: counts of trusted pointer,
click, key, touch and wheel input since the page called it (see the
[SDK guide](../sdk/README.md#watching-the-page)). `/v1/check` returns
`identification.behavior` with `status: "observed"`, `ruleVersion: 2`,
`source: "client_reported"` and the `patterns` that matched:

| Pattern | Matches when |
| --- | --- |
| `clicks_without_movement` | Every mouse click (at least one) had at most one trusted mouse pointer-move event before its press, since the previous trusted press or watcher start. Event count, not distance. |
| `centered_clicks` | Every mouse click (at least one) landed within ±1 CSS px on both axes of its clicked element's bounding-box centre; both dimensions exceed 4 px. |
| `instant_keys` | At least half of the key presses were released within 5 ms. |
| `text_without_keys` | Text was inserted without a key press before it (CDP `Input.insertText`, Playwright's `fill`). |
| `no_input` | No pointer move, click, key press, inserted text, touch or wheel event at all. |

The compact response lists them as `behavior` (an empty list when none matched). These
are context for your own rules, not a verdict, and they never change `automation`:
keyboard-only users, autofill, dictation, on-screen keyboards and identifications made
at page load match some of them. Evidence accepts `version: 1` or `version: 2` with the
same exact fields and every count as a non-negative integer. Version 2 requires a mouse
press as well as a mouse click, fixing WebKit touch compatibility clicks that version 1
could miscount. Deploy this compatible API before an SDK emitting version 2. The
behavior evaluation is now `ruleVersion: 2` for the new context flag below; the existing
pattern meanings have not changed.
Evidence without `watch()` has no section, not an empty/clean evaluation. An observed
zero-input snapshot matches `no_input`, not automation.

A single stationary click is not proof of automation. Neither are repeated stationary or
centred clicks: double-clicks, a late watcher and assistive mouse input can produce them;
automation can generate trusted events and evade both patterns with movement and
off-centre clicks. These are behavioral context, never automatic bot verdicts or
signup/login blocking rules. See the [controlled study](../evaluation/behavior.md) for
sample-size guidance and limitations. No transmitted counters or identity inputs were
added.

##### Suspicious click pattern

The API derives `suspiciousClickPattern` from those same aggregates, with no additional
SDK collection. It is a **reviewable pattern, not a bot verdict**, and never changes
`automation`, identity hashes or protected-action decisions.

| Value | Meaning |
| --- | --- |
| `true` | Behavior evidence v2 has at least 3 mouse clicks and every click matches **both** `clicks_without_movement` and `centered_clicks`. |
| `false` | Behavior evidence v2 has at least 3 mouse clicks, but that combination does not match. This does not establish human input. |
| Unknown | No watcher evidence, fewer than 3 mouse clicks, unavailable/invalid identification, or legacy behavior evidence v1. V1 remains accepted, but its known touch ambiguity cannot produce a reliable mouse-only flag. |

Three is an initial minimum sample floor excluding a single click or a lone double-click,
**not a calibrated automation threshold**. Ordinary stationary repeats, a late watcher,
changing layouts and assistive mouse input can still return `true`. Automation that adds
movement or clicks off-centre can return `false`. Keyboard and touch activations do not
supply the required mouse samples in v2; identification before input stays unknown.
The SDK's cumulative totals are not independent samples or a sliding window.

The compact REST/Connect response exposes this boolean at the top level when known.
Unknown is omitted, following the existing compact convention. With `detail: true`,
REST includes `identification.behavior.suspiciousClickPattern` as `true`, `false` or
`null`; the behavior section itself remains absent without watcher evidence. RPC also
has the top-level optional boolean and the optional boolean inside `BehaviorCheck`.
Unknown is unset/omitted in protobuf/Connect JSON, never encoded as `false`. For compact
JavaScript callers, `result.suspiciousClickPattern ?? null` normalizes missing to null.

Only the API changes. Existing behavior evidence versions 1 and 2 are still accepted;
old clients can ignore the additive response fields. Regenerate RPC clients to read
`CheckResponse.suspicious_click_pattern` (field 23) and
`BehaviorCheck.suspicious_click_pattern` (field 6); existing field numbers are unchanged.
There is no SDK evidence upgrade, new telemetry or rollout configuration.

#### Spoofing indicators

The SDK puts the browser's own `navigator.userAgent`, `navigator.language` and
low-entropy client hints (`navigator.userAgentData` brands, mobile, platform) in its
evidence, as read, under `spoofing`. `/v1/check` compares them with the request the public
listener received and returns `identification.spoofing` (compact: `spoofing`). The section
has the automation shape (`status`, `ruleVersion: 1`,
`source: "client_reported_vs_request_headers"`, `indicators`, `unavailableProbes`):

| Name | `true` means | Unknown when |
| --- | --- | --- |
| `user_agent_mismatch` | The reported user agent differs from `User-Agent`. | Either side is missing. |
| `client_hints_mismatch` | The reported brands (in any order), mobile flag or platform differ from `Sec-CH-UA`, `Sec-CH-UA-Mobile` and `Sec-CH-UA-Platform`. | Only one side has client hints, or a header does not parse. Neither side having them (Firefox, Safari) counts as agreement. |
| `language_mismatch` | The primary subtag of the reported language differs from the first `Accept-Language` tag (`en-US` and `en` agree, as WebKit reports `ja` while sending `ja-JP`). | Either side is missing or `*`. |
| `tls_mismatch` | The TLS handshake matches a known client other than the browser the user agent names: Chrome evidence posted by curl, Python, Go or Node, or a Firefox user agent on Chrome's handshake. | The JA4 is not in the reference table, or the user agent names no known browser. |

Both sides come from the same browser, so they agree for ordinary visitors in
Chromium, Firefox and WebKit. A mismatch means the evidence and the request did not come
from the same unmodified browser: a user-agent switcher that changes one side only,
evidence captured in one browser and posted from another client, or forged evidence
posted by a script. It is not proof of intent. A script can send matching headers, and
some libraries imitate a browser's handshake, so `not_detected` does not show the browser
is genuine. Headless Chromium sends no `Accept-Language` by default; that leaves the
language probe unknown rather than positive. A time zone or IP comparison is deliberately
not part of this check, since VPN users and travellers would fail it.

Unlike `tampering`, which reports altered canvas or audio readback in the browser (often a
privacy tool), `spoofing` compares the evidence with the request around it. The user
agent, language and client hints are stored with the identification for its hour, as the
request headers they are compared with are; the API never logs them.

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
A `vpn` match is `{"scope":"listed_vpn_range"}` for a listed network or
`{"scope":"listed_vpn_server"}` for an exact address in the provider-server lists.
The latter is VPN infrastructure association, not a verified browsing exit or
provider identity. A `datacenter` match is
`{"scope":"listed_datacenter_range"}` and a `proxy` match is
`{"protocols":["http","socks5"],"scope":"listed_open_proxy"}`. These objects are in the
`detail: true` response; the default response and the RPC message carry `true` for a
listed `vpn`, `tor`, `datacenter` or `proxy` and leave the key out otherwise.
No match yields null, never false or a residential/human verdict. Facts for a source
that is not loaded report `not_configured`. Residential proxies and VPNs missing from the
lists are not detected, and datacenter ranges include VPN ranges as the upstream defines them.

VPN detection uses the public lists below; no VPN accounts, profiles or live
VPN connections are required. The existing network updater downloads the lists
hourly in `--loop` mode or when scheduled hourly. Refreshing does not fill gaps
in the upstream lists: unlisted PrivateVPN addresses or other missing providers
remain unknown. Tunnel endpoint DNS and hosting/datacenter matches alone are not
proof that an address is a VPN exit.

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
| [Joe12387 Open Source VPN IP Lists](https://github.com/Joe12387/open-source-vpn-ip-lists) | Exact IPv4/IPv6 addresses from ten provider-server lists: AirVPN, IVPN, Mullvad, NordVPN, OVPN, PIA, ProtonVPN, RiseupVPN, Surfshark and Windscribe. The upstream describes first-party provider data, including entry addresses: association is not proof of egress, and retired IPs may linger. No CIDR expansion or hosting inference. Does not include PrivateVPN (which is different from PIA). | CC0-1.0; exact license pinned and retained in the manifest. | 7 days from the earlier of the README's declared publication day (UTC midnight) and its commit time. |
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
snapshot expiry. The API rechecks both limits on each lookup and retains no checked
address.

Upgrade API readers before the network updater. The optional `vpn_servers`
snapshot source requires the new reader; older readers reject that field and
retain their last-good manifest. Its refresh and expiry are independent of X4B;
one source failing never renews the other's timestamps. Existing X4B matches
keep their original scope/provenance, with server-list matches used as a fallback.
A failed provider-list download rejects the entire server-list refresh instead
of publishing partial data as a newly refreshed complete list.

Old bare-address Tor entries
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

`/v1/identify` validates the evidence the SDK posts as follows:

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
| `automation`, `tampering`, `spoofing`, `behavior` | Optional evidence, as described above. |

Each map has at most 32 entries. Names are 1–64 ASCII characters, start with a
letter and otherwise contain letters, digits, underscores or dots. Unknown fields and
unsolicited visitor metadata are rejected. Non-null IDs must match the canonical hash
for the reported schema; changing only the version does not translate an identity
between schemas.

#### Replays and age

- `replayed` (`identification.replayed` with `detail: true`): `false` the first time an
  identification is looked up, `true` after that. One hashed marker per identification,
  expiring with it. When Redis cannot answer, the field is absent, never `false`.
- `ageMs` (`identification.ageMs`): milliseconds since the listener stored the
  identification, by the API's clock.

An identification can be looked up more than once within its hour, so a signup flow that
checks it at two steps keeps working; treat `replayed` as a signal for your own rules,
such as one identification per signup, not as a block.

### Visitor reconciliation

Configure a **dedicated database and least-privilege role** on an existing PostgreSQL
cluster, then apply migrations explicitly before relying on visitor results:

```sh
cargo build --manifest-path api/Cargo.toml --locked
# Supply OPENFINGERPRINT_POSTGRES_URL and OPENFINGERPRINT_VISITOR_NAMESPACE privately.
./api/target/debug/openfingerprint-api --migrate-visitors
```

Normal API startup never runs DDL. Missing migrations or an unavailable database leave
visitor identity unavailable; they do not create a memory/Redis replacement. The API
uses at most eight PostgreSQL connections per replica and a two-second resolution budget.
Redis must still supply the identification before any identity lookup, even when a
PostgreSQL decision already exists.

#### Three different identifiers

- `identificationId`: a random 128-bit reference to one hour-long observation.
- `fingerprint`: the deterministic evidence hash, submitted by the SDK and used
  internally, never returned by checks. Its hashing, meaning and storage keys are unchanged.
- `visitorId`: a separate random 128-bit server-issued reference to a retained browser
  evidence grouping. It is not an account, authentication credential or physical-device ID.

With PostgreSQL configured, successful compact checks add `visitorId`. It is absent
when unknown. With `detail: true`, `identification.visitorId` carries the same value and
`identification.reconciliation` explains the decision: `status`, `ruleVersion`,
optional `visitorId` and `method`. Identification verification and reconciliation
statuses remain independent. Without PostgreSQL, visitor fields are absent and checks
return no browser identity.

Statuses include `resolved`, `insufficient_evidence`, `ambiguous`, `unavailable`,
`namespace_mismatch`, `invalid_site`, `invalid_observation_time` and
`expired_identification`; `invalid_evidence` is returned for rejected stored evidence.
Methods are `new`, `exact` and `locale-v1`. These are categorical decisions, not
confidence percentages or calibrated accuracy claims.

#### Initial rules

Visitor issuance requires a verified non-null full fingerprint and every expected
policy-included schema-1 probe in its expected component/hint map. Unknown names,
incomplete included evidence and unrecognized exclusion masks cannot mint visitors,
even if the older fingerprint verifier can verify their smaller profiles.

The supported masks are the empty mask and the SDK's Safari 17+ mask
(`audio`, `canvas`, `screen`). Excluded diagnostics are not required. The latter
mask is exact-only; eligibility is based on the evidence policy, not a second
user-agent classifier.

1. An exact full SHA-256 match in the same deployment/customer partition, canonical origin and schema
   returns its existing visitor.
2. Migration 002 adds `locale-v1`: all six rendering components and every hint except
   `locale` must equal an immutable reference profile. All four complete identity
   groups must match too, with the same schema and exclusions. This permits language
   or time-zone changes, not arbitrary hardware, software or rendering changes.
3. Candidate retrieval is an indexed composite-signature lookup capped at eight
   visitors plus an overflow sentinel. Multiple candidates abstain; none is selected
   by score, ordering or group count. Existing exact mappings take precedence.
4. Sufficient evidence without a qualifying candidate creates a visitor. Partial
   groups and core-only matches never authorize reconciliation.
5. Accepted changed fingerprints become permanent exact aliases. They do not become
   new reference profiles. Existing visitors are never automatically merged, and
   a chain of small changes cannot expand the baseline.

These groups are correlated, not independent votes. The locale rule is a narrow
experimental policy, **not independently calibrated on real devices**. Identical
non-locale evidence can belong to different browsers; the rule can then merge their
observations. Even exact evidence cannot distinguish identical configurations.
Browser updates and cumulative changes outside the rule can still split a returning
browser. Neither a visitor ID nor absence of automation establishes trust.

Automation, tampering, spoofing and behavior verdicts, network inputs, headers and
JA4 never participate in matching. The SDK gains no probes, cache, cookies or stored
identity; `identify()` still returns only `{ identificationId }`.

#### Customer scopes

Your trusted backend can select a customer/account partition on each check:

```json
{"identificationId":"<ID from /v1/identify>","visitorScope":"customer-account-id"}
```

For shared hosting, set `OPENFINGERPRINT_VISITOR_REQUIRE_SCOPE=true` and inject the
scope from the authenticated customer account. Reject or overwrite a caller-supplied
scope; never trust a browser, API-key owner or request body to choose another customer's
partition. Use the stable customer/organization ID, not an end user's ID or API key.

The scope can be an opaque account ID or an optional hex/base64url
`HMAC-SHA256(platformSecret, "openfingerprint:scope:v1:" + accountId)` calculated by the
trusted backend. Send only the HMAC result; keep the secret server-side and stable.
The API treats it as an opaque scope, not a signature it verifies. Changing the scope
or HMAC secret selects a different partition.

Every exact match, candidate index, reference profile, exact alias, frozen decision
and reconciliation lock uses the partition. Visitor IDs are independently random
128-bit values, not transformations of a global visitor ID. Knowing one customer's ID
does not provide a conversion to another customer's. Scopes are not returned or logged.

A request scope overrides `OPENFINGERPRINT_VISITOR_SCOPE`. Without either, existing
unscoped identities remain unchanged. A configured default is useful for single-customer
self-hosting; required-scope mode forbids a default to avoid accidental shared fallback.
Startup rejects configured scoping without PostgreSQL rather than silently disabling it.
New scoped partitions never adopt old unscoped IDs or aliases. Existing data is retained;
switching existing callers to scopes intentionally starts new visitor identities.
Domain/email/IP-only checks do not need a scope. A supplied malformed scope is rejected
even without PostgreSQL; a valid scope cannot produce visitor IDs without PostgreSQL.

No schema migration is needed. Existing indexed `namespace` keys store
`<deployment>:scope:v1:<lowercase SHA-256 of scope>` for scoped data; no raw account
ID or scope is retained. Deployment namespaces cannot contain colons, so these keys
cannot collide with a legacy unscoped namespace. Hashing is not secrecy for guessable
account IDs; use the optional HMAC if those IDs should not reach this service.
SQL/rule migration history remains deployment-wide.

#### Isolation, retention and concurrency

Set a stable deployment namespace. New identifications are stamped with it by the
server; legacy observations without one and records from another deployment cannot
acquire visitors. Customer scopes subdivide that deployment. Exact canonical origins
remain separate site partitions: subdomains are not joined. Origin is browser-supplied
and forgeable, **not authentication**. The public identify listener and SDK do not
accept customer scopes; the trusted backend selects one when checking the observation.

The scope does not prove who owns an `identificationId` or restrict who may look it up.
Protect these short-lived references and enforce customer authorization in the gateway.
The internal listener must remain private; required-scope mode is not authentication.
`replayed` remains an observation-wide lookup signal, not a per-customer visitor key.

PostgreSQL retains visitor references, original component/hint and group hashes,
exclusion/schema metadata, exact aliases and migration history until explicit deletion.
There is no 30-day rotation or inactivity expiry. No IP, raw header, raw probe, JA4,
account, email or behavioral history is copied into this store. Hashes remain
pseudonymous data, including low-entropy values that can be guessed.

Identification decisions expire at the original observation deadline, not one hour
after the first lookup. Expired decisions cannot be read and are pruned in indexed
batches of 1,000, normally every minute, draining additional batches immediately.
Physical deletion can lag during an outage or backlog; backups need their own retention
and deletion policy. Canonical profiles and exact aliases are not pruned.

A transaction takes a shared migration lock and deterministic identification/signature
locks before reading candidates or writing visitors, aliases and decisions together.
Concurrent API replicas, including distinct identifications with equivalent qualifying
evidence, converge on one visitor. Decisions are immutable for the life of an
identification within its customer partition, including insufficient and ambiguous results. Failed transactions roll
back. A lost response is retried by reading the committed decision; database/Redis
failures remain unknown instead of generating replacement IDs.

The continuity guarantee depends on retaining the authoritative database and its
acknowledged writes. Use durable storage, tested backups and a failover policy matching
your recovery-point requirement. Recovering an old backup can lose newer identities;
no matching algorithm repairs lost authoritative history. Configure gateway quotas and
database capacity for indefinite alias growth. Storage rejection is unavailable, never
a reason to evict identities or mint substitutes.

For an approved full namespace deletion, an operator can run parameterized equivalents
of the following transaction against this dedicated database:

```sql
BEGIN;
DELETE FROM of_resolutions
WHERE namespace = 'your_namespace' OR starts_with(namespace, 'your_namespace:scope:v1:');
DELETE FROM of_visitors
WHERE namespace = 'your_namespace' OR starts_with(namespace, 'your_namespace:scope:v1:');
COMMIT;
```

This removes both legacy and scoped data for the deployment. For one customer only,
compute its exact partition key as described above and delete by equality instead.
Visitor deletion cascades to exact aliases and rule indexes. Coordinate deletion with
writers and backup retention; ongoing traffic can create new identities. There is no
public deletion or account-linking endpoint.

#### Forward migrations and later rules

Committed SQL in `api/migrations/` is append-only. `--migrate-visitors` checks ordered
migration checksums, rejects edited/unsupported histories, and applies each pending
migration transactionally under an exclusive database advisory lock. An interrupted
migration rolls back; rerunning resumes after the last committed migration.

Migration 001 establishes durable exact matching. Migration 002 backfills locale
indexes from retained immutable reference hashes, **without assigning or merging IDs**.
An index may reference several existing visitors; that makes future fuzzy lookups
ambiguous while their established exact mappings stay intact.

To add a rule, add a new numbered SQL migration and register it in `MIGRATIONS` in
`src/visitor.rs`, implement its bounded comparison and locking, and extend the labelled
regression cases. Derive new indexes only from available retained evidence; missing
historical inputs stay unsupported. Do not change fingerprint domains, visitor IDs,
namespace, old aliases or frozen decisions. `ruleVersion` records the applied visitor
migration revision that made each decision.

Deploy compatible readers before explicitly applying a rule migration. Backfills
currently run transactionally while new resolutions are blocked; large histories need
an operator-sized maintenance window, otherwise checks may report unavailable.
Existing identification decisions remain unchanged after upgrading. Older binaries
refuse to make new decisions against an unknown newer revision. Do not downgrade the
database or silently run new rules through old readers. Rule retirement/correction
needs a new migration and explicit policy; an ordinary upgrade is not permission to
merge existing visitors or rewrite old assignments.

The matcher, migrations and checks are MIT-licensed and identical for self-hosters.
There is no hosted-only reconciliation tier.

#### Verification and limits

```sh
# A disposable local database only; these tests create and drop isolated schemas.
# Supply OPENFINGERPRINT_TEST_POSTGRES_URL with explicit sslmode=disable.
node api/test-visitors.mjs
```

Without that variable the runner explicitly reports a skip; CI supplies PostgreSQL.
Tests cover exact repeats, locale changes, partial groups, incomplete evidence, site/
namespace/customer-scope isolation, scoped defaults and required scopes, expired
observations with persistent identities, concurrent replicas,
frozen decisions, rule migration ambiguity, rollback/failure and REST/protobuf parity.
Independently assigned **synthetic** browser labels exercise both expected false splits
and unavoidable indistinguishable-evidence false merges; they are not real-device
measurements or population accuracy. The existing evaluation recorder does not retain
component/hint hashes, so a consented real-device churn study still needs an explicitly
approved extension. Fingerprint.com is a reference, not ground truth.

### Connect, gRPC and gRPC-Web (`openfingerprint.v1.OpenFingerprint/Check`)

The `/v1/check` verdicts and identification evidence are also an RPC, on the same internal
listener, without authentication and refusing any `Origin` header. It speaks the [Connect](https://connectrpc.com/) protocol, gRPC and gRPC-Web, so any of
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
`CheckRequest` has `identification_id`, optional `visitor_scope` (wire number 8),
`domain`, `email`, `ip` and optional `detail`
(default false). `CheckResponse` always keeps the compact verdict fields. With
`detail: true` it also includes a typed `identification` message, evaluated once by the
same rules as REST. No identification requested means no identification message.
Reflection (`grpc.reflection.v1` and `v1alpha`) is open like the rest.

For example, using an ID returned by the public listener:

```json
{"identificationId":"<ID from /v1/identify>","detail":true}
```

| Detail field | Meaning |
| --- | --- |
| `status`, `reason` | The same identification outcome and rejection/unavailability reason as REST. An unknown or expired ID is `invalid_input` / `unknown_identification`; a malformed ID is `invalid_input` / `invalid_identification_id`. Redis failure is `unavailable` / `identification_unavailable`, not an invalid ID. |
| `schemaVersion`, `replayed`, `ageMs` | The validated evidence schema, lookup marker and age by the API's clock. |
| `origin`, `ja4`, `tlsClient` | The origin and TLS observations of the public identify listener. An unlisted JA4 has no `tlsClient`; it is unknown, not a mismatch. |
| `automation`, `tampering`, `spoofing` | Typed `status`, `indicators`, `ruleVersion`, `unavailableProbes`, `source` and optional `reason`. An unknown verdict stays `unknown`; it does not turn into `false`. |
| `behavior` | Typed `status`, `patterns`, `ruleVersion`, `source`, optional `reason` and optional `suspiciousClickPattern`. The flag is unset when evidence is insufficient; false stays explicitly present. Absent without `watch()` evidence; patterns and the flag are context, not a verdict. |
| `evidence` | Counts only: `includedComponents`, `includedHints`, `unavailableProbes` and `excludedProbes`. No profile hashes, raw probes or behavioral input counts are returned. |

Unset optional scalars and absent messages mean unknown/missing, never false or zero.
An explicitly observed zero count remains present. Repeated fields and maps are empty
when they have no entries; use the enclosing message and status to distinguish absent
behavior from observed behavior without patterns. Protobuf JSON omits nulls and empty
lists/maps, uses camelCase (`schemaVersion`, `ruleVersion`, `unavailableProbes`, including
for tampering), and encodes `int64` ages as strings. These are representation differences,
not different evidence. REST is unchanged. Domain, email and IP details remain REST-only.

Visitor fields have the same semantics across REST, Connect and gRPC: compact
`visitor_id` uses wire number 22; detail has `visitor_id` at 15 and
`reconciliation` at 16. Unknown visitor IDs remain unset. The removed top-level
`fingerprint` name and wire number 1 are reserved and never emitted, even with detail.
`IdentificationDetail.fingerprint` (wire number 4) and
`EvidenceSummary.identity_groups` (wire number 1) are also removed and reserved.

Regenerate clients from the updated protobuf. Clients reading profile hashes must
migrate to `visitor_id`; detail no longer exposes an exact profile hash.
Evidence is for shadow analysis/review, not authentication or blocking. No new detection,
logging, IP retention or browser inputs are introduced.

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
`{"error":"<reason>"}`: 400 invalid envelope, 403 browser Origin, or 413 oversized body.
Unsupported methods return 405.

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
| `openfingerprint_spoofing_checks_total{status}`, `openfingerprint_spoofing_indicators_total{indicator}` | Evidence compared with the request the public listener received, by verdict, and how often each comparison found a mismatch. They count evaluations, not visitors. |
| `openfingerprint_automation_checks_total{status}`, `openfingerprint_automation_indicators_total{indicator}` | Valid automation reports evaluated, by verdict (`detected`, `unknown`, `not_detected`), and how often each probe was positive. One positive probe is enough for `detected`, so the indicator counts show which probes fire in practice. They count evaluated reports, not visitors. |
| `openfingerprint_identifications_total{result}` | Browser posts to `/v1/identify`: `stored`, `origin_refused`, `rate_limited`, `invalid` (not valid evidence) and `error` (Redis could not store it). |
| `openfingerprint_identification_lookups_total{result}` | Identifications looked up by `/v1/check`: `found`, `unknown` (never stored or expired) and `error`. |
| `openfingerprint_behavior_observations_total{evidence,mouse_clicks}` | One observation per successfully stored identification: `evidence` is `missing`, `v1` or `v2`; mouse-click sample size is `unknown` for missing, otherwise `0`, `1`, `2`, `3_4`, `5_9` or `10_plus`. Includes denominators for every pattern slice. |
| `openfingerprint_behavior_patterns_total{evidence,mouse_clicks,pattern}` | Descriptive pattern matches per stored observation, with the same version/sample labels and the five fixed pattern names above. Repeated `/v1/check`/RPC evaluations do not increment either behavior metric. |
| `openfingerprint_suspicious_click_patterns_total{result}` | Context flags per successfully stored identification snapshot, with fixed `result` values `true`, `false`, `unknown`. Includes missing, legacy and insufficient evidence as unknown; repeated checks, rejected reports and failed stores do not increment it. |
| `openfingerprint_identification_tls_clients_total{client}` | Stored identifications by the client their JA4 matched, `unknown` for an unlisted fingerprint, `none` when none was read. A rising `unknown` share means the reference table needs new browser versions. |
| `openfingerprint_identify_certificates`, `openfingerprint_identify_certificate_reload_failures_total` | Certificates loaded for the public listener, and reloads that failed (the previous certificates stay in use). |
| `openfingerprint_replay_checks_total{result}` | Identification lookups: `new` (first), `replayed` (looked up before) and `error` (Redis could not answer, so `replayed` was left out). |
| `openfingerprint_http_request_duration_seconds{route,status}` | Histogram of time to produce a response. `route` is `check`, `identify` (the public listener), `rpc` or `other`; `status` is `2xx`, `4xx`, `5xx` or `other`. `rpc` covers the Connect/gRPC/gRPC-Web endpoint and reflection; gRPC failures are HTTP 200, so only Connect shows `4xx`. Buckets run from 1 ms to 5 s. |
| `openfingerprint_check_step_duration_seconds{step}` | Histogram of where a `/v1/check` spends time. Sections: `identification` (reading it from Redis), `evidence`, `domain`, `ip_country`, `ip_network`. The `domain` section runs `domain_mx`, `domain_registration` and `domain_mail_auth` concurrently, so it lasts as long as the slowest, not their sum. Beneath them: `dns_lookup` (each MX or TXT query), `redis_get` and `redis_set` (RDAP cache), `replay` (the lookup marker), `rdap_fetch` and `whois_fetch` (registry calls on a cache miss, including the wait for a per-registry slot). A step cut short by its timeout is recorded at the time it was cut. |
| `openfingerprint_country_data_loaded` | 1 when a valid country database is loaded (not necessarily fresh). |
| `openfingerprint_country_data_expiry_timestamp_seconds` | When the country database stops being used, or 0 when unavailable. |
| `openfingerprint_country_data_reload_failures_total` | Changed country files rejected, including rollbacks to older builds. |

Behavior counters count submitted snapshots, not unique visitors, independent click
samples or accuracy. Multiple identifications can overlap the same cumulative events.
Missing evidence is not observed zero input; version 1 may contain misclassified WebKit
touch. For repeated-click context, divide pattern counts in the `v2` sample buckets
`3_4|5_9|10_plus` by observations in those same buckets, not by all checks or all visits.
Do not sum overlapping patterns into a detection rate. The
[study](../evaluation/behavior.md#aggregate-observability) gives a runnable PromQL example.
No visitor IDs, IPs, coordinates or request-supplied strings occur in these labels.
For the context flag, `true + false` is the eligible-snapshot denominator; `unknown`
is separate, not a negative result. A `true / (true + false)` ratio is pattern
prevalence, not bot prevalence or detection accuracy; a zero denominator is unknown.

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
with each API release, runs the API with its public identify Service (TCP passthrough,
certificates from TLS Secrets), optional NetworkPolicies, a bundled
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

This runs formatting, Clippy, unit tests and a real loopback self-check with both
listeners and a generated certificate. It posts evidence over TLS and checks
identifications, replays and age, input combinations, automation, tampering and spoofing
rules, partial failures, scoped domain matches, public-suffix
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
