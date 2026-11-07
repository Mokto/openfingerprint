# Changelog

## [0.8.0](https://github.com/Mokto/openfingerprint/compare/api-v0.7.0...api-v0.8.0) (2026-11-07)


### Features

* **data:** add domains read directly from live temp-mail services as a disposable source ([#47](https://github.com/Mokto/openfingerprint/issues/47)) ([b95c922](https://github.com/Mokto/openfingerprint/commit/b95c922c8f2939ffe8e844730a9af60f97f6218a))


### Bug Fixes

* **api:** copy every reviewed data file into the updater image ([#49](https://github.com/Mokto/openfingerprint/issues/49)) ([5ee507a](https://github.com/Mokto/openfingerprint/commit/5ee507ac5f9771e91d250f72b20f1e9aa7dcb4eb))

## [0.7.0](https://github.com/Mokto/openfingerprint/compare/api-v0.6.0...api-v0.7.0) (2026-11-07)


### ⚠ BREAKING CHANGES

* **api:** report domain registration dates from RDAP, cached in Redis ([#27](https://github.com/Mokto/openfingerprint/issues/27))
* **api:** /v1/check no longer accepts mx; the API resolves MX itself through OPENFINGERPRINT_DNS (default: system nameserver). The chart's dns.enabled option is removed; the API policy always allows UDP 53 to networkPolicy.dnsTo.
* **api:** remove the in-process per-site rate limiter ([#23](https://github.com/Mokto/openfingerprint/issues/23))

### Features

* add challenge-bound collection with Redis-backed single-use events ([#29](https://github.com/Mokto/openfingerprint/issues/29)) ([8846292](https://github.com/Mokto/openfingerprint/commit/88462929fafb089a1b423405ab013d7ab1c58bcc))
* add opt-in automation indicators to the SDK and /v1/check ([#28](https://github.com/Mokto/openfingerprint/issues/28)) ([8dde374](https://github.com/Mokto/openfingerprint/commit/8dde3742e03f929c66a1be51a25bb114c9c42923))
* add opt-in WebRTC address check comparing STUN-reflexive addresses with the request IP ([#46](https://github.com/Mokto/openfingerprint/issues/46)) ([b1dd08e](https://github.com/Mokto/openfingerprint/commit/b1dd08e527e39199e7a3df55f1e5f82bdaf2ed6b))
* add ten automation probes as evidence version 2 in the SDK and /v1/check ([#42](https://github.com/Mokto/openfingerprint/issues/42)) ([9d2de42](https://github.com/Mokto/openfingerprint/commit/9d2de42f9dfc9e8ec3530aeffe1c1c854486d74e))
* **api:** add IP country lookup from local DB-IP Country Lite data ([#32](https://github.com/Mokto/openfingerprint/issues/32)) ([1175c6e](https://github.com/Mokto/openfingerprint/commit/1175c6ecbe33d8e38f50e63a2304a998a0f30c3f))
* **api:** add local network intelligence for collection (Tor, ASN, cloud ranges) ([#31](https://github.com/Mokto/openfingerprint/issues/31)) ([8825dd3](https://github.com/Mokto/openfingerprint/commit/8825dd3f37bc56f0cd82083511397def56809795))
* **api:** add public mailbox, relay, typo suggestion and MX provider signals ([#30](https://github.com/Mokto/openfingerprint/issues/30)) ([870c987](https://github.com/Mokto/openfingerprint/commit/870c98709f6643e99889f464f4283ea572596806))
* **api:** add VPN, datacenter and open-proxy range evidence to network intelligence ([#45](https://github.com/Mokto/openfingerprint/issues/45)) ([db40f28](https://github.com/Mokto/openfingerprint/commit/db40f2891c68410240bbd4d590fc7c466220484d))
* **api:** always look up MX records in the API and drop the caller mx field ([#25](https://github.com/Mokto/openfingerprint/issues/25)) ([34125dd](https://github.com/Mokto/openfingerprint/commit/34125dd9237fb6264fc3e780f95be65999af1e88))
* **api:** look up registration dates over WHOIS for TLDs without RDAP, and harden registry and MX lookups ([#35](https://github.com/Mokto/openfingerprint/issues/35)) ([b5ad40e](https://github.com/Mokto/openfingerprint/commit/b5ad40e13ad4b8c3f4788576c2f457a589eedd31))
* **api:** recognise seventeen more MX providers, including Proofpoint and Amazon SES ([#40](https://github.com/Mokto/openfingerprint/issues/40)) ([643364b](https://github.com/Mokto/openfingerprint/commit/643364b04e2fc488baf1642172a0612ad20706ad))
* **api:** remove the in-process per-site rate limiter ([#23](https://github.com/Mokto/openfingerprint/issues/23)) ([af21cc1](https://github.com/Mokto/openfingerprint/commit/af21cc10127e9d661496039ccfa541f79e9006eb))
* **api:** report domain registration dates from RDAP, cached in Redis ([#27](https://github.com/Mokto/openfingerprint/issues/27)) ([c16c52c](https://github.com/Mokto/openfingerprint/commit/c16c52c2ae528602ae910e44335febec7dfbe078))
* **api:** report SPF and DMARC status, with TCP for truncated DNS answers ([#44](https://github.com/Mokto/openfingerprint/issues/44)) ([a9fa0df](https://github.com/Mokto/openfingerprint/commit/a9fa0df184d804ed8672b63ff7a48dbbb9f58f99))
* **api:** return partial identity group hashes in signals evidence ([#39](https://github.com/Mokto/openfingerprint/issues/39)) ([df67935](https://github.com/Mokto/openfingerprint/commit/df67935fa2d89ab218d69f96bd5a30974c33b84b))
* **chart:** alert on Redis errors and failing MX or registry lookups ([#37](https://github.com/Mokto/openfingerprint/issues/37)) ([d1c140f](https://github.com/Mokto/openfingerprint/commit/d1c140faa17c4e2705f320b96e3229f4a9b1af22))
* **data:** review eleven more email relay domains ([#38](https://github.com/Mokto/openfingerprint/issues/38)) ([67c9984](https://github.com/Mokto/openfingerprint/commit/67c99843e902e08880e59c7d0767749cee619b20))


### Bug Fixes

* **api:** reject invalid RDAP dates and expire Tor matches per observation ([#36](https://github.com/Mokto/openfingerprint/issues/36)) ([a6e01dd](https://github.com/Mokto/openfingerprint/commit/a6e01ddf598ea67d775f6bfa8b92110b866a0c60))

## [0.6.0](https://github.com/Mokto/openfingerprint/compare/api-v0.5.1...api-v0.6.0) (2026-11-06)


### Features

* **api:** infer disposable domains from MX hosts, looked up by the API or supplied by the caller ([#18](https://github.com/Mokto/openfingerprint/issues/18)) ([9f173c3](https://github.com/Mokto/openfingerprint/commit/9f173c356a3a8b26c9b7bc6aacbd3fe7f1d99140))

## [0.5.1](https://github.com/Mokto/openfingerprint/compare/api-v0.5.0...api-v0.5.1) (2026-11-06)


### Bug Fixes

* **api:** stop repeating the instance label on the chart's Deployment and Service ([#20](https://github.com/Mokto/openfingerprint/issues/20)) ([6770758](https://github.com/Mokto/openfingerprint/commit/6770758402fdc2a34bc6cb3ba17cb02df7d2c273))

## [0.5.0](https://github.com/Mokto/openfingerprint/compare/api-v0.4.0...api-v0.5.0) (2026-11-06)


### ⚠ BREAKING CHANGES

* **api:** Remove collect/check endpoints, visitor observations and tokens, email checks and linking history. Preserve the verify contract and existing server credentials; no signing key is required.

### Features

* **api:** add open-data domain snapshots to /v1/check ([#17](https://github.com/Mokto/openfingerprint/issues/17)) ([86a237f](https://github.com/Mokto/openfingerprint/commit/86a237f5943c9b3ae174007b7456ce2a4b39d123))
* **api:** add stateless /v1/check for signals, domain and IP ([#15](https://github.com/Mokto/openfingerprint/issues/15)) ([2c82ae6](https://github.com/Mokto/openfingerprint/commit/2c82ae604365b91d6048a3294f1d157ea43696aa))
* **api:** reload domain data without restart, add metrics and a Helm chart ([#19](https://github.com/Mokto/openfingerprint/issues/19)) ([85d0e01](https://github.com/Mokto/openfingerprint/commit/85d0e019e4a2a28a7167a27db932fcdba4a9a286))

## [0.4.0](https://github.com/Mokto/openfingerprint/compare/api-v0.3.0...api-v0.4.0) (2026-11-05)


### Features

* make locale identity stable across incognito and DST (schema 5) ([#10](https://github.com/Mokto/openfingerprint/issues/10)) ([41f7f5c](https://github.com/Mokto/openfingerprint/commit/41f7f5c5e15038b96bad0eea70e2dad3625a3bc7))

## [0.3.0](https://github.com/Mokto/openfingerprint/compare/api-v0.2.0...api-v0.3.0) (2026-11-04)


### Features

* **api:** add stateless server profile verification ([#7](https://github.com/Mokto/openfingerprint/issues/7)) ([6f64264](https://github.com/Mokto/openfingerprint/commit/6f642648c92a44a3afece593c928fe04e1f920c4))

## [0.2.0](https://github.com/Mokto/openfingerprint/compare/api-v0.1.0...api-v0.2.0) (2026-11-04)


### Features

* **api:** support HTTPS subdomain origin patterns ([#5](https://github.com/Mokto/openfingerprint/issues/5)) ([03cf530](https://github.com/Mokto/openfingerprint/commit/03cf530c29138b1e495668313038f9b1bb9cebd0))

## 0.1.0 (2026-11-04)


### Features

* **api:** add experimental signup-check API and multi-arch releases ([#3](https://github.com/Mokto/openfingerprint/issues/3)) ([d604d7d](https://github.com/Mokto/openfingerprint/commit/d604d7d826fa97ac450977b680de581fabff4877))
