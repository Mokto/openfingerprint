# Changelog

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
