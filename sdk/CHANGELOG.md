# Changelog

## [0.10.2](https://github.com/Mokto/openfingerprint/compare/sdk-v0.10.1...sdk-v0.10.2) (2026-11-10)


### Documentation

* link each synced README to its page on openfingerprint.com ([#99](https://github.com/Mokto/openfingerprint/issues/99)) ([597cbd4](https://github.com/Mokto/openfingerprint/commit/597cbd4de2e0346abecff927a31006267614219c))

## [0.10.1](https://github.com/Mokto/openfingerprint/compare/sdk-v0.10.0...sdk-v0.10.1) (2026-11-09)


### Bug Fixes

* stop flagging a wrapped Function.prototype.toString as automation ([#87](https://github.com/Mokto/openfingerprint/issues/87)) ([3e0d86c](https://github.com/Mokto/openfingerprint/commit/3e0d86cb7c04fd3d2b4beb36a985deb272e51dab))

## [0.10.0](https://github.com/Mokto/openfingerprint/compare/sdk-v0.9.0...sdk-v0.10.0) (2026-11-08)


### ⚠ BREAKING CHANGES

* the API has no authentication and ignores OPENFINGERPRINT_SITES (with a startup warning) and any Authorization header. The routes /v1/challenges, /v1/collect and /v1/events/consume, OPENFINGERPRINT_TRUSTED_PROXIES, OPENFINGERPRINT_COLLECTION_TTL_SECONDS and OPENFINGERPRINT_COLLECTION_CAPACITY are gone, and metrics drop the challenges, collect and consume route labels.

### Features

* remove authentication and challenge-bound collection, add replay and token age signals ([#76](https://github.com/Mokto/openfingerprint/issues/76)) ([f7ce6a6](https://github.com/Mokto/openfingerprint/commit/f7ce6a63a231a7bebb7a17d562b2c0d13661185d))

## [0.9.0](https://github.com/Mokto/openfingerprint/compare/sdk-v0.8.0...sdk-v0.9.0) (2026-11-07)


### ⚠ BREAKING CHANGES

* **api:** compact flat /v1/check response, short IDs and opaque SDK token ([#66](https://github.com/Mokto/openfingerprint/issues/66))

### Features

* **api:** compact flat /v1/check response, short IDs and opaque SDK token ([#66](https://github.com/Mokto/openfingerprint/issues/66)) ([13e522f](https://github.com/Mokto/openfingerprint/commit/13e522fab1c5e9f4193eccc9cb9bebedda0c39b1))

## [0.8.0](https://github.com/Mokto/openfingerprint/compare/sdk-v0.7.0...sdk-v0.8.0) (2026-11-07)


### Features

* add canvas and audio tampering indicators, separate from automation ([#54](https://github.com/Mokto/openfingerprint/issues/54)) ([a22c26f](https://github.com/Mokto/openfingerprint/commit/a22c26f10bd267e821beaaecdbf21316eb137ad2))

## [0.7.0](https://github.com/Mokto/openfingerprint/compare/sdk-v0.6.1...sdk-v0.7.0) (2026-11-07)


### Features

* add challenge-bound collection with Redis-backed single-use events ([#29](https://github.com/Mokto/openfingerprint/issues/29)) ([8846292](https://github.com/Mokto/openfingerprint/commit/88462929fafb089a1b423405ab013d7ab1c58bcc))
* add offline identification accuracy study tools ([#41](https://github.com/Mokto/openfingerprint/issues/41)) ([7e4aa69](https://github.com/Mokto/openfingerprint/commit/7e4aa6923e83df2bd3ad619af2632096ed1a4d55))
* add opt-in automation indicators to the SDK and /v1/check ([#28](https://github.com/Mokto/openfingerprint/issues/28)) ([8dde374](https://github.com/Mokto/openfingerprint/commit/8dde3742e03f929c66a1be51a25bb114c9c42923))
* add opt-in WebRTC address check comparing STUN-reflexive addresses with the request IP ([#46](https://github.com/Mokto/openfingerprint/issues/46)) ([b1dd08e](https://github.com/Mokto/openfingerprint/commit/b1dd08e527e39199e7a3df55f1e5f82bdaf2ed6b))
* add ten automation probes as evidence version 2 in the SDK and /v1/check ([#42](https://github.com/Mokto/openfingerprint/issues/42)) ([9d2de42](https://github.com/Mokto/openfingerprint/commit/9d2de42f9dfc9e8ec3530aeffe1c1c854486d74e))
* **api:** add local network intelligence for collection (Tor, ASN, cloud ranges) ([#31](https://github.com/Mokto/openfingerprint/issues/31)) ([8825dd3](https://github.com/Mokto/openfingerprint/commit/8825dd3f37bc56f0cd82083511397def56809795))

## [0.6.1](https://github.com/Mokto/openfingerprint/compare/sdk-v0.6.0...sdk-v0.6.1) (2026-11-05)


### Bug Fixes

* include MIT notice in SDK bundles and export package.json ([#13](https://github.com/Mokto/openfingerprint/issues/13)) ([8085f7f](https://github.com/Mokto/openfingerprint/commit/8085f7f51d50854735f7f08d2b337b6e36e7f40f))
