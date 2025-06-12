# Changelog

All notable changes to this project will be documented in this file.


This changelog is maintained using [git-cliff](https://git-cliff.org/) and [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/).

## [unreleased]

### 🧪 Testing

- [#481](https://github.com/near/mpc/pull/481)(@near-bookrock): Test that threshold from previous running state is used when serving sign requests in resharing (#481)

## [2.2.0-rc1] - 2025-06-11

### ⚙️ Miscellaneous Tasks

- [#490](https://github.com/near/mpc/pull/490)(@near-bookrock): Bump versions for new release candidate (#490)


## [2.0.1-rc2] - 2025-06-10

### 🚀 Features

- [#466](https://github.com/near/mpc/pull/466)(@near-bookrock): *(TEE)* Implement remote attestation information generation (#466)


### 🐛 Bug Fixes

- [#480](https://github.com/near/mpc/pull/480)(@near-bookrock): Use threshold number for previous running state in resharing (#480)


### ⚙️ Miscellaneous Tasks

- [#477](https://github.com/near/mpc/pull/477)(@netrome): Add MIT license and third party license notices (#477)


## [2.0.1-rc1] - 2025-06-03

### 🚀 Features

- [#438](https://github.com/near/mpc/pull/438)(@near-bookrock): Parallel resharing and running (#438)


### 🐛 Bug Fixes

- [#370](https://github.com/near/mpc/pull/370)(@near-bookrock): Return early in Indexer thread and listen_blocks if channel to MPC node is closed.


### 💼 Other

- [#416](https://github.com/near/mpc/pull/416)(@andrei-near): Fix import keyshare  (#416)


### ⚙️ Miscellaneous Tasks

- [#366](https://github.com/near/mpc/pull/366)(@near-bookrock): Add metrics for latency of signature request responses (#366)

- [#373](https://github.com/near/mpc/pull/373)(@near-bookrock): Add metrics for latency of signature request responses in seconds

- [#371](https://github.com/near/mpc/pull/371)(@near-bookrock): Remove spawn_blocking call wrapping the indexer thread (#371)

- [#406](https://github.com/near/mpc/pull/406)(@near-bookrock): Remove unwrap in `monitor_passive_channels_inner` (#406)


## [2.0.0-rc.1] - 2025-04-11

### 🚀 Features

- [#294](https://github.com/near/mpc/pull/294)(@near-bookrock): *(EdDSA)* Add support for EdDSA signature requests on the smart contract (#294)


### 🐛 Bug Fixes

- [#209](https://github.com/near/mpc/pull/209)(@pbeza): *(audit)* Fix TLS certificate verification (#209)

- [#268](https://github.com/near/mpc/pull/268)(@near-bookrock): Pinned legacy contract dependency to git revistion (#268)

- [#328](https://github.com/near/mpc/pull/328)(@near-bookrock): Add pre-computed edwards_point of EdDSA keys to contract state (#328)

- [#358](https://github.com/near/mpc/pull/358)(@near-bookrock): Use internal tag for signature response type for backwards compatibility (#358)


### 💼 Other

- [#260](https://github.com/near/mpc/pull/260)(@andrei-near): MPC Load Balancer removal (#260)

- [#267](https://github.com/near/mpc/pull/267)(@andrei-near): Implement import-export keyshare (#267)

- [#274](https://github.com/near/mpc/pull/274)(@peter-near): Removed unused cipher key generation (#274)

- [#292](https://github.com/near/mpc/pull/292)(@andrei-near): Tokio runtime for import/export keyshare commands (#292)

- [#300](https://github.com/near/mpc/pull/300)(@andrei-near): Vote leave cmd (#300)

- [#269](https://github.com/near/mpc/pull/269)(@kuksag): Reuse `PayloadHash` and `Epsilon` types from contact (#269)

- [#304](https://github.com/near/mpc/pull/304)(@andrei-near): Warpbuild GHA runners (#304)

- [#331](https://github.com/near/mpc/pull/331)(@andrei-near): Option to use own funding account (#331)

- [#335](https://github.com/near/mpc/pull/335)(@andrei-near): MPC_HOME_DIR in image init script (#335)

- [#336](https://github.com/near/mpc/pull/336)(@peter-near): Added IDE configs to git ignore (#336)


### 🚜 Refactor

- [#210](https://github.com/near/mpc/pull/210)(@pbeza): *(audit)* Remove explicit .into_iter (#210)

- [#215](https://github.com/near/mpc/pull/215)(@pbeza): *(audit)* Shorten CLI's function bodies (#215)

- [#283](https://github.com/near/mpc/pull/283)(@near-bookrock): Use `[u8; 32]` instead of Scalar type from `k256` crate in contract (#283)

- [#341](https://github.com/near/mpc/pull/341)(@near-bookrock): Remove ScalarExt trait (#341)


### 🧪 Testing

- [#265](https://github.com/near/mpc/pull/265)(@bowenwang1996): Reduce flakiness by reducing the amount of assets buffered in tests (#265)

- [#339](https://github.com/near/mpc/pull/339)(@near-bookrock): Test public key derivation in contract (#339)

- [#347](https://github.com/near/mpc/pull/347)(@near-bookrock): *(eddsa)* Add integration test for EdDSA signature requests (#347)

- [#348](https://github.com/near/mpc/pull/348)(@near-bookrock): Enable EdDSA signature requets in pytests (#348)


### ⚙️ Miscellaneous Tasks

- [#281](https://github.com/near/mpc/pull/281)(@near-bookrock): Remove self dependency to `legacy_contract` (#281)

- [#286](https://github.com/near/mpc/pull/286)(@near-bookrock): Pin `near-sdk` version to 5.2.1 (#286)

- [#282](https://github.com/near/mpc/pull/282)(@near-bookrock): Move `crypto-shared` to a module in contract (#282)

- [#359](https://github.com/near/mpc/pull/359)(@near-bookrock): Fix typo in codebase edd25519 to ed25519

- [#334](https://github.com/near/mpc/pull/334)(@near-bookrock): Add docs to EdDSA fields in `PublicKeyExtended`. (#334)


## [testnet-upgrade] - 2025-01-09

### 💼 Other

- [#59](https://github.com/near/mpc/pull/59)(@andrei-near): Replace cache with rust-cache (#59)

- [#115](https://github.com/near/mpc/pull/115)(@andrei-near): Workflow to build and publish MPC docker images (#115)

- [#116](https://github.com/near/mpc/pull/116)(@andrei-near): Docker image builder nit (#116)



