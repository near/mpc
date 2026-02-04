# Changelog

All notable changes to this project will be documented in this file.


This changelog is maintained using [git-cliff](https://git-cliff.org/) and [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/).

## [3.4.1] - 2026-02-04

### 🚀 Features

- : *(contract)* Define contract API for verification of foreign transactions (#1923)


### 🐛 Bug Fixes

- : Ensure test_verify_tee_expired_attestation_triggers_resharing is not flaky (#1939)


### 📚 Documentation

- : Foreign chain transaction design doc (#1920)

- : Update release guide (#1928)

- : Post-discussion updates for foreign chain transaction design doc (#1925)

- : Extractor-based foreign chain transaction validation design update (#1931)

- : Derive separate tweak for foreign transaction validation (#1938)


### ⚙️ Miscellaneous Tasks

- : Bump near crates, remove AccountId conversions (#1894)

- : Add CLAUDE.md and AGENTS.md to make coding agents more effective (#1916)

- : Update 3.3.2 mainnet contract history, clean-up previous contract migrations (#1914)

- : Remove the use of jemalloc (#1935)

- : TEE testnet automation scripts and launcher (#1879)

- : *(clippy)* Enable warning on `assertions_on_result_states` clippy lint (#1933)

- : Update nearcore to 2.10.6 (#1947)


## [3.4.0] - 2026-01-29

### 🚀 Features

- : Remove storage deposit requirement from contract (#1887)


### 🐛 Bug Fixes

- : TCP user keepalive (#1801)

- : Cargo-make check-all using wrong profile parameter (#1830)

- : Update deps dcap-qvl and oneshot to avoid known vulnerabilities (#1854)

- : Hot loop bug in running state when no keyshares are found (#1865)

- : Bump wasmtime version due to RUSTSEC-2026-0006 (#1876)


### 💼 Other

- : *(nix)* Include `apple-sdk_14` package to build `neard` on MacOs (#1808)

- : *(nix)* Include `neard` as a nix flake (#1812)

- : *(nix)* Remove neard as a tool in dev shell (#1845)


### 📚 Documentation

- : Add port 80 configuration support (#1850)


### ⚡ Performance

- : Avoid fragmented header writes on TCP connections (#1859)


### 🧪 Testing

- : Added automated localnet setup (#1804)

- : Add benchmark regression tests for `Participants` struct (#1813)

- : Make account creation much faster using async transactions (#1886)

- : Add CI test for mpc-node through non-tee launcher (#1885)

- : Add 3.3.2 contract to contract-history (#1896)

- : Add fixture tests for key derivation path (#1899)


### ⚙️ Miscellaneous Tasks

- : Make pprof web server endpoint queriable (#1816)

- : Bump nearcore to 2.10.5 (#1818)

- : Update ts repo ref (#1819)

- : Fix cargo-deny warnings, adapt to changes in dcap-qvl (#1823)

- : Make launcher-script more user friendly (#1838)

- : *(metrics)* Track tokio runtime and task metrics and export it to prometheus (#1837)

- : Remove outdated research file (#1840)

- : [**breaking**] Use hex for attestation dto types (#1843)

- : Check licenses is up to date on CI (#1849)

- : Use `--force` flag for cargo-binstall installations (#1862)

- : Create histogram for bytes written on p2p TCP streams (#1855)

- : Optimize rust cache in CI (#1871)

- : Bump `axum` to 0.8.8 (#1873)

- : Enable ignored tests (#1878)

- : Bump flume to version `0.12.0` (#1881)

- : Bump crate versions to 3.4.0 and update changelog (#1903)


## [3.3.2] - 2026-01-20

### 🐛 Bug Fixes

- : Include default value for pprof address (#1802)


### ⚙️ Miscellaneous Tasks

- : Bump crate versions to 3.3.2 and update changelog (#1806)


## [3.3.1] - 2026-01-19

### 🐛 Bug Fixes

- : Revert #1707 (use SocketAddr instead of custom struct) (#1795)


### 💼 Other

- : Add instruction how to get `rust-analyzer` to work with nix flakes (#1786)


### ⚙️ Miscellaneous Tasks

- : Update version and changelog for `3.3.1` release (#1798)


## [3.3.0] - 2026-01-16

### 🚀 Features

- : *(node)* Add web endpoint to collect CPU profiles with `pprof-rs` (#1723)

- : *(launcher)* Add ability to use the launcher also for non tee setups. (#1735)


### 🐛 Bug Fixes

- : Ruint unsoundness issue RUSTSEC-2025-0137 (#1729)

- : Enable TCP_KEEPALIVE for network connections (#1752)

- : *(network)* Do not accept incoming connection if previous one is still active (#1764)

- : Don't crash MPC node on startup for failed attestation submission (#1772)


### 💼 Other

- : *(rust)* Add support for Nix build environment (#1738)

- : *(nix)* Add instructions to enable direnv with Nix flake (#1767)

- : *(nix)* Resolve openssl-sys compilation errors in devShell (#1771)


### 🚜 Refactor

- : Return Result type in `is_caller_an_attested_participant ` (#1697)


### 📚 Documentation

- : Update readme to reflect correct test terminology (#1733)

- : Support running two MPC CVMs (Frodo + Sam) on the same physical machine (#1661)


### ⚡ Performance

- : Enable `TCP_NODELAY` for nodes' P2P TCP connections (#1713)

- : *(contract)* Contract should not store full attestation submission (#1663)


### 🧪 Testing

- : Improve pytest handling of crate builds (#1708)

- : Refactor wait_for_state to avoid self.contract_state() in tight loop (#1709)

- : Fix contract integration tests (#1725)

- : Handle transaction nonces locally (#1769)


### ⚙️ Miscellaneous Tasks

- : Initial contribution guidelines (#1699)

- : Add cargo-deny support (#1705)

- : Update testnet contract (#1707)

- : Ignore `RUSTSEC-2025-0137` in cargo-deny check (#1715)

- : Use `SocketAddr` instead of custom struct for addresses in configs (#1717)

- : Update tee testnet guide (#1718)

- : Update rkyv version to fix `RUSTSEC-2026-0001` (#1722)

- : Fix typo (#1720)

- : Ignore `RUSTSEC-2026-0002` in cargo-deny check (#1726)

- : Unify ckd and sign sandbox tests (#1739)

- : Use attestation crate types (#1744)

- : Update to nearcore 2.10.4 (#1749)

- : CI check to enforce TODO comment format (#1742)

- : Improve log messages for tokio tasks (#1756)

- : Remove dead Python code (#1761)

- : Update mainnet history contract to 3.2.0 (#1774)

- : Add missing metrics in eddsa (#1776)

- : Nodes accept peer with same or higher protocol version (#1778)

- : Refactor CI tests to group fast tests in a single run (#1780)

- : Skip `TODO` format checks for `CHANGELOG.md` (#1790)

- : Update version and changelog for `3.3.0` release (#1791)


## [3.2.0] - 2025-12-18

### 🚀 Features

- : Add derivation path support for ckd (#1627)

- : Add robust ecdsa SignatureScheme variant (#1670)

- : Add new signature scheme variant to contract (#1658)

- : Robust_ecdsa provider implementation (#1679)


### 🐛 Bug Fixes

- : Use gas value in the new config for the update promise (#1614)

- : Code hashes can now be be voted for in all code protocol states (#1620)

- : Correct error reporting of invalid TEE participants (#1635)

- : Remove votes from `UpdateEntry` (#1636)

- : Bump `ProposedUpdatesEntries` to `V3` and clean up `V2` (#1665)

- : Fix derivation_path params in ckd-example-cli (#1673)


### 🚜 Refactor

- : Remove `ReportData::new()` (#1626)

- : Remove stale comment and improve if condition for charging of attestation storage (#1642)

- : Move gas constants for voting from test to common module (#1668)

- : Clarify that `tee_state` contains attestations for not just active participants (#1695)


### 📚 Documentation

- : Create a guide for localnet + MPC node running in TEE setup (#1456)

- : Testnet with tee support guide (#1604)


### ⚡ Performance

- : Use procedural macro to include expected measurements at compile time (#1659)


### 🧪 Testing

- : *(pytest)* Run all pytests with 1 validator (#1623)

- : Migration system test (#1637)

- : Refactor pytests, several improvements preparing for robust ecdsa integration (#1671)

- : Refactor integration test in the node, improve PortSeed struct (#1672)

- : Fix sign sandbox tests (#1678)

- : Add tests for robust ecdsa (#1682)


### ⚙️ Miscellaneous Tasks

- : Remove `latest_code_hash` method from contract (#1613)

- : Introduce a gas constant for `vote_update` (#1612)

- : Update config files (#1618)

- : Update reference to ts repo (#1633)

- : Enforce kebab-case for crate names (#1648)

- : Broken contract verification (#1651)

- : Bump nearcore to 2.10.2 (#1653)

- : Run test profile on cargo nextest invocation (#1676)

- : Enable debug-asserttions on CI test profile (#1681)

- : Update version and changelog for 3.2.0 release  (#1692)

- : *(contract)* Sandbox code organization (#1683)

- : Bump nearcore to 2.10.3 (#1698)


## [3.1.0] - 2025-12-04

### 🚀 Features

- : Scale all remaining sandbox tests (#1552)

- : Add cargo-make support (#1554)

- : Embed abi in contract (#1563)

- : *(launcher)* Add support for multiple MPC hashes with fallback logic (#1527)

- : *(contract)* Make contract configuration values configurable (#1566)

- : Clear update votes from non-participants after resharing (#1559)


### 🐛 Bug Fixes

- : Only allow contract itself to call `migrate` function (#1556)

- : Check python code quality in CI enabled (#1576)

- : Wrong tag name in gcp image creation (#1594)


### 📚 Documentation

- : Create release changelog for `3.1.0` release (#1610)


### 🧪 Testing

- : Fix broken example `pytest` command (#1581)

- : *(pytest fix)* Remove 1 validator override in pytests (#1538)


### ⚙️ Miscellaneous Tasks

- : Remove pub migrate function and make gas deposit for upgrades configurable (#1501)

- : Provide cargo-binstall with a token (#1558)

- : Bump attestation submission frequency (#1561)

- : Don't take self needlessly on contract methods (#1569)

- : *(dead-code)* Remove `allowed_code_hashes` and `mig_migration_info` methods from the contract (#1580)

- : Bump `near-sdk` to 5.18.1  (#1579)

- : Create mpc attestation wrapper crate (#1577)

- : Bump nearcore to 2.10.0 (#1593)

- : Bump project version to `3.1.0` (#1586)

- : Make attestation crate independent of the mpc (#1588)

- : Document how to make a release (#1551)

- : Update dockerhub configuration parameter and add integration test for validate_image_hash using Docker Hub image (#1584)

- : Use `jemalloc` as memory allocator (#1602)

- : Remove dead legacy code in contract (#1607)

- : Remove legacy support in devnet (#1603)

- : Bump nearcore to 2.10.1 (#1609)


## [3.0.6] - 2025-11-25

### 🚀 Features

- : Fix rust-cache in CI (#1533)

- : Allow participants to withdraw their update vote (#1537)

- : Initial ckd example app (#1542)


### 🐛 Bug Fixes

- : Both test could be fixed by bumping gas appropiately (#1521)

- : Enable pytest optimizations removed in #1511  (#1530)

- : Use reproducible build in existing test (#1531)

- : Use correct nearcore commit in submodule (#1539)

- : Patch nearcore version 210 (#1547)


### 📚 Documentation

- : Design TEE-enabled backup service (#1467)


### ⚙️ Miscellaneous Tasks

- : Bump crate versions to 3.0.6 and update changelog (#1549)


## [3.0.5] - 2025-11-23

### 🚀 Features

- : Periodic mpc build workflow (#1505)

- : Contract allows querying update proposals (#1506)

- : Sandbox tests support for any number of participants (#1510)


### 🐛 Bug Fixes

- : *(contract)* Fix ProposeUpdate vote method and add unit test (#1488)

- : Remove balance checks (#1490)

- : *(test)* Enable and update test_from_str_valid (#1492)

- : Nightly build MPC workflow (#1509)

- : Use patched near core supporting reproducible builds (#1525)


### 🧪 Testing

- : Add unit tests for `do_update` function in `contract.rs` (#1498)

- : Update attestation test and refresh asset extraction files (#1504)


### ⚙️ Miscellaneous Tasks

- : Update mainnet to use 3_0_2 release for backwards compatibilit… (#1503)

- : Bump nearcore dependency to `2.10.0-rc.3` (#1511)

- : Bump crate versions to 3.0.5 and update changelog (#1523)


## [3.0.4] - 2025-11-18

### 🚀 Features

- : *(verification)* Allow RTMR2 to match production or dev measurements (#1428)

- : Add support for abi snapshots (#1438)

- : Add pytest with CKD private verification (#1459)

- : Group compatible pytests to use shared cluster (#1468)


### 🐛 Bug Fixes

- : *(localnet)* Ensure MPC node can sync after delay by updating neard retention policy (#1448)

- : Align waiting time with number of added domains (#1446)

- : Update snapshot after recent contract ABI changes (#1463)

- : Separate build workflows for launcher and node (#1469)

- : Make sure cargo-near is installed from binary release (#1471)

- : Fetch mpc secret store key and add gcp image (#1480)


### ⚙️ Miscellaneous Tasks

- : Update testnet contract (#1451)

- : Update contract readme wrt CKD (#1454)

- : Improved docker workflows for node and launcher image (#1460)

- : Extend localnet guide to include eddsa and ckd examples as well (#1464)

- : Bump crate versions to 3.0.4 and update changelog (#1487)


## [3.0.3] - 2025-11-12

### 🐛 Bug Fixes

- : Reduce log noise in migration monitor task (#1441)


### ⚙️ Miscellaneous Tasks

- : Fix key names in localnet guide (#1434)

- : Bump nearcore to include 2.9.1 (#1444)

- : Bump crate versions to 3.0.3 and update changelog (#1445)


## [3.0.2] - 2025-11-11

### 🚀 Features

- : Validate attestation before submission (#1412)


### 🐛 Bug Fixes

- : Test_latest_allowed_image_hash_is_written assuming wrong order (#1405)

- : Remove wrong near_sdk::PublicKey conversions (#1413)

- : Disable state sync in `start.sh` for localnet (#1414)

- : Path to store latest mpc node image hashes in devnet (#1418)

- : *(tee)* Add  prefix to written image digest for launcher compatibility (#1426)

- : Enable user_views tests in the contract (#1432)

- : Add pub_migrate function to get current contract migration unstuck (#1436)


### 🧪 Testing

- : Improve unit tests (#1406)


### ⚙️ Miscellaneous Tasks

- : Downgrade account balance fetch log to debug level (#1409)

- : Remove "exit 1" that could close ssh session (#1427)

- : Bump protocol version (#1430)

- : Update version and changelog for 3.0.2 release (#1439)


## [3.0.1] - 2025-11-06

### 🚀 Features

- : Add default behavior if `MPC_LATEST_ALLOWED_HASH_FILE` is not set (#1401)


### 🐛 Bug Fixes

- : Compute fresh attestations before submitting (#1396)

- : Node uses correct latest docker image hash (#1403)


### ⚙️ Miscellaneous Tasks

- : Small operator guide fixes (#1385)

- : Generate backup encryption key if env var is not provided (#1398)

- : Update nearcore to a modified 2.9 with testnet voting date set (#1397)

- : Update version and changelog for 3.0.1 release (#1404)


## [3.0.0] - 2025-11-05

### 🚀 Features

- : *(devnet)* Loadtest tracks success statistics (#489)

- : *(contract)* Add support for TEE (#410)

- : *(contract)* Add method to contract to get allowed image hashes (#511)

- : *(Tee)* Automatic kickout mechanism for invalid TEE status (#468)

- : *(contract)* Verification of TEE RTMRs 0-2 and MRTD (#509)

- : *(indexer)* Periodically fetch allowed image hashes from mpc contract (#513)

- : *(tee)* Node monitors latest allowed image hashes from contract (#525)

- : Initial launcher script (#524)

- : *(tee)* Generate p2p key/near signer key inside MPC node (#445)

- : *(contract)* Verification of RTMR3 (#516)

- : *(contract)* Verify `report_data` field of the TEE quote (#537)

- : *(remote attestation )* RTMRs and app_compose field checks (#541)

- : Submit remote attestation on startup (#543)

- : *(Tee)* Join logic for new participant and readme (#553)

- : *(devnet)* Enable ssd support (#558)

- : *(pytest)* Interactive pytest (#576)

- : Enable network hardship simulation (#560)

- : *(tee)* Add p2p public key to StaticWebData and http endpoint (#639)

- : *(tee)* Custom attestation module (#632)

- : *(tee)* Implement attestation quote generation in attestation module (#653)

- : *(contract)* Key resharing can be cancelled on the contract (#665)

- : *(metrics)* Expose peers block height metric (#684)

- : *(tee)* Implement TEE quote verification in attestation module (#683)

- : Added TEE enabled dockerfile + github workflow (#722)

- : Add support for cargo-near reproducible build (#734)

- : *(tee)* Add Docker image verification logic to attestation (#711)

- : Export account balances as metric (#776)

- : Add CLI script to deploy the Launcher in dstack CVM (#747)

- : Build info metrics (#769)

- : Add CKD support to the MPC contract (#885)

- : Add DomainId to CKDRequest (#934)

- : CKD support in indexer - node/src/indexer/ changes (#956)

- : CKD support in indexer - store + web changes (#957)

- : *(tee)* Clean TEE state when concluding a resharing (#942)

- : Overwrite mpc/near configs from ENV vars (#964)

- : CKD indexer - queue refactor (#968)

- : CKD provider support (#974)

- : Cli option to configure attestation authority (#967)

- : Added pytests for CKD (#985)

- : DomainId separation enforcement in the contract (#1008)

- : Improve asset cleanup behavior when entering running or resharing (#1032)

- : Make leader explicit in completed requests (#1038)

- : CKD support in devnet (#1023)

- : Change of participant set leads to exit of running state. (#1061)

- : Achieve reproducible builds for the mpc node and launcher (#1064)

- : *(pytest)* Restrict signer keys to MPC contract method (clean) (#1070)

- : Failed cluster signatures metrics main (#1153)

- : Contract supports migration service (#1162)

- : Devnet add missing image_hash and latest_allowed_hash_file (#1155)

- : Enforce all participants to have valid attestations (#1197)

- : Update to use new ts rerandomization+coordinator API (#1219)

- : Metrics tracking participant ids in failed signature computations (#1233)

- : Import keyshares into empty keyshare storage (#1215)

- : New dtos_contract::PublicKey type (#1225)

- : Re-submit attestation if node detects it has no attestation on chain (#1223)

- : Add near_sdk compatible serde serialization for dto types + Bls types (#1241)

- : Indexer fetches migration state from contract and displays it on a web-endpoint (#1250)

- : Ckd bls pivot (#1239)

- : Onboarding logic for MPC node (#1267)

- : Support CKD with BLS in pytests (#1272)

- : Scaffold initial backup service (#1289)

- : Import keyshares into non empty keyshare storage (#1216)

- : Migration service web server and client logic (#1283)

- : Add public key enforcement feature (#1270)

- : Add read-only getter for keyshares (#1300)

- : Backup_cli store secrets in json file (#1301)

- : Add enforcement that contract call are by attested participants (#1313)

- : Backup-cli http over mtls support (#1317)

- : Mpc node spawns recovery web endpoint (1295) (#1319)

- : Use pre predecessor_account_id (#1316)

- : Add secrets.json migration support for 2.2.0 → 3.0.0 upgrade path (#1329)

- : Update to current ts version, more changes than I expected, some tricky deps changes as well (#1339)

- : Ensure docker compose file is up to date in get docker compose hash (#1353)

- : Implement public key registration for the backup service (#1333)

- : Update launcher to remove old MPC container (#1366)

- : More detailed error messages when attestation validation fails (#1369)

- : Don't enforce secure time (#1375)

- : *(launcher)* Allow passing through NEAR_TESTS_PROTOCOL_UPGRADE_OVERRIDE env var (#1380)

- : Send AES-256 encrypted secrets over mutual TLS instead of plaintext (#1376)

- : Implement `KeyshareStorageAdapter` for keyshare persistence (#1384)


### 🐛 Bug Fixes

- : *(tee)* Hotfix of TEE `report_data` verification (#552)

- : *(tee)* Ensure quote verification status is `UpToDate` (#585)

- : *(devnet)* Refill contract account for initalization (#578)

- : Ignore peers who are behind in a computation (#595)

- : Harden launcher docker-compose config against privilege escalation (#589)

- : *(dstack)* Bump dstack rust sdk version (#617)

- : *(tee)* Don't re-encode tdx_quote to hex (#627)

- : *(tee)* Serialize `quote_collateral` to a `serde_json::Value` instead of String (#629)

- : *(launcher)* Enforce env var allow-list and custom host/port parsing in user-config (#588)

- : *(dstack)* Bump dstack rust sdk version (#620)

- : Create tokio enter guard for spawning TEE related tasks (#612)

- : Add boot nodes at near indexer config init state (#667)

- : Adjust invariant checks when selecting participants (#680)

- : *(deployment)* Gcp start script key error (#705)

- : Transparent serialization for Hash32 (#704)

- : *(devnet)* Compatibility with upcoming mpc node version 3.0.0 (#715)

- : Fixes test_from_str_valid test in the contract crate (#724)

- : Display error message when participant list is empty in mpc-node generate-test-configs (#740)

- : Bumping nearcore to 2.7.0-rc4 (#755)

- : Defer creating `allowed_image_hash` file until write (#768)

- : *(launcher)* Fixing of issues found during testing (#762)

- : Spawn mointor docker images task before listening to blocks indefinitely (#778)

- : Update README.md to fix the broken link to Cait-Sith blog post (#785)

- : Replay all RTMR3 required events (#800)

- : Node ignores peers lagging 50 blocks behind (#802)

- : *(node)* Enforce RTMR3 validation on event checks (#780)

- : Node abort_key_event_instance instead of abort_key_event (#807)

- : Verify docker compose hashes correctly (#774)

- : *(contract)* Correct tee_status and verify_tee logic (#816)

- : Fix typos and name inconsistencies (#838)

- : Api mismatch for submitting participant info (#852)

- : Propose join and rename to submit_participant_info (#851)

- : Use download_config parameter in mpc-node cli (#788)

- : *(tee)* Ensure participants run valid TEE or none (#887)

- : Increase gas limit for sign calls (#925)

- : CI get docker manifest timeouts (#928)

- : Add domainid ckdrequest again (#955)

- : *(tee)* Avoid passing `ExpectedMeasurements` as a parameter in contract (#971)

- : Redundant secure_time validation for app compose (#997)

- : Use correct assert_matches (#1022)

- : Use version controlled contracts in compatibility tests (#1031)

- : Add missing bs58 dependency in contract_history crate (#1040)

- : Return participants with invalid attestation in error message (#1096)

- : Ignore broken tests (#1149)

- : Don't cleanup allowed hashes on getters (#1146)

- : Stream while syncing instead of waiting for full sync. (#738)

- : Add needed deps in dockerfile, remove unnecessary (#1170)

- : Contract was refunding too much of deposit (#1165)

- : Address post-merge code review comments for PR #1183 (#1189)

- : Restore exact workflow before #1113 not including MPC launcher (#1193)

- : Node should retry attestation submission until its observed onchain (#1174)

- : Resubmit participant info more frequently (#1202)

- : Run attestation requests within a tokio runtime (#1229)

- : `tee_authority::get_with_backoff` was ending up in a hot loop (#1247)

- : Remove references to stale scripts (#1258)

- : Devnet using ckd with BLS (#1266)

- : Use more efficient DomainRegistry (#1281)

- : Remaining issues in TDX external guide (#1282)

- : Bug wasm execution failed error when running mpc localnet nodes (#1330)

- : Use port 24566 instead of 24567 for boot node arg in localnet guide (#1350)

- : Ensure hex serialization in vote-code-hash (#1358)

- : Disable state sync in localnet (#1364)

- : Github actions by pinning versions, added zizmor to CI (#1365)

- : Continue when receiver has lagged messages and log event (#1374)

- : Update operator guide with correct port configuration (#1381)

- : Update the measurements that are actually used in the contract (#1382)


### 🚜 Refactor

- : *(launcher)* Update user-config format and values (#670)

- : *(tee)* Move attestation generation logic (#758)

- : *(attestation)* Remove `TcbInfo` wrapper struct (#882)

- : Remove `Quote` wrapper struct in attestation (#884)

- : Consistent usage of SerializableEdwardsPoint in crypto_shared/types.rs (#890)

- : Get rid of `mod.rs` files (#998)

- : Make `verify_tee_participant` API infallible (#1098)


### 📚 Documentation

- : Added doc on how to deploy an MPC node within a TEE (#733)

- : Operator guide first version (#886)

- : Document disaster recovery plan (#877)

- : Update readme to list testnet RPC providers for devnet tool (#954)

- : Tdx cloud providers (#980)

- : Update operator's guide with CVM update flow (#983)

- : TEE design doc (#979)

- : Explain how to get dstack logs (#992)

- : Add link to HLD (#993)

- : Make the launcher docs more readable (#1002)

- : Port collision documentation (#999)

- : Update production_settings (#1001)

- : Add explanation about key generation (#1033)

- : How to add MPC node key into account (#1030)

- : Getting lasted MPC hash from the contract (#1043)

- : Voting_new_hash (#1045)

- : Add vote_new_parameters documentation (#1041)

- : Update TEE difference table (#1059)

- : Update local key provider section (#1048)

- : Update information about MPC node retrieval (#1072)

- : Add submit_participant_info details (#1062)

- : Add reproducible build instructions for Dstack (#1106)

- : Update RTMR generation instructions for dstack 0.5.4 (#1154)

- : Update contract README with gas cost details (#1178)

- : Document contract interface crate (#1256)

- : Operator guide includes installation instructions for dstack-vmm instead of referencing their readme (#1262)

- : *(localnet)* Refine `localnet` setup instructions (#1278)


### 🧪 Testing

- : Test that threshold from previous running state is used when serving sign requests in resharing (#481)

- : *(node)* Add timeout to avoid race condition in integration test (#498)

- : *(pytest)* Resolve pytest nonce conflicts (#555)

- : Create pytest to test cancellation of key resharing (#682)

- : *(tee)* Add an integration test for attestation verification (#746)

- : *(tee)* Add contract integration test for MPC image hash voting (#819)

- : Re-organize tests in attestation crate (#834)

- : *(contract)* Integration test to ensure contract rejects invalid remote attestations (#828)

- : Expired attestation kickout flow (#1099)

- : Move sandbox integration tests into separate directory. (#1168)

- : Add grace period test for multi-node voting (#1183)

- : Rewrite upgrade test as a sandbox integration tests (#1186)

- : Wait for TEE attestations on resharings in pytests (#1200)

- : Proposal for adding new participant without valid TEE attestation should fail (#986)

- : Resolve flaky test caused by ordering of attestations (#1211)

- : *(contract)* System test for `submit_tee_participant_info` (#1066)


### ⚙️ Miscellaneous Tasks

- : Update devnet docs (#493)

- : Initial Changelog + CI check (#494)

- : *(pytests)* Split cluster setup logic  (#508)

- : Increase bytes allocated to version in report data from u8 to u16 (#526)

- : *(tee)* Launcher cleanup (#549)

- : Fix docker build and publish action (#564)

- : Sanitize docker build CI to replace invalid tag symbol (#571)

- : Remove p2p and signer key retrival via gcp (#572)

- : Enable support for JSON logging (#569)

- : Migrated stats into IndexerState (#586)

- : Add info logs when creating file handle for TEE image hash (#574)

- : Add `near_responder_id` and number of responder keys in `gcp-start.sh` logic (#573)

- : Keep MPC node running if image hash is disallowed (#575)

- : Bump nearcore to `2.7.0-rc.2` (#615)

- : Rename cait-sith -> threshold-signatures (#640)

- : Define release process (#631)

- : Build Docker image as part of CI tests (#649)

- : Use workspace for dependencies (#651)

- : Add `--enable-bulk-memory-opt` requirement in contract readme (#659)

- : Do not wait for indexer sync before generating TEE attestation (#662)

- : Use the right `protocol_state` type for MpcContractV1 state (#669)

- : Update pytest build step to include `--enable-bulk-memory` flag (#673)

- : Setup `black` as formatter for pytest code (#677)

- : Make python formatter apply for the whole repo (#686)

- : *(readme)* Eddsa example in readme.md (#633)

- : Add TEE Launcher image building step to CI (#685)

- : Fix failing CI for TEE Launcher build (#692)

- : Add `tee_launcher` tests in CI (#688)

- : Specify TEE Launcher image from `nearone` registry (#694)

- : Remove unused threshold parameter in start_cluster_with_mpc (#700)

- : *(deployment)* Gcp start bash script: avoid unnecessary warning (#707)

- : Rename web endpoint /get_public_data to /public_data (#708)

- : Override org-wide issue template (#718)

- : Move MPC node modules to `lib.rs` (#720)

- : *(devnet)* Add support for voting new approved code hash on devnet (#742)

- : Remove mpc-keys crate in contract (#749)

- : *(lazy_static)* Replace lazy_static with LazyLock  (#660)

- : Add python linter (#750)

- : Allow contract to generate ABI (#751)

- : Execute python lint/format CI only when needed (#773)

- : Remove i/o code from attestation crate (#775)

- : Unify near-sdk versions (#783)

- : *(ci)* Split ci-tests into multiple jobs (#787)

- : Remove nightly features from fmt config (#790)

- : Fix cargo-near install failure in CI (#793)

- : *(launcher)* Small update of variable and file name for better clarity (#792)

- : *(pytests)* Speedup - reduce rpc poll timeout and send txs in parallel (#796)

- : *(ci)* Add clippy all-features (#798)

- : *(pytest)* Improve test_lost_assets.py performance and coverage (#810)

- : *(pytest)* Fix flaky test_signature_lifecycle (#812)

- : Use our own fork of dcap-qvl v0.2.4 (#813)

- : Remove default features prometheus (#821)

- : Implement serde + borsh (de)serialization for attestation crate types (#806)

- : Upd near-crypto in infra/scripts/generate_keys/ (#822)

- : Update `dcap-qvl` crate to upstream version (#840)

- : *(launcher script)* Update readme (#833)

- : Replace `YamlValue` with a String wrapper for docker_compose_file (#870)

- : Add docker TEE build as a CI check (#835)

- : Added  test_vote_code_hash_doesnt_accept_account_id_not_in_participant_list test (#871)

- : Implement borsh schema for attestation crate types (#873)

- : *(test)* More detailed error checking in contract test (#874)

- : Update phala cloud API endpoint for collateral generation (#876)

- : *(tee)* Remove account key from report data (#869)

- : Integrate ts#22 refactor (#867)

- : Integrate the attestation module into the contract code (#878)

- : Remove `near_crypto` from attestation crate (#889)

- : *(contract)* Remove stale log of random seed in contract (#922)

- : Remove `near_crypto` dependency from smart contract (#933)

- : Move config.rs unit test behind feature gated test module (#937)

- : *(deploy script)* Update MPC node ports  (#872)

- : [**breaking**] Remove near_crypto from node code (#914)

- : *(node)* Move tls into crate (#963)

- : Bump version tracing-subscriber (#989)

- : Bump dcap-qvl to released version (#991)

- : Use configuration value instead of constant for `TEE_UPGRADE_PERIOD` (#995)

- : Upgrade `ed25519-dalek` version in contract (#1000)

- : Use crates.io version of dstack-sdk (#1004)

- : Enable running with dstack TEE authority in start.sh (#1010)

- : Delete `docker_release_tee.yaml` workflow (#1007)

- : Fix warning while building contract in pytests (#1011)

- : Fix deployment start script  (#1021)

- : Use `test_utils` crate for image hashes in contract tests (#1013)

- : Set MPC authority stared by launcher to always expect real TDX HW (#1018)

- : Test for new docker images (#1036)

- : Avoid storing migration contract binary (#1047)

- : Enhance mock attestation struct with conditional validation (#1016)

- : *(test)* Fix resharing tests (#1068)

- : Update disaster recovery doc (#1082)

- : Refactor to adapt to API changes in threshold-signatures (#1093)

- : Unify launcher folders (#1104)

- : Remove redundant and duplicate clippy check for `devnet` crate (#1108)

- : Create an interface for submitting transactions with response (#1101)

- : Update ci to use reproducible builds (#1113)

- : Move contract crate into root workspace (#1102)

- : Add detailed steps for mpc node image code inspection during upgrades (#1116)

- : Fix build script for builds in detached head (#1122)

- : Added security policy (#1124)

- : Pin serde to `1.0.2191` to fix compilation issue with `dstack-sdk` (#1125)

- : *(ci)* Separate CI actions for launcher and node (#1127)

- : *(docs)* Update docs after #1127 (#1131)

- : Move all workspace members in to `/crates` directory (#1136)

- : Update user guide with dstack 0.5.4 changes (#1115)

- : Adapt to API changes in ts#78 (#1143)

- : Index nodes by account id & TLS key in TEE State (#1120)

- : Use workspace versions in contract Cargo.toml (#1142)

- : Remove enum `VersionedMpcContract` contract state in favor of a single version struct (#1111)

- : Bring back legacy CI (#1157)

- : Update error message in image hash watcher (#1159)

- : Create DTO types for the attestation submission method (#1151)

- : Use time durations instead of block numbers for tee grace period (#1166)

- : Make sure devnet tests ckd (#1190)

- : Add github action for unused dependencies (#1141)

- : Remove redundant `allow` attribute (#1221)

- : Use base58 encoding for public key serialization on node HTTP server. (#1230)

- : Document how to run a local mpc network (#1231)

- : Remove unneeded deps in attestation crate (#1251)

- : Added systemd service for VMM (#1253)

- : Resolve flaky integration tests (#1273)

- : Contract unit tests for ckd (#1261)

- : Contract move helpers (#1276)

- : Add support for CKD BLS in contract sandbox tests (#1274)

- : Use read-write lock for keyshare storage (#1305)

- : Enforce sorted cargo dependencies on CI (#1315)

- : Bump nearcore to 2.9.0 (#1323)

- : Use pinned nextest version and standard installation action (#1326)

- : Use proper serialization format for PersistentSecrets (#1338)

- : Add support for dockerized localnet (#1336)

- : Cargo update and fix deprecated API usage (#1340)

- : Document reproducible builds in README.md (#1347)

- : Use 0 as SOURCE_DATE_EPOCH for repro builds (#1352)

- : Move test-utils to ts repo (#1344)

- : Updated hard-coded TCB info for 3.0.0 release (#1378)

- : Set crate versions to 3.0.0 and update changelog (#1383)

- : Support publishing images from git tags (#1388)


### ◀️ Revert

- : "refactor(tee): move attestation generation logic" (#779)


## [2.2.0-rc1] - 2025-06-11

### ⚙️ Miscellaneous Tasks

- : Bump versions for new release candidate (#490)


## [2.0.1-rc2] - 2025-06-10

### 🚀 Features

- : *(TEE)* Implement remote attestation information generation (#466)


### 🐛 Bug Fixes

- : Use threshold number for previous running state in resharing (#480)


### ⚙️ Miscellaneous Tasks

- : Add MIT license and third party license notices (#477)


## [2.0.1-rc1] - 2025-06-03

### 🚀 Features

- : Parallel resharing and running (#438)


### 🐛 Bug Fixes

- : Return early in Indexer thread and listen_blocks if channel to MPC node is closed.


### 💼 Other

- : Fix import keyshare  (#416)


### ⚙️ Miscellaneous Tasks

- : Add metrics for latency of signature request responses (#366)

- : Add metrics for latency of signature request responses in seconds

- : Remove spawn_blocking call wrapping the indexer thread (#371)

- : Remove unwrap in `monitor_passive_channels_inner` (#406)


## [2.0.0-rc.1] - 2025-04-11

### 🚀 Features

- : *(EdDSA)* Add support for EdDSA signature requests on the smart contract (#294)


### 🐛 Bug Fixes

- : *(audit)* Fix TLS certificate verification (#209)

- : Pinned legacy contract dependency to git revistion (#268)

- : Add pre-computed edwards_point of EdDSA keys to contract state (#328)

- : Use internal tag for signature response type for backwards compatibility (#358)


### 💼 Other

- : MPC Load Balancer removal (#260)

- : Implement import-export keyshare (#267)

- : Removed unused cipher key generation (#274)

- : Tokio runtime for import/export keyshare commands (#292)

- : Vote leave cmd (#300)

- : Reuse `PayloadHash` and `Epsilon` types from contact (#269)

- : Warpbuild GHA runners (#304)

- : Option to use own funding account (#331)

- : MPC_HOME_DIR in image init script (#335)

- : Added IDE configs to git ignore (#336)


### 🚜 Refactor

- : *(audit)* Remove explicit .into_iter (#210)

- : *(audit)* Shorten CLI's function bodies (#215)

- : Use `[u8; 32]` instead of Scalar type from `k256` crate in contract (#283)

- : Remove ScalarExt trait (#341)


### 🧪 Testing

- : Reduce flakiness by reducing the amount of assets buffered in tests (#265)

- : Test public key derivation in contract (#339)

- : *(eddsa)* Add integration test for EdDSA signature requests (#347)

- : Enable EdDSA signature requets in pytests (#348)


### ⚙️ Miscellaneous Tasks

- : Remove self dependency to `legacy_contract` (#281)

- : Pin `near-sdk` version to 5.2.1 (#286)

- : Move `crypto-shared` to a module in contract (#282)

- : Fix typo in codebase edd25519 to ed25519

- : Add docs to EdDSA fields in `PublicKeyExtended`. (#334)


## [testnet-upgrade] - 2025-01-09

### 💼 Other

- : Replace cache with rust-cache (#59)

- : Workflow to build and publish MPC docker images (#115)

- : Docker image builder nit (#116)



