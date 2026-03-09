# Changelog

All notable changes to this project will be documented in this file.


This changelog is maintained using [git-cliff](https://git-cliff.org/) and [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/).

## [9.9.4] - 2026-03-09

### 💼 Other

- (@SimonRastikian): V9.9.3


## [9.9.2] - 2026-03-09

### 💼 Other

- (@SimonRastikian): V9.9.2


### 🚜 Refactor

- (@anodar): Retry read calls in localnet script (#2318)


### ⚙️ Miscellaneous Tasks

- (@barakeinav1): Rename shadowed variable in verify_event_log_rtmr3 (#2325)

- (@gilcu3): Added borsch schema snapshot test (#2319)

- (@gilcu3): Replace ed25519_dalek::VerifyingKey with Ed25519PublicKey in node-types crate (#2338)


## [3.6.0] - 2026-03-05

### 🚀 Features

- (@DSharifi): Add new collection type, `BoundedVec`, to the bounded collections crate (#2199)

- (@barakeinav1): Allow passing mpc_ env variables (#2132)

- (@DSharifi): Create `near-mpc-sdk` crate with types for sign requests (#2202)

- (@DSharifi): *(sdk)* The SDK can build foreign chain requests for bitcoin (#2218)

- (@DSharifi): *(sdk)* The SDK can build foreign chain requests for abstract (#2222)

- (@DSharifi): *(sdk)* The SDK can build foreign chain requests for starknet (#2224)

- (@DSharifi): *(sdk)* Add verification support of  foreign transaction signatures (#2233)

- (@DSharifi): *(sdk)* Chain-specific builder entry points for foreign chain request builder (#2254)

- (@olga24912): Add StarkNet event log extraction support (#2258)

- (@DSharifi): *(sdk)* Add borsh serialization derives to all contract interface types and SDK verifier (#2266)

- (@DSharifi): *(sdk)* Verify foreign transaction payload signatures (#2265)

- (@gilcu3): Added support for abi generation in mpc-sdk and signature-verifier crate (#2281)


### 🐛 Bug Fixes

- (@gilcu3): Update wasmtime to avoid vulnerability in CVE-2026-27204 (#2237)

- (@gilcu3): Bug in from_be_bytes_mod_order when not a multiple of 8 bytes (#2257)

- (@gilcu3): Use bounded incoming message buffers for all protocols (#2268)

- (@gilcu3): Reject foreign chain transaction if requested chain not in policy (#2308)

- (@netrome): Don't log raw mpc protocol messages (#2310)

- (@gilcu3): Reject wrong payload versions for foreign chain transaction (#2309)

- (@netrome): Ensure resharing leaders wait for start events to prevent them from getting stuck forever (#2317)


### 💼 Other

- (@gilcu3): Make sure nix includes all needed tools (#2195)

- (@SimonRastikian): Automate MPC release process (#2200)

- (@anodar): Clang version in Nix flake for Darwin (#2291)


### 🚜 Refactor

- (@anodar): Use strong threshold types in signature provider layer (#2279)

- (@gilcu3): Unify crypto conversions (#2277)

- (@gilcu3): Create mpc-crypto-types crate (#2294)

- (@anodar): Handle errors on conversions to usize (#2313)

- (@gilcu3): Reduce code duplication in buffer limit tests (#2295)


### 📚 Documentation

- (@gilcu3): Rework the mpc readme (#2251)

- (@barakeinav1): CVM upgrade mechanism with launcher and OS measurement voting (#2270)

- (@pbeza): Archive Signer design for legacy HOT key support (#2204)


### ⚡ Performance

- (@SimonRastikian): Split eddsa benchmarks (#2276)


### ⚙️ Miscellaneous Tasks

- (@pbeza): Rename docs and scripts to kebab-case, add file naming CI check (#2212)

- (@pbeza): Add `check-use-in-fn.py` CI script (#2169)

- (@gilcu3): Add ts crate to the workspace (#2227)

- (@netrome): Make CLAUDE.md a symlink to AGENTS.md (#2229)

- (@barakeinav1): Launcher update process guide and automation script (#2172)

- (@gilcu3): Make dependabot separate minor bumps from major bumps (#2249)

- (@DSharifi): Create standalone crate to verify signatures that are in dto format (#2259)

- (@dependabot[bot]): Bump the rust-minor-and-patch group with 2 updates (#2278)

- (@gilcu3): Allow concurrent execution of release image workflow (#2304)

- (@gilcu3): Update migration code and contract history after 3.5.1 is deployed (#2235)

- (@gilcu3): Build docker workflows cancelling each other (#2312)

- (@gilcu3): Update nearcore to 2.10.7 (#2314)

- (@netrome): Update changelog, licenses and bump crate versions for 3.6.0 (#2321)


## [3.5.1] - 2026-02-20

### 🐛 Bug Fixes

- (@netrome): Ensure nodes can read 3.4.1 state (#2189)

- (@gilcu3): Add_domain_votes are preserver after resharing (#2190)


### 📚 Documentation

- (@kevindeforth): Indexer proposal (#2103)


### ⚙️ Miscellaneous Tasks

- (@gilcu3): Make logs -error reading config from chain- explicit (#2174)

- (@gilcu3): Resolve rustdoc warnings and enforce warnings check in CI (#2192)

- (@netrome): Update changelog and bump crate versions for 3.5.1 (#2198)


## [3.5.0] - 2026-02-19

### 🚀 Features

- (@DSharifi): Implement JSON rpc client and extractor for bitcoin (#1980)

- (@netrome): Foreign chain config & parsing (#1968)

- (@netrome): Canonical sign payload for foreign chain transactions (#1998)

- (@gilcu3): Implement verify foreign key logic in the contract (#2008)

- (@netrome): Automatic foreign chain policy voting (#1997)

- (@DSharifi): Foreign chain inspector for `abstract` block chain (#2015)

- (@andrei-near): Add claude reviewer (#2039)

- (@gilcu3): Integrate foreign chain tx feature in the node (#2055)

- (@netrome): Allow SecretDB to open unknown column families (#2065)

- (@pbeza): *(dtos)* Add Participants JSON serialization types to contract-interface (#1990)

- (@netrome): Remove observed_at_block special response field (#2070)

- (@DSharifi): Add extractor for evm `Log`s  (#2075)

- (@gilcu3): Integrate Abstract in the node (#2087)

- (@netrome): Starknet inspector (#2084)

- (@pbeza): Update Claude model to use Opus 4.6 for code reviews (#2129)

- (@DSharifi): Return payload hash instead of the payload for the sign foreign chain requests (#2126)

- (@gilcu3): Adding consistent hashing to select RPC providers (#2158)

- (@netrome): Domain separation (#2163)

- (@DSharifi): Add on chain metrics for sign request payload version (#2179)

- (@netrome): Add abstract rpc configuration in localnet guide + foreign policy serialization fix (#2180)


### 🐛 Bug Fixes

- (@gilcu3): Broken reproducibility (#2014)

- (@netrome): Three small post-merge fixes from #1997 (#2043)

- (@netrome): Remove accidentally included prompt file (#2107)

- (@gilcu3): Make run_receive_messages_loop infallible, log error on internal failures (#2124)

- (@gilcu3): Ecdsa background tasks should be infallible (#2133)

- (@SimonRastikian): Updating the documentation (#2137)

- (@gilcu3): Boot nodes deduplication in docs (#2149)


### 💼 Other

- (@DSharifi): Bump cargo resolver version to version `3` (#2048)

- (@DSharifi): Use nixpkgss to install cargo-nextest (#2092)

- (@DSharifi): Set Cargo linker for aarch64-darwin to resolve -lSystem (#2184)


### 🚜 Refactor

- (@pbeza): Improve gas benchmark tests by optimizing account handling (#2044)

- (@SimonRastikian): Const string contract methods (#2141)


### 📚 Documentation

- (@barakeinav1): Add node migration guide for operators (#2013)


### 🧪 Testing

- (@gilcu3): Check if 100s is enough to avoid flaky tests (#1993)

- (@netrome): System test for foreign chain policy voting (#2023)

- (@netrome): System test for foreign transaction validation (#2072)

- (@gilcu3): Added system test for starknet (#2125)


### ⚙️ Miscellaneous Tasks

- (@barakeinav1): Correct error codes (#1985)

- (@DSharifi): *(nix)* Bump cargo-near version to 0.19.1 (#1995)

- (@gilcu3): Make cargo-deny and license checks optional in CI (#2000)

- (@gilcu3): Add missing verify foreign chain functions to the contract (#1991)

- (@gilcu3): Bump gcloud-sdk to fix jsonwebsocket vuln (#1967)

- (@DSharifi): Move `rustfmt.toml` file to workspace root (#2019)

- (@DSharifi): Use `jsonrpsee` to support JSON-RPC v2 instead of manual implementation (#2010)

- (@DSharifi): *(cargo-deny)* Remove unnecessary skip for `prost` (#2028)

- (@gilcu3): Update ts reference (#2034)

- (@gilcu3): Update contract history to 3.4.1 (#2026)

- (@DSharifi): Remove `cargo-about` third-party licenses check from CI (#2041)

- (@DSharifi): Update near cli version in nix shell (#2046)

- (@DSharifi): Run `cargo-update` on lock file (#2049)

- (@DSharifi): Remove usage of `near_o11` for metrics and test logger (#2027)

- (@gilcu3): Upgrade and organize workspace deps (#2052)

- (@gilcu3): Disable flaky robust-ecdsa test (#2059)

- (@DSharifi): Revert the revert of using socket addresses (#2035)

- (@DSharifi): Make API types specific per chain (#2079)

- (@DSharifi): Make nix and ci version of tools in sync (#2082)

- (@gilcu3): Update keccak to 0.1.6 (#2097)

- (@gilcu3): Enable all steps in cargo deny except advisories in fast CI (#2098)

- (@SimonRastikian): Dependabot with exceptions (#2100)

- (@DSharifi): Add `From` and `TryFrom` conversions between dto and foreign chain inspector types (#2104)

- (@gilcu3): Add exceptions to dependabot that are known to fail because of devnet (#2117)

- (@pbeza): Extract Claude review prompt into standalone file (#2115)

- (@DSharifi): Validate local RPC provider config with on chain config (#2131)

- (@gilcu3): Bump buildkit and runner images versions to overcome build failure (#2146)

- (@gilcu3): Disable rust cache temporarily, as warpbuilds is providing different runners for the same label (#2153)

- (@DSharifi): *(nix)* Add jq and ruff to dev shell packages (#2144)

- (@pbeza): Add CI workflow to validate PR title type against changed files (#2155)

- (@DSharifi): Use non empty colletion types for foreign chain types (#2139)

- (@gilcu3): Enable back rust-cache (#2162)

- (@pbeza): Add `lychee` CI check for markdown link validation (#2148)

- (@pbeza): Update `format_pr_comments` script to read JSON from file argument (#2152)

- (@gilcu3): Fix flaky claude review permissions (#2168)

- (@DSharifi): Exclude .direnv from lychee link checker (#2176)

- (@gilcu3): Fix lychee not respecting gitignore (#2181)

- (@SimonRastikian): Bump crate versions to 3.5.0 and update changelog (#2187)


## [3.4.1] - 2026-02-05

### 🚀 Features

- (@DSharifi): *(contract)* Define contract API for verification of foreign transactions (#1923)

- (@gilcu3): Added indexer types for verify foreign tx (#1948)

- (@netrome): Add foreign chain policy types and voting method (#1961)


### 🐛 Bug Fixes

- (@gilcu3): Ensure test_verify_tee_expired_attestation_triggers_resharing is not flaky (#1939)

- (@kevindeforth): Properly fix network race condition (#1831)

- (@kevindeforth): *(network)* TCP Listener task must not die (#1983)


### 📚 Documentation

- (@netrome): Foreign chain transaction design doc (#1920)

- (@barakeinav1): Update release guide (#1928)

- (@netrome): Post-discussion updates for foreign chain transaction design doc (#1925)

- (@netrome): Extractor-based foreign chain transaction validation design update (#1931)

- (@netrome): Derive separate tweak for foreign transaction validation (#1938)

- (@DSharifi): Include set of reommended extensions for VSCode (#1953)

- (@DSharifi): Add note on branch being pushed to github pre `git-cliff` instructions (#1964)


### 🧪 Testing

- (@gilcu3): Add timeout/retry mechanism to try to fix flaky test creating many accounts (#1945)

- (@gilcu3): Enable test_embedded abi test (#1951)

- (@barakeinav1): Add localnet TEE automation scripts and templates (#1937)


### ⚙️ Miscellaneous Tasks

- (@gilcu3): Bump near crates, remove AccountId conversions (#1894)

- (@netrome): Add CLAUDE.md and AGENTS.md to make coding agents more effective (#1916)

- (@gilcu3): Update 3.3.2 mainnet contract history, clean-up previous contract migrations (#1914)

- (@gilcu3): Remove the use of jemalloc (#1935)

- (@barakeinav1): TEE testnet automation scripts and launcher (#1879)

- (@DSharifi): *(clippy)* Enable warning on `assertions_on_result_states` clippy lint (#1933)

- (@gilcu3): Update nearcore to 2.10.6 (#1947)

- (@DSharifi): RPC requests to EVM chains should have separate struct per chain (#1950)

- (@gilcu3): Remove extra license file (#1973)

- (@DSharifi): Add `git-cliff` to nix dev environment (#1982)

- (@SimonRastikian): Bump crate versions to 3.4.1 (#1972)


## [3.4.0] - 2026-01-29

### 🚀 Features

- (@netrome): Remove storage deposit requirement from contract (#1887)


### 🐛 Bug Fixes

- (@andrei-near): TCP user keepalive (#1801)

- (@gilcu3): Cargo-make check-all using wrong profile parameter (#1830)

- (@gilcu3): Update deps dcap-qvl and oneshot to avoid known vulnerabilities (#1854)

- (@gilcu3): Hot loop bug in running state when no keyshares are found (#1865)

- (@gilcu3): Bump wasmtime version due to RUSTSEC-2026-0006 (#1876)


### 💼 Other

- (@DSharifi): *(nix)* Include `apple-sdk_14` package to build `neard` on MacOs (#1808)

- (@DSharifi): *(nix)* Include `neard` as a nix flake (#1812)

- (@DSharifi): *(nix)* Remove neard as a tool in dev shell (#1845)


### 📚 Documentation

- (@barakeinav1): Add port 80 configuration support (#1850)


### ⚡ Performance

- (@DSharifi): Avoid fragmented header writes on TCP connections (#1859)


### 🧪 Testing

- (@gilcu3): Added automated localnet setup (#1804)

- (@pbeza): Add benchmark regression tests for `Participants` struct (#1813)

- (@gilcu3): Make account creation much faster using async transactions (#1886)

- (@gilcu3): Add CI test for mpc-node through non-tee launcher (#1885)

- (@gilcu3): Add 3.3.2 contract to contract-history (#1896)

- (@gilcu3): Add fixture tests for key derivation path (#1899)


### ⚙️ Miscellaneous Tasks

- (@DSharifi): Make pprof web server endpoint queriable (#1816)

- (@netrome): Bump nearcore to 2.10.5 (#1818)

- (@gilcu3): Update ts repo ref (#1819)

- (@gilcu3): Fix cargo-deny warnings, adapt to changes in dcap-qvl (#1823)

- (@gilcu3): Make launcher-script more user friendly (#1838)

- (@DSharifi): *(metrics)* Track tokio runtime and task metrics and export it to prometheus (#1837)

- (@gilcu3): Remove outdated research file (#1840)

- (@gilcu3): [**breaking**] Use hex for attestation dto types (#1843)

- (@DSharifi): Check licenses is up to date on CI (#1849)

- (@DSharifi): Use `--force` flag for cargo-binstall installations (#1862)

- (@DSharifi): Create histogram for bytes written on p2p TCP streams (#1855)

- (@gilcu3): Optimize rust cache in CI (#1871)

- (@DSharifi): Bump `axum` to 0.8.8 (#1873)

- (@gilcu3): Enable ignored tests (#1878)

- (@DSharifi): Bump flume to version `0.12.0` (#1881)

- (@barakeinav1): Bump crate versions to 3.4.0 and update changelog (#1903)


## [3.3.2] - 2026-01-20

### 🐛 Bug Fixes

- (@DSharifi): Include default value for pprof address (#1802)


### ⚙️ Miscellaneous Tasks

- (@kevindeforth): Bump crate versions to 3.3.2 and update changelog (#1806)


## [3.3.1] - 2026-01-19

### 🐛 Bug Fixes

- (@netrome): Revert #1707 (use SocketAddr instead of custom struct) (#1795)


### 💼 Other

- (@DSharifi): Add instruction how to get `rust-analyzer` to work with nix flakes (#1786)


### ⚙️ Miscellaneous Tasks

- (@netrome): Update version and changelog for `3.3.1` release (#1798)


## [3.3.0] - 2026-01-16

### 🚀 Features

- (@DSharifi): *(node)* Add web endpoint to collect CPU profiles with `pprof-rs` (#1723)

- (@barakeinav1): *(launcher)* Add ability to use the launcher also for non tee setups. (#1735)


### 🐛 Bug Fixes

- (@gilcu3): Ruint unsoundness issue RUSTSEC-2025-0137 (#1729)

- (@gilcu3): Enable TCP_KEEPALIVE for network connections (#1752)

- (@kevindeforth): *(network)* Do not accept incoming connection if previous one is still active (#1764)

- (@DSharifi): Don't crash MPC node on startup for failed attestation submission (#1772)


### 💼 Other

- (@DSharifi): *(rust)* Add support for Nix build environment (#1738)

- (@DSharifi): *(nix)* Add instructions to enable direnv with Nix flake (#1767)

- (@DSharifi): *(nix)* Resolve openssl-sys compilation errors in devShell (#1771)


### 🚜 Refactor

- (@DSharifi): Return Result type in `is_caller_an_attested_participant ` (#1697)


### 📚 Documentation

- (@kevindeforth): Update readme to reflect correct test terminology (#1733)

- (@barakeinav1): Support running two MPC CVMs (Frodo + Sam) on the same physical machine (#1661)


### ⚡ Performance

- (@DSharifi): Enable `TCP_NODELAY` for nodes' P2P TCP connections (#1713)

- (@DSharifi): *(contract)* Contract should not store full attestation submission (#1663)


### 🧪 Testing

- (@gilcu3): Improve pytest handling of crate builds (#1708)

- (@gilcu3): Refactor wait_for_state to avoid self.contract_state() in tight loop (#1709)

- (@pbeza): Fix contract integration tests (#1725)

- (@gilcu3): Handle transaction nonces locally (#1769)


### ⚙️ Miscellaneous Tasks

- (@netrome): Initial contribution guidelines (#1699)

- (@gilcu3): Add cargo-deny support (#1705)

- (@gilcu3): Update testnet contract (#1707)

- (@DSharifi): Ignore `RUSTSEC-2025-0137` in cargo-deny check (#1715)

- (@DSharifi): Use `SocketAddr` instead of custom struct for addresses in configs (#1717)

- (@barakeinav1): Update tee testnet guide (#1718)

- (@DSharifi): Update rkyv version to fix `RUSTSEC-2026-0001` (#1722)

- (@pbeza): Fix typo (#1720)

- (@DSharifi): Ignore `RUSTSEC-2026-0002` in cargo-deny check (#1726)

- (@kevindeforth): Unify ckd and sign sandbox tests (#1739)

- (@gilcu3): Use attestation crate types (#1744)

- (@gilcu3): Update to nearcore 2.10.4 (#1749)

- (@pbeza): CI check to enforce TODO comment format (#1742)

- (@gilcu3): Improve log messages for tokio tasks (#1756)

- (@pbeza): Remove dead Python code (#1761)

- (@gilcu3): Update mainnet history contract to 3.2.0 (#1774)

- (@gilcu3): Add missing metrics in eddsa (#1776)

- (@kevindeforth): Nodes accept peer with same or higher protocol version (#1778)

- (@gilcu3): Refactor CI tests to group fast tests in a single run (#1780)

- (@pbeza): Skip `TODO` format checks for `CHANGELOG.md` (#1790)

- (@pbeza): Update version and changelog for `3.3.0` release (#1791)


## [3.2.0] - 2025-12-18

### 🚀 Features

- (@gilcu3): Add derivation path support for ckd (#1627)

- (@gilcu3): Add robust ecdsa SignatureScheme variant (#1670)

- (@kevindeforth): Add new signature scheme variant to contract (#1658)

- (@gilcu3): Robust_ecdsa provider implementation (#1679)


### 🐛 Bug Fixes

- (@DSharifi): Use gas value in the new config for the update promise (#1614)

- (@DSharifi): Code hashes can now be be voted for in all code protocol states (#1620)

- (@barakeinav1): Correct error reporting of invalid TEE participants (#1635)

- (@pbeza): Remove votes from `UpdateEntry` (#1636)

- (@pbeza): Bump `ProposedUpdatesEntries` to `V3` and clean up `V2` (#1665)

- (@gilcu3): Fix derivation_path params in ckd-example-cli (#1673)


### 🚜 Refactor

- (@pbeza): Remove `ReportData::new()` (#1626)

- (@DSharifi): Remove stale comment and improve if condition for charging of attestation storage (#1642)

- (@pbeza): Move gas constants for voting from test to common module (#1668)

- (@DSharifi): Clarify that `tee_state` contains attestations for not just active participants (#1695)


### 📚 Documentation

- (@barakeinav1): Create a guide for localnet + MPC node running in TEE setup (#1456)

- (@barakeinav1): Testnet with tee support guide (#1604)


### ⚡ Performance

- (@netrome): Use procedural macro to include expected measurements at compile time (#1659)


### 🧪 Testing

- (@DSharifi): *(pytest)* Run all pytests with 1 validator (#1623)

- (@kevindeforth): Migration system test (#1637)

- (@gilcu3): Refactor pytests, several improvements preparing for robust ecdsa integration (#1671)

- (@gilcu3): Refactor integration test in the node, improve PortSeed struct (#1672)

- (@kevindeforth): Fix sign sandbox tests (#1678)

- (@gilcu3): Add tests for robust ecdsa (#1682)


### ⚙️ Miscellaneous Tasks

- (@DSharifi): Remove `latest_code_hash` method from contract (#1613)

- (@pbeza): Introduce a gas constant for `vote_update` (#1612)

- (@barakeinav1): Update config files (#1618)

- (@gilcu3): Update reference to ts repo (#1633)

- (@gilcu3): Enforce kebab-case for crate names (#1648)

- (@gilcu3): Broken contract verification (#1651)

- (@netrome): Bump nearcore to 2.10.2 (#1653)

- (@DSharifi): Run test profile on cargo nextest invocation (#1676)

- (@DSharifi): Enable debug-asserttions on CI test profile (#1681)

- (@gilcu3): Update version and changelog for 3.2.0 release  (#1692)

- (@kevindeforth): *(contract)* Sandbox code organization (#1683)

- (@gilcu3): Bump nearcore to 2.10.3 (#1698)


## [3.1.0] - 2025-12-04

### 🚀 Features

- (@gilcu3): Scale all remaining sandbox tests (#1552)

- (@gilcu3): Add cargo-make support (#1554)

- (@gilcu3): Embed abi in contract (#1563)

- (@barakeinav1): *(launcher)* Add support for multiple MPC hashes with fallback logic (#1527)

- (@DSharifi): *(contract)* Make contract configuration values configurable (#1566)

- (@pbeza): Clear update votes from non-participants after resharing (#1559)


### 🐛 Bug Fixes

- (@DSharifi): Only allow contract itself to call `migrate` function (#1556)

- (@gilcu3): Check python code quality in CI enabled (#1576)

- (@gilcu3): Wrong tag name in gcp image creation (#1594)


### 📚 Documentation

- (@DSharifi): Create release changelog for `3.1.0` release (#1610)


### 🧪 Testing

- (@DSharifi): Fix broken example `pytest` command (#1581)

- (@DSharifi): *(pytest fix)* Remove 1 validator override in pytests (#1538)


### ⚙️ Miscellaneous Tasks

- (@DSharifi): Remove pub migrate function and make gas deposit for upgrades configurable (#1501)

- (@gilcu3): Provide cargo-binstall with a token (#1558)

- (@gilcu3): Bump attestation submission frequency (#1561)

- (@DSharifi): Don't take self needlessly on contract methods (#1569)

- (@DSharifi): *(dead-code)* Remove `allowed_code_hashes` and `mig_migration_info` methods from the contract (#1580)

- (@DSharifi): Bump `near-sdk` to 5.18.1  (#1579)

- (@gilcu3): Create mpc attestation wrapper crate (#1577)

- (@netrome): Bump nearcore to 2.10.0 (#1593)

- (@DSharifi): Bump project version to `3.1.0` (#1586)

- (@gilcu3): Make attestation crate independent of the mpc (#1588)

- (@netrome): Document how to make a release (#1551)

- (@barakeinav1): Update dockerhub configuration parameter and add integration test for validate_image_hash using Docker Hub image (#1584)

- (@DSharifi): Use `jemalloc` as memory allocator (#1602)

- (@DSharifi): Remove dead legacy code in contract (#1607)

- (@gilcu3): Remove legacy support in devnet (#1603)

- (@netrome): Bump nearcore to 2.10.1 (#1609)


## [3.0.6] - 2025-11-25

### 🚀 Features

- (@gilcu3): Fix rust-cache in CI (#1533)

- (@kevindeforth): Allow participants to withdraw their update vote (#1537)

- (@gilcu3): Initial ckd example app (#1542)


### 🐛 Bug Fixes

- (@gilcu3): Both test could be fixed by bumping gas appropiately (#1521)

- (@gilcu3): Enable pytest optimizations removed in #1511  (#1530)

- (@gilcu3): Use reproducible build in existing test (#1531)

- (@gilcu3): Use correct nearcore commit in submodule (#1539)

- (@gilcu3): Patch nearcore version 210 (#1547)


### 📚 Documentation

- (@pbeza): Design TEE-enabled backup service (#1467)


### ⚙️ Miscellaneous Tasks

- (@netrome): Bump crate versions to 3.0.6 and update changelog (#1549)


## [3.0.5] - 2025-11-23

### 🚀 Features

- (@andrei-near): Periodic mpc build workflow (#1505)

- (@kevindeforth): Contract allows querying update proposals (#1506)

- (@gilcu3): Sandbox tests support for any number of participants (#1510)


### 🐛 Bug Fixes

- (@kevindeforth): *(contract)* Fix ProposeUpdate vote method and add unit test (#1488)

- (@gilcu3): Remove balance checks (#1490)

- (@barakeinav1): *(test)* Enable and update test_from_str_valid (#1492)

- (@andrei-near): Nightly build MPC workflow (#1509)

- (@netrome): Use patched near core supporting reproducible builds (#1525)


### 🧪 Testing

- (@pbeza): Add unit tests for `do_update` function in `contract.rs` (#1498)

- (@barakeinav1): Update attestation test and refresh asset extraction files (#1504)


### ⚙️ Miscellaneous Tasks

- (@DSharifi): Update mainnet to use 3_0_2 release for backwards compatibilit… (#1503)

- (@DSharifi): Bump nearcore dependency to `2.10.0-rc.3` (#1511)

- (@netrome): Bump crate versions to 3.0.5 and update changelog (#1523)


## [3.0.4] - 2025-11-18

### 🚀 Features

- (@barakeinav1): *(verification)* Allow RTMR2 to match production or dev measurements (#1428)

- (@gilcu3): Add support for abi snapshots (#1438)

- (@gilcu3): Add pytest with CKD private verification (#1459)

- (@gilcu3): Group compatible pytests to use shared cluster (#1468)


### 🐛 Bug Fixes

- (@barakeinav1): *(localnet)* Ensure MPC node can sync after delay by updating neard retention policy (#1448)

- (@gilcu3): Align waiting time with number of added domains (#1446)

- (@gilcu3): Update snapshot after recent contract ABI changes (#1463)

- (@netrome): Separate build workflows for launcher and node (#1469)

- (@gilcu3): Make sure cargo-near is installed from binary release (#1471)

- (@gilcu3): Fetch mpc secret store key and add gcp image (#1480)


### ⚙️ Miscellaneous Tasks

- (@gilcu3): Update testnet contract (#1451)

- (@gilcu3): Update contract readme wrt CKD (#1454)

- (@netrome): Improved docker workflows for node and launcher image (#1460)

- (@gilcu3): Extend localnet guide to include eddsa and ckd examples as well (#1464)

- (@netrome): Bump crate versions to 3.0.4 and update changelog (#1487)


## [3.0.3] - 2025-11-12

### 🐛 Bug Fixes

- (@pbeza): Reduce log noise in migration monitor task (#1441)


### ⚙️ Miscellaneous Tasks

- (@barakeinav1): Fix key names in localnet guide (#1434)

- (@netrome): Bump nearcore to include 2.9.1 (#1444)

- (@netrome): Bump crate versions to 3.0.3 and update changelog (#1445)


## [3.0.2] - 2025-11-11

### 🚀 Features

- (@gilcu3): Validate attestation before submission (#1412)


### 🐛 Bug Fixes

- (@gilcu3): Test_latest_allowed_image_hash_is_written assuming wrong order (#1405)

- (@gilcu3): Remove wrong near_sdk::PublicKey conversions (#1413)

- (@pbeza): Disable state sync in `start.sh` for localnet (#1414)

- (@gilcu3): Path to store latest mpc node image hashes in devnet (#1418)

- (@barakeinav1): *(tee)* Add  prefix to written image digest for launcher compatibility (#1426)

- (@gilcu3): Enable user_views tests in the contract (#1432)

- (@gilcu3): Add pub_migrate function to get current contract migration unstuck (#1436)


### 🧪 Testing

- (@kevindeforth): Improve unit tests (#1406)


### ⚙️ Miscellaneous Tasks

- (@Copilot): Downgrade account balance fetch log to debug level (#1409)

- (@barakeinav1): Remove "exit 1" that could close ssh session (#1427)

- (@netrome): Bump protocol version (#1430)

- (@netrome): Update version and changelog for 3.0.2 release (#1439)


## [3.0.1] - 2025-11-06

### 🚀 Features

- (@pbeza): Add default behavior if `MPC_LATEST_ALLOWED_HASH_FILE` is not set (#1401)


### 🐛 Bug Fixes

- (@gilcu3): Compute fresh attestations before submitting (#1396)

- (@kevindeforth): Node uses correct latest docker image hash (#1403)


### ⚙️ Miscellaneous Tasks

- (@barakeinav1): Small operator guide fixes (#1385)

- (@kevindeforth): Generate backup encryption key if env var is not provided (#1398)

- (@netrome): Update nearcore to a modified 2.9 with testnet voting date set (#1397)

- (@netrome): Update version and changelog for 3.0.1 release (#1404)


## [3.0.0] - 2025-11-05

### 🚀 Features

- (@kevindeforth): *(devnet)* Loadtest tracks success statistics (#489)

- (@pbeza): *(contract)* Add support for TEE (#410)

- (@DSharifi): *(contract)* Add method to contract to get allowed image hashes (#511)

- (@kevindeforth): *(Tee)* Automatic kickout mechanism for invalid TEE status (#468)

- (@pbeza): *(contract)* Verification of TEE RTMRs 0-2 and MRTD (#509)

- (@DSharifi): *(indexer)* Periodically fetch allowed image hashes from mpc contract (#513)

- (@DSharifi): *(tee)* Node monitors latest allowed image hashes from contract (#525)

- (@barakeinav1): Initial launcher script (#524)

- (@kuksag): *(tee)* Generate p2p key/near signer key inside MPC node (#445)

- (@pbeza): *(contract)* Verification of RTMR3 (#516)

- (@pbeza): *(contract)* Verify `report_data` field of the TEE quote (#537)

- (@barakeinav1): *(remote attestation )* RTMRs and app_compose field checks (#541)

- (@DSharifi): Submit remote attestation on startup (#543)

- (@kevindeforth): *(Tee)* Join logic for new participant and readme (#553)

- (@kevindeforth): *(devnet)* Enable ssd support (#558)

- (@kevindeforth): *(pytest)* Interactive pytest (#576)

- (@kevindeforth): Enable network hardship simulation (#560)

- (@barakeinav1): *(tee)* Add p2p public key to StaticWebData and http endpoint (#639)

- (@pbeza): *(tee)* Custom attestation module (#632)

- (@pbeza): *(tee)* Implement attestation quote generation in attestation module (#653)

- (@DSharifi): *(contract)* Key resharing can be cancelled on the contract (#665)

- (@kevindeforth): *(metrics)* Expose peers block height metric (#684)

- (@pbeza): *(tee)* Implement TEE quote verification in attestation module (#683)

- (@gilcu3): Added TEE enabled dockerfile + github workflow (#722)

- (@gilcu3): Add support for cargo-near reproducible build (#734)

- (@pbeza): *(tee)* Add Docker image verification logic to attestation (#711)

- (@kevindeforth): Export account balances as metric (#776)

- (@barakeinav1): Add CLI script to deploy the Launcher in dstack CVM (#747)

- (@andrei-near): Build info metrics (#769)

- (@gilcu3): Add CKD support to the MPC contract (#885)

- (@gilcu3): Add DomainId to CKDRequest (#934)

- (@gilcu3): CKD support in indexer - node/src/indexer/ changes (#956)

- (@gilcu3): CKD support in indexer - store + web changes (#957)

- (@pbeza): *(tee)* Clean TEE state when concluding a resharing (#942)

- (@andrei-near): Overwrite mpc/near configs from ENV vars (#964)

- (@gilcu3): CKD indexer - queue refactor (#968)

- (@gilcu3): CKD provider support (#974)

- (@netrome): Cli option to configure attestation authority (#967)

- (@gilcu3): Added pytests for CKD (#985)

- (@gilcu3): DomainId separation enforcement in the contract (#1008)

- (@kevindeforth): Improve asset cleanup behavior when entering running or resharing (#1032)

- (@gilcu3): Make leader explicit in completed requests (#1038)

- (@gilcu3): CKD support in devnet (#1023)

- (@kevindeforth): Change of participant set leads to exit of running state. (#1061)

- (@gilcu3): Achieve reproducible builds for the mpc node and launcher (#1064)

- (@barakeinav1): *(pytest)* Restrict signer keys to MPC contract method (clean) (#1070)

- (@andrei-near): Failed cluster signatures metrics main (#1153)

- (@kevindeforth): Contract supports migration service (#1162)

- (@barakeinav1): Devnet add missing image_hash and latest_allowed_hash_file (#1155)

- (@DSharifi): Enforce all participants to have valid attestations (#1197)

- (@gilcu3): Update to use new ts rerandomization+coordinator API (#1219)

- (@kevindeforth): Metrics tracking participant ids in failed signature computations (#1233)

- (@kevindeforth): Import keyshares into empty keyshare storage (#1215)

- (@gilcu3): New dtos_contract::PublicKey type (#1225)

- (@pbeza): Re-submit attestation if node detects it has no attestation on chain (#1223)

- (@gilcu3): Add near_sdk compatible serde serialization for dto types + Bls types (#1241)

- (@kevindeforth): Indexer fetches migration state from contract and displays it on a web-endpoint (#1250)

- (@gilcu3): Ckd bls pivot (#1239)

- (@kevindeforth): Onboarding logic for MPC node (#1267)

- (@gilcu3): Support CKD with BLS in pytests (#1272)

- (@pbeza): Scaffold initial backup service (#1289)

- (@kevindeforth): Import keyshares into non empty keyshare storage (#1216)

- (@kevindeforth): Migration service web server and client logic (#1283)

- (@barakeinav1): Add public key enforcement feature (#1270)

- (@gilcu3): Add read-only getter for keyshares (#1300)

- (@gilcu3): Backup_cli store secrets in json file (#1301)

- (@barakeinav1): Add enforcement that contract call are by attested participants (#1313)

- (@gilcu3): Backup-cli http over mtls support (#1317)

- (@kevindeforth): Mpc node spawns recovery web endpoint (1295) (#1319)

- (@barakeinav1): Use pre predecessor_account_id (#1316)

- (@Copilot): Add secrets.json migration support for 2.2.0 → 3.0.0 upgrade path (#1329)

- (@gilcu3): Update to current ts version, more changes than I expected, some tricky deps changes as well (#1339)

- (@gilcu3): Ensure docker compose file is up to date in get docker compose hash (#1353)

- (@pbeza): Implement public key registration for the backup service (#1333)

- (@barakeinav1): Update launcher to remove old MPC container (#1366)

- (@netrome): More detailed error messages when attestation validation fails (#1369)

- (@netrome): Don't enforce secure time (#1375)

- (@netrome): *(launcher)* Allow passing through NEAR_TESTS_PROTOCOL_UPGRADE_OVERRIDE env var (#1380)

- (@kevindeforth): Send AES-256 encrypted secrets over mutual TLS instead of plaintext (#1376)

- (@pbeza): Implement `KeyshareStorageAdapter` for keyshare persistence (#1384)


### 🐛 Bug Fixes

- (@pbeza): *(tee)* Hotfix of TEE `report_data` verification (#552)

- (@pbeza): *(tee)* Ensure quote verification status is `UpToDate` (#585)

- (@kevindeforth): *(devnet)* Refill contract account for initalization (#578)

- (@kevindeforth): Ignore peers who are behind in a computation (#595)

- (@barakeinav1): Harden launcher docker-compose config against privilege escalation (#589)

- (@DSharifi): *(dstack)* Bump dstack rust sdk version (#617)

- (@DSharifi): *(tee)* Don't re-encode tdx_quote to hex (#627)

- (@DSharifi): *(tee)* Serialize `quote_collateral` to a `serde_json::Value` instead of String (#629)

- (@barakeinav1): *(launcher)* Enforce env var allow-list and custom host/port parsing in user-config (#588)

- (@DSharifi): *(dstack)* Bump dstack rust sdk version (#620)

- (@DSharifi): Create tokio enter guard for spawning TEE related tasks (#612)

- (@andrei-near): Add boot nodes at near indexer config init state (#667)

- (@kuksag): Adjust invariant checks when selecting participants (#680)

- (@kevindeforth): *(deployment)* Gcp start script key error (#705)

- (@netrome): Transparent serialization for Hash32 (#704)

- (@kevindeforth): *(devnet)* Compatibility with upcoming mpc node version 3.0.0 (#715)

- (@gilcu3): Fixes test_from_str_valid test in the contract crate (#724)

- (@gilcu3): Display error message when participant list is empty in mpc-node generate-test-configs (#740)

- (@andrei-near): Bumping nearcore to 2.7.0-rc4 (#755)

- (@DSharifi): Defer creating `allowed_image_hash` file until write (#768)

- (@barakeinav1): *(launcher)* Fixing of issues found during testing (#762)

- (@kevindeforth): Spawn mointor docker images task before listening to blocks indefinitely (#778)

- (@jaswinder6991): Update README.md to fix the broken link to Cait-Sith blog post (#785)

- (@gilcu3): Replay all RTMR3 required events (#800)

- (@DSharifi): Node ignores peers lagging 50 blocks behind (#802)

- (@barakeinav1): *(node)* Enforce RTMR3 validation on event checks (#780)

- (@kevindeforth): Node abort_key_event_instance instead of abort_key_event (#807)

- (@gilcu3): Verify docker compose hashes correctly (#774)

- (@barakeinav1): *(contract)* Correct tee_status and verify_tee logic (#816)

- (@gilcu3): Fix typos and name inconsistencies (#838)

- (@kevindeforth): Api mismatch for submitting participant info (#852)

- (@kevindeforth): Propose join and rename to submit_participant_info (#851)

- (@gilcu3): Use download_config parameter in mpc-node cli (#788)

- (@pbeza): *(tee)* Ensure participants run valid TEE or none (#887)

- (@kevindeforth): Increase gas limit for sign calls (#925)

- (@gilcu3): CI get docker manifest timeouts (#928)

- (@gilcu3): Add domainid ckdrequest again (#955)

- (@pbeza): *(tee)* Avoid passing `ExpectedMeasurements` as a parameter in contract (#971)

- (@think-in-universe): Redundant secure_time validation for app compose (#997)

- (@gilcu3): Use correct assert_matches (#1022)

- (@netrome): Use version controlled contracts in compatibility tests (#1031)

- (@netrome): Add missing bs58 dependency in contract_history crate (#1040)

- (@DSharifi): Return participants with invalid attestation in error message (#1096)

- (@netrome): Ignore broken tests (#1149)

- (@pbeza): Don't cleanup allowed hashes on getters (#1146)

- (@robin-near): Stream while syncing instead of waiting for full sync. (#738)

- (@gilcu3): Add needed deps in dockerfile, remove unnecessary (#1170)

- (@pbeza): Contract was refunding too much of deposit (#1165)

- (@pbeza): Address post-merge code review comments for PR #1183 (#1189)

- (@gilcu3): Restore exact workflow before #1113 not including MPC launcher (#1193)

- (@DSharifi): Node should retry attestation submission until its observed onchain (#1174)

- (@pbeza): Resubmit participant info more frequently (#1202)

- (@netrome): Run attestation requests within a tokio runtime (#1229)

- (@pbeza): `tee_authority::get_with_backoff` was ending up in a hot loop (#1247)

- (@netrome): Remove references to stale scripts (#1258)

- (@gilcu3): Devnet using ckd with BLS (#1266)

- (@gilcu3): Use more efficient DomainRegistry (#1281)

- (@gilcu3): Remaining issues in TDX external guide (#1282)

- (@gilcu3): Bug wasm execution failed error when running mpc localnet nodes (#1330)

- (@netrome): Use port 24566 instead of 24567 for boot node arg in localnet guide (#1350)

- (@gilcu3): Ensure hex serialization in vote-code-hash (#1358)

- (@netrome): Disable state sync in localnet (#1364)

- (@gilcu3): Github actions by pinning versions, added zizmor to CI (#1365)

- (@gilcu3): Continue when receiver has lagged messages and log event (#1374)

- (@barakeinav1): Update operator guide with correct port configuration (#1381)

- (@gilcu3): Update the measurements that are actually used in the contract (#1382)


### 🚜 Refactor

- (@barakeinav1): *(launcher)* Update user-config format and values (#670)

- (@pbeza): *(tee)* Move attestation generation logic (#758)

- (@DSharifi): *(attestation)* Remove `TcbInfo` wrapper struct (#882)

- (@DSharifi): Remove `Quote` wrapper struct in attestation (#884)

- (@netrome): Consistent usage of SerializableEdwardsPoint in crypto_shared/types.rs (#890)

- (@netrome): Get rid of `mod.rs` files (#998)

- (@DSharifi): Make `verify_tee_participant` API infallible (#1098)


### 📚 Documentation

- (@gilcu3): Added doc on how to deploy an MPC node within a TEE (#733)

- (@barakeinav1): Operator guide first version (#886)

- (@kevindeforth): Document disaster recovery plan (#877)

- (@DSharifi): Update readme to list testnet RPC providers for devnet tool (#954)

- (@barakeinav1): Tdx cloud providers (#980)

- (@barakeinav1): Update operator's guide with CVM update flow (#983)

- (@barakeinav1): TEE design doc (#979)

- (@barakeinav1): Explain how to get dstack logs (#992)

- (@barakeinav1): Add link to HLD (#993)

- (@think-in-universe): Make the launcher docs more readable (#1002)

- (@barakeinav1): Port collision documentation (#999)

- (@barakeinav1): Update production_settings (#1001)

- (@barakeinav1): Add explanation about key generation (#1033)

- (@barakeinav1): How to add MPC node key into account (#1030)

- (@barakeinav1): Getting lasted MPC hash from the contract (#1043)

- (@barakeinav1): Voting_new_hash (#1045)

- (@barakeinav1): Add vote_new_parameters documentation (#1041)

- (@barakeinav1): Update TEE difference table (#1059)

- (@barakeinav1): Update local key provider section (#1048)

- (@barakeinav1): Update information about MPC node retrieval (#1072)

- (@barakeinav1): Add submit_participant_info details (#1062)

- (@barakeinav1): Add reproducible build instructions for Dstack (#1106)

- (@barakeinav1): Update RTMR generation instructions for dstack 0.5.4 (#1154)

- (@pbeza): Update contract README with gas cost details (#1178)

- (@netrome): Document contract interface crate (#1256)

- (@netrome): Operator guide includes installation instructions for dstack-vmm instead of referencing their readme (#1262)

- (@pbeza): *(localnet)* Refine `localnet` setup instructions (#1278)


### 🧪 Testing

- (@DSharifi): Test that threshold from previous running state is used when serving sign requests in resharing (#481)

- (@kevindeforth): *(node)* Add timeout to avoid race condition in integration test (#498)

- (@kevindeforth): *(pytest)* Resolve pytest nonce conflicts (#555)

- (@DSharifi): Create pytest to test cancellation of key resharing (#682)

- (@pbeza): *(tee)* Add an integration test for attestation verification (#746)

- (@pbeza): *(tee)* Add contract integration test for MPC image hash voting (#819)

- (@DSharifi): Re-organize tests in attestation crate (#834)

- (@pbeza): *(contract)* Integration test to ensure contract rejects invalid remote attestations (#828)

- (@pbeza): Expired attestation kickout flow (#1099)

- (@DSharifi): Move sandbox integration tests into separate directory. (#1168)

- (@pbeza): Add grace period test for multi-node voting (#1183)

- (@DSharifi): Rewrite upgrade test as a sandbox integration tests (#1186)

- (@DSharifi): Wait for TEE attestations on resharings in pytests (#1200)

- (@DSharifi): Proposal for adding new participant without valid TEE attestation should fail (#986)

- (@DSharifi): Resolve flaky test caused by ordering of attestations (#1211)

- (@pbeza): *(contract)* System test for `submit_tee_participant_info` (#1066)


### ⚙️ Miscellaneous Tasks

- (@netrome): Update devnet docs (#493)

- (@netrome): Initial Changelog + CI check (#494)

- (@kuksag): *(pytests)* Split cluster setup logic  (#508)

- (@DSharifi): Increase bytes allocated to version in report data from u8 to u16 (#526)

- (@kevindeforth): *(tee)* Launcher cleanup (#549)

- (@DSharifi): Fix docker build and publish action (#564)

- (@andrei-near): Sanitize docker build CI to replace invalid tag symbol (#571)

- (@kuksag): Remove p2p and signer key retrival via gcp (#572)

- (@netrome): Enable support for JSON logging (#569)

- (@sergey-ni): Migrated stats into IndexerState (#586)

- (@DSharifi): Add info logs when creating file handle for TEE image hash (#574)

- (@kuksag): Add `near_responder_id` and number of responder keys in `gcp-start.sh` logic (#573)

- (@DSharifi): Keep MPC node running if image hash is disallowed (#575)

- (@netrome): Bump nearcore to `2.7.0-rc.2` (#615)

- (@gilcu3): Rename cait-sith -> threshold-signatures (#640)

- (@netrome): Define release process (#631)

- (@andrei-near): Build Docker image as part of CI tests (#649)

- (@DSharifi): Use workspace for dependencies (#651)

- (@DSharifi): Add `--enable-bulk-memory-opt` requirement in contract readme (#659)

- (@DSharifi): Do not wait for indexer sync before generating TEE attestation (#662)

- (@DSharifi): Use the right `protocol_state` type for MpcContractV1 state (#669)

- (@DSharifi): Update pytest build step to include `--enable-bulk-memory` flag (#673)

- (@DSharifi): Setup `black` as formatter for pytest code (#677)

- (@kuksag): Make python formatter apply for the whole repo (#686)

- (@IkerAlus): *(readme)* Eddsa example in readme.md (#633)

- (@kuksag): Add TEE Launcher image building step to CI (#685)

- (@kuksag): Fix failing CI for TEE Launcher build (#692)

- (@kuksag): Add `tee_launcher` tests in CI (#688)

- (@kuksag): Specify TEE Launcher image from `nearone` registry (#694)

- (@DSharifi): Remove unused threshold parameter in start_cluster_with_mpc (#700)

- (@kevindeforth): *(deployment)* Gcp start bash script: avoid unnecessary warning (#707)

- (@kevindeforth): Rename web endpoint /get_public_data to /public_data (#708)

- (@netrome): Override org-wide issue template (#718)

- (@netrome): Move MPC node modules to `lib.rs` (#720)

- (@DSharifi): *(devnet)* Add support for voting new approved code hash on devnet (#742)

- (@kuksag): Remove mpc-keys crate in contract (#749)

- (@hackpk): *(lazy_static)* Replace lazy_static with LazyLock  (#660)

- (@kuksag): Add python linter (#750)

- (@kuksag): Allow contract to generate ABI (#751)

- (@gilcu3): Execute python lint/format CI only when needed (#773)

- (@DSharifi): Remove i/o code from attestation crate (#775)

- (@gilcu3): Unify near-sdk versions (#783)

- (@kevindeforth): *(ci)* Split ci-tests into multiple jobs (#787)

- (@gilcu3): Remove nightly features from fmt config (#790)

- (@gilcu3): Fix cargo-near install failure in CI (#793)

- (@barakeinav1): *(launcher)* Small update of variable and file name for better clarity (#792)

- (@kevindeforth): *(pytests)* Speedup - reduce rpc poll timeout and send txs in parallel (#796)

- (@kevindeforth): *(ci)* Add clippy all-features (#798)

- (@kevindeforth): *(pytest)* Improve test_lost_assets.py performance and coverage (#810)

- (@kevindeforth): *(pytest)* Fix flaky test_signature_lifecycle (#812)

- (@gilcu3): Use our own fork of dcap-qvl v0.2.4 (#813)

- (@gilcu3): Remove default features prometheus (#821)

- (@DSharifi): Implement serde + borsh (de)serialization for attestation crate types (#806)

- (@gilcu3): Upd near-crypto in infra/scripts/generate_keys/ (#822)

- (@DSharifi): Update `dcap-qvl` crate to upstream version (#840)

- (@barakeinav1): *(launcher script)* Update readme (#833)

- (@DSharifi): Replace `YamlValue` with a String wrapper for docker_compose_file (#870)

- (@DSharifi): Add docker TEE build as a CI check (#835)

- (@gilcu3): Added  test_vote_code_hash_doesnt_accept_account_id_not_in_participant_list test (#871)

- (@DSharifi): Implement borsh schema for attestation crate types (#873)

- (@kevindeforth): *(test)* More detailed error checking in contract test (#874)

- (@DSharifi): Update phala cloud API endpoint for collateral generation (#876)

- (@pbeza): *(tee)* Remove account key from report data (#869)

- (@gilcu3): Integrate ts#22 refactor (#867)

- (@DSharifi): Integrate the attestation module into the contract code (#878)

- (@DSharifi): Remove `near_crypto` from attestation crate (#889)

- (@kevindeforth): *(contract)* Remove stale log of random seed in contract (#922)

- (@DSharifi): Remove `near_crypto` dependency from smart contract (#933)

- (@DSharifi): Move config.rs unit test behind feature gated test module (#937)

- (@barakeinav1): *(deploy script)* Update MPC node ports  (#872)

- (@DSharifi): [**breaking**] Remove near_crypto from node code (#914)

- (@kevindeforth): *(node)* Move tls into crate (#963)

- (@gilcu3): Bump version tracing-subscriber (#989)

- (@gilcu3): Bump dcap-qvl to released version (#991)

- (@DSharifi): Use configuration value instead of constant for `TEE_UPGRADE_PERIOD` (#995)

- (@DSharifi): Upgrade `ed25519-dalek` version in contract (#1000)

- (@DSharifi): Use crates.io version of dstack-sdk (#1004)

- (@netrome): Enable running with dstack TEE authority in start.sh (#1010)

- (@DSharifi): Delete `docker_release_tee.yaml` workflow (#1007)

- (@gilcu3): Fix warning while building contract in pytests (#1011)

- (@gilcu3): Fix deployment start script  (#1021)

- (@DSharifi): Use `test_utils` crate for image hashes in contract tests (#1013)

- (@barakeinav1): Set MPC authority stared by launcher to always expect real TDX HW (#1018)

- (@andrei-near): Test for new docker images (#1036)

- (@gilcu3): Avoid storing migration contract binary (#1047)

- (@DSharifi): Enhance mock attestation struct with conditional validation (#1016)

- (@kevindeforth): *(test)* Fix resharing tests (#1068)

- (@kevindeforth): Update disaster recovery doc (#1082)

- (@gilcu3): Refactor to adapt to API changes in threshold-signatures (#1093)

- (@barakeinav1): Unify launcher folders (#1104)

- (@DSharifi): Remove redundant and duplicate clippy check for `devnet` crate (#1108)

- (@DSharifi): Create an interface for submitting transactions with response (#1101)

- (@gilcu3): Update ci to use reproducible builds (#1113)

- (@DSharifi): Move contract crate into root workspace (#1102)

- (@gilcu3): Add detailed steps for mpc node image code inspection during upgrades (#1116)

- (@DSharifi): Fix build script for builds in detached head (#1122)

- (@gilcu3): Added security policy (#1124)

- (@DSharifi): Pin serde to `1.0.2191` to fix compilation issue with `dstack-sdk` (#1125)

- (@gilcu3): *(ci)* Separate CI actions for launcher and node (#1127)

- (@gilcu3): *(docs)* Update docs after #1127 (#1131)

- (@DSharifi): Move all workspace members in to `/crates` directory (#1136)

- (@barakeinav1): Update user guide with dstack 0.5.4 changes (#1115)

- (@gilcu3): Adapt to API changes in ts#78 (#1143)

- (@kevindeforth): Index nodes by account id & TLS key in TEE State (#1120)

- (@gilcu3): Use workspace versions in contract Cargo.toml (#1142)

- (@DSharifi): Remove enum `VersionedMpcContract` contract state in favor of a single version struct (#1111)

- (@gilcu3): Bring back legacy CI (#1157)

- (@DSharifi): Update error message in image hash watcher (#1159)

- (@DSharifi): Create DTO types for the attestation submission method (#1151)

- (@DSharifi): Use time durations instead of block numbers for tee grace period (#1166)

- (@gilcu3): Make sure devnet tests ckd (#1190)

- (@DSharifi): Add github action for unused dependencies (#1141)

- (@pbeza): Remove redundant `allow` attribute (#1221)

- (@DSharifi): Use base58 encoding for public key serialization on node HTTP server. (#1230)

- (@DSharifi): Document how to run a local mpc network (#1231)

- (@gilcu3): Remove unneeded deps in attestation crate (#1251)

- (@gilcu3): Added systemd service for VMM (#1253)

- (@kevindeforth): Resolve flaky integration tests (#1273)

- (@gilcu3): Contract unit tests for ckd (#1261)

- (@kevindeforth): Contract move helpers (#1276)

- (@gilcu3): Add support for CKD BLS in contract sandbox tests (#1274)

- (@kevindeforth): Use read-write lock for keyshare storage (#1305)

- (@DSharifi): Enforce sorted cargo dependencies on CI (#1315)

- (@netrome): Bump nearcore to 2.9.0 (#1323)

- (@netrome): Use pinned nextest version and standard installation action (#1326)

- (@gilcu3): Use proper serialization format for PersistentSecrets (#1338)

- (@netrome): Add support for dockerized localnet (#1336)

- (@pbeza): Cargo update and fix deprecated API usage (#1340)

- (@Copilot): Document reproducible builds in README.md (#1347)

- (@gilcu3): Use 0 as SOURCE_DATE_EPOCH for repro builds (#1352)

- (@gilcu3): Move test-utils to ts repo (#1344)

- (@gilcu3): Updated hard-coded TCB info for 3.0.0 release (#1378)

- (@netrome): Set crate versions to 3.0.0 and update changelog (#1383)

- (@netrome): Support publishing images from git tags (#1388)


### ◀️ Revert

- (@DSharifi): "refactor(tee): move attestation generation logic" (#779)


## [2.2.0-rc1] - 2025-06-11

### ⚙️ Miscellaneous Tasks

- (@DSharifi): Bump versions for new release candidate (#490)


## [2.0.1-rc2] - 2025-06-10

### 🚀 Features

- (@DSharifi): *(TEE)* Implement remote attestation information generation (#466)


### 🐛 Bug Fixes

- (@DSharifi): Use threshold number for previous running state in resharing (#480)


### ⚙️ Miscellaneous Tasks

- (@netrome): Add MIT license and third party license notices (#477)


## [2.0.1-rc1] - 2025-06-03

### 🚀 Features

- (@DSharifi): Parallel resharing and running (#438)


### 🐛 Bug Fixes

- (@DSharifi): Return early in Indexer thread and listen_blocks if channel to MPC node is closed.


### 💼 Other

- (@andrei-near): Fix import keyshare  (#416)


### ⚙️ Miscellaneous Tasks

- (@DSharifi): Add metrics for latency of signature request responses (#366)

- (@DSharifi): Add metrics for latency of signature request responses in seconds

- (@DSharifi): Remove spawn_blocking call wrapping the indexer thread (#371)

- (@DSharifi): Remove unwrap in `monitor_passive_channels_inner` (#406)


## [2.0.0-rc.1] - 2025-04-11

### 🚀 Features

- (@DSharifi): *(EdDSA)* Add support for EdDSA signature requests on the smart contract (#294)


### 🐛 Bug Fixes

- (@pbeza): *(audit)* Fix TLS certificate verification (#209)

- (@DSharifi): Pinned legacy contract dependency to git revistion (#268)

- (@DSharifi): Add pre-computed edwards_point of EdDSA keys to contract state (#328)

- (@DSharifi): Use internal tag for signature response type for backwards compatibility (#358)


### 💼 Other

- (@andrei-near): MPC Load Balancer removal (#260)

- (@andrei-near): Implement import-export keyshare (#267)

- (@peter-near): Removed unused cipher key generation (#274)

- (@andrei-near): Tokio runtime for import/export keyshare commands (#292)

- (@andrei-near): Vote leave cmd (#300)

- (@kuksag): Reuse `PayloadHash` and `Epsilon` types from contact (#269)

- (@andrei-near): Warpbuild GHA runners (#304)

- (@andrei-near): Option to use own funding account (#331)

- (@andrei-near): MPC_HOME_DIR in image init script (#335)

- (@peter-near): Added IDE configs to git ignore (#336)


### 🚜 Refactor

- (@pbeza): *(audit)* Remove explicit .into_iter (#210)

- (@pbeza): *(audit)* Shorten CLI's function bodies (#215)

- (@DSharifi): Use `[u8; 32]` instead of Scalar type from `k256` crate in contract (#283)

- (@DSharifi): Remove ScalarExt trait (#341)


### 🧪 Testing

- (@bowenwang1996): Reduce flakiness by reducing the amount of assets buffered in tests (#265)

- (@DSharifi): Test public key derivation in contract (#339)

- (@DSharifi): *(eddsa)* Add integration test for EdDSA signature requests (#347)

- (@DSharifi): Enable EdDSA signature requets in pytests (#348)


### ⚙️ Miscellaneous Tasks

- (@DSharifi): Remove self dependency to `legacy_contract` (#281)

- (@DSharifi): Pin `near-sdk` version to 5.2.1 (#286)

- (@DSharifi): Move `crypto-shared` to a module in contract (#282)

- (@DSharifi): Fix typo in codebase edd25519 to ed25519

- (@DSharifi): Add docs to EdDSA fields in `PublicKeyExtended`. (#334)


## [testnet-upgrade] - 2025-01-09

### 💼 Other

- (@andrei-near): Replace cache with rust-cache (#59)

- (@andrei-near): Workflow to build and publish MPC docker images (#115)

- (@andrei-near): Docker image builder nit (#116)



