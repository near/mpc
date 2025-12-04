# Changelog

All notable changes to this project will be documented in this file.


This changelog is maintained using [git-cliff](https://git-cliff.org/) and [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/).

## [3.1.0] - 2025-12-04

### 🚀 Features

- [#1552](https://github.com/near/mpc/pull/1552)(@gilcu3): Scale all remaining sandbox tests (#1552)

- [#1554](https://github.com/near/mpc/pull/1554)(@gilcu3): Add cargo-make support (#1554)

- [#1563](https://github.com/near/mpc/pull/1563)(@gilcu3): Embed abi in contract (#1563)

- [#1527](https://github.com/near/mpc/pull/1527)(@barakeinav1): *(launcher)* Add support for multiple MPC hashes with fallback logic (#1527)

- [#1566](https://github.com/near/mpc/pull/1566)(@DSharifi): *(contract)* Make contract configuration values configurable (#1566)

- [#1559](https://github.com/near/mpc/pull/1559)(@pbeza): Clear update votes from non-participants after resharing (#1559)


### 🐛 Bug Fixes

- [#1556](https://github.com/near/mpc/pull/1556)(@DSharifi): Only allow contract itself to call `migrate` function (#1556)

- [#1576](https://github.com/near/mpc/pull/1576)(@gilcu3): Check python code quality in CI enabled (#1576)

- [#1594](https://github.com/near/mpc/pull/1594)(@gilcu3): Wrong tag name in gcp image creation (#1594)


### 🧪 Testing

- [#1581](https://github.com/near/mpc/pull/1581)(@DSharifi): Fix broken example `pytest` command (#1581)


### ⚙️ Miscellaneous Tasks

- [#1501](https://github.com/near/mpc/pull/1501)(@DSharifi): Remove pub migrate function and make gas deposit for upgrades configurable (#1501)

- [#1558](https://github.com/near/mpc/pull/1558)(@gilcu3): Provide cargo-binstall with a token (#1558)

- [#1561](https://github.com/near/mpc/pull/1561)(@gilcu3): Bump attestation submission frequency (#1561)

- [#1569](https://github.com/near/mpc/pull/1569)(@DSharifi): Don't take self needlessly on contract methods (#1569)

- [#1580](https://github.com/near/mpc/pull/1580)(@DSharifi): *(dead-code)* Remove `allowed_code_hashes` and `mig_migration_info` methods from the contract (#1580)

- [#1579](https://github.com/near/mpc/pull/1579)(@DSharifi): Bump `near-sdk` to 5.18.1  (#1579)

- [#1577](https://github.com/near/mpc/pull/1577)(@gilcu3): Create mpc attestation wrapper crate (#1577)

- [#1593](https://github.com/near/mpc/pull/1593)(@netrome): Bump nearcore to 2.10.0 (#1593)

- [#1586](https://github.com/near/mpc/pull/1586)(@DSharifi): Bump project version to `3.1.0` (#1586)

- [#1588](https://github.com/near/mpc/pull/1588)(@gilcu3): Make attestation crate independent of the mpc (#1588)

- [#1551](https://github.com/near/mpc/pull/1551)(@netrome): Document how to make a release (#1551)

- [#1584](https://github.com/near/mpc/pull/1584)(@barakeinav1): Update dockerhub configuration parameter and add integration test for validate_image_hash using Docker Hub image (#1584)

- [#1602](https://github.com/near/mpc/pull/1602)(@DSharifi): Use `jemalloc` as memory allocator (#1602)

- [#1607](https://github.com/near/mpc/pull/1607)(@DSharifi): Remove dead legacy code in contract (#1607)

- [#1603](https://github.com/near/mpc/pull/1603)(@gilcu3): Remove legacy support in devnet (#1603)

- [#1609](https://github.com/near/mpc/pull/1609)(@netrome): Bump nearcore to 2.10.1 (#1609)


## [3.0.6] - 2025-11-25

### 🚀 Features

- [#1533](https://github.com/near/mpc/pull/1533)(@gilcu3): Fix rust-cache in CI (#1533)

- [#1537](https://github.com/near/mpc/pull/1537)(@kevindeforth): Allow participants to withdraw their update vote (#1537)

- [#1542](https://github.com/near/mpc/pull/1542)(@gilcu3): Initial ckd example app (#1542)


### 🐛 Bug Fixes

- [#1521](https://github.com/near/mpc/pull/1521)(@gilcu3): Both test could be fixed by bumping gas appropiately (#1521)

- [#1530](https://github.com/near/mpc/pull/1530)(@gilcu3): Enable pytest optimizations removed in #1511  (#1530)

- [#1531](https://github.com/near/mpc/pull/1531)(@gilcu3): Use reproducible build in existing test (#1531)

- [#1539](https://github.com/near/mpc/pull/1539)(@gilcu3): Use correct nearcore commit in submodule (#1539)

- [#1547](https://github.com/near/mpc/pull/1547)(@gilcu3): Patch nearcore version 210 (#1547)


### 📚 Documentation

- [#1467](https://github.com/near/mpc/pull/1467)(@pbeza): Design TEE-enabled backup service (#1467)


### ⚙️ Miscellaneous Tasks

- [#1549](https://github.com/near/mpc/pull/1549)(@netrome): Bump crate versions to 3.0.6 and update changelog (#1549)


## [3.0.5] - 2025-11-23

### 🚀 Features

- [#1505](https://github.com/near/mpc/pull/1505)(@andrei-near): Periodic mpc build workflow (#1505)

- [#1506](https://github.com/near/mpc/pull/1506)(@kevindeforth): Contract allows querying update proposals (#1506)

- [#1510](https://github.com/near/mpc/pull/1510)(@gilcu3): Sandbox tests support for any number of participants (#1510)


### 🐛 Bug Fixes

- [#1488](https://github.com/near/mpc/pull/1488)(@kevindeforth): *(contract)* Fix ProposeUpdate vote method and add unit test (#1488)

- [#1490](https://github.com/near/mpc/pull/1490)(@gilcu3): Remove balance checks (#1490)

- [#1492](https://github.com/near/mpc/pull/1492)(@barakeinav1): *(test)* Enable and update test_from_str_valid (#1492)

- [#1509](https://github.com/near/mpc/pull/1509)(@andrei-near): Nightly build MPC workflow (#1509)

- [#1525](https://github.com/near/mpc/pull/1525)(@netrome): Use patched near core supporting reproducible builds (#1525)


### 🧪 Testing

- [#1498](https://github.com/near/mpc/pull/1498)(@pbeza): Add unit tests for `do_update` function in `contract.rs` (#1498)

- [#1504](https://github.com/near/mpc/pull/1504)(@barakeinav1): Update attestation test and refresh asset extraction files (#1504)


### ⚙️ Miscellaneous Tasks

- [#1503](https://github.com/near/mpc/pull/1503)(@DSharifi): Update mainnet to use 3_0_2 release for backwards compatibilit… (#1503)

- [#1511](https://github.com/near/mpc/pull/1511)(@DSharifi): Bump nearcore dependency to `2.10.0-rc.3` (#1511)

- [#1523](https://github.com/near/mpc/pull/1523)(@netrome): Bump crate versions to 3.0.5 and update changelog (#1523)


## [3.0.4] - 2025-11-18

### 🚀 Features

- [#1428](https://github.com/near/mpc/pull/1428)(@barakeinav1): *(verification)* Allow RTMR2 to match production or dev measurements (#1428)

- [#1438](https://github.com/near/mpc/pull/1438)(@gilcu3): Add support for abi snapshots (#1438)

- [#1459](https://github.com/near/mpc/pull/1459)(@gilcu3): Add pytest with CKD private verification (#1459)

- [#1468](https://github.com/near/mpc/pull/1468)(@gilcu3): Group compatible pytests to use shared cluster (#1468)


### 🐛 Bug Fixes

- [#1448](https://github.com/near/mpc/pull/1448)(@barakeinav1): *(localnet)* Ensure MPC node can sync after delay by updating neard retention policy (#1448)

- [#1446](https://github.com/near/mpc/pull/1446)(@gilcu3): Align waiting time with number of added domains (#1446)

- [#1463](https://github.com/near/mpc/pull/1463)(@gilcu3): Update snapshot after recent contract ABI changes (#1463)

- [#1469](https://github.com/near/mpc/pull/1469)(@netrome): Separate build workflows for launcher and node (#1469)

- [#1471](https://github.com/near/mpc/pull/1471)(@gilcu3): Make sure cargo-near is installed from binary release (#1471)

- [#1480](https://github.com/near/mpc/pull/1480)(@gilcu3): Fetch mpc secret store key and add gcp image (#1480)


### ⚙️ Miscellaneous Tasks

- [#1451](https://github.com/near/mpc/pull/1451)(@gilcu3): Update testnet contract (#1451)

- [#1454](https://github.com/near/mpc/pull/1454)(@gilcu3): Update contract readme wrt CKD (#1454)

- [#1460](https://github.com/near/mpc/pull/1460)(@netrome): Improved docker workflows for node and launcher image (#1460)

- [#1464](https://github.com/near/mpc/pull/1464)(@gilcu3): Extend localnet guide to include eddsa and ckd examples as well (#1464)

- [#1487](https://github.com/near/mpc/pull/1487)(@netrome): Bump crate versions to 3.0.4 and update changelog (#1487)


## [3.0.3] - 2025-11-12

### 🐛 Bug Fixes

- [#1441](https://github.com/near/mpc/pull/1441)(@pbeza): Reduce log noise in migration monitor task (#1441)


### ⚙️ Miscellaneous Tasks

- [#1434](https://github.com/near/mpc/pull/1434)(@barakeinav1): Fix key names in localnet guide (#1434)

- [#1444](https://github.com/near/mpc/pull/1444)(@netrome): Bump nearcore to include 2.9.1 (#1444)

- [#1445](https://github.com/near/mpc/pull/1445)(@netrome): Bump crate versions to 3.0.3 and update changelog (#1445)


## [3.0.2] - 2025-11-11

### 🚀 Features

- [#1412](https://github.com/near/mpc/pull/1412)(@gilcu3): Validate attestation before submission (#1412)


### 🐛 Bug Fixes

- [#1405](https://github.com/near/mpc/pull/1405)(@gilcu3): Test_latest_allowed_image_hash_is_written assuming wrong order (#1405)

- [#1413](https://github.com/near/mpc/pull/1413)(@gilcu3): Remove wrong near_sdk::PublicKey conversions (#1413)

- [#1414](https://github.com/near/mpc/pull/1414)(@pbeza): Disable state sync in `start.sh` for localnet (#1414)

- [#1418](https://github.com/near/mpc/pull/1418)(@gilcu3): Path to store latest mpc node image hashes in devnet (#1418)

- [#1426](https://github.com/near/mpc/pull/1426)(@barakeinav1): *(tee)* Add  prefix to written image digest for launcher compatibility (#1426)

- [#1432](https://github.com/near/mpc/pull/1432)(@gilcu3): Enable user_views tests in the contract (#1432)

- [#1436](https://github.com/near/mpc/pull/1436)(@gilcu3): Add pub_migrate function to get current contract migration unstuck (#1436)


### 🧪 Testing

- [#1406](https://github.com/near/mpc/pull/1406)(@kevindeforth): Improve unit tests (#1406)


### ⚙️ Miscellaneous Tasks

- [#1409](https://github.com/near/mpc/pull/1409)(@Copilot): Downgrade account balance fetch log to debug level (#1409)

- [#1427](https://github.com/near/mpc/pull/1427)(@barakeinav1): Remove "exit 1" that could close ssh session (#1427)

- [#1430](https://github.com/near/mpc/pull/1430)(@netrome): Bump protocol version (#1430)

- [#1439](https://github.com/near/mpc/pull/1439)(@netrome): Update version and changelog for 3.0.2 release (#1439)


## [3.0.1] - 2025-11-06

### 🚀 Features

- [#1401](https://github.com/near/mpc/pull/1401)(@pbeza): Add default behavior if `MPC_LATEST_ALLOWED_HASH_FILE` is not set (#1401)


### 🐛 Bug Fixes

- [#1396](https://github.com/near/mpc/pull/1396)(@gilcu3): Compute fresh attestations before submitting (#1396)

- [#1403](https://github.com/near/mpc/pull/1403)(@kevindeforth): Node uses correct latest docker image hash (#1403)


### ⚙️ Miscellaneous Tasks

- [#1385](https://github.com/near/mpc/pull/1385)(@barakeinav1): Small operator guide fixes (#1385)

- [#1398](https://github.com/near/mpc/pull/1398)(@kevindeforth): Generate backup encryption key if env var is not provided (#1398)

- [#1397](https://github.com/near/mpc/pull/1397)(@netrome): Update nearcore to a modified 2.9 with testnet voting date set (#1397)

- [#1404](https://github.com/near/mpc/pull/1404)(@netrome): Update version and changelog for 3.0.1 release (#1404)


## [3.0.0] - 2025-11-05

### 🚀 Features

- [#489](https://github.com/near/mpc/pull/489)(@kevindeforth): *(devnet)* Loadtest tracks success statistics (#489)

- [#410](https://github.com/near/mpc/pull/410)(@pbeza): *(contract)* Add support for TEE (#410)

- [#511](https://github.com/near/mpc/pull/511)(@DSharifi): *(contract)* Add method to contract to get allowed image hashes (#511)

- [#468](https://github.com/near/mpc/pull/468)(@kevindeforth): *(Tee)* Automatic kickout mechanism for invalid TEE status (#468)

- [#509](https://github.com/near/mpc/pull/509)(@pbeza): *(contract)* Verification of TEE RTMRs 0-2 and MRTD (#509)

- [#513](https://github.com/near/mpc/pull/513)(@DSharifi): *(indexer)* Periodically fetch allowed image hashes from mpc contract (#513)

- [#525](https://github.com/near/mpc/pull/525)(@DSharifi): *(tee)* Node monitors latest allowed image hashes from contract (#525)

- [#524](https://github.com/near/mpc/pull/524)(@barakeinav1): Initial launcher script (#524)

- [#445](https://github.com/near/mpc/pull/445)(@kuksag): *(tee)* Generate p2p key/near signer key inside MPC node (#445)

- [#516](https://github.com/near/mpc/pull/516)(@pbeza): *(contract)* Verification of RTMR3 (#516)

- [#537](https://github.com/near/mpc/pull/537)(@pbeza): *(contract)* Verify `report_data` field of the TEE quote (#537)

- [#541](https://github.com/near/mpc/pull/541)(@barakeinav1): *(remote attestation )* RTMRs and app_compose field checks (#541)

- [#543](https://github.com/near/mpc/pull/543)(@DSharifi): Submit remote attestation on startup (#543)

- [#553](https://github.com/near/mpc/pull/553)(@kevindeforth): *(Tee)* Join logic for new participant and readme (#553)

- [#558](https://github.com/near/mpc/pull/558)(@kevindeforth): *(devnet)* Enable ssd support (#558)

- [#576](https://github.com/near/mpc/pull/576)(@kevindeforth): *(pytest)* Interactive pytest (#576)

- [#560](https://github.com/near/mpc/pull/560)(@kevindeforth): Enable network hardship simulation (#560)

- [#639](https://github.com/near/mpc/pull/639)(@barakeinav1): *(tee)* Add p2p public key to StaticWebData and http endpoint (#639)

- [#632](https://github.com/near/mpc/pull/632)(@pbeza): *(tee)* Custom attestation module (#632)

- [#653](https://github.com/near/mpc/pull/653)(@pbeza): *(tee)* Implement attestation quote generation in attestation module (#653)

- [#665](https://github.com/near/mpc/pull/665)(@DSharifi): *(contract)* Key resharing can be cancelled on the contract (#665)

- [#684](https://github.com/near/mpc/pull/684)(@kevindeforth): *(metrics)* Expose peers block height metric (#684)

- [#683](https://github.com/near/mpc/pull/683)(@pbeza): *(tee)* Implement TEE quote verification in attestation module (#683)

- [#722](https://github.com/near/mpc/pull/722)(@gilcu3): Added TEE enabled dockerfile + github workflow (#722)

- [#734](https://github.com/near/mpc/pull/734)(@gilcu3): Add support for cargo-near reproducible build (#734)

- [#711](https://github.com/near/mpc/pull/711)(@pbeza): *(tee)* Add Docker image verification logic to attestation (#711)

- [#776](https://github.com/near/mpc/pull/776)(@kevindeforth): Export account balances as metric (#776)

- [#747](https://github.com/near/mpc/pull/747)(@barakeinav1): Add CLI script to deploy the Launcher in dstack CVM (#747)

- [#769](https://github.com/near/mpc/pull/769)(@andrei-near): Build info metrics (#769)

- [#885](https://github.com/near/mpc/pull/885)(@gilcu3): Add CKD support to the MPC contract (#885)

- [#934](https://github.com/near/mpc/pull/934)(@gilcu3): Add DomainId to CKDRequest (#934)

- [#956](https://github.com/near/mpc/pull/956)(@gilcu3): CKD support in indexer - node/src/indexer/ changes (#956)

- [#957](https://github.com/near/mpc/pull/957)(@gilcu3): CKD support in indexer - store + web changes (#957)

- [#942](https://github.com/near/mpc/pull/942)(@pbeza): *(tee)* Clean TEE state when concluding a resharing (#942)

- [#964](https://github.com/near/mpc/pull/964)(@andrei-near): Overwrite mpc/near configs from ENV vars (#964)

- [#968](https://github.com/near/mpc/pull/968)(@gilcu3): CKD indexer - queue refactor (#968)

- [#974](https://github.com/near/mpc/pull/974)(@gilcu3): CKD provider support (#974)

- [#967](https://github.com/near/mpc/pull/967)(@netrome): Cli option to configure attestation authority (#967)

- [#985](https://github.com/near/mpc/pull/985)(@gilcu3): Added pytests for CKD (#985)

- [#1008](https://github.com/near/mpc/pull/1008)(@gilcu3): DomainId separation enforcement in the contract (#1008)

- [#1032](https://github.com/near/mpc/pull/1032)(@kevindeforth): Improve asset cleanup behavior when entering running or resharing (#1032)

- [#1038](https://github.com/near/mpc/pull/1038)(@gilcu3): Make leader explicit in completed requests (#1038)

- [#1023](https://github.com/near/mpc/pull/1023)(@gilcu3): CKD support in devnet (#1023)

- [#1061](https://github.com/near/mpc/pull/1061)(@kevindeforth): Change of participant set leads to exit of running state. (#1061)

- [#1064](https://github.com/near/mpc/pull/1064)(@gilcu3): Achieve reproducible builds for the mpc node and launcher (#1064)

- [#1070](https://github.com/near/mpc/pull/1070)(@barakeinav1): *(pytest)* Restrict signer keys to MPC contract method (clean) (#1070)

- [#1153](https://github.com/near/mpc/pull/1153)(@andrei-near): Failed cluster signatures metrics main (#1153)

- [#1162](https://github.com/near/mpc/pull/1162)(@kevindeforth): Contract supports migration service (#1162)

- [#1155](https://github.com/near/mpc/pull/1155)(@barakeinav1): Devnet add missing image_hash and latest_allowed_hash_file (#1155)

- [#1197](https://github.com/near/mpc/pull/1197)(@DSharifi): Enforce all participants to have valid attestations (#1197)

- [#1219](https://github.com/near/mpc/pull/1219)(@gilcu3): Update to use new ts rerandomization+coordinator API (#1219)

- [#1233](https://github.com/near/mpc/pull/1233)(@kevindeforth): Metrics tracking participant ids in failed signature computations (#1233)

- [#1215](https://github.com/near/mpc/pull/1215)(@kevindeforth): Import keyshares into empty keyshare storage (#1215)

- [#1225](https://github.com/near/mpc/pull/1225)(@gilcu3): New dtos_contract::PublicKey type (#1225)

- [#1223](https://github.com/near/mpc/pull/1223)(@pbeza): Re-submit attestation if node detects it has no attestation on chain (#1223)

- [#1241](https://github.com/near/mpc/pull/1241)(@gilcu3): Add near_sdk compatible serde serialization for dto types + Bls types (#1241)

- [#1250](https://github.com/near/mpc/pull/1250)(@kevindeforth): Indexer fetches migration state from contract and displays it on a web-endpoint (#1250)

- [#1239](https://github.com/near/mpc/pull/1239)(@gilcu3): Ckd bls pivot (#1239)

- [#1267](https://github.com/near/mpc/pull/1267)(@kevindeforth): Onboarding logic for MPC node (#1267)

- [#1272](https://github.com/near/mpc/pull/1272)(@gilcu3): Support CKD with BLS in pytests (#1272)

- [#1289](https://github.com/near/mpc/pull/1289)(@pbeza): Scaffold initial backup service (#1289)

- [#1216](https://github.com/near/mpc/pull/1216)(@kevindeforth): Import keyshares into non empty keyshare storage (#1216)

- [#1283](https://github.com/near/mpc/pull/1283)(@kevindeforth): Migration service web server and client logic (#1283)

- [#1270](https://github.com/near/mpc/pull/1270)(@barakeinav1): Add public key enforcement feature (#1270)

- [#1300](https://github.com/near/mpc/pull/1300)(@gilcu3): Add read-only getter for keyshares (#1300)

- [#1301](https://github.com/near/mpc/pull/1301)(@gilcu3): Backup_cli store secrets in json file (#1301)

- [#1313](https://github.com/near/mpc/pull/1313)(@barakeinav1): Add enforcement that contract call are by attested participants (#1313)

- [#1317](https://github.com/near/mpc/pull/1317)(@gilcu3): Backup-cli http over mtls support (#1317)

- [#1319](https://github.com/near/mpc/pull/1319)(@kevindeforth): Mpc node spawns recovery web endpoint (1295) (#1319)

- [#1316](https://github.com/near/mpc/pull/1316)(@barakeinav1): Use pre predecessor_account_id (#1316)

- [#1329](https://github.com/near/mpc/pull/1329)(@Copilot): Add secrets.json migration support for 2.2.0 → 3.0.0 upgrade path (#1329)

- [#1339](https://github.com/near/mpc/pull/1339)(@gilcu3): Update to current ts version, more changes than I expected, some tricky deps changes as well (#1339)

- [#1353](https://github.com/near/mpc/pull/1353)(@gilcu3): Ensure docker compose file is up to date in get docker compose hash (#1353)

- [#1333](https://github.com/near/mpc/pull/1333)(@pbeza): Implement public key registration for the backup service (#1333)

- [#1366](https://github.com/near/mpc/pull/1366)(@barakeinav1): Update launcher to remove old MPC container (#1366)

- [#1369](https://github.com/near/mpc/pull/1369)(@netrome): More detailed error messages when attestation validation fails (#1369)

- [#1375](https://github.com/near/mpc/pull/1375)(@netrome): Don't enforce secure time (#1375)

- [#1380](https://github.com/near/mpc/pull/1380)(@netrome): *(launcher)* Allow passing through NEAR_TESTS_PROTOCOL_UPGRADE_OVERRIDE env var (#1380)

- [#1376](https://github.com/near/mpc/pull/1376)(@kevindeforth): Send AES-256 encrypted secrets over mutual TLS instead of plaintext (#1376)

- [#1384](https://github.com/near/mpc/pull/1384)(@pbeza): Implement `KeyshareStorageAdapter` for keyshare persistence (#1384)


### 🐛 Bug Fixes

- [#552](https://github.com/near/mpc/pull/552)(@pbeza): *(tee)* Hotfix of TEE `report_data` verification (#552)

- [#585](https://github.com/near/mpc/pull/585)(@pbeza): *(tee)* Ensure quote verification status is `UpToDate` (#585)

- [#578](https://github.com/near/mpc/pull/578)(@kevindeforth): *(devnet)* Refill contract account for initalization (#578)

- [#595](https://github.com/near/mpc/pull/595)(@kevindeforth): Ignore peers who are behind in a computation (#595)

- [#589](https://github.com/near/mpc/pull/589)(@barakeinav1): Harden launcher docker-compose config against privilege escalation (#589)

- [#617](https://github.com/near/mpc/pull/617)(@DSharifi): *(dstack)* Bump dstack rust sdk version (#617)

- [#627](https://github.com/near/mpc/pull/627)(@DSharifi): *(tee)* Don't re-encode tdx_quote to hex (#627)

- [#629](https://github.com/near/mpc/pull/629)(@DSharifi): *(tee)* Serialize `quote_collateral` to a `serde_json::Value` instead of String (#629)

- [#588](https://github.com/near/mpc/pull/588)(@barakeinav1): *(launcher)* Enforce env var allow-list and custom host/port parsing in user-config (#588)

- [#620](https://github.com/near/mpc/pull/620)(@DSharifi): *(dstack)* Bump dstack rust sdk version (#620)

- [#612](https://github.com/near/mpc/pull/612)(@DSharifi): Create tokio enter guard for spawning TEE related tasks (#612)

- [#667](https://github.com/near/mpc/pull/667)(@andrei-near): Add boot nodes at near indexer config init state (#667)

- [#680](https://github.com/near/mpc/pull/680)(@kuksag): Adjust invariant checks when selecting participants (#680)

- [#705](https://github.com/near/mpc/pull/705)(@kevindeforth): *(deployment)* Gcp start script key error (#705)

- [#704](https://github.com/near/mpc/pull/704)(@netrome): Transparent serialization for Hash32 (#704)

- [#715](https://github.com/near/mpc/pull/715)(@kevindeforth): *(devnet)* Compatibility with upcoming mpc node version 3.0.0 (#715)

- [#724](https://github.com/near/mpc/pull/724)(@gilcu3): Fixes test_from_str_valid test in the contract crate (#724)

- [#740](https://github.com/near/mpc/pull/740)(@gilcu3): Display error message when participant list is empty in mpc-node generate-test-configs (#740)

- [#755](https://github.com/near/mpc/pull/755)(@andrei-near): Bumping nearcore to 2.7.0-rc4 (#755)

- [#768](https://github.com/near/mpc/pull/768)(@DSharifi): Defer creating `allowed_image_hash` file until write (#768)

- [#762](https://github.com/near/mpc/pull/762)(@barakeinav1): *(launcher)* Fixing of issues found during testing (#762)

- [#778](https://github.com/near/mpc/pull/778)(@kevindeforth): Spawn mointor docker images task before listening to blocks indefinitely (#778)

- [#785](https://github.com/near/mpc/pull/785)(@jaswinder6991): Update README.md to fix the broken link to Cait-Sith blog post (#785)

- [#800](https://github.com/near/mpc/pull/800)(@gilcu3): Replay all RTMR3 required events (#800)

- [#802](https://github.com/near/mpc/pull/802)(@DSharifi): Node ignores peers lagging 50 blocks behind (#802)

- [#780](https://github.com/near/mpc/pull/780)(@barakeinav1): *(node)* Enforce RTMR3 validation on event checks (#780)

- [#807](https://github.com/near/mpc/pull/807)(@kevindeforth): Node abort_key_event_instance instead of abort_key_event (#807)

- [#774](https://github.com/near/mpc/pull/774)(@gilcu3): Verify docker compose hashes correctly (#774)

- [#816](https://github.com/near/mpc/pull/816)(@barakeinav1): *(contract)* Correct tee_status and verify_tee logic (#816)

- [#838](https://github.com/near/mpc/pull/838)(@gilcu3): Fix typos and name inconsistencies (#838)

- [#852](https://github.com/near/mpc/pull/852)(@kevindeforth): Api mismatch for submitting participant info (#852)

- [#851](https://github.com/near/mpc/pull/851)(@kevindeforth): Propose join and rename to submit_participant_info (#851)

- [#788](https://github.com/near/mpc/pull/788)(@gilcu3): Use download_config parameter in mpc-node cli (#788)

- [#887](https://github.com/near/mpc/pull/887)(@pbeza): *(tee)* Ensure participants run valid TEE or none (#887)

- [#925](https://github.com/near/mpc/pull/925)(@kevindeforth): Increase gas limit for sign calls (#925)

- [#928](https://github.com/near/mpc/pull/928)(@gilcu3): CI get docker manifest timeouts (#928)

- [#955](https://github.com/near/mpc/pull/955)(@gilcu3): Add domainid ckdrequest again (#955)

- [#971](https://github.com/near/mpc/pull/971)(@pbeza): *(tee)* Avoid passing `ExpectedMeasurements` as a parameter in contract (#971)

- [#997](https://github.com/near/mpc/pull/997)(@think-in-universe): Redundant secure_time validation for app compose (#997)

- [#1022](https://github.com/near/mpc/pull/1022)(@gilcu3): Use correct assert_matches (#1022)

- [#1031](https://github.com/near/mpc/pull/1031)(@netrome): Use version controlled contracts in compatibility tests (#1031)

- [#1040](https://github.com/near/mpc/pull/1040)(@netrome): Add missing bs58 dependency in contract_history crate (#1040)

- [#1096](https://github.com/near/mpc/pull/1096)(@DSharifi): Return participants with invalid attestation in error message (#1096)

- [#1149](https://github.com/near/mpc/pull/1149)(@netrome): Ignore broken tests (#1149)

- [#1146](https://github.com/near/mpc/pull/1146)(@pbeza): Don't cleanup allowed hashes on getters (#1146)

- [#738](https://github.com/near/mpc/pull/738)(@robin-near): Stream while syncing instead of waiting for full sync. (#738)

- [#1170](https://github.com/near/mpc/pull/1170)(@gilcu3): Add needed deps in dockerfile, remove unnecessary (#1170)

- [#1165](https://github.com/near/mpc/pull/1165)(@pbeza): Contract was refunding too much of deposit (#1165)

- [#1189](https://github.com/near/mpc/pull/1189)(@pbeza): Address post-merge code review comments for PR #1183 (#1189)

- [#1193](https://github.com/near/mpc/pull/1193)(@gilcu3): Restore exact workflow before #1113 not including MPC launcher (#1193)

- [#1174](https://github.com/near/mpc/pull/1174)(@DSharifi): Node should retry attestation submission until its observed onchain (#1174)

- [#1202](https://github.com/near/mpc/pull/1202)(@pbeza): Resubmit participant info more frequently (#1202)

- [#1229](https://github.com/near/mpc/pull/1229)(@netrome): Run attestation requests within a tokio runtime (#1229)

- [#1247](https://github.com/near/mpc/pull/1247)(@pbeza): `tee_authority::get_with_backoff` was ending up in a hot loop (#1247)

- [#1258](https://github.com/near/mpc/pull/1258)(@netrome): Remove references to stale scripts (#1258)

- [#1266](https://github.com/near/mpc/pull/1266)(@gilcu3): Devnet using ckd with BLS (#1266)

- [#1281](https://github.com/near/mpc/pull/1281)(@gilcu3): Use more efficient DomainRegistry (#1281)

- [#1282](https://github.com/near/mpc/pull/1282)(@gilcu3): Remaining issues in TDX external guide (#1282)

- [#1330](https://github.com/near/mpc/pull/1330)(@gilcu3): Bug wasm execution failed error when running mpc localnet nodes (#1330)

- [#1350](https://github.com/near/mpc/pull/1350)(@netrome): Use port 24566 instead of 24567 for boot node arg in localnet guide (#1350)

- [#1358](https://github.com/near/mpc/pull/1358)(@gilcu3): Ensure hex serialization in vote-code-hash (#1358)

- [#1364](https://github.com/near/mpc/pull/1364)(@netrome): Disable state sync in localnet (#1364)

- [#1365](https://github.com/near/mpc/pull/1365)(@gilcu3): Github actions by pinning versions, added zizmor to CI (#1365)

- [#1374](https://github.com/near/mpc/pull/1374)(@gilcu3): Continue when receiver has lagged messages and log event (#1374)

- [#1381](https://github.com/near/mpc/pull/1381)(@barakeinav1): Update operator guide with correct port configuration (#1381)

- [#1382](https://github.com/near/mpc/pull/1382)(@gilcu3): Update the measurements that are actually used in the contract (#1382)


### 🚜 Refactor

- [#670](https://github.com/near/mpc/pull/670)(@barakeinav1): *(launcher)* Update user-config format and values (#670)

- [#758](https://github.com/near/mpc/pull/758)(@pbeza): *(tee)* Move attestation generation logic (#758)

- [#882](https://github.com/near/mpc/pull/882)(@DSharifi): *(attestation)* Remove `TcbInfo` wrapper struct (#882)

- [#884](https://github.com/near/mpc/pull/884)(@DSharifi): Remove `Quote` wrapper struct in attestation (#884)

- [#890](https://github.com/near/mpc/pull/890)(@netrome): Consistent usage of SerializableEdwardsPoint in crypto_shared/types.rs (#890)

- [#998](https://github.com/near/mpc/pull/998)(@netrome): Get rid of `mod.rs` files (#998)

- [#1098](https://github.com/near/mpc/pull/1098)(@DSharifi): Make `verify_tee_participant` API infallible (#1098)


### 📚 Documentation

- [#733](https://github.com/near/mpc/pull/733)(@gilcu3): Added doc on how to deploy an MPC node within a TEE (#733)

- [#886](https://github.com/near/mpc/pull/886)(@barakeinav1): Operator guide first version (#886)

- [#877](https://github.com/near/mpc/pull/877)(@kevindeforth): Document disaster recovery plan (#877)

- [#954](https://github.com/near/mpc/pull/954)(@DSharifi): Update readme to list testnet RPC providers for devnet tool (#954)

- [#980](https://github.com/near/mpc/pull/980)(@barakeinav1): Tdx cloud providers (#980)

- [#983](https://github.com/near/mpc/pull/983)(@barakeinav1): Update operator's guide with CVM update flow (#983)

- [#979](https://github.com/near/mpc/pull/979)(@barakeinav1): TEE design doc (#979)

- [#992](https://github.com/near/mpc/pull/992)(@barakeinav1): Explain how to get dstack logs (#992)

- [#993](https://github.com/near/mpc/pull/993)(@barakeinav1): Add link to HLD (#993)

- [#1002](https://github.com/near/mpc/pull/1002)(@think-in-universe): Make the launcher docs more readable (#1002)

- [#999](https://github.com/near/mpc/pull/999)(@barakeinav1): Port collision documentation (#999)

- [#1001](https://github.com/near/mpc/pull/1001)(@barakeinav1): Update production_settings (#1001)

- [#1033](https://github.com/near/mpc/pull/1033)(@barakeinav1): Add explanation about key generation (#1033)

- [#1030](https://github.com/near/mpc/pull/1030)(@barakeinav1): How to add MPC node key into account (#1030)

- [#1043](https://github.com/near/mpc/pull/1043)(@barakeinav1): Getting lasted MPC hash from the contract (#1043)

- [#1045](https://github.com/near/mpc/pull/1045)(@barakeinav1): Voting_new_hash (#1045)

- [#1041](https://github.com/near/mpc/pull/1041)(@barakeinav1): Add vote_new_parameters documentation (#1041)

- [#1059](https://github.com/near/mpc/pull/1059)(@barakeinav1): Update TEE difference table (#1059)

- [#1048](https://github.com/near/mpc/pull/1048)(@barakeinav1): Update local key provider section (#1048)

- [#1072](https://github.com/near/mpc/pull/1072)(@barakeinav1): Update information about MPC node retrieval (#1072)

- [#1062](https://github.com/near/mpc/pull/1062)(@barakeinav1): Add submit_participant_info details (#1062)

- [#1106](https://github.com/near/mpc/pull/1106)(@barakeinav1): Add reproducible build instructions for Dstack (#1106)

- [#1154](https://github.com/near/mpc/pull/1154)(@barakeinav1): Update RTMR generation instructions for dstack 0.5.4 (#1154)

- [#1178](https://github.com/near/mpc/pull/1178)(@pbeza): Update contract README with gas cost details (#1178)

- [#1256](https://github.com/near/mpc/pull/1256)(@netrome): Document contract interface crate (#1256)

- [#1262](https://github.com/near/mpc/pull/1262)(@netrome): Operator guide includes installation instructions for dstack-vmm instead of referencing their readme (#1262)

- [#1278](https://github.com/near/mpc/pull/1278)(@pbeza): *(localnet)* Refine `localnet` setup instructions (#1278)


### 🧪 Testing

- [#481](https://github.com/near/mpc/pull/481)(@DSharifi): Test that threshold from previous running state is used when serving sign requests in resharing (#481)

- [#498](https://github.com/near/mpc/pull/498)(@kevindeforth): *(node)* Add timeout to avoid race condition in integration test (#498)

- [#555](https://github.com/near/mpc/pull/555)(@kevindeforth): *(pytest)* Resolve pytest nonce conflicts (#555)

- [#682](https://github.com/near/mpc/pull/682)(@DSharifi): Create pytest to test cancellation of key resharing (#682)

- [#746](https://github.com/near/mpc/pull/746)(@pbeza): *(tee)* Add an integration test for attestation verification (#746)

- [#819](https://github.com/near/mpc/pull/819)(@pbeza): *(tee)* Add contract integration test for MPC image hash voting (#819)

- [#834](https://github.com/near/mpc/pull/834)(@DSharifi): Re-organize tests in attestation crate (#834)

- [#828](https://github.com/near/mpc/pull/828)(@pbeza): *(contract)* Integration test to ensure contract rejects invalid remote attestations (#828)

- [#1099](https://github.com/near/mpc/pull/1099)(@pbeza): Expired attestation kickout flow (#1099)

- [#1168](https://github.com/near/mpc/pull/1168)(@DSharifi): Move sandbox integration tests into separate directory. (#1168)

- [#1183](https://github.com/near/mpc/pull/1183)(@pbeza): Add grace period test for multi-node voting (#1183)

- [#1186](https://github.com/near/mpc/pull/1186)(@DSharifi): Rewrite upgrade test as a sandbox integration tests (#1186)

- [#1200](https://github.com/near/mpc/pull/1200)(@DSharifi): Wait for TEE attestations on resharings in pytests (#1200)

- [#986](https://github.com/near/mpc/pull/986)(@DSharifi): Proposal for adding new participant without valid TEE attestation should fail (#986)

- [#1211](https://github.com/near/mpc/pull/1211)(@DSharifi): Resolve flaky test caused by ordering of attestations (#1211)

- [#1066](https://github.com/near/mpc/pull/1066)(@pbeza): *(contract)* System test for `submit_tee_participant_info` (#1066)


### ⚙️ Miscellaneous Tasks

- [#493](https://github.com/near/mpc/pull/493)(@netrome): Update devnet docs (#493)

- [#494](https://github.com/near/mpc/pull/494)(@netrome): Initial Changelog + CI check (#494)

- [#508](https://github.com/near/mpc/pull/508)(@kuksag): *(pytests)* Split cluster setup logic  (#508)

- [#526](https://github.com/near/mpc/pull/526)(@DSharifi): Increase bytes allocated to version in report data from u8 to u16 (#526)

- [#549](https://github.com/near/mpc/pull/549)(@kevindeforth): *(tee)* Launcher cleanup (#549)

- [#564](https://github.com/near/mpc/pull/564)(@DSharifi): Fix docker build and publish action (#564)

- [#571](https://github.com/near/mpc/pull/571)(@andrei-near): Sanitize docker build CI to replace invalid tag symbol (#571)

- [#572](https://github.com/near/mpc/pull/572)(@kuksag): Remove p2p and signer key retrival via gcp (#572)

- [#569](https://github.com/near/mpc/pull/569)(@netrome): Enable support for JSON logging (#569)

- [#586](https://github.com/near/mpc/pull/586)(@sergey-ni): Migrated stats into IndexerState (#586)

- [#574](https://github.com/near/mpc/pull/574)(@DSharifi): Add info logs when creating file handle for TEE image hash (#574)

- [#573](https://github.com/near/mpc/pull/573)(@kuksag): Add `near_responder_id` and number of responder keys in `gcp-start.sh` logic (#573)

- [#575](https://github.com/near/mpc/pull/575)(@DSharifi): Keep MPC node running if image hash is disallowed (#575)

- [#615](https://github.com/near/mpc/pull/615)(@netrome): Bump nearcore to `2.7.0-rc.2` (#615)

- [#640](https://github.com/near/mpc/pull/640)(@gilcu3): Rename cait-sith -> threshold-signatures (#640)

- [#631](https://github.com/near/mpc/pull/631)(@netrome): Define release process (#631)

- [#649](https://github.com/near/mpc/pull/649)(@andrei-near): Build Docker image as part of CI tests (#649)

- [#651](https://github.com/near/mpc/pull/651)(@DSharifi): Use workspace for dependencies (#651)

- [#659](https://github.com/near/mpc/pull/659)(@DSharifi): Add `--enable-bulk-memory-opt` requirement in contract readme (#659)

- [#662](https://github.com/near/mpc/pull/662)(@DSharifi): Do not wait for indexer sync before generating TEE attestation (#662)

- [#669](https://github.com/near/mpc/pull/669)(@DSharifi): Use the right `protocol_state` type for MpcContractV1 state (#669)

- [#673](https://github.com/near/mpc/pull/673)(@DSharifi): Update pytest build step to include `--enable-bulk-memory` flag (#673)

- [#677](https://github.com/near/mpc/pull/677)(@DSharifi): Setup `black` as formatter for pytest code (#677)

- [#686](https://github.com/near/mpc/pull/686)(@kuksag): Make python formatter apply for the whole repo (#686)

- [#633](https://github.com/near/mpc/pull/633)(@IkerAlus): *(readme)* Eddsa example in readme.md (#633)

- [#685](https://github.com/near/mpc/pull/685)(@kuksag): Add TEE Launcher image building step to CI (#685)

- [#692](https://github.com/near/mpc/pull/692)(@kuksag): Fix failing CI for TEE Launcher build (#692)

- [#688](https://github.com/near/mpc/pull/688)(@kuksag): Add `tee_launcher` tests in CI (#688)

- [#694](https://github.com/near/mpc/pull/694)(@kuksag): Specify TEE Launcher image from `nearone` registry (#694)

- [#700](https://github.com/near/mpc/pull/700)(@DSharifi): Remove unused threshold parameter in start_cluster_with_mpc (#700)

- [#707](https://github.com/near/mpc/pull/707)(@kevindeforth): *(deployment)* Gcp start bash script: avoid unnecessary warning (#707)

- [#708](https://github.com/near/mpc/pull/708)(@kevindeforth): Rename web endpoint /get_public_data to /public_data (#708)

- [#718](https://github.com/near/mpc/pull/718)(@netrome): Override org-wide issue template (#718)

- [#720](https://github.com/near/mpc/pull/720)(@netrome): Move MPC node modules to `lib.rs` (#720)

- [#742](https://github.com/near/mpc/pull/742)(@DSharifi): *(devnet)* Add support for voting new approved code hash on devnet (#742)

- [#749](https://github.com/near/mpc/pull/749)(@kuksag): Remove mpc-keys crate in contract (#749)

- [#660](https://github.com/near/mpc/pull/660)(@hackpk): *(lazy_static)* Replace lazy_static with LazyLock  (#660)

- [#750](https://github.com/near/mpc/pull/750)(@kuksag): Add python linter (#750)

- [#751](https://github.com/near/mpc/pull/751)(@kuksag): Allow contract to generate ABI (#751)

- [#773](https://github.com/near/mpc/pull/773)(@gilcu3): Execute python lint/format CI only when needed (#773)

- [#775](https://github.com/near/mpc/pull/775)(@DSharifi): Remove i/o code from attestation crate (#775)

- [#783](https://github.com/near/mpc/pull/783)(@gilcu3): Unify near-sdk versions (#783)

- [#787](https://github.com/near/mpc/pull/787)(@kevindeforth): *(ci)* Split ci-tests into multiple jobs (#787)

- [#790](https://github.com/near/mpc/pull/790)(@gilcu3): Remove nightly features from fmt config (#790)

- [#793](https://github.com/near/mpc/pull/793)(@gilcu3): Fix cargo-near install failure in CI (#793)

- [#792](https://github.com/near/mpc/pull/792)(@barakeinav1): *(launcher)* Small update of variable and file name for better clarity (#792)

- [#796](https://github.com/near/mpc/pull/796)(@kevindeforth): *(pytests)* Speedup - reduce rpc poll timeout and send txs in parallel (#796)

- [#798](https://github.com/near/mpc/pull/798)(@kevindeforth): *(ci)* Add clippy all-features (#798)

- [#810](https://github.com/near/mpc/pull/810)(@kevindeforth): *(pytest)* Improve test_lost_assets.py performance and coverage (#810)

- [#812](https://github.com/near/mpc/pull/812)(@kevindeforth): *(pytest)* Fix flaky test_signature_lifecycle (#812)

- [#813](https://github.com/near/mpc/pull/813)(@gilcu3): Use our own fork of dcap-qvl v0.2.4 (#813)

- [#821](https://github.com/near/mpc/pull/821)(@gilcu3): Remove default features prometheus (#821)

- [#806](https://github.com/near/mpc/pull/806)(@DSharifi): Implement serde + borsh (de)serialization for attestation crate types (#806)

- [#822](https://github.com/near/mpc/pull/822)(@gilcu3): Upd near-crypto in infra/scripts/generate_keys/ (#822)

- [#840](https://github.com/near/mpc/pull/840)(@DSharifi): Update `dcap-qvl` crate to upstream version (#840)

- [#833](https://github.com/near/mpc/pull/833)(@barakeinav1): *(launcher script)* Update readme (#833)

- [#870](https://github.com/near/mpc/pull/870)(@DSharifi): Replace `YamlValue` with a String wrapper for docker_compose_file (#870)

- [#835](https://github.com/near/mpc/pull/835)(@DSharifi): Add docker TEE build as a CI check (#835)

- [#871](https://github.com/near/mpc/pull/871)(@gilcu3): Added  test_vote_code_hash_doesnt_accept_account_id_not_in_participant_list test (#871)

- [#873](https://github.com/near/mpc/pull/873)(@DSharifi): Implement borsh schema for attestation crate types (#873)

- [#874](https://github.com/near/mpc/pull/874)(@kevindeforth): *(test)* More detailed error checking in contract test (#874)

- [#876](https://github.com/near/mpc/pull/876)(@DSharifi): Update phala cloud API endpoint for collateral generation (#876)

- [#869](https://github.com/near/mpc/pull/869)(@pbeza): *(tee)* Remove account key from report data (#869)

- [#867](https://github.com/near/mpc/pull/867)(@gilcu3): Integrate ts#22 refactor (#867)

- [#878](https://github.com/near/mpc/pull/878)(@DSharifi): Integrate the attestation module into the contract code (#878)

- [#889](https://github.com/near/mpc/pull/889)(@DSharifi): Remove `near_crypto` from attestation crate (#889)

- [#922](https://github.com/near/mpc/pull/922)(@kevindeforth): *(contract)* Remove stale log of random seed in contract (#922)

- [#933](https://github.com/near/mpc/pull/933)(@DSharifi): Remove `near_crypto` dependency from smart contract (#933)

- [#937](https://github.com/near/mpc/pull/937)(@DSharifi): Move config.rs unit test behind feature gated test module (#937)

- [#872](https://github.com/near/mpc/pull/872)(@barakeinav1): *(deploy script)* Update MPC node ports  (#872)

- [#914](https://github.com/near/mpc/pull/914)(@DSharifi): [**breaking**] Remove near_crypto from node code (#914)

- [#963](https://github.com/near/mpc/pull/963)(@kevindeforth): *(node)* Move tls into crate (#963)

- [#989](https://github.com/near/mpc/pull/989)(@gilcu3): Bump version tracing-subscriber (#989)

- [#991](https://github.com/near/mpc/pull/991)(@gilcu3): Bump dcap-qvl to released version (#991)

- [#995](https://github.com/near/mpc/pull/995)(@DSharifi): Use configuration value instead of constant for `TEE_UPGRADE_PERIOD` (#995)

- [#1000](https://github.com/near/mpc/pull/1000)(@DSharifi): Upgrade `ed25519-dalek` version in contract (#1000)

- [#1004](https://github.com/near/mpc/pull/1004)(@DSharifi): Use crates.io version of dstack-sdk (#1004)

- [#1010](https://github.com/near/mpc/pull/1010)(@netrome): Enable running with dstack TEE authority in start.sh (#1010)

- [#1007](https://github.com/near/mpc/pull/1007)(@DSharifi): Delete `docker_release_tee.yaml` workflow (#1007)

- [#1011](https://github.com/near/mpc/pull/1011)(@gilcu3): Fix warning while building contract in pytests (#1011)

- [#1021](https://github.com/near/mpc/pull/1021)(@gilcu3): Fix deployment start script  (#1021)

- [#1013](https://github.com/near/mpc/pull/1013)(@DSharifi): Use `test_utils` crate for image hashes in contract tests (#1013)

- [#1018](https://github.com/near/mpc/pull/1018)(@barakeinav1): Set MPC authority stared by launcher to always expect real TDX HW (#1018)

- [#1036](https://github.com/near/mpc/pull/1036)(@andrei-near): Test for new docker images (#1036)

- [#1047](https://github.com/near/mpc/pull/1047)(@gilcu3): Avoid storing migration contract binary (#1047)

- [#1016](https://github.com/near/mpc/pull/1016)(@DSharifi): Enhance mock attestation struct with conditional validation (#1016)

- [#1068](https://github.com/near/mpc/pull/1068)(@kevindeforth): *(test)* Fix resharing tests (#1068)

- [#1082](https://github.com/near/mpc/pull/1082)(@kevindeforth): Update disaster recovery doc (#1082)

- [#1093](https://github.com/near/mpc/pull/1093)(@gilcu3): Refactor to adapt to API changes in threshold-signatures (#1093)

- [#1104](https://github.com/near/mpc/pull/1104)(@barakeinav1): Unify launcher folders (#1104)

- [#1108](https://github.com/near/mpc/pull/1108)(@DSharifi): Remove redundant and duplicate clippy check for `devnet` crate (#1108)

- [#1101](https://github.com/near/mpc/pull/1101)(@DSharifi): Create an interface for submitting transactions with response (#1101)

- [#1113](https://github.com/near/mpc/pull/1113)(@gilcu3): Update ci to use reproducible builds (#1113)

- [#1102](https://github.com/near/mpc/pull/1102)(@DSharifi): Move contract crate into root workspace (#1102)

- [#1116](https://github.com/near/mpc/pull/1116)(@gilcu3): Add detailed steps for mpc node image code inspection during upgrades (#1116)

- [#1122](https://github.com/near/mpc/pull/1122)(@DSharifi): Fix build script for builds in detached head (#1122)

- [#1124](https://github.com/near/mpc/pull/1124)(@gilcu3): Added security policy (#1124)

- [#1125](https://github.com/near/mpc/pull/1125)(@DSharifi): Pin serde to `1.0.2191` to fix compilation issue with `dstack-sdk` (#1125)

- [#1127](https://github.com/near/mpc/pull/1127)(@gilcu3): *(ci)* Separate CI actions for launcher and node (#1127)

- [#1131](https://github.com/near/mpc/pull/1131)(@gilcu3): *(docs)* Update docs after #1127 (#1131)

- [#1136](https://github.com/near/mpc/pull/1136)(@DSharifi): Move all workspace members in to `/crates` directory (#1136)

- [#1115](https://github.com/near/mpc/pull/1115)(@barakeinav1): Update user guide with dstack 0.5.4 changes (#1115)

- [#1143](https://github.com/near/mpc/pull/1143)(@gilcu3): Adapt to API changes in ts#78 (#1143)

- [#1120](https://github.com/near/mpc/pull/1120)(@kevindeforth): Index nodes by account id & TLS key in TEE State (#1120)

- [#1142](https://github.com/near/mpc/pull/1142)(@gilcu3): Use workspace versions in contract Cargo.toml (#1142)

- [#1111](https://github.com/near/mpc/pull/1111)(@DSharifi): Remove enum `VersionedMpcContract` contract state in favor of a single version struct (#1111)

- [#1157](https://github.com/near/mpc/pull/1157)(@gilcu3): Bring back legacy CI (#1157)

- [#1159](https://github.com/near/mpc/pull/1159)(@DSharifi): Update error message in image hash watcher (#1159)

- [#1151](https://github.com/near/mpc/pull/1151)(@DSharifi): Create DTO types for the attestation submission method (#1151)

- [#1166](https://github.com/near/mpc/pull/1166)(@DSharifi): Use time durations instead of block numbers for tee grace period (#1166)

- [#1190](https://github.com/near/mpc/pull/1190)(@gilcu3): Make sure devnet tests ckd (#1190)

- [#1141](https://github.com/near/mpc/pull/1141)(@DSharifi): Add github action for unused dependencies (#1141)

- [#1221](https://github.com/near/mpc/pull/1221)(@pbeza): Remove redundant `allow` attribute (#1221)

- [#1230](https://github.com/near/mpc/pull/1230)(@DSharifi): Use base58 encoding for public key serialization on node HTTP server. (#1230)

- [#1231](https://github.com/near/mpc/pull/1231)(@DSharifi): Document how to run a local mpc network (#1231)

- [#1251](https://github.com/near/mpc/pull/1251)(@gilcu3): Remove unneeded deps in attestation crate (#1251)

- [#1253](https://github.com/near/mpc/pull/1253)(@gilcu3): Added systemd service for VMM (#1253)

- [#1273](https://github.com/near/mpc/pull/1273)(@kevindeforth): Resolve flaky integration tests (#1273)

- [#1261](https://github.com/near/mpc/pull/1261)(@gilcu3): Contract unit tests for ckd (#1261)

- [#1276](https://github.com/near/mpc/pull/1276)(@kevindeforth): Contract move helpers (#1276)

- [#1274](https://github.com/near/mpc/pull/1274)(@gilcu3): Add support for CKD BLS in contract sandbox tests (#1274)

- [#1305](https://github.com/near/mpc/pull/1305)(@kevindeforth): Use read-write lock for keyshare storage (#1305)

- [#1315](https://github.com/near/mpc/pull/1315)(@DSharifi): Enforce sorted cargo dependencies on CI (#1315)

- [#1323](https://github.com/near/mpc/pull/1323)(@netrome): Bump nearcore to 2.9.0 (#1323)

- [#1326](https://github.com/near/mpc/pull/1326)(@netrome): Use pinned nextest version and standard installation action (#1326)

- [#1338](https://github.com/near/mpc/pull/1338)(@gilcu3): Use proper serialization format for PersistentSecrets (#1338)

- [#1336](https://github.com/near/mpc/pull/1336)(@netrome): Add support for dockerized localnet (#1336)

- [#1340](https://github.com/near/mpc/pull/1340)(@pbeza): Cargo update and fix deprecated API usage (#1340)

- [#1347](https://github.com/near/mpc/pull/1347)(@Copilot): Document reproducible builds in README.md (#1347)

- [#1352](https://github.com/near/mpc/pull/1352)(@gilcu3): Use 0 as SOURCE_DATE_EPOCH for repro builds (#1352)

- [#1344](https://github.com/near/mpc/pull/1344)(@gilcu3): Move test-utils to ts repo (#1344)

- [#1378](https://github.com/near/mpc/pull/1378)(@gilcu3): Updated hard-coded TCB info for 3.0.0 release (#1378)

- [#1383](https://github.com/near/mpc/pull/1383)(@netrome): Set crate versions to 3.0.0 and update changelog (#1383)

- [#1388](https://github.com/near/mpc/pull/1388)(@netrome): Support publishing images from git tags (#1388)


### ◀️ Revert

- [#779](https://github.com/near/mpc/pull/779)(@DSharifi): "refactor(tee): move attestation generation logic" (#779)


## [2.2.0-rc1] - 2025-06-11

### ⚙️ Miscellaneous Tasks

- [#490](https://github.com/near/mpc/pull/490)(@DSharifi): Bump versions for new release candidate (#490)


## [2.0.1-rc2] - 2025-06-10

### 🚀 Features

- [#466](https://github.com/near/mpc/pull/466)(@DSharifi): *(TEE)* Implement remote attestation information generation (#466)


### 🐛 Bug Fixes

- [#480](https://github.com/near/mpc/pull/480)(@DSharifi): Use threshold number for previous running state in resharing (#480)


### ⚙️ Miscellaneous Tasks

- [#477](https://github.com/near/mpc/pull/477)(@netrome): Add MIT license and third party license notices (#477)


## [2.0.1-rc1] - 2025-06-03

### 🚀 Features

- [#438](https://github.com/near/mpc/pull/438)(@DSharifi): Parallel resharing and running (#438)


### 🐛 Bug Fixes

- [#370](https://github.com/near/mpc/pull/370)(@DSharifi): Return early in Indexer thread and listen_blocks if channel to MPC node is closed.


### 💼 Other

- [#416](https://github.com/near/mpc/pull/416)(@andrei-near): Fix import keyshare  (#416)


### ⚙️ Miscellaneous Tasks

- [#366](https://github.com/near/mpc/pull/366)(@DSharifi): Add metrics for latency of signature request responses (#366)

- [#373](https://github.com/near/mpc/pull/373)(@DSharifi): Add metrics for latency of signature request responses in seconds

- [#371](https://github.com/near/mpc/pull/371)(@DSharifi): Remove spawn_blocking call wrapping the indexer thread (#371)

- [#406](https://github.com/near/mpc/pull/406)(@DSharifi): Remove unwrap in `monitor_passive_channels_inner` (#406)


## [2.0.0-rc.1] - 2025-04-11

### 🚀 Features

- [#294](https://github.com/near/mpc/pull/294)(@DSharifi): *(EdDSA)* Add support for EdDSA signature requests on the smart contract (#294)


### 🐛 Bug Fixes

- [#209](https://github.com/near/mpc/pull/209)(@pbeza): *(audit)* Fix TLS certificate verification (#209)

- [#268](https://github.com/near/mpc/pull/268)(@DSharifi): Pinned legacy contract dependency to git revistion (#268)

- [#328](https://github.com/near/mpc/pull/328)(@DSharifi): Add pre-computed edwards_point of EdDSA keys to contract state (#328)

- [#358](https://github.com/near/mpc/pull/358)(@DSharifi): Use internal tag for signature response type for backwards compatibility (#358)


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

- [#283](https://github.com/near/mpc/pull/283)(@DSharifi): Use `[u8; 32]` instead of Scalar type from `k256` crate in contract (#283)

- [#341](https://github.com/near/mpc/pull/341)(@DSharifi): Remove ScalarExt trait (#341)


### 🧪 Testing

- [#265](https://github.com/near/mpc/pull/265)(@bowenwang1996): Reduce flakiness by reducing the amount of assets buffered in tests (#265)

- [#339](https://github.com/near/mpc/pull/339)(@DSharifi): Test public key derivation in contract (#339)

- [#347](https://github.com/near/mpc/pull/347)(@DSharifi): *(eddsa)* Add integration test for EdDSA signature requests (#347)

- [#348](https://github.com/near/mpc/pull/348)(@DSharifi): Enable EdDSA signature requets in pytests (#348)


### ⚙️ Miscellaneous Tasks

- [#281](https://github.com/near/mpc/pull/281)(@DSharifi): Remove self dependency to `legacy_contract` (#281)

- [#286](https://github.com/near/mpc/pull/286)(@DSharifi): Pin `near-sdk` version to 5.2.1 (#286)

- [#282](https://github.com/near/mpc/pull/282)(@DSharifi): Move `crypto-shared` to a module in contract (#282)

- [#359](https://github.com/near/mpc/pull/359)(@DSharifi): Fix typo in codebase edd25519 to ed25519

- [#334](https://github.com/near/mpc/pull/334)(@DSharifi): Add docs to EdDSA fields in `PublicKeyExtended`. (#334)


## [testnet-upgrade] - 2025-01-09

### 💼 Other

- [#59](https://github.com/near/mpc/pull/59)(@andrei-near): Replace cache with rust-cache (#59)

- [#115](https://github.com/near/mpc/pull/115)(@andrei-near): Workflow to build and publish MPC docker images (#115)

- [#116](https://github.com/near/mpc/pull/116)(@andrei-near): Docker image builder nit (#116)



