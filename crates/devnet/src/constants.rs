pub const ONE_NEAR: u128 = 1_000_000_000_000_000_000_000_000;
/// Below this minimum balance we consider an account to be possibly unusable.
pub const MINIMUM_BALANCE_TO_REMAIN_IN_ACCOUNTS: u128 = ONE_NEAR / 10;
/// When we need to refill an account (during an update operation), we will not
/// refill it if it's more than this percent of the desired balance. That way, we don't
/// end up topping up accounts all the time with tiny amounts.
pub const PERCENT_OF_ORIGINAL_BALANCE_BELOW_WHICH_TO_REFILL: u128 = 70;

/// The default docker image to deploy the node with.
pub const DEFAULT_MPC_DOCKER_IMAGE: &str = "nearone/mpc-node-gcp:testnet-release";
/// The default parallel signing contract path to test with.
pub const DEFAULT_PARALLEL_SIGN_CONTRACT_PATH: &str =
    "../../target/near/test_parallel_contract/test_parallel_contract.wasm";
/// Address of the mpc contract on testnet
pub const TESTNET_CONTRACT_ACCOUNT_ID: &str = "v1.signer-prod.testnet";

/// Chain id of the localnet chain (matches `deployment/localnet/genesis.json`).
pub const LOCALNET_CHAIN_ID: &str = "mpc-localnet";
/// Default chain id, used when none is configured.
pub const TESTNET_CHAIN_ID: &str = "testnet";
/// Genesis-funded master account on localnet, used for funding instead of a faucet.
pub const LOCALNET_MASTER_ACCOUNT_ID: &str = "test.near";
/// Placeholder contract account used to bring up the localnet cluster + validator before the real
/// contract is deployed. The neard validator does not use it, and no MPC node jobs run until the
/// real contract exists, so the placeholder is never actually contacted.
pub const LOCALNET_PLACEHOLDER_CONTRACT: &str = "placeholder.test.near";
/// Directory (relative to the devnet working dir) holding the static localnet chain assets shared
/// by the MPC node image and the neard validator: `genesis.json`, `config.json`, `node_key.json`,
/// `validator_key.json`.
pub const LOCALNET_ASSETS_DIR: &str = "../../deployment/localnet";
/// Path to the localnet validator key, whose secret key controls the genesis-funded master account.
pub const LOCALNET_VALIDATOR_KEY_PATH: &str = "../../deployment/localnet/validator_key.json";
