use attestation::{
    attestation::{Attestation, DstackAttestation, LocalAttestation},
    collateral::Collateral,
    quote::QuoteBytes,
};
use dstack_sdk_types::dstack::TcbInfo as DstackTcbInfo;
use mpc_primitives::hash::{LauncherDockerComposeHash, MpcDockerImageHash};
use near_sdk::PublicKey;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const TEST_TCB_INFO_STRING: &str = include_str!("../assets/tcb_info.json");
pub const TEST_APP_COMPOSE_STRING: &str = include_str!("../assets/app_compose.json");
pub const TEST_APP_COMPOSE_WITH_SERVICES_STRING: &str =
    include_str!("../assets/app_compose_with_services.json");

/// App compose field corresponds to the `DEFAULT_IMAGE_DIGEST` field in
/// test_utils/assets/launcher_image_compose.yaml
pub const TEST_MPC_IMAGE_DIGEST_HEX: &str = include_str!("../assets/mpc_image_digest.txt");
pub const TEST_LAUNCHER_IMAGE_COMPOSE_STRING: &str =
    include_str!("../assets/launcher_image_compose.yaml");

pub fn launcher_compose_digest() -> LauncherDockerComposeHash {
    let digest: [u8; 32] = Sha256::digest(TEST_LAUNCHER_IMAGE_COMPOSE_STRING).into();
    LauncherDockerComposeHash::from(digest)
}

pub fn image_digest() -> MpcDockerImageHash {
    let digest: [u8; 32] = hex::decode(TEST_MPC_IMAGE_DIGEST_HEX)
        .expect("File has valid hex encoding.")
        .try_into()
        .expect("Hex file decoded is 32 bytes.");

    MpcDockerImageHash::from(digest)
}

pub fn collateral() -> Value {
    let quote_collateral_json_string = include_str!("../assets/collateral.json");
    quote_collateral_json_string
        .parse()
        .expect("Quote collateral file is a valid json.")
}

pub fn quote() -> QuoteBytes {
    let quote_collateral_json_string = include_str!("../assets/quote.json");
    serde_json::from_str(quote_collateral_json_string)
        .expect("Quote collateral file is a valid json.")
}

pub fn mock_local_attestation(quote_verification_result: bool) -> Attestation {
    Attestation::Local(LocalAttestation::new(quote_verification_result))
}

pub fn p2p_tls_key() -> PublicKey {
    let key_file = include_str!("../assets/near_p2p_public_key.pub");
    key_file.parse().expect("File contains a valid public key")
}

pub fn mock_dstack_attestation() -> Attestation {
    let quote = quote();
    let collateral = Collateral::try_from_json(collateral()).unwrap();

    let tcb_info: DstackTcbInfo = serde_json::from_str(TEST_TCB_INFO_STRING).unwrap();

    Attestation::Dstack(DstackAttestation::new(quote, collateral, tcb_info))
}
