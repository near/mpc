use interfaces::{
    attestation::{Attestation, DstackAttestation, Quote, TcbInfo},
    crypto::Ed25519PublicKey,
};
use mpc_primitives::hash::{LauncherDockerComposeHash, MpcDockerImageHash};
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

pub fn quote() -> Quote {
    let quote_collateral_json_string = include_str!("../assets/quote.json");
    serde_json::from_str(quote_collateral_json_string)
        .expect("Quote collateral file is a valid json.")
}

pub fn p2p_tls_key() -> interfaces::crypto::Ed25519PublicKey {
    let key_file = include_str!("../assets/near_p2p_public_key.pub");
    let near_public_key: near_sdk::PublicKey =
        key_file.parse().expect("File contains a valid public key");
    let tls_key_data: [u8; 32] = near_public_key.as_bytes()[1..].try_into().unwrap();

    Ed25519PublicKey::from(tls_key_data)
}

pub fn mock_dstack_attestation() -> Attestation {
    let quote = quote();
    let collateral_json_string = include_str!("../assets/collateral.json");
    let collateral = serde_json::from_str(collateral_json_string).unwrap();

    let tcb_info: TcbInfo = serde_json::from_str(TEST_TCB_INFO_STRING).unwrap();

    Attestation::Dstack(DstackAttestation::new(quote, collateral, tcb_info))
}
