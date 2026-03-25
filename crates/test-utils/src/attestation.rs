use mpc_attestation::{
    attestation::{Attestation, DstackAttestation},
    quote::QuoteBytes,
    tcb_info::TcbInfo,
};
use mpc_primitives::hash::{LauncherDockerComposeHash, LauncherImageHash, NodeImageHash};
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

/// Unix time as of 2026/03/20, represents a date where
/// the measurements stored in ../assets are valid. When these measurements are
/// modified, this value should be updated as well
pub const VALID_ATTESTATION_TIMESTAMP: u64 = 1774018367;

pub fn launcher_compose_digest() -> LauncherDockerComposeHash {
    let digest: [u8; 32] = Sha256::digest(TEST_LAUNCHER_IMAGE_COMPOSE_STRING).into();
    LauncherDockerComposeHash::from(digest)
}

/// Extracts the launcher image hash from the `launcher_image_compose.yaml` asset.
/// Parses `services.launcher.image` and extracts the `sha256:<hex>` digest.
pub fn launcher_image_hash() -> LauncherImageHash {
    let compose: serde_yaml::Value =
        serde_yaml::from_str(TEST_LAUNCHER_IMAGE_COMPOSE_STRING).expect("valid YAML");
    let image = compose["services"]["launcher"]["image"]
        .as_str()
        .expect("services.launcher.image must be a string");
    let hash_hex = image
        .rsplit_once("sha256:")
        .expect("image must contain sha256: digest")
        .1;
    let bytes: [u8; 32] = hex::decode(hash_hex)
        .expect("Launcher image hash is valid hex")
        .try_into()
        .expect("Launcher image hash is 32 bytes");
    LauncherImageHash::from(bytes)
}

pub fn image_digest() -> NodeImageHash {
    let digest: [u8; 32] = hex::decode(TEST_MPC_IMAGE_DIGEST_HEX)
        .expect("File has valid hex encoding.")
        .try_into()
        .expect("Hex file decoded is 32 bytes.");

    NodeImageHash::from(digest)
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

pub fn p2p_tls_key() -> [u8; 32] {
    parse_key(include_str!("../assets/near_p2p_public_key.pub"))
}

pub fn account_key() -> [u8; 32] {
    parse_key(include_str!("../assets/near_account_public_key.pub"))
}

fn parse_key(key_file: &str) -> [u8; 32] {
    *key_file
        .parse::<near_mpc_contract_interface::types::Ed25519PublicKey>()
        .expect("File contains a valid public key")
        .as_bytes()
}

pub fn near_p2p_tls_key() -> near_sdk::PublicKey {
    let key_file = include_str!("../assets/near_p2p_public_key.pub");
    key_file.parse().expect("File contains a valid public key")
}

pub fn near_account_key() -> near_sdk::PublicKey {
    let key_file = include_str!("../assets/near_account_public_key.pub");
    key_file.parse().expect("File contains a valid public key")
}

pub fn mock_dstack_attestation() -> Attestation {
    let quote = quote();
    let collateral_json_string = include_str!("../assets/collateral.json");
    let collateral = serde_json::from_str(collateral_json_string).unwrap();

    let tcb_info: TcbInfo = serde_json::from_str(TEST_TCB_INFO_STRING).unwrap();

    Attestation::Dstack(DstackAttestation::new(quote, collateral, tcb_info))
}

pub fn mock_dto_dstack_attestation() -> near_mpc_contract_interface::types::Attestation {
    let quote = quote().into();
    let collateral_json_string = include_str!("../assets/collateral.json");
    let collateral = serde_json::from_str(collateral_json_string).unwrap();

    let tcb_info: near_mpc_contract_interface::types::TcbInfo =
        serde_json::from_str(TEST_TCB_INFO_STRING).unwrap();

    near_mpc_contract_interface::types::Attestation::Dstack(
        near_mpc_contract_interface::types::DstackAttestation::new(quote, collateral, tcb_info),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_mock_dto_dstack_attestation_works() {
        mock_dto_dstack_attestation();
    }

    #[test]
    fn test_mock_dstack_attestation_works() {
        mock_dstack_attestation();
    }

    #[test]
    fn test_near_p2p_tls_key_works() {
        near_p2p_tls_key();
    }

    #[test]
    fn test_near_account_key_works() {
        near_account_key();
    }

    #[test]
    fn test_p2p_tls_key_works() {
        p2p_tls_key();
    }

    #[test]
    fn test_account_key_works() {
        account_key();
    }

    #[test]
    fn test_launcher_compose_digest_works() {
        launcher_compose_digest();
    }

    #[test]
    fn test_image_digest_works() {
        image_digest();
    }

    #[test]
    fn test_launcher_image_hash_works() {
        launcher_image_hash();
    }
}
