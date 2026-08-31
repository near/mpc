use mpc_attestation::{
    TcbInfo,
    attestation::{Attestation, DstackAttestation},
    quote::QuoteBytes,
};
use mpc_primitives::hash::{LauncherDockerComposeHash, LauncherImageHash, NodeImageHash};
use near_mpc_contract_interface::types::HexVec;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tee_verifier_interface::{Collateral, VerifiedReport};

pub const TEST_TCB_INFO_STRING: &str = include_str!("../assets/tcb_info.json");
pub const TEST_COLLATERAL_STRING: &str = include_str!("../assets/collateral.json");
pub const TEST_PUBLIC_DATA_STRING: &str = include_str!("../assets/public_data.json");
pub const TEST_APP_COMPOSE_STRING: &str = include_str!("../assets/app_compose.json");
pub const TEST_APP_COMPOSE_WITH_SERVICES_STRING: &str =
    include_str!("../assets/app_compose_with_services.json");

/// App compose field corresponds to the `DEFAULT_IMAGE_DIGEST` field in
/// test_utils/assets/launcher_image_compose.yaml
pub const TEST_MPC_IMAGE_DIGEST_HEX: &str = include_str!("../assets/mpc_image_digest.txt");
pub const TEST_LAUNCHER_IMAGE_COMPOSE_STRING: &str =
    include_str!("../assets/launcher_image_compose.yaml");

/// The instant (Unix seconds) at which the committed attestation fixtures verify.
/// Update whenever the fixtures are regenerated.
pub const VALID_ATTESTATION_TIMESTAMP: u64 = 1_786_622_400;

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

/// The captured collateral, with the NUL terminators the quote's C strings carry stripped.
fn captured_collateral() -> Value {
    let public_data: Value = TEST_PUBLIC_DATA_STRING
        .parse()
        .expect("public_data.json is valid json");
    let mut collateral = public_data["tee_participant_info"]["Dstack"]["collateral"].clone();
    for field in collateral
        .as_object_mut()
        .expect("collateral is a json object")
        .values_mut()
    {
        if let Some(text) = field.as_str() {
            *field = Value::from(text.trim_end_matches('\0'));
        }
    }
    collateral
}

/// Collateral in the shape `/public_data` returns, so plain serde is enough to read it.
pub fn collateral() -> Collateral {
    serde_json::from_value(captured_collateral()).expect("captured collateral deserializes")
}

pub fn quote() -> QuoteBytes {
    let quote_json_string = include_str!("../assets/quote.json");
    let bytes: Vec<u8> =
        serde_json::from_str(quote_json_string).expect("Quote file is a valid json byte array.");
    QuoteBytes::from(bytes)
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

/// Secret counterpart of [`account_key`], the key the fixture quote's report_data binds, so tests
/// can sign `submit_participant_info` as the fixture node. Raw "ed25519:..." string. Committable
/// only because the node is a throwaway localnet one with no standing on any network.
pub fn account_secret_key() -> &'static str {
    include_str!("../assets/near_account_secret_key").trim()
}

pub fn mock_dstack_attestation_inner() -> DstackAttestation {
    let tcb_info: TcbInfo = serde_json::from_str(TEST_TCB_INFO_STRING).unwrap();
    DstackAttestation::new(quote(), collateral(), tcb_info)
}

pub fn mock_dstack_attestation() -> Attestation {
    Attestation::Dstack(mock_dstack_attestation_inner())
}

/// The [`VerifiedReport`] the real `tee-verifier` would return for the fixture
/// quote, produced by running the DCAP step at [`VALID_ATTESTATION_TIMESTAMP`]
/// (when the fixture collateral is valid).
pub fn verified_report() -> VerifiedReport {
    mock_dstack_attestation_inner()
        .verify_dcap_quote(VALID_ATTESTATION_TIMESTAMP)
        .expect("fixture quote verifies at VALID_ATTESTATION_TIMESTAMP")
}

pub fn mock_dto_dstack_attestation() -> near_mpc_contract_interface::types::Attestation {
    let quote = HexVec::from(Vec::from(quote()));
    let collateral = serde_json::from_str(TEST_COLLATERAL_STRING).unwrap();

    let tcb_info: near_mpc_contract_interface::types::TcbInfo =
        serde_json::from_str(TEST_TCB_INFO_STRING).unwrap();

    near_mpc_contract_interface::types::Attestation::Dstack(
        near_mpc_contract_interface::types::DstackAttestation::new(quote, collateral, tcb_info),
    )
}

#[cfg(test)]
#[expect(non_snake_case)]
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

    /// `collateral.json` is the captured collateral with its byte fields hex-encoded, which is the
    /// shape the contract DTO reads. Regenerate with:
    ///
    ///   UPDATE_FIXTURES=1 cargo test -p test-utils collateral_fixture
    #[test]
    fn collateral_fixture__should_match_the_captured_public_data() {
        // Given
        const BYTE_FIELDS: [&str; 4] = [
            "root_ca_crl",
            "pck_crl",
            "tcb_info_signature",
            "qe_identity_signature",
        ];
        let mut collateral = captured_collateral();
        for name in BYTE_FIELDS {
            let bytes: Vec<u8> = serde_json::from_value(collateral[name].clone())
                .unwrap_or_else(|_| panic!("{name} is a byte array"));
            collateral[name] = Value::from(hex::encode(bytes));
        }

        // When
        let expected = format!(
            "{}\n",
            serde_json::to_string_pretty(&collateral).expect("collateral serializes")
        );
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/collateral.json");
        if std::env::var_os("UPDATE_FIXTURES").is_some() {
            std::fs::write(path, &expected).expect("collateral.json is writable");
        }

        // Then
        assert_eq!(
            expected, TEST_COLLATERAL_STRING,
            "collateral.json is stale; regenerate with UPDATE_FIXTURES=1"
        );
    }

    #[test]
    fn account_secret_key__should_pair_with_account_public_key() {
        // Given: a NEAR ed25519 secret key is base58 of `seed || public_key`.
        let secret = account_secret_key()
            .strip_prefix("ed25519:")
            .expect("secret key is ed25519-prefixed");
        let decoded = bs58::decode(secret).into_vec().expect("base58 secret key");
        let seed: [u8; 32] = decoded[..32]
            .try_into()
            .expect("secret key holds a 32-byte seed");

        // When
        let derived = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();

        // Then
        assert_eq!(derived.to_bytes(), account_key());
        assert_eq!(decoded[32..], account_key());
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
