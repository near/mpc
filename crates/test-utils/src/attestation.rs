use include_measurements::include_measurements;
use mpc_attestation::{
    TcbInfo,
    attestation::{
        Attestation, DstackAttestation, ExpectedMeasurements, Measurements, VerifiedQuote,
    },
    quote::QuoteBytes,
};
use mpc_primitives::hash::{LauncherDockerComposeHash, LauncherImageHash, NodeImageHash};
use near_mpc_contract_interface::types::{Ed25519PublicKey, HexVec, MockAttestation};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tee_verifier_interface::{Collateral, CollateralDates, VerifiedReport};

/// An attestation captured from a real CVM with the `/public_data` endpoint, and the files
/// `create-assets.sh` derives from it. See `assets/README.md`.
pub struct AttestationFixture {
    tcb_info: &'static str,
    /// The captured collateral with its byte fields hex-encoded, the shape the contract DTO reads.
    collateral: &'static str,
    public_data: &'static str,
    app_compose: &'static str,
    /// The `DEFAULT_IMAGE_DIGEST` in [`Self::launcher_compose`], as bare hex.
    pub mpc_image_digest_hex: &'static str,
    pub launcher_compose: &'static str,
    /// Absolute path of the fixture's asset folder.
    dir: &'static str,
    /// The OS measurements the fixture CVM ran with.
    pub measurements: ExpectedMeasurements,
    /// The instant (Unix seconds) at which the attestation verifies.
    pub valid_timestamp: u64,
    quote: &'static str,
    p2p_public_key: &'static str,
    account_public_key: &'static str,
    account_secret_key: &'static str,
}

/// Taken on a `dstack-0.6.5` (release) CVM running the `main-a70db1b` launcher and node images.
pub const DSTACK_0_6_5: AttestationFixture = AttestationFixture {
    tcb_info: include_str!("../assets/dstack-0.6.5/tcb_info.json"),
    collateral: include_str!("../assets/dstack-0.6.5/collateral.json"),
    public_data: include_str!("../assets/dstack-0.6.5/public_data.json"),
    app_compose: include_str!("../assets/dstack-0.6.5/app_compose.json"),
    mpc_image_digest_hex: include_str!("../assets/dstack-0.6.5/mpc_image_digest.txt"),
    launcher_compose: include_str!("../assets/dstack-0.6.5/launcher_image_compose.yaml"),
    dir: concat!(env!("CARGO_MANIFEST_DIR"), "/assets/dstack-0.6.5"),
    measurements: include_measurements!("assets/dstack-0.6.5/tcb_info.json"),
    valid_timestamp: 1_795_046_400,
    quote: include_str!("../assets/dstack-0.6.5/quote.json"),
    p2p_public_key: include_str!("../assets/dstack-0.6.5/near_p2p_public_key.pub"),
    account_public_key: include_str!("../assets/dstack-0.6.5/near_account_public_key.pub"),
    account_secret_key: include_str!("../assets/dstack-0.6.5/near_account_secret_key"),
};

/// Taken on a `dstack-dev-0.5.8` CVM.
// TODO(#5237): remove once mainnet nodes run dstack 0.6.
pub const DSTACK_0_5_8: AttestationFixture = AttestationFixture {
    tcb_info: include_str!("../assets/dstack-0.5.8/tcb_info.json"),
    collateral: include_str!("../assets/dstack-0.5.8/collateral.json"),
    public_data: include_str!("../assets/dstack-0.5.8/public_data.json"),
    app_compose: include_str!("../assets/dstack-0.5.8/app_compose.json"),
    mpc_image_digest_hex: include_str!("../assets/dstack-0.5.8/mpc_image_digest.txt"),
    launcher_compose: include_str!("../assets/dstack-0.5.8/launcher_image_compose.yaml"),
    dir: concat!(env!("CARGO_MANIFEST_DIR"), "/assets/dstack-0.5.8"),
    measurements: include_measurements!("assets/dstack-0.5.8/tcb_info.json"),
    valid_timestamp: 1_786_622_400,
    quote: include_str!("../assets/dstack-0.5.8/quote.json"),
    p2p_public_key: include_str!("../assets/dstack-0.5.8/near_p2p_public_key.pub"),
    account_public_key: include_str!("../assets/dstack-0.5.8/near_account_public_key.pub"),
    account_secret_key: include_str!("../assets/dstack-0.5.8/near_account_secret_key"),
};

/// The fixture tests use unless they run on every fixture.
pub const LATEST: &AttestationFixture = &DSTACK_0_6_5;

impl AttestationFixture {
    pub fn asset_path(&self, file: &str) -> std::path::PathBuf {
        std::path::Path::new(self.dir).join(file)
    }

    pub fn launcher_compose_digest(&self) -> LauncherDockerComposeHash {
        let digest: [u8; 32] = Sha256::digest(self.launcher_compose).into();
        LauncherDockerComposeHash::from(digest)
    }

    /// The `sha256:<hex>` digest in the launcher compose's `services.launcher.image`.
    pub fn launcher_image_hash(&self) -> LauncherImageHash {
        let compose: serde_yaml::Value =
            serde_yaml::from_str(self.launcher_compose).expect("valid YAML");
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

    pub fn image_digest(&self) -> NodeImageHash {
        let digest: [u8; 32] = hex::decode(self.mpc_image_digest_hex)
            .expect("File has valid hex encoding.")
            .try_into()
            .expect("Hex file decoded is 32 bytes.");
        NodeImageHash::from(digest)
    }

    /// The captured collateral, with the NUL terminators the quote's C strings carry stripped.
    fn captured_collateral(&self) -> Value {
        let public_data: Value = self
            .public_data
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
    pub fn collateral(&self) -> Collateral {
        serde_json::from_value(self.captured_collateral())
            .expect("captured collateral deserializes")
    }

    pub fn quote(&self) -> QuoteBytes {
        let bytes: Vec<u8> =
            serde_json::from_str(self.quote).expect("Quote file is a valid json byte array.");
        QuoteBytes::from(bytes)
    }

    pub fn p2p_tls_key(&self) -> Ed25519PublicKey {
        parse_key(self.p2p_public_key)
    }

    pub fn account_key(&self) -> Ed25519PublicKey {
        parse_key(self.account_public_key)
    }

    pub fn near_p2p_tls_key(&self) -> near_sdk::PublicKey {
        self.p2p_public_key
            .parse()
            .expect("File contains a valid public key")
    }

    pub fn near_account_key(&self) -> near_sdk::PublicKey {
        self.account_public_key
            .parse()
            .expect("File contains a valid public key")
    }

    /// Secret counterpart of [`Self::account_key`], the key the quote's report_data binds, so tests
    /// can sign `submit_participant_info` as the fixture node. Raw "ed25519:..." string.
    /// Committable only because the node is a throwaway localnet one with no standing on any
    /// network.
    pub fn account_secret_key(&self) -> &'static str {
        self.account_secret_key.trim()
    }

    pub fn tcb_info(&self) -> TcbInfo {
        serde_json::from_str(self.tcb_info).expect("tcb_info.json deserializes")
    }

    pub fn dstack_attestation_inner(&self) -> DstackAttestation {
        DstackAttestation::new(self.quote(), self.collateral(), self.tcb_info())
    }

    pub fn dstack_attestation(&self) -> Attestation {
        Attestation::Dstack(self.dstack_attestation_inner())
    }

    /// The [`VerifiedReport`] the real `tee-verifier` would return for the quote, produced by
    /// running the DCAP step at [`Self::valid_timestamp`].
    pub fn verified_report(&self) -> VerifiedReport {
        self.verified_quote().report
    }

    /// The [`CollateralDates`] the real `tee-verifier` would return alongside
    /// [`Self::verified_report`].
    pub fn collateral_dates(&self) -> CollateralDates {
        self.verified_quote().collateral_dates
    }

    fn verified_quote(&self) -> VerifiedQuote {
        self.dstack_attestation_inner()
            .verify_dcap_quote(self.valid_timestamp)
            .expect("fixture quote verifies at its valid_timestamp")
    }

    pub fn dto_dstack_attestation(&self) -> near_mpc_contract_interface::types::Attestation {
        let quote = HexVec::from(Vec::from(self.quote()));
        let collateral = serde_json::from_str(self.collateral).unwrap();
        let tcb_info: near_mpc_contract_interface::types::TcbInfo =
            serde_json::from_str(self.tcb_info).unwrap();

        near_mpc_contract_interface::types::Attestation::Dstack(
            near_mpc_contract_interface::types::DstackAttestation::new(quote, collateral, tcb_info),
        )
    }
}

fn parse_key(key_file: &str) -> Ed25519PublicKey {
    key_file.parse().expect("File contains a valid public key")
}

pub const TEST_TCB_INFO_STRING: &str = LATEST.tcb_info;
pub const TEST_COLLATERAL_STRING: &str = LATEST.collateral;
pub const TEST_PUBLIC_DATA_STRING: &str = LATEST.public_data;
pub const TEST_APP_COMPOSE_STRING: &str = LATEST.app_compose;
pub const TEST_APP_COMPOSE_WITH_SERVICES_STRING: &str =
    include_str!("../assets/app_compose_with_services.json");
pub const TEST_MPC_IMAGE_DIGEST_HEX: &str = LATEST.mpc_image_digest_hex;
pub const TEST_LAUNCHER_IMAGE_COMPOSE_STRING: &str = LATEST.launcher_compose;
pub const VALID_ATTESTATION_TIMESTAMP: u64 = LATEST.valid_timestamp;

pub fn measurements() -> ExpectedMeasurements {
    LATEST.measurements
}

pub fn launcher_compose_digest() -> LauncherDockerComposeHash {
    LATEST.launcher_compose_digest()
}

pub fn launcher_image_hash() -> LauncherImageHash {
    LATEST.launcher_image_hash()
}

pub fn image_digest() -> NodeImageHash {
    LATEST.image_digest()
}

pub fn collateral() -> Collateral {
    LATEST.collateral()
}

pub fn quote() -> QuoteBytes {
    LATEST.quote()
}

pub fn p2p_tls_key() -> Ed25519PublicKey {
    LATEST.p2p_tls_key()
}

pub fn account_key() -> Ed25519PublicKey {
    LATEST.account_key()
}

pub fn near_p2p_tls_key() -> near_sdk::PublicKey {
    LATEST.near_p2p_tls_key()
}

pub fn near_account_key() -> near_sdk::PublicKey {
    LATEST.near_account_key()
}

pub fn account_secret_key() -> &'static str {
    LATEST.account_secret_key()
}

pub fn mock_tcb_info() -> TcbInfo {
    LATEST.tcb_info()
}

pub fn mock_dstack_attestation_inner() -> DstackAttestation {
    LATEST.dstack_attestation_inner()
}

pub fn mock_dstack_attestation() -> Attestation {
    LATEST.dstack_attestation()
}

pub fn verified_report() -> VerifiedReport {
    LATEST.verified_report()
}

pub fn collateral_dates() -> CollateralDates {
    LATEST.collateral_dates()
}

pub fn mock_dto_dstack_attestation() -> near_mpc_contract_interface::types::Attestation {
    LATEST.dto_dstack_attestation()
}

pub fn mock_expiring_at(expiry_timestamp_seconds: u64) -> MockAttestation {
    MockAttestation::WithConstraints {
        mpc_docker_image_hash: None,
        launcher_docker_compose_hash: None,
        expiry_timestamp_seconds: Some(expiry_timestamp_seconds),
        expected_measurements: None,
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    fn fixture_accessors__should_parse_every_asset(
        #[values(&DSTACK_0_5_8, &DSTACK_0_6_5)] fixture: &AttestationFixture,
    ) {
        // Given: the fixture's committed asset files

        // When / Then: every accessor parses its asset without panicking
        fixture.dto_dstack_attestation();
        fixture.dstack_attestation();
        fixture.near_p2p_tls_key();
        fixture.near_account_key();
        fixture.p2p_tls_key();
        fixture.account_key();
        fixture.launcher_compose_digest();
        fixture.image_digest();
        fixture.launcher_image_hash();
    }

    /// `collateral.json` is the captured collateral with its byte fields hex-encoded, which is the
    /// shape the contract DTO reads. Regenerate with:
    ///
    ///   UPDATE_FIXTURES=1 cargo test -p test-utils collateral_fixture
    #[rstest]
    fn collateral_fixture__should_match_the_captured_public_data(
        #[values(&DSTACK_0_5_8, &DSTACK_0_6_5)] fixture: &AttestationFixture,
    ) {
        // Given
        const BYTE_FIELDS: [&str; 4] = [
            "root_ca_crl",
            "pck_crl",
            "tcb_info_signature",
            "qe_identity_signature",
        ];
        let mut collateral = fixture.captured_collateral();
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
        if std::env::var_os("UPDATE_FIXTURES").is_some() {
            std::fs::write(fixture.asset_path("collateral.json"), &expected)
                .expect("collateral.json is writable");
        }

        // Then
        assert_eq!(
            expected, fixture.collateral,
            "collateral.json is stale; regenerate with UPDATE_FIXTURES=1"
        );
    }

    #[rstest]
    fn account_secret_key__should_pair_with_account_public_key(
        #[values(&DSTACK_0_5_8, &DSTACK_0_6_5)] fixture: &AttestationFixture,
    ) {
        // Given: a NEAR ed25519 secret key is base58 of `seed || public_key`.
        let secret = fixture
            .account_secret_key()
            .strip_prefix("ed25519:")
            .expect("secret key is ed25519-prefixed");
        let decoded = bs58::decode(secret).into_vec().expect("base58 secret key");
        let seed: [u8; 32] = decoded[..32]
            .try_into()
            .expect("secret key holds a 32-byte seed");

        // When
        let derived = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();

        // Then
        assert_eq!(derived.to_bytes(), fixture.account_key().0);
        assert_eq!(decoded[32..], fixture.account_key().0);
    }
}
