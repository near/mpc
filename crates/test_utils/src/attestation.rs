use attestation::{
    app_compose::AppCompose,
    attestation::{Attestation, DstackAttestation, StaticWebData},
};
use mpc_primitives::hash::{LauncherDockerComposeHash, MpcDockerImageHash};
use near_sdk::env::sha256;
use regex::Regex;

pub const STATIC_WEB_DATA_STRING: &str = include_str!("../assets/static_web_data.json");

pub fn mock_dstack_attestation() -> DstackAttestation {
    let static_web_data: StaticWebData<Vec<u8>> =
        serde_json::from_str(STATIC_WEB_DATA_STRING).unwrap();

    let Attestation::Dstack(dstack_attestation) = static_web_data.tee_participant_info else {
        panic!("STATIC_WEB_DATA_STRING must be a dstack attestation.")
    };

    dstack_attestation
}

pub trait DstackAttestationTestUtils {
    fn p2p_tls_public_key(&self) -> ed25519_dalek::VerifyingKey;

    fn launcher_compose_digest(&self) -> LauncherDockerComposeHash;

    fn mpc_image_digest(&self) -> MpcDockerImageHash;
}

impl DstackAttestationTestUtils for DstackAttestation {
    fn p2p_tls_public_key(&self) -> ed25519_dalek::VerifyingKey {
        let static_web_data: StaticWebData<ed25519_dalek::VerifyingKey> =
            serde_json::from_str(STATIC_WEB_DATA_STRING).unwrap();

        static_web_data.near_p2p_public_key
    }

    fn launcher_compose_digest(&self) -> LauncherDockerComposeHash {
        let app_compose: AppCompose = serde_json::from_str(&self.tcb_info.app_compose).unwrap();

        let launcher_compose_digest: [u8; 32] = sha256(app_compose.docker_compose_file.as_bytes())
            .try_into()
            .expect("Hash is 32 bytes");

        LauncherDockerComposeHash::from(launcher_compose_digest)
    }

    fn mpc_image_digest(&self) -> MpcDockerImageHash {
        let app_compose_string = &self.tcb_info.app_compose;

        let hex_regex = Regex::new(r"[a-f0-9]{64}").unwrap();

        let hex_formatted_image_digest = app_compose_string
            .lines()
            .find(|line| line.contains("DEFAULT_IMAGE_DIGEST"))
            .and_then(|line| hex_regex.find(line))
            .map(|m| m.as_str())
            .expect("No DEFAULT_IMAGE_DIGEST hash found");

        let image_digest: [u8; 32] = hex::decode(hex_formatted_image_digest)
            .expect("File has valid hex encoding.")
            .try_into()
            .expect("Hex file decoded is 32 bytes.");

        MpcDockerImageHash::from(image_digest)
    }
}
