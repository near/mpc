use serde::{Deserialize, Serialize};

use crate::{attestation::Attestation, crypto::Ed25519PublicKey};

#[derive(Clone, Serialize, Deserialize)]
pub struct StaticWebData {
    pub near_signer_public_key: Ed25519PublicKey,
    pub near_p2p_public_key: Ed25519PublicKey,
    pub near_responder_public_keys: Vec<Ed25519PublicKey>,
    pub tee_participant_info: Attestation,
}
