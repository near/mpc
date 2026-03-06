use mpc_attestation::attestation::Attestation;
use mpc_crypto_types::Ed25519PublicKey;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct StaticWebData {
    pub near_signer_public_key: Ed25519PublicKey,

    pub near_p2p_public_key: Ed25519PublicKey,

    pub near_responder_public_keys: Vec<Ed25519PublicKey>,

    pub tee_participant_info: Option<Attestation>,
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::*;
    use mpc_crypto_types::ed25519_dalek::SigningKey;
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    fn gen_ed25519_public_key(seed: u64) -> Ed25519PublicKey {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let sk = SigningKey::generate(&mut rng);
        Ed25519PublicKey::from(&sk.verifying_key())
    }

    #[test]
    fn static_web_data__should_not_change_after_serialization_roundtrip() {
        // Given
        let near_signer_public_key = gen_ed25519_public_key(1);
        let near_p2p_public_key = gen_ed25519_public_key(2);
        let near_responder_public_keys = vec![
            gen_ed25519_public_key(3),
            gen_ed25519_public_key(4),
            gen_ed25519_public_key(5),
        ];

        let data = StaticWebData {
            near_signer_public_key: near_signer_public_key.clone(),
            near_p2p_public_key: near_p2p_public_key.clone(),
            near_responder_public_keys: near_responder_public_keys.clone(),
            tee_participant_info: None,
        };

        // When
        let json = serde_json::to_string_pretty(&data).expect("serialize should work");
        println!("Serialized JSON:\n{json}");

        let decoded: StaticWebData = serde_json::from_str(&json).expect("deserialize should work");

        // Then
        assert_eq!(decoded.near_signer_public_key, near_signer_public_key);
        assert_eq!(decoded.near_p2p_public_key, near_p2p_public_key);
        assert_eq!(
            decoded.near_responder_public_keys,
            near_responder_public_keys
        );
    }
}
