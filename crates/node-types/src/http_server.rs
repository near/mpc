use attestation::attestation::Attestation;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct StaticWebData {
    #[serde(with = "verifying_key_bs58")]
    pub near_signer_public_key: VerifyingKey,

    #[serde(with = "verifying_key_bs58")]
    pub near_p2p_public_key: VerifyingKey,

    #[serde(with = "verifying_key_bs58::vec")]
    pub near_responder_public_keys: Vec<VerifyingKey>,

    pub tee_participant_info: Option<Attestation>,
}

pub mod verifying_key_bs58 {
    use anyhow::{self, Context};
    use ed25519_dalek::VerifyingKey;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    const ED25519_PREFIX: &str = "ed25519";

    fn encode_key(key: &VerifyingKey) -> String {
        format!(
            "{ED25519_PREFIX}:{}",
            bs58::encode(key.as_bytes()).into_string()
        )
    }

    fn decode_key(s: &str) -> anyhow::Result<VerifyingKey> {
        let prefix = format!("{ED25519_PREFIX}:");
        let encoded = s
            .strip_prefix(&prefix)
            .ok_or_else(|| anyhow::anyhow!("missing ED25519 prefix"))?;

        let bytes: [u8; 32] = bs58::decode(encoded)
            .into_vec()
            .context("base58 decode error")?
            .try_into()
            .map_err(|key_bytes: Vec<u8>| {
                anyhow::anyhow!("public key has unexpected length: {}", key_bytes.len())
            })?;

        VerifyingKey::from_bytes(&bytes).context("key is not valid")
    }

    pub fn serialize<S>(key: &VerifyingKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_key(key))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<VerifyingKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let base_58_encoded_key = String::deserialize(deserializer)?;
        decode_key(&base_58_encoded_key).map_err(serde::de::Error::custom)
    }

    pub mod vec {
        use super::*;
        pub fn serialize<S>(keys: &[VerifyingKey], serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let encoded: Vec<String> = keys.iter().map(encode_key).collect();
            encoded.serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<VerifyingKey>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let base58_encoded_keys: Vec<String> = Vec::<String>::deserialize(deserializer)?;

            base58_encoded_keys
                .iter()
                .map(|base58_encoded_key| {
                    decode_key(base58_encoded_key).map_err(serde::de::Error::custom)
                })
                .collect()
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    fn gen_verifying_key(seed: u64) -> VerifyingKey {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let sk = SigningKey::generate(&mut rng);
        sk.verifying_key()
    }

    #[test]
    fn verifying_key_bs58__should_serialize_to_exact_snapshot() {
        // Given
        #[derive(Serialize)]
        #[serde(transparent)]
        struct Bs58(#[serde(with = "verifying_key_bs58")] VerifyingKey);

        let public_key = Bs58(gen_verifying_key(42));

        // When
        let serialized =
            serde_json::to_value(&public_key).expect("should be able to serialize public key");

        // Then
        assert_eq!(
            serialized
                .as_str()
                .expect("serialized value should be string"),
            "ed25519:99466FdMtvpCZchWcPC9JZemHfm9Daw4ASc8eT6GRhkW"
        );
    }

    #[test]
    fn static_web_data__should_not_change_after_serialization_roundtrip() {
        // Given
        let near_signer_public_key = gen_verifying_key(1);
        let near_p2p_public_key = gen_verifying_key(2);
        let near_responder_public_keys = vec![
            gen_verifying_key(3),
            gen_verifying_key(4),
            gen_verifying_key(5),
        ];

        let data = StaticWebData {
            near_signer_public_key,
            near_p2p_public_key,
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

    #[test]
    fn serialized_keys__should_have_ed25519_prefix_and_valid_base58() {
        // Given
        let near_signer_public_key = gen_verifying_key(10);
        let near_p2p_public_key = gen_verifying_key(20);
        let near_responder_public_keys = vec![gen_verifying_key(30)];

        let data = StaticWebData {
            near_signer_public_key,
            near_p2p_public_key,
            near_responder_public_keys: near_responder_public_keys.clone(),
            tee_participant_info: None,
        };

        // When
        let json = serde_json::to_string(&data).expect("serialize should work");

        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("json parse should work");

        let signer_str = parsed["near_signer_public_key"]
            .as_str()
            .expect("signer key should be string");

        let p2p_str = parsed["near_p2p_public_key"]
            .as_str()
            .expect("p2p key should be string");

        let responder_str = parsed["near_responder_public_keys"]
            .as_array()
            .expect("Is vector of keys")
            .first()
            .unwrap()
            .as_str()
            .expect("responder key should be string");

        // Then
        for (label, encoded) in [
            ("signer", signer_str),
            ("p2p", p2p_str),
            ("responder", responder_str),
        ] {
            assert!(
                encoded.starts_with("ed25519:"),
                "expected {label} key to start with 'ed25519:', got {encoded}"
            );

            let base58_part = &encoded["ed25519:".len()..];
            let _decoded_bytes: [u8; 32] = bs58::decode(base58_part)
                .into_vec()
                .expect("base58 decode should work")
                .try_into()
                .expect("key must be decoded to 32 bytes");
        }
    }
}
