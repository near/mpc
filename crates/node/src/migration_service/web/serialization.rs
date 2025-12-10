use base64::Engine;

use crate::config::AesKey256;
use crate::keyshare::Keyshare;
use crate::migration_service::web::encryption::decrypt_bytes;
use crate::migration_service::web::encryption::encrypt_bytes;

pub fn serialize_and_encrypt_keyshares(
    keyshares: &[Keyshare],
    backup_encryption_key: &AesKey256,
) -> anyhow::Result<String> {
    let keyshares_json = serde_json::to_string(&keyshares).inspect_err(|err| {
        let msg = err.to_string();
        tracing::error!(msg);
    })?;

    let nonce_and_cipher_bytes = encrypt_bytes(backup_encryption_key, keyshares_json.as_bytes())
        .inspect_err(|err| {
            tracing::error!("encryption error: {err}");
        })?;

    Ok(base64::engine::general_purpose::STANDARD.encode(nonce_and_cipher_bytes))
}

pub fn decrypt_and_deserialize_keyshares(
    base64_ciphertext: &[u8],
    backup_encryption_key: &AesKey256,
) -> anyhow::Result<Vec<Keyshare>> {
    let nonce_and_cipher_bytes =
        base64::engine::general_purpose::STANDARD.decode(base64_ciphertext)?;
    let serde_keyshares_bytes =
        decrypt_bytes(backup_encryption_key, nonce_and_cipher_bytes.as_slice()).inspect_err(
            |err| {
                tracing::error!("decryption error: {err}");
            },
        )?;

    let res = serde_json::from_slice::<Vec<Keyshare>>(&serde_keyshares_bytes)
        .inspect_err(|err| tracing::error!("deserialization error: {err}"))?;
    Ok(res)
}

#[cfg(test)]
mod tests {
    use rand::{RngCore, SeedableRng as _};

    use crate::keyshare::test_utils::KeysetBuilder;

    use super::{decrypt_and_deserialize_keyshares, serialize_and_encrypt_keyshares};

    #[test]
    fn test_encrypt_decrypt_cycle() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        let keyset = KeysetBuilder::new_populated(10, 100, &mut rng);
        let encrypted_and_serialized = serialize_and_encrypt_keyshares(keyset.keyshares(), &key)
            .expect("serialization must succeed");
        let res = decrypt_and_deserialize_keyshares(encrypted_and_serialized.as_bytes(), &key)
            .expect("deserialization must succeed");
        assert_eq!(keyset.keyshares(), res);
    }
}
