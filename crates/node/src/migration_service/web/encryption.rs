use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes256Gcm, KeyInit,
};

const NONCE_LEN: usize = 12;

pub(crate) fn encrypt_bytes(key: &[u8; 32], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|err| anyhow::anyhow!("encryption failed: {err}"))?;
    let mut nonce_and_cipher = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    nonce_and_cipher.extend_from_slice(&nonce);
    nonce_and_cipher.extend_from_slice(&ciphertext);
    Ok(nonce_and_cipher)
}

pub(crate) fn decrypt_bytes(key: &[u8; 32], nonce_and_cipher: &[u8]) -> anyhow::Result<Vec<u8>> {
    if nonce_and_cipher.len() < NONCE_LEN {
        anyhow::bail!("ciphertext too short: missing nonce");
    }

    let (nonce_bytes, ciphertext) = nonce_and_cipher.split_at(NONCE_LEN);

    let cipher = Aes256Gcm::new(key.into());
    let plaintext_bytes = cipher
        .decrypt(nonce_bytes.into(), ciphertext)
        .map_err(|err| anyhow::anyhow!("encryption failed: {err}"))?;
    Ok(plaintext_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Generate a random 256-bit key
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let plaintext = b"Near intents is cool";
        let encrypted = encrypt_bytes(&key, plaintext).expect("encryption should succeed");
        assert!(encrypted.len() > NONCE_LEN);
        let decrypted = decrypt_bytes(&key, &encrypted).expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_fails_on_tampered_data() {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let plaintext = b"Near intents is still cool";
        let mut encrypted = encrypt_bytes(&key, plaintext).expect("encryption should succeed");
        // Flip one byte in the ciphertext
        let last_index = encrypted.len() - 1;
        encrypted[last_index] ^= 0xFF;
        // Decryption should fail due to tag mismatch
        assert!(
            decrypt_bytes(&key, &encrypted).is_err(),
            "decryption should fail on tampered ciphertext"
        );
    }

    #[test]
    fn test_decrypt_fails_on_truncated_input() {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);

        // Input shorter than NONCE_LEN must fail
        let short = vec![0u8; NONCE_LEN - 1];
        assert!(
            decrypt_bytes(&key, &short).is_err(),
            "should fail when nonce is missing"
        );
    }

    #[test]
    fn test_decrypt_fails_on_wrong_key() {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let plaintext = b"this should fail";
        let encrypted = encrypt_bytes(&key, plaintext).expect("encryption should succeed");
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        // Decryption should fail because of wrong key
        assert!(
            decrypt_bytes(&key, &encrypted).is_err(),
            "decryption should fail with wrong key"
        );
    }
}
