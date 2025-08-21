use super::constants::{PKCS8_HEADER, PKCS8_MIDDLE};
use rustls::pki_types::PrivatePkcs8KeyDer;

/// Generates an ED25519 keypair, returning the pem-encoded private key and the
/// hex-encoded public key.
pub fn generate_keypair(
) -> anyhow::Result<(near_crypto::ED25519SecretKey, near_crypto::ED25519PublicKey)> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    Ok((
        keypair_to_raw_ed25519_secret_key(&key_pair)?,
        near_crypto::ED25519PublicKey(key_pair.public_key_raw().try_into()?),
    ))
}

/// Converts a keypair to an ED25519 secret key, asserting that it is the
/// exact kind of keypair we expect.
pub fn keypair_to_raw_ed25519_secret_key(
    keypair: &rcgen::KeyPair,
) -> anyhow::Result<near_crypto::ED25519SecretKey> {
    let pkcs8_encoded = keypair.serialize_der();
    if pkcs8_encoded.len() != 16 + 32 + 3 + 32 {
        anyhow::bail!("Invalid PKCS8 length");
    }
    if pkcs8_encoded[..16] != PKCS8_HEADER {
        anyhow::bail!("Invalid PKCS8 header");
    }
    if pkcs8_encoded[16 + 32..16 + 32 + 3] != PKCS8_MIDDLE {
        anyhow::bail!("Invalid PKCS8 middle");
    }

    let mut key = [0u8; 64];
    key[..32].copy_from_slice(&pkcs8_encoded[16..16 + 32]);
    key[32..].copy_from_slice(&pkcs8_encoded[16 + 32 + 3..]);

    Ok(near_crypto::ED25519SecretKey(key))
}

/// Converts an ED25519 secret key to a keypair that can be used in TLS.
pub(crate) fn raw_ed25519_secret_key_to_keypair(
    key: &near_crypto::ED25519SecretKey,
) -> anyhow::Result<rcgen::KeyPair> {
    let mut pkcs8_encoded = Vec::with_capacity(16 + 32 + 3 + 32);
    pkcs8_encoded.extend_from_slice(&PKCS8_HEADER);
    pkcs8_encoded.extend_from_slice(&key.0[..32]);
    pkcs8_encoded.extend_from_slice(&PKCS8_MIDDLE);
    pkcs8_encoded.extend_from_slice(&key.0[32..]);
    let private_key = PrivatePkcs8KeyDer::from(pkcs8_encoded.as_slice());
    let keypair = rcgen::KeyPair::try_from(&private_key)?;
    Ok(keypair)
}

#[cfg(test)]
mod tests {
    use crate::p2p::keys::{
        generate_keypair, keypair_to_raw_ed25519_secret_key, raw_ed25519_secret_key_to_keypair,
    };

    #[test]
    fn test_pkcs8_ed25519_encoding() {
        let (private_key, _) = generate_keypair().unwrap();
        let keypair = raw_ed25519_secret_key_to_keypair(&private_key).unwrap();
        let private_key2 = keypair_to_raw_ed25519_secret_key(&keypair).unwrap();
        assert_eq!(private_key, private_key2);
    }
}
