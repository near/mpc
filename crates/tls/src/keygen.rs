use rustls::pki_types::PrivatePkcs8KeyDer;

const PUBLIC_KEY_SIZE: usize = 32;
const PRIVATE_KEY_SIZE: usize = 32;
const PKCS8_HEADER_SIZE: usize = 16;
const PKCS8_MIDDLE_SIZE: usize = 3;

const PKCS8_HEADER: [u8; PKCS8_HEADER_SIZE] = [
    0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

const PKCS8_MIDDLE: [u8; PKCS8_MIDDLE_SIZE] = [0x81, 0x21, 0x00];

/// Converts an ED25519 secret key to a keypair that can be used in TLS.
pub(crate) fn raw_ed25519_secret_key_to_keypair(
    key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<rcgen::KeyPair> {
    let private_key_bytes: &[u8; PRIVATE_KEY_SIZE] = key.as_bytes();

    let verifying_key = key.verifying_key();
    let public_key_bytes: &[u8; PUBLIC_KEY_SIZE] = verifying_key.as_bytes();

    let mut pkcs8_encoded = Vec::with_capacity(
        PKCS8_HEADER_SIZE + PRIVATE_KEY_SIZE + PKCS8_MIDDLE_SIZE + PUBLIC_KEY_SIZE,
    );
    pkcs8_encoded.extend_from_slice(&PKCS8_HEADER);
    pkcs8_encoded.extend_from_slice(private_key_bytes);
    pkcs8_encoded.extend_from_slice(&PKCS8_MIDDLE);
    pkcs8_encoded.extend_from_slice(public_key_bytes);
    let private_key = PrivatePkcs8KeyDer::from(pkcs8_encoded.as_slice());
    let keypair = rcgen::KeyPair::try_from(&private_key)?;
    Ok(keypair)
}

#[cfg(test)]
mod tests {
    use crate::keygen::raw_ed25519_secret_key_to_keypair;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_public_key_match() {
        let sk: SigningKey = SigningKey::generate(&mut OsRng);
        let expected_pk: [u8; 32] = sk.verifying_key().to_bytes();

        let kp: rcgen::KeyPair = raw_ed25519_secret_key_to_keypair(&sk).expect("rcgen KeyPair");
        let found_pk = kp.public_key_raw().to_vec();
        assert_eq!(found_pk.as_slice(), &expected_pk);
        assert_eq!(kp.algorithm(), &rcgen::PKCS_ED25519);
    }
}
