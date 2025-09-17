//! Key Derivation Function for eddsa keys.
use curve25519_dalek::Scalar;
use threshold_signatures::eddsa::KeygenOutput;
use threshold_signatures::frost_ed25519::keys::SigningShare;
use threshold_signatures::frost_ed25519::{Ed25519Group, Group, VerifyingKey};

pub(crate) fn derive_keygen_output(keygen_output: &KeygenOutput, tweak: [u8; 32]) -> KeygenOutput {
    let tweak = Scalar::from_bytes_mod_order(tweak);
    let private_share = SigningShare::new(keygen_output.private_share.to_scalar() + tweak);
    let public_key = VerifyingKey::new(
        keygen_output.public_key.to_element() + Ed25519Group::generator() * tweak,
    );
    KeygenOutput {
        private_share,
        public_key,
    }
}

#[cfg(test)]
mod test {
    use rand::Rng;

    use super::*;

    #[test]
    fn test_private_key_derivation() {
        let random_bytes: [u8; 32] = rand::thread_rng().gen();

        let scalar = Scalar::from_bytes_mod_order(random_bytes);
        let private_share = SigningShare::new(scalar);

        let public_key_element = Ed25519Group::generator() * scalar;
        let public_key = VerifyingKey::new(public_key_element);

        let keygen_output = KeygenOutput {
            private_share,
            public_key,
        };

        let tweak: [u8; 32] = rand::thread_rng().gen();
        let derived_keygen_output = derive_keygen_output(&keygen_output, tweak);

        assert_eq!(
            derived_keygen_output.public_key.to_element(),
            derived_keygen_output.private_share.to_scalar() * Ed25519Group::generator(),
        );
    }
}
