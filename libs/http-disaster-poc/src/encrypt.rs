pub trait EncryptTo {
    fn encrypt_to(&self, recipient: PublicKey, msg: &str) -> String;
}

pub trait DecryptFrom {
    fn decrypt_from(&self, sender: PublicKey, msg: &str) -> String;
}

impl EncryptTo for SecretKey {
    fn encrypt_to(&self, recipient: PublicKey, msg: &str) -> String {
        let shared_secret: [u8; 32] = SharedSecret::new(&recipient, self).secret_bytes();
        let cipher = Aes256Gcm::new(&shared_secret.into());
        let nonce = Aes256Gcm::generate_nonce(rand::rngs::StdRng::seed_from_u64(1337));

        let encrypted = cipher
            .encrypt(&nonce, msg.as_bytes())
            .expect("should be able to encrypt message");

        encrypted.hexify()
    }
}

impl DecryptFrom for SecretKey {
    fn decrypt_from(&self, sender: PublicKey, secret: &str) -> String {
        let shared_secret: [u8; 32] = SharedSecret::new(&sender, self).secret_bytes();
        let cipher = Aes256Gcm::new(&shared_secret.into());
        let nonce = Aes256Gcm::generate_nonce(rand::rngs::StdRng::seed_from_u64(1337));

        let msg_bytes = <Vec<u8>>::dehexify(secret).expect("secret should be hex encoded");

        let decrypted = cipher
            .decrypt(&nonce, msg_bytes.as_slice())
            .expect("should be able to decrypt message bytes");

        String::from_utf8(decrypted).expect("decrypted message should be valid UTF8")
    }
}

use aes_gcm::{AeadCore, Aes256Gcm, KeyInit as _, aead::Aead};
use array_bytes::{Dehexify, Hexify};
use rand::SeedableRng as _;
use secp256k1::{PublicKey, SecretKey, ecdh::SharedSecret};

#[cfg(test)]
mod tests {
    use super::*;

    use secp256k1::{Keypair, rand::SeedableRng};

    #[test]
    fn recipient_should_be_able_to_decrypt_encrypted_message() {
        let mut rng = secp256k1::rand::rngs::StdRng::seed_from_u64(1337);

        // Given
        let sender_keypair = Keypair::new_global(&mut rng);
        let recipient_keypair = Keypair::new_global(&mut rng);
        let msg = "Simplicity--the art of maximizing the amount
of work not done--is essential. ";

        // When
        let encrypted = sender_keypair
            .secret_key()
            .encrypt_to(recipient_keypair.public_key(), msg);

        let decrypted = recipient_keypair
            .secret_key()
            .decrypt_from(sender_keypair.public_key(), &encrypted);

        // Then
        assert_ne!(msg, encrypted);
        assert_eq!(msg, decrypted);
    }
}
