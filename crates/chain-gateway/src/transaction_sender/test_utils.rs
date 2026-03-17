use ed25519_dalek::SigningKey;

use crate::transaction_sender::TransactionSigner;

impl TransactionSigner {
    pub fn from_rng<R>(rng: &mut R) -> Self
    where
        R: rand::RngCore,
    {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let signing_key = SigningKey::from_bytes(&bytes);
        TransactionSigner::from_key("test.near".parse().unwrap(), signing_key)
    }
}
