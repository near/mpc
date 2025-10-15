pub struct PrivateKey {}
pub struct PublicKey {}
pub struct KeyShares {}

impl PrivateKey {
    pub fn public_key(&self) -> PublicKey {
        PublicKey {}
    }
}
