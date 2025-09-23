use anyhow::Context;
use k256::{
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    AffinePoint, EncodedPoint,
};
use near_sdk::CurveType;
/// Helper functions to convert back and forth public key types
pub trait PublicKeyConversion: Sized {
    fn to_near_sdk_public_key(&self) -> anyhow::Result<near_sdk::PublicKey>;
    fn from_near_sdk_public_key(public_key: &near_sdk::PublicKey) -> anyhow::Result<Self>;
}

impl PublicKeyConversion for threshold_signatures::frost_secp256k1::VerifyingKey {
    fn to_near_sdk_public_key(&self) -> anyhow::Result<near_sdk::PublicKey> {
        let bytes = self.to_element().to_encoded_point(false).to_bytes();
        anyhow::ensure!(bytes[0] == 0x04);

        near_sdk::PublicKey::from_parts(CurveType::SECP256K1, bytes[1..65].to_vec())
            .context("Failed to convert public key to near crypto type")
    }

    fn from_near_sdk_public_key(public_key: &near_sdk::PublicKey) -> anyhow::Result<Self> {
        match public_key.curve_type() {
            CurveType::SECP256K1 => {
                // Skip first byte as it represents the curve type.
                let key_data: [u8; 64] = public_key.as_bytes()[1..]
                    .try_into()
                    .context("Infallible. Key must be 64 bytes")?;

                let mut bytes = [0u8; 65];
                bytes[0] = 0x04;
                bytes[1..65].copy_from_slice(&key_data);

                let encoded_point = EncodedPoint::from_bytes(bytes)?;
                let affine_point = AffinePoint::from_encoded_point(&encoded_point)
                    .into_option()
                    .ok_or(anyhow::anyhow!(
                        "Failed to convert encoded point to affine point"
                    ))?;
                Ok(threshold_signatures::frost_secp256k1::VerifyingKey::new(
                    affine_point.into(),
                ))
            }
            _ => anyhow::bail!("Unsupported public key type"),
        }
    }
}

impl PublicKeyConversion for threshold_signatures::frost_ed25519::VerifyingKey {
    fn to_near_sdk_public_key(&self) -> anyhow::Result<near_sdk::PublicKey> {
        let data = self.serialize()?;
        let data: [u8; 32] = data
            .try_into()
            .or_else(|_| anyhow::bail!("Serialized public key is not 32 bytes."))?;

        near_sdk::PublicKey::from_parts(CurveType::ED25519, data.to_vec()).context("Infallible.")
    }

    fn from_near_sdk_public_key(public_key: &near_sdk::PublicKey) -> anyhow::Result<Self> {
        let key_bytes = public_key.as_bytes();

        // Skip first byte as it is reserved as an identifier for the curve type.
        let key_data: [u8; 32] = key_bytes[1..]
            .try_into()
            .context("Invariant broken, public key must 32 bytes.")?;

        threshold_signatures::frost_ed25519::VerifyingKey::deserialize(&key_data)
            .context("Failed to convert SDK public key to ed25519_dalek::VerifyingKey")
    }
}
impl PublicKeyConversion for ed25519_dalek::VerifyingKey {
    fn to_near_sdk_public_key(&self) -> anyhow::Result<near_sdk::PublicKey> {
        let data: [u8; 32] = self.to_bytes();
        near_sdk::PublicKey::from_parts(CurveType::ED25519, data.to_vec()).context("Infallible.")
    }

    fn from_near_sdk_public_key(public_key: &near_sdk::PublicKey) -> anyhow::Result<Self> {
        let key_bytes = public_key.as_bytes();

        // Skip first byte as it is reserved as an identifier for the curve type.
        let key_data: [u8; 32] = key_bytes[1..]
            .try_into()
            .context("Invariant broken, public key must 32 bytes.")?;

        ed25519_dalek::VerifyingKey::from_bytes(&key_data)
            .context("Failed to convert SDK public key to ed25519_dalek::VerifyingKey")
    }
}

#[cfg(test)]
mod tests {
    use crate::trait_extensions::crypto::PublicKeyConversion;

    #[test]
    fn check_pubkey_conversion_to_sdk() -> anyhow::Result<()> {
        use crate::tests::TestGenerators;
        let x = TestGenerators::new(4, 3)
            .make_eddsa_keygens()
            .values()
            .next()
            .unwrap()
            .clone();
        x.public_key.to_near_sdk_public_key()?;
        Ok(())
    }

    #[test]
    fn check_pubkey_conversion_from_sdk() -> anyhow::Result<()> {
        use std::str::FromStr;
        let near_sdk =
            near_sdk::PublicKey::from_str("ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp")?;
        let _ = threshold_signatures::frost_secp256k1::VerifyingKey::from_near_sdk_public_key(
            &near_sdk,
        )?;
        Ok(())
    }
}
