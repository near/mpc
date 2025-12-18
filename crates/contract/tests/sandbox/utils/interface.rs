// These are temporary conversions to avoid breaking the contract API.
// Once we complete the migration from near_sdk::PublicKey they should not be
// needed anymore
use contract_interface::types::{self as dtos};
use threshold_signatures::confidential_key_derivation::{self as ckd};

pub trait IntoInterfaceType<InterfaceType> {
    fn into_interface_type(self) -> InterfaceType;
}

pub(crate) trait IntoContractType<ContractType> {
    fn into_contract_type(self) -> ContractType;
}

impl IntoInterfaceType<dtos::Ed25519PublicKey> for &near_sdk::PublicKey {
    fn into_interface_type(self) -> dtos::Ed25519PublicKey {
        // This function should not be called with any other type
        assert!(self.curve_type() == near_sdk::CurveType::ED25519);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.as_bytes()[1..]);
        dtos::Ed25519PublicKey::from(bytes)
    }
}

impl IntoInterfaceType<dtos::Bls12381G1PublicKey> for &ckd::ElementG1 {
    fn into_interface_type(self) -> dtos::Bls12381G1PublicKey {
        dtos::Bls12381G1PublicKey::from(self.to_compressed())
    }
}

impl IntoContractType<near_sdk::PublicKey> for &dtos::Ed25519PublicKey {
    fn into_contract_type(self) -> near_sdk::PublicKey {
        near_sdk::PublicKey::from_parts(near_sdk::CurveType::ED25519, self.0.into()).unwrap()
    }
}

impl IntoContractType<ckd::ElementG1> for &dtos::Bls12381G1PublicKey {
    fn into_contract_type(self) -> ckd::ElementG1 {
        ckd::ElementG1::from_compressed(&self.0).unwrap()
    }
}

impl IntoContractType<near_sdk::PublicKey> for &dtos::PublicKey {
    fn into_contract_type(self) -> near_sdk::PublicKey {
        match self {
            dtos::PublicKey::Secp256k1(secp256k1_public_key) => near_sdk::PublicKey::from_parts(
                near_sdk::CurveType::SECP256K1,
                secp256k1_public_key.as_bytes().to_vec(),
            )
            .unwrap(),
            dtos::PublicKey::Ed25519(ed25519_public_key) => near_sdk::PublicKey::from_parts(
                near_sdk::CurveType::ED25519,
                ed25519_public_key.as_bytes().to_vec(),
            )
            .unwrap(),
            dtos::PublicKey::Bls12381(_bls12381_public_key) => {
                // This conversion is not possible
                unreachable!()
            }
        }
    }
}
