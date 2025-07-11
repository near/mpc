use near_sdk::PublicKey;

use crate::attestation::Attestation;

pub struct LocalTeeAuthorityConfig;

pub struct DstackTeeAuthorityConfig;

enum TeeAuthority {
    Local(LocalTeeAuthorityConfig),
    Dstack(DstackTeeAuthorityConfig),
}

impl TeeAuthority {
    async fn generate_attestation(
        &self,
        _tls_public_key: &PublicKey,
        _account_public_key: &PublicKey,
    ) -> Attestation {
        match self {
            TeeAuthority::Local(_config) => {
                // Generate attestation using local TEE authority
                todo!("Implement local TEE attestation generation")
            }
            TeeAuthority::Dstack(_config) => {
                // Generate attestation using Dstack TEE authority
                todo!("Implement Dstack TEE attestation generation")
            }
        }
    }
}
