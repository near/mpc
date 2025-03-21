use super::permanent::PermanentKeyshareData;
use super::{KeyShare, KeyShareData, Secp256k1Data};
use crate::hkdf::affine_point_to_public_key;
use k256::elliptic_curve::Field;
use k256::{AffinePoint, Scalar};
use mpc_contract::primitives::domain::DomainId;
use mpc_contract::primitives::key_state::{EpochId, KeyEventId, KeyForDomain, Keyset};

pub fn generate_dummy_keyshare(epoch_id: u64, domain_id: u64, attempt_id: u64) -> KeyShare {
    KeyShare {
        key_id: KeyEventId::new(
            EpochId::new(epoch_id),
            DomainId(domain_id),
            serde_json::from_str(&format!("{}", attempt_id)).unwrap(),
        ),
        data: KeyShareData::Secp256k1(Secp256k1Data {
            private_share: Scalar::random(&mut rand::thread_rng()),
            public_key: AffinePoint::IDENTITY,
        }),
    }
}

pub fn permanent_keyshare_from_keyshares(
    epoch_id: u64,
    keyshares: &[KeyShare],
) -> PermanentKeyshareData {
    PermanentKeyshareData {
        epoch_id: EpochId::new(epoch_id),
        keyshares: keyshares.to_vec(),
    }
}

pub fn keyset_from_permanent_keyshare(permanent: &PermanentKeyshareData) -> Keyset {
    let keys = permanent
        .keyshares
        .iter()
        .map(|keyshare| {
            let key = match &keyshare.data {
                KeyShareData::Secp256k1(secp256k1_data) => {
                    affine_point_to_public_key(secp256k1_data.public_key).unwrap()
                }
            };
            KeyForDomain {
                domain_id: keyshare.key_id.domain_id,
                key: key.to_string().parse().unwrap(),
                attempt: keyshare.key_id.attempt_id,
            }
        })
        .collect();
    Keyset::new(permanent.epoch_id, keys)
}
