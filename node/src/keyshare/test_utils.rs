use super::permanent::PermanentKeyshareData;
use super::{Keyshare, KeyshareData};
use crate::providers::{ecdsa, eddsa};
use crate::tests::TestGenerators;
use cait_sith::ecdsa::KeygenOutput;
use mpc_contract::primitives::domain::DomainId;
use mpc_contract::primitives::key_state::{EpochId, KeyEventId, KeyForDomain, Keyset};

pub fn generate_dummy_keyshare(epoch_id: u64, domain_id: u64, attempt_id: u64) -> Keyshare {
    let key = TestGenerators::new(2, 2)
        .make_ecdsa_keygens()
        .into_iter()
        .next()
        .unwrap()
        .1;
    Keyshare {
        key_id: KeyEventId::new(
            EpochId::new(epoch_id),
            DomainId(domain_id),
            serde_json::from_str(&format!("{}", attempt_id)).unwrap(),
        ),
        data: KeyshareData::Secp256k1(KeygenOutput {
            private_share: key.private_share,
            public_key: key.public_key,
        }),
    }
}

fn permanent_keyshare_from_keyshares(
    epoch_id: u64,
    keyshares: &[Keyshare],
) -> PermanentKeyshareData {
    PermanentKeyshareData {
        epoch_id: EpochId::new(epoch_id),
        keyshares: keyshares.to_vec(),
    }
}

fn keyset_from_permanent_keyshare(permanent: &PermanentKeyshareData) -> Keyset {
    let keys = permanent
        .keyshares
        .iter()
        .map(|keyshare| {
            let key = match &keyshare.data {
                KeyshareData::Secp256k1(data) => {
                    ecdsa::affine_point_to_public_key(data.public_key).unwrap()
                }
                KeyshareData::Ed25519(data) => {
                    eddsa::convert_to_near_pubkey(&data.public_key_package).unwrap()
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

pub struct KeysetBuilder {
    epoch_id: u64,
    keys: Vec<Keyshare>,
}

impl KeysetBuilder {
    pub fn new(epoch_id: u64) -> Self {
        Self {
            epoch_id,
            keys: Vec::new(),
        }
    }

    pub fn from_keyshares(epoch_id: u64, keyshares: &[Keyshare]) -> Self {
        Self {
            epoch_id,
            keys: keyshares.to_vec(),
        }
    }

    pub fn keyshares(&self) -> &[Keyshare] {
        &self.keys
    }

    pub fn add_keyshare(&mut self, keyshare: Keyshare) -> &mut Self {
        self.keys.push(keyshare);
        self
    }

    pub fn keyset(&self) -> Keyset {
        keyset_from_permanent_keyshare(&self.permanent_key_data())
    }

    pub fn permanent_key_data(&self) -> PermanentKeyshareData {
        permanent_keyshare_from_keyshares(self.epoch_id, &self.keys)
    }

    pub fn generated(&self) -> Vec<KeyForDomain> {
        self.keyset().domains
    }
}
