use super::permanent::PermanentKeyshareData;
use super::{Keyshare, KeyshareData};
use mpc_contract::primitives::domain::DomainId;
use mpc_contract::primitives::key_state::{EpochId, KeyEventId, KeyForDomain, Keyset};
use rand::{CryptoRng, RngCore, SeedableRng};
use threshold_signatures::ecdsa::KeygenOutput;
use threshold_signatures::test_utils::TestGenerators;

pub fn make_key_id(epoch_id: u64, domain_id: u64, attempt_id: u64) -> KeyEventId {
    KeyEventId::new(
        EpochId::new(epoch_id),
        DomainId(domain_id),
        serde_json::from_str(&format!("{attempt_id}")).unwrap(),
    )
}
/// returns two shares for the same key
pub fn generate_dummy_keyshares<R: CryptoRng + RngCore + SeedableRng + Send + 'static>(
    epoch_id: u64,
    domain_id: u64,
    attempt_id: u64,
    rng: &mut R,
) -> (Keyshare, Keyshare) {
    let keyshares = TestGenerators::new(2, 2).make_ecdsa_keygens(rng);
    let mut iter = keyshares.into_iter().map(|share| {
        let key = share.1;

        Keyshare {
            key_id: make_key_id(epoch_id, domain_id, attempt_id),
            data: KeyshareData::Secp256k1(KeygenOutput {
                private_share: key.private_share,
                public_key: key.public_key,
            }),
        }
    });
    (iter.next().unwrap(), iter.next().unwrap())
}

#[test]
pub fn test_generate_dummy_keyshares() {
    let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
    let (keyshare, alternate_keyshare) = generate_dummy_keyshares(0, 1, 0, &mut rng);
    assert_ne!(alternate_keyshare, keyshare);
    // ensure that the keyshares are different
    assert_ne!(alternate_keyshare.data, keyshare.data);
    // ensure that the keyshares are for the same public key
    assert_eq!(
        alternate_keyshare.public_key().unwrap(),
        keyshare.public_key().unwrap()
    );
}

pub fn generate_dummy_keyshare<R: CryptoRng + RngCore + SeedableRng + Send + 'static>(
    epoch_id: u64,
    domain_id: u64,
    attempt_id: u64,
    rng: &mut R,
) -> Keyshare {
    let key = TestGenerators::new(2, 2)
        .make_ecdsa_keygens(rng)
        .into_iter()
        .next()
        .unwrap()
        .1;
    Keyshare {
        key_id: make_key_id(epoch_id, domain_id, attempt_id),
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
            let public_key = keyshare.public_key().unwrap();
            KeyForDomain {
                domain_id: keyshare.key_id.domain_id,
                key: public_key.try_into().unwrap(),
                attempt: keyshare.key_id.attempt_id,
            }
        })
        .collect();
    Keyset::new(permanent.epoch_id, keys)
}

#[derive(Clone)]
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

    pub fn new_populated<R: CryptoRng + RngCore + SeedableRng + Send + 'static>(
        epoch_id: u64,
        num_keys: u64,
        rng: &mut R,
    ) -> Self {
        let mut res = KeysetBuilder::new(epoch_id);
        for domain_id in 0..num_keys {
            let attempt_id: u64 = rand::random();
            let keyshare = generate_dummy_keyshare(epoch_id, domain_id, attempt_id, rng);
            res.add_keyshare(keyshare);
        }
        res
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
