use super::permanent::PermanentKeyshareData;
use super::{Keyshare, KeyshareData};
use near_mpc_contract_interface::types::{
    DomainId, EpochId, KeyEventId, KeyForDomain, Keyset, PublicKey, PublicKeyExtended,
};
use rand::{CryptoRng, RngCore, SeedableRng};
use threshold_signatures::ecdsa::KeygenOutput;
use threshold_signatures::frost_secp256k1::Secp256K1Sha256;
use threshold_signatures::test_utils::{generate_participants_with_random_ids, run_keygen};

const NUM_PARTICIPANTS: usize = 2;
const THRESHOLD: usize = 2;

pub fn make_key_id(epoch_id: u64, domain_id: u64, attempt_id: u64) -> KeyEventId {
    KeyEventId::new(
        EpochId::new(epoch_id),
        DomainId(domain_id),
        serde_json::from_str(&format!("{}", attempt_id)).unwrap(),
    )
}
/// returns two shares for the same key
pub fn generate_dummy_keyshares<R: CryptoRng + RngCore + SeedableRng + Send + 'static>(
    epoch_id: u64,
    domain_id: u64,
    attempt_id: u64,
    rng: &mut R,
) -> (Keyshare, Keyshare) {
    let keyshares: std::collections::HashMap<_, _> = run_keygen::<Secp256K1Sha256, _>(
        &generate_participants_with_random_ids(NUM_PARTICIPANTS, rng),
        THRESHOLD,
        rng,
    )
    .into_iter()
    .collect();
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
    let key = run_keygen::<Secp256K1Sha256, _>(
        &generate_participants_with_random_ids(NUM_PARTICIPANTS, rng),
        THRESHOLD,
        rng,
    )
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
    PermanentKeyshareData::new(EpochId::new(epoch_id), keyshares.to_vec())
        .expect("test keyshares should be consistent")
}

fn keyset_from_keyshares(epoch_id: u64, keyshares: &[Keyshare]) -> Keyset {
    let keys = keyshares
        .iter()
        .map(|keyshare| {
            let public_key = keyshare.public_key().unwrap();
            let key = match public_key {
                PublicKey::Secp256k1(pk) => {
                    let near_pk = near_sdk::PublicKey::from(pk);
                    PublicKeyExtended::Secp256k1 {
                        near_public_key: near_pk.to_string(),
                    }
                }
                PublicKey::Ed25519(pk) => {
                    let edwards_point = pk.0;
                    let near_pk = near_sdk::PublicKey::from(pk);
                    PublicKeyExtended::Ed25519 {
                        near_public_key_compressed: near_pk.to_string(),
                        edwards_point,
                    }
                }
                PublicKey::Bls12381(pk) => PublicKeyExtended::Bls12381 {
                    public_key: PublicKey::Bls12381(pk),
                },
            };
            KeyForDomain {
                domain_id: keyshare.key_id.domain_id,
                key,
                attempt: keyshare.key_id.attempt_id,
            }
        })
        .collect();
    Keyset {
        epoch_id: EpochId::new(epoch_id),
        domains: keys,
    }
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
        keyset_from_keyshares(self.epoch_id, &self.keys)
    }

    pub fn permanent_key_data(&self) -> PermanentKeyshareData {
        permanent_keyshare_from_keyshares(self.epoch_id, &self.keys)
    }

    pub fn generated(&self) -> Vec<KeyForDomain> {
        self.keyset().domains
    }
}
