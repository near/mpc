mod sign;

use aes_gcm::aead::rand_core::{CryptoRng, RngCore};
use cait_sith::protocol::{Participant, Protocol};

#[derive(Debug)]
pub enum SignatureOutput {
    Coordinator(frost_ed25519::Signature),
    Participant,
}

pub fn sign<RNG: CryptoRng + RngCore + 'static + Send>(
    rng: RNG,
    is_coordinator: bool,
    participants: Vec<Participant>,
    me: Participant,
    key_package: frost_ed25519::keys::KeyPackage,
    pubkeys: frost_ed25519::keys::PublicKeyPackage,
    msg_hash: Vec<u8>,
) -> anyhow::Result<Box<dyn Protocol<Output = SignatureOutput>>> {
    sign::sign_internal(
        rng,
        is_coordinator,
        participants,
        me,
        key_package,
        pubkeys,
        msg_hash,
    )
}

fn to_frost_identifier(participant: Participant) -> frost_ed25519::Identifier {
    frost_ed25519::Identifier::derive(participant.bytes().as_slice())
        .expect("Identifier derivation must succeed: cipher suite is guaranteed to be implemented")
}
