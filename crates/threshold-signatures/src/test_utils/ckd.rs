use blstrs::Scalar;
use elliptic_curve::{Field as _, Group as _};
use rand::{RngCore, SeedableRng};
use rand_core::CryptoRngCore;

use crate::confidential_key_derivation::protocol::ckd as ckd_plain;
use crate::confidential_key_derivation::{
    AppId, CKDOutput, CKDOutputOption, ElementG1, ElementG2, KeygenOutput, PublicVerificationKey,
    ckd_pv,
};
use crate::errors::ProtocolError;
use crate::participants::Participant;
use crate::test_utils::{GenProtocol, check_one_coordinator_output, run_protocol};

pub fn generate_ckd_app_package(rng: &mut impl RngCore) -> (AppId, Scalar, PublicVerificationKey) {
    let app_id = AppId::try_from(b"Near App").unwrap();
    let app_sk = Scalar::random(rng);
    let app_pk = PublicVerificationKey::new(
        ElementG1::generator() * app_sk,
        ElementG2::generator() * app_sk,
    );
    (app_id, app_sk, app_pk)
}

/// Runs the confidential key derivation protocol and returns the coordinator's
/// output. Shares are taken from `key_packages` in order, each participant
/// getting a freshly seeded RNG.
pub fn run_ckd<R>(
    key_packages: &[(Participant, KeygenOutput)],
    coordinator: Participant,
    app_id: &AppId,
    app_pk: &ElementG1,
    rng: &mut R,
) -> Result<CKDOutput, ProtocolError>
where
    R: CryptoRngCore + SeedableRng + Send + 'static,
{
    let participants: Vec<Participant> = key_packages.iter().map(|(p, _)| *p).collect();
    let mut protocols: GenProtocol<CKDOutputOption> = Vec::with_capacity(key_packages.len());
    for (p, key_pair) in key_packages {
        let rng_p = R::seed_from_u64(rng.next_u64());
        let protocol = ckd_plain(
            &participants,
            coordinator,
            *p,
            key_pair.clone(),
            app_id.clone(),
            *app_pk,
            rng_p,
        )
        .expect("ckd protocol init");
        protocols.push((*p, Box::new(protocol)));
    }
    collect_coordinator_output(protocols, coordinator)
}

/// Like [`run_ckd`] but for the publicly-verifiable variant, which takes a
/// [`PublicVerificationKey`].
pub fn run_ckd_pv<R>(
    key_packages: &[(Participant, KeygenOutput)],
    coordinator: Participant,
    app_id: &AppId,
    app_pk: &PublicVerificationKey,
    rng: &mut R,
) -> Result<CKDOutput, ProtocolError>
where
    R: CryptoRngCore + SeedableRng + Send + 'static,
{
    let participants: Vec<Participant> = key_packages.iter().map(|(p, _)| *p).collect();
    let mut protocols: GenProtocol<CKDOutputOption> = Vec::with_capacity(key_packages.len());
    for (p, key_pair) in key_packages {
        let rng_p = R::seed_from_u64(rng.next_u64());
        let protocol = ckd_pv(
            &participants,
            coordinator,
            *p,
            key_pair.clone(),
            app_id.clone(),
            app_pk.clone(),
            rng_p,
        )
        .expect("ckd protocol init");
        protocols.push((*p, Box::new(protocol)));
    }
    collect_coordinator_output(protocols, coordinator)
}

fn collect_coordinator_output(
    protocols: GenProtocol<CKDOutputOption>,
    coordinator: Participant,
) -> Result<CKDOutput, ProtocolError> {
    let result = run_protocol(protocols)?;
    check_one_coordinator_output(result, coordinator)
}
