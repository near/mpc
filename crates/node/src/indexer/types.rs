use crate::{types::CKDRequest, types::SignatureRequest};
use anyhow::Context;
use contract_interface::types as dtos;
use k256::{
    ecdsa::RecoveryId,
    elliptic_curve::{ops::Reduce, point::AffineCoordinates, Curve, CurveArithmetic},
    AffinePoint, Scalar, Secp256k1,
};
use mpc_contract::{
    crypto_shared::CKDResponse,
    primitives::{
        domain::DomainId,
        key_state::{KeyEventId, Keyset},
        signature::Tweak,
    },
};
use near_indexer_primitives::types::Gas;
use near_sdk::AccountId;
use serde::{Deserialize, Serialize};
use threshold_signatures::ecdsa::Signature;
use threshold_signatures::frost_ed25519;
use threshold_signatures::frost_secp256k1::VerifyingKey;

const TGAS: u64 = 1_000_000_000_000;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
pub struct SerializableScalar {
    pub scalar: Scalar,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
struct SerializableAffinePoint {
    pub affine_point: AffinePoint,
}

/* The format in which the chain signatures contract expects
 * to receive the details of the original request. `epsilon`
 * is used to refer to the (serializable) tweak derived from the caller's
 * account id and the derivation path.
 */
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChainSignatureRequest {
    pub tweak: Tweak,
    pub payload: Payload,
    pub domain_id: DomainId,
}

impl ChainSignatureRequest {
    pub fn new(tweak: Tweak, payload: Payload, domain_id: DomainId) -> Self {
        ChainSignatureRequest {
            tweak,
            payload,
            domain_id,
        }
    }
}

/* The format in which the chain contract expects
 * to receive the details of the original ckd request.
 */
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChainCKDRequest {
    pub app_public_key: dtos::Bls12381G1PublicKey,
    pub app_id: AccountId,
    pub domain_id: DomainId,
}

impl ChainCKDRequest {
    pub fn new(
        app_public_key: dtos::Bls12381G1PublicKey,
        app_id: AccountId,
        domain_id: DomainId,
    ) -> Self {
        ChainCKDRequest {
            app_public_key,
            app_id,
            domain_id,
        }
    }
}

pub type ChainSignatureResponse = mpc_contract::crypto_shared::SignatureResponse;
pub type ChainCKDResponse = mpc_contract::crypto_shared::CKDResponse;

pub use mpc_contract::crypto_shared::k256_types;
use mpc_contract::crypto_shared::{ed25519_types, SignatureResponse};
use mpc_contract::primitives::signature::Payload;

const MAX_RECOVERY_ID: u8 = 3;

fn k256_signature_response(
    big_r: AffinePoint,
    s: Scalar,
    recovery_id: u8,
) -> anyhow::Result<ChainSignatureResponse> {
    if recovery_id > MAX_RECOVERY_ID {
        anyhow::bail!("Invalid Recovery Id: recovery id larger than 3.");
    }

    let k256_signature = k256_types::Signature::new(big_r, s, recovery_id);
    Ok(ChainSignatureResponse::Secp256k1(k256_signature))
}
pub trait ChainRespondArgs {}

/* These arguments are passed to the `respond` function of the
 * chain signatures contract. It takes both the details of the
 * original request and the completed signature, then verifies
 * that the signature matches the requested key and payload.
 */
#[derive(Serialize, Debug, Deserialize, Clone)]
pub struct ChainSignatureRespondArgs {
    pub request: ChainSignatureRequest,
    response: ChainSignatureResponse,
}

impl ChainRespondArgs for ChainSignatureRespondArgs {}

/* These arguments are passed to the `respond_ckd` function of the
 * chain contract. It takes both the details of the
 * original request and the completed ckd.
 */
#[derive(Serialize, Debug, Deserialize, Clone)]
pub struct ChainCKDRespondArgs {
    pub request: ChainCKDRequest,
    response: ChainCKDResponse,
}

impl ChainRespondArgs for ChainCKDRespondArgs {}

#[derive(Serialize, Debug)]
pub struct ChainGetPendingSignatureRequestArgs {
    pub request: ChainSignatureRequest,
}

#[derive(Serialize, Debug)]
pub struct ChainGetPendingCKDRequestArgs {
    pub request: ChainCKDRequest,
}

#[derive(Serialize, Debug)]
pub struct GetAttestationArgs {
    pub tls_public_key: contract_interface::types::Ed25519PublicKey,
}

#[derive(Serialize, Debug)]
pub struct ChainVotePkArgs {
    pub key_event_id: KeyEventId,
    pub public_key: dtos::PublicKey,
}

#[derive(Serialize, Debug)]
pub struct ChainVoteResharedArgs {
    pub key_event_id: KeyEventId,
}

#[derive(Serialize, Debug)]
pub struct ChainStartReshareArgs {
    pub key_event_id: KeyEventId,
}

#[derive(Serialize, Debug)]
pub struct ChainStartKeygenArgs {
    pub key_event_id: KeyEventId,
}

#[derive(Serialize, Debug)]
pub struct ChainVoteAbortKeyEventInstanceArgs {
    pub key_event_id: KeyEventId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitParticipantInfoArgs {
    pub proposed_participant_attestation: contract_interface::types::Attestation,
    pub tls_public_key: contract_interface::types::Ed25519PublicKey,
}

#[derive(Serialize, Debug)]
pub struct ConcludeNodeMigrationArgs {
    pub keyset: Keyset,
}
/// Request to send a transaction to the contract on chain.
#[derive(Serialize, Debug)]
#[serde(untagged)]
pub enum ChainSendTransactionRequest {
    Respond(ChainSignatureRespondArgs),
    CKDRespond(ChainCKDRespondArgs),
    VotePk(ChainVotePkArgs),
    StartKeygen(ChainStartKeygenArgs),
    VoteReshared(ChainVoteResharedArgs),
    StartReshare(ChainStartReshareArgs),
    VoteAbortKeyEventInstance(ChainVoteAbortKeyEventInstanceArgs),
    VerifyTee(),
    // Boxed as this variant is big, 2168 bytes.
    // Big discrepancies in variant sizes will lead to memory fragmentation
    // due to rust's memory layout for enums.
    //
    // For more info see clippy lint:
    // https://rust-lang.github.io/rust-clippy/master/index.html#large_enum_variant
    SubmitParticipantInfo(Box<SubmitParticipantInfoArgs>),

    ConcludeNodeMigration(ConcludeNodeMigrationArgs),
}

impl ChainSendTransactionRequest {
    pub fn method(&self) -> &'static str {
        match self {
            ChainSendTransactionRequest::Respond(_) => "respond",
            ChainSendTransactionRequest::CKDRespond(_) => "respond_ckd",
            ChainSendTransactionRequest::VotePk(_) => "vote_pk",
            ChainSendTransactionRequest::VoteReshared(_) => "vote_reshared",
            ChainSendTransactionRequest::StartReshare(_) => "start_reshare_instance",
            ChainSendTransactionRequest::StartKeygen(_) => "start_keygen_instance",
            ChainSendTransactionRequest::VoteAbortKeyEventInstance(_) => {
                "vote_abort_key_event_instance"
            }
            ChainSendTransactionRequest::VerifyTee() => "verify_tee",
            ChainSendTransactionRequest::SubmitParticipantInfo(_) => "submit_participant_info",
            ChainSendTransactionRequest::ConcludeNodeMigration(_) => "conclude_node_migration",
        }
    }

    pub fn gas_required(&self) -> Gas {
        match self {
            Self::Respond(_)
            | Self::CKDRespond(_)
            | Self::VotePk(_)
            | Self::VoteReshared(_)
            | Self::StartReshare(_)
            | Self::StartKeygen(_)
            | Self::VoteAbortKeyEventInstance(_)
            // This is too high in most settings, see https://github.com/near/mpc/issues/166
            | Self::VerifyTee() => 300 * TGAS,
            Self::SubmitParticipantInfo(_) => 300 * TGAS,
            Self::ConcludeNodeMigration(_) => 300 * TGAS,
        }
    }
}

impl ChainSignatureRespondArgs {
    /// WARNING: this function assumes the input full signature is valid and comes from an authentic response
    pub fn new_ecdsa(
        request: &SignatureRequest,
        response: &Signature,
        public_key: &VerifyingKey,
    ) -> anyhow::Result<Self> {
        let recovery_id = Self::brute_force_recovery_id(
            &public_key.to_element().to_affine(),
            response,
            request
                .payload
                .as_ecdsa()
                .ok_or_else(|| anyhow::anyhow!("Payload is not an ECDSA payload"))?,
        )?;
        Ok(ChainSignatureRespondArgs {
            request: ChainSignatureRequest::new(
                request.tweak.clone(),
                request.payload.clone(),
                request.domain,
            ),
            response: k256_signature_response(response.big_r, response.s, recovery_id)?,
        })
    }

    pub fn new_eddsa(
        request: &SignatureRequest,
        response: &frost_ed25519::Signature,
    ) -> anyhow::Result<Self> {
        let response = response
            .serialize()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Response is not 64 bytes"))?;
        Ok(ChainSignatureRespondArgs {
            request: ChainSignatureRequest::new(
                request.tweak.clone(),
                request.payload.clone(),
                request.domain,
            ),
            response: SignatureResponse::Ed25519 {
                signature: ed25519_types::Signature::new(response),
            },
        })
    }

    /// Brute forces the recovery id to find a recovery_id that matches the public key
    pub(crate) fn brute_force_recovery_id(
        expected_pk: &AffinePoint,
        signature: &Signature,
        msg_hash: &[u8; 32],
    ) -> anyhow::Result<u8> {
        let partial_signature = k256::ecdsa::Signature::from_scalars(
            <<Secp256k1 as CurveArithmetic>::Scalar as Reduce<<Secp256k1 as Curve>::Uint>>
            ::reduce_bytes(&signature.big_r.x()), signature.s)
            .context("Cannot create signature from cait_sith signature")?;
        let expected_pk = match k256::ecdsa::VerifyingKey::from_affine(*expected_pk) {
            Ok(pk) => pk,
            _ => anyhow::bail!("The affine point cannot be transformed into a verifying key"),
        };
        match RecoveryId::trial_recovery_from_prehash(&expected_pk, msg_hash, &partial_signature) {
            Ok(rec_id) => Ok(rec_id.to_byte()),
            _ => anyhow::bail!(
                "No recovery id found for such a tuple of public key, signature, message hash"
            ),
        }
    }
}

impl ChainCKDRespondArgs {
    pub fn new_ckd(request: &CKDRequest, response: &CKDResponse) -> anyhow::Result<Self> {
        Ok(ChainCKDRespondArgs {
            request: ChainCKDRequest::new(
                request.app_public_key.clone(),
                request.app_id.clone(),
                request.domain_id,
            ),
            response: response.clone(),
        })
    }
}

#[cfg(test)]
mod recovery_id_tests {
    use crate::indexer::types::ChainSignatureRespondArgs;
    use k256::ecdsa::{RecoveryId, SigningKey};
    use k256::elliptic_curve::{point::DecompressPoint, PrimeField};
    use k256::AffinePoint;
    use rand::rngs::OsRng;
    use threshold_signatures::ecdsa::Signature;

    #[test]
    fn test_brute_force_recovery_id() {
        for _ in 0..256 {
            // generate a pair of ecdsa keys
            let mut rng = OsRng;
            let signing_key = SigningKey::random(&mut rng);

            // compute a signature with recovery id
            let prehash: [u8; 32] = rand::random();
            match signing_key.sign_prehash_recoverable(&prehash) {
                // match signing_key.sign_digest_recoverable(digest) {
                Ok((signature, recid)) => {
                    let (r, s) = signature.split_scalars();

                    // Create a full signature
                    // any big_r creation works here as we only need its x coordinate during brute force (big_r.x())

                    let r_bytes = r.to_repr();
                    let hypothetical_big_r = AffinePoint::decompress(&r_bytes, 0.into()).unwrap();

                    let full_sig = Signature {
                        big_r: hypothetical_big_r,
                        s: *s.as_ref(),
                    };

                    let tested_recid = ChainSignatureRespondArgs::brute_force_recovery_id(
                        signing_key.verifying_key().as_affine(),
                        &full_sig,
                        &prehash,
                    )
                    .unwrap();

                    // compute recovery_id using our function
                    let tested_recid = RecoveryId::from_byte(tested_recid).unwrap();

                    assert!(tested_recid.is_x_reduced() == recid.is_x_reduced());
                    assert!(tested_recid.is_y_odd() == recid.is_y_odd());
                }
                Err(_) => panic!("The signature in the test has failed"),
            }
        }
    }
}
