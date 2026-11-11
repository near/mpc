use anyhow::Context;
use near_mpc_bounded_collections::BoundedVec;
use near_mpc_contract_interface::types::{self as dtos, ECDSA_PAYLOAD_SIZE_BYTES, Payload, Tweak};
use threshold_signatures::ReconstructionThreshold;
use threshold_signatures::ecdsa::{KeygenOutput, Signature};
use threshold_signatures::frost_secp256k1::VerifyingKey;

use crate::network::NetworkTaskChannel;
use crate::network::computation::MpcLeaderCentricComputation as _;
use crate::providers::ecdsa::OnlinePresignSignComputation;
use crate::providers::ecdsa::triple::PairedTriple;
use crate::types::{SignatureRequest, VerifyForeignTxRequestV2};

/// The signature of the V2 payload that answers a request with [`Self::outcome`].
pub(crate) struct SignedOutcome {
    pub(crate) outcome: dtos::ForeignTxVerificationOutcome,
    pub(crate) payload_hash: dtos::Hash256,
    pub(crate) signature: Signature,
    pub(crate) public_key: VerifyingKey,
}

/// What the leader of a V2 attempt or inconclusive round signs the payload with.
pub(crate) struct OutcomeSigning {
    pub(crate) request: VerifyForeignTxRequestV2,
    pub(crate) keygen_out: KeygenOutput,
    pub(crate) reconstruction_threshold: ReconstructionThreshold,
    pub(crate) triples: PairedTriple,
}

impl OutcomeSigning {
    /// Signs the payload that answers the request with `outcome`, as the leader of `channel`.
    pub(crate) async fn sign(
        self,
        channel: &mut NetworkTaskChannel,
        outcome: dtos::ForeignTxVerificationOutcome,
    ) -> anyhow::Result<SignedOutcome> {
        let payload_hash = self
            .request
            .sign_payload(outcome.clone())?
            .compute_msg_hash()?;
        let (signature, public_key) = OnlinePresignSignComputation {
            keygen_out: self.keygen_out,
            reconstruction_threshold: self.reconstruction_threshold,
            triples: self.triples,
            msg_hash: payload_hash.clone().into(),
            tweak: Tweak::new([0; 32]),
        }
        .compute(channel)
        .await?;
        Ok(SignedOutcome {
            outcome,
            payload_hash,
            signature: signature.context("the leader should obtain a signature")?,
            public_key,
        })
    }
}

/// The signature request a follower runs the shared signing protocol with. Only its payload and
/// tweak reach the protocol.
pub(crate) fn sign_request(
    request: &VerifyForeignTxRequestV2,
    payload_hash: dtos::Hash256,
) -> SignatureRequest {
    let payload_hash: [u8; ECDSA_PAYLOAD_SIZE_BYTES] = payload_hash.into();
    let payload: BoundedVec<u8, ECDSA_PAYLOAD_SIZE_BYTES, ECDSA_PAYLOAD_SIZE_BYTES> =
        payload_hash.into();
    SignatureRequest {
        id: request.id,
        receipt_id: request.receipt_id,
        payload: Payload::Ecdsa(payload),
        tweak: Tweak::new([0; 32]),
        entropy: request.entropy,
        timestamp_nanosec: request.timestamp_nanosec,
        domain: request.request.domain_id,
    }
}
