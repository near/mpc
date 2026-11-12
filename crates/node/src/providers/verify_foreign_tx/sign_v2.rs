mod leader;
mod signer;

use std::collections::BTreeSet;
use std::sync::Arc;

use near_mpc_contract_interface::types as dtos;
use threshold_signatures::ecdsa::Signature;
use threshold_signatures::frost_secp256k1::VerifyingKey;
use tokio::time::Duration;

use crate::network::MeshNetworkClient;
use crate::primitives::ParticipantId;
use crate::providers::verify_foreign_tx::VerifyForeignTxProvider;
use crate::providers::verify_foreign_tx::node_outcome::NodeVerdict;
use crate::providers::verify_foreign_tx::node_outcome_statement::{
    NodeOutcomeSigningKey, NodeOutcomeStatement, SignedNodeOutcome,
};
use crate::providers::verify_foreign_tx::open_requests::OpenVerifyForeignTxRequestsV2;
use crate::types::{VerifyForeignTxId, VerifyForeignTxRequestV2};

/// The deadline of one V2 signing round, counted from its Start.
pub(crate) const ROUND_DEADLINE: Duration = Duration::from_secs(5);

/// The interval at which a node sends its node outcome again while the request is open, so a
/// peer that connects late, or that reads an outcome key late, still gets it.
const OUTCOME_RESEND_INTERVAL: Duration = Duration::from_secs(2);

/// What a node needs, beyond the V1 flow, to answer V2 requests.
pub(crate) struct VerifyForeignTxV2Context {
    pub(crate) open_requests: Arc<OpenVerifyForeignTxRequestsV2>,
    pub(crate) signing_key: NodeOutcomeSigningKey,
    pub(crate) network: Arc<MeshNetworkClient>,
}

/// The signature of a V2 signing round for [`Self::verdict`].
pub(crate) struct SignedVerdict {
    pub(crate) verdict: NodeVerdict,
    pub(crate) payload_hash: dtos::Hash256,
    pub(crate) signature: Signature,
    pub(crate) public_key: VerifyingKey,
}

impl VerifyForeignTxProvider {
    /// Inspects a V2 request whose block is final, signs this node's outcome and sends it to
    /// every participant, again and again while the request is open. A node that does not
    /// support the chain stays silent.
    pub(crate) async fn inspect_and_send_node_outcome(
        &self,
        request: VerifyForeignTxRequestV2,
    ) -> anyhow::Result<()> {
        let me = self.ecdsa_signature_provider.my_participant_id();
        if !self
            .v2_chain_supporters(request.request.chain())
            .contains(&me)
        {
            return Ok(());
        }
        let outcome = self
            .reach_node_outcome(&request.request, &request.expected_values_hash)
            .await?;
        let signed = self.v2.signing_key.sign(NodeOutcomeStatement {
            yield_id: request.yield_id,
            signer: me,
            outcome,
        })?;
        keep_and_send_while_open(&self.v2.network, &self.v2.open_requests, request.id, signed)
            .await;
        Ok(())
    }

    /// The participants the contract lists as supporting `chain`, in this node's view. Only
    /// their node outcomes count.
    fn v2_chain_supporters(&self, chain: dtos::ForeignChain) -> BTreeSet<ParticipantId> {
        self.supporters_by_foreign_chain
            .borrow()
            .get(&chain)
            .into_iter()
            .flatten()
            .copied()
            .collect()
    }
}

/// Keeps this node's own `outcome` and sends it to every participant, again every
/// [`OUTCOME_RESEND_INTERVAL`] until the request `id` closes. It is kept again each time, since
/// it verifies only once this node's outcome key is on chain.
async fn keep_and_send_while_open(
    network: &MeshNetworkClient,
    open_requests: &OpenVerifyForeignTxRequestsV2,
    id: VerifyForeignTxId,
    outcome: SignedNodeOutcome,
) {
    let me = network.my_participant_id();
    while open_requests.get(id).is_some() {
        if let Err(error) = network.node_outcomes().receive(me, outcome.clone()) {
            tracing::debug!(%error, "own node outcome not kept");
        }
        network.broadcast_node_outcome(&outcome);
        tokio::time::sleep(OUTCOME_RESEND_INTERVAL).await;
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests;
