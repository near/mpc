use threshold_signatures::{ecdsa::Signature, frost_secp256k1::VerifyingKey};

use crate::metrics;
use crate::types::{SignatureRequest, VerifyForeignTxRequest};
use crate::{
    network::NetworkTaskChannel, primitives::UniqueId,
    providers::verify_foreign_tx::VerifyForeignTxProvider, types::SignatureId,
};
use contract_interface::types as dtos;
use mpc_contract::primitives::signature::{Bytes, Payload, Tweak};
use tokio::time::{timeout, Duration};

#[allow(unused)]
use foreign_chain_inspector;

fn build_signature_request(
    request: &VerifyForeignTxRequest,
    foreign_tx_payload: &dtos::ForeignTxSignPayload,
) -> anyhow::Result<SignatureRequest> {
    let payload_hash: [u8; 32] = foreign_tx_payload.compute_msg_hash()?.into();
    let payload_bytes =
        Bytes::new(payload_hash.to_vec()).map_err(|err| anyhow::format_err!("{err}"))?;
    Ok(SignatureRequest {
        id: request.id,
        receipt_id: request.receipt_id,
        payload: Payload::Ecdsa(payload_bytes),
        tweak: Tweak::new(request.tweak.0),
        entropy: request.entropy,
        timestamp_nanosec: request.timestamp_nanosec,
        domain: request.domain_id,
    })
}

impl<ForeignChainPolicyReader: Send + Sync, HttpClient: Send + Sync>
    VerifyForeignTxProvider<ForeignChainPolicyReader, HttpClient>
{
    pub(super) async fn make_verify_foreign_tx_leader(
        &self,
        id: SignatureId,
    ) -> anyhow::Result<(Signature, VerifyingKey)> {
        let foreign_tx_request = self.verify_foreign_tx_request_store.get(id).await?;

        let response_payload = self
            .execute_foreign_chain_request(&foreign_tx_request.request)
            .await?;

        let sign_request = build_signature_request(&foreign_tx_request, &response_payload)?;

        self.ecdsa_signature_provider
            .make_signature_leader_given_request(id, sign_request)
            .await
    }

    pub(super) async fn make_verify_foreign_tx_follower(
        &self,
        channel: NetworkTaskChannel,
        id: SignatureId,
        presignature_id: UniqueId,
    ) -> anyhow::Result<()> {
        metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_RECEIVED.inc();
        let foreign_tx_request = timeout(
            Duration::from_secs(self.config.signature.timeout_sec),
            self.verify_foreign_tx_request_store.get(id),
        )
        .await??;
        metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_LOOKUP_SUCCEEDED.inc();

        let response_payload = self
            .execute_foreign_chain_request(&foreign_tx_request.request)
            .await?;

        let sign_request = build_signature_request(&foreign_tx_request, &response_payload)?;

        self.ecdsa_signature_provider
            .make_signature_follower_given_request(channel, presignature_id, sign_request)
            .await
    }

    async fn execute_foreign_chain_request(
        &self,
        _request: &dtos::ForeignChainRpcRequest,
    ) -> anyhow::Result<dtos::ForeignTxSignPayload> {
        unimplemented!()
    }
}
