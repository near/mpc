use crate::indexer::transaction::TransactionSigner;
use crate::metrics;
use crate::sign_request::SignatureRequest;
use cait_sith::FullSignature;
use k256::{AffinePoint, Scalar, Secp256k1};
use near_client;
use near_indexer_primitives::types::AccountId;
use near_indexer_primitives::types::{BlockReference, Finality};
use near_o11y::WithSpanContextExt;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Debug, PartialEq, Eq, Serialize, Clone, Copy)]
struct SerializableScalar {
    pub scalar: Scalar,
}

impl From<Scalar> for SerializableScalar {
    fn from(scalar: Scalar) -> Self {
        SerializableScalar { scalar }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Clone, Copy)]
struct SerializableAffinePoint {
    pub affine_point: AffinePoint,
}

/* The format in which the chain signatures contract expects
 * to receive the details of the original request. `epsilon`
 * is used to refer to the tweak derived from the caller's
 * account id and the derivation path.
 */
#[derive(Serialize, Debug, Clone)]
struct ChainSignatureRequest {
    pub epsilon: SerializableScalar,
    pub payload_hash: SerializableScalar,
}

impl ChainSignatureRequest {
    pub fn new(payload_hash: Scalar, epsilon: Scalar) -> Self {
        let epsilon = SerializableScalar { scalar: epsilon };
        let payload_hash = SerializableScalar {
            scalar: payload_hash,
        };
        ChainSignatureRequest {
            epsilon,
            payload_hash,
        }
    }
}

/* The format in which the chain signatures contract expects
 * to receive the completed signature.
 */
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
struct ChainSignatureResponse {
    pub big_r: SerializableAffinePoint,
    pub s: SerializableScalar,
    pub recovery_id: u8,
}

impl ChainSignatureResponse {
    pub fn new(big_r: AffinePoint, s: Scalar, recovery_id: u8) -> Self {
        ChainSignatureResponse {
            big_r: SerializableAffinePoint {
                affine_point: big_r,
            },
            s: SerializableScalar { scalar: s },
            recovery_id,
        }
    }
}

/* These arguments are passed to the `respond` function of the
 * chain signatures contract. It takes both the details of the
 * original request and the completed signature, then verifies
 * that the signature matches the requested key and payload.
 */
#[derive(Serialize)]
pub struct ChainRespondArgs {
    request: ChainSignatureRequest,
    response: ChainSignatureResponse,
}

impl ChainRespondArgs {
    pub fn new(request: &SignatureRequest, response: &FullSignature<Secp256k1>) -> Self {
        ChainRespondArgs {
            request: ChainSignatureRequest::new(request.msg_hash, request.tweak),
            // TODO: figure out correct recovery_id
            response: ChainSignatureResponse::new(response.big_r, response.s, 0),
        }
    }
}

pub(crate) async fn handle_sign_responses(
    tx_signer: Option<Arc<TransactionSigner>>,
    mpc_contract_id: AccountId,
    mut receiver: mpsc::Receiver<ChainRespondArgs>,
    view_client: actix::Addr<near_client::ViewClientActor>,
    client: actix::Addr<near_client::ClientActor>,
) {
    while let Some(respond_args) = receiver.recv().await {
        let Some(tx_signer) = tx_signer.clone() else {
            tracing::error!(target: "mpc", "Transaction signer unavailable; account secret key not provided");
            continue;
        };
        let mpc_contract_id = mpc_contract_id.clone();
        let view_client = view_client.clone();
        let client = client.clone();
        actix::spawn(async move {
            let Ok(response_ser) = serde_json::to_string(&respond_args) else {
                tracing::error!(target: "mpc", "Failed to serialize response args");
                return;
            };
            tracing::debug!(target = "mpc", "tx args {:?}", response_ser);

            let Ok(Ok(block)) = view_client
                .send(
                    near_client::GetBlock(BlockReference::Finality(Finality::Final))
                        .with_span_context(),
                )
                .await
            else {
                tracing::warn!(
                    target = "mpc",
                    "failed to get block hash to send response tx"
                );
                return;
            };

            let transaction = tx_signer.create_and_sign_function_call_tx(
                mpc_contract_id.clone(),
                "respond".to_string(),
                response_ser.into(),
                block.header.hash,
                block.header.height,
            );
            tracing::info!(
                target = "mpc",
                "sending response tx {:?}",
                transaction.get_hash()
            );

            let result = client
                .send(
                    near_client::ProcessTxRequest {
                        transaction,
                        is_forwarded: false,
                        check_only: false,
                    }
                    .with_span_context(),
                )
                .await;
            match result {
                Ok(response) => match response {
                    // We're not a validator, so we should always be routing the transaction.
                    near_client::ProcessTxResponse::RequestRouted => {
                        metrics::MPC_NUM_SIGN_RESPONSES_SENT.inc();
                    }
                    _ => {
                        metrics::MPC_NUM_SIGN_RESPONSES_FAILED_TO_SEND_IMMEDIATELY.inc();
                        tracing::error!(
                            target: "mpc",
                            "Failed to send response tx: unexpected ProcessTxResponse: {:?}",
                            response
                        );
                    }
                },
                Err(err) => {
                    metrics::MPC_NUM_SIGN_RESPONSES_FAILED_TO_SEND_IMMEDIATELY.inc();
                    tracing::error!(target: "mpc", "Failed to send response tx: {:?}", err);
                }
            }
        });
    }
}
