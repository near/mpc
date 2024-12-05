use crate::metrics;
use crate::sign_request::SignatureRequest;
use cait_sith::FullSignature;
use k256::{AffinePoint, Scalar, Secp256k1};
use near_client;
use near_crypto::KeyFile;
use near_indexer_primitives::near_primitives::transaction::{
    FunctionCallAction, SignedTransaction, Transaction, TransactionV0,
};
use near_indexer_primitives::types::AccountId;
use near_o11y::WithSpanContextExt;
use serde::Serialize;
use std::path::Path;
use tokio::sync::mpsc;

pub fn load_near_credentials(home_dir: &Path, filename: String) -> anyhow::Result<KeyFile> {
    let path = home_dir.join(filename);
    Ok(KeyFile::from_file(&path)?)
}

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
 * to receive the details of the original request. `serializable_tweak`
 * is used to refer to the tweak derived from the caller's
 * account id and the derivation path.
 */
#[derive(Serialize, Debug, Clone)]
struct ChainSignatureRequest {
    pub serializable_tweak: SerializableScalar,
    pub payload_hash: SerializableScalar,
}

impl ChainSignatureRequest {
    pub fn new(payload_hash: Scalar, tweak: Scalar) -> Self {
        let serializable_tweak = SerializableScalar { scalar: tweak };
        let payload_hash = SerializableScalar {
            scalar: payload_hash,
        };
        ChainSignatureRequest {
            serializable_tweak,
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

pub(crate) async fn chain_sender(
    key_file: KeyFile,
    mpc_contract_id: AccountId,
    mut receiver: mpsc::Receiver<ChainRespondArgs>,
    client: actix::Addr<near_client::ClientActor>,
) {
    while let Some(respond_args) = receiver.recv().await {
        let Ok(response_ser) = serde_json::to_string(&respond_args) else {
            tracing::error!(target: "mpc", "Failed to serialize response args");
            continue;
        };

        let Ok(Ok(status)) = client
            .send(
                near_client::Status {
                    is_health_check: false,
                    detailed: false,
                }
                .with_span_context(),
            )
            .await
        else {
            continue;
        };
        let block_hash = status.sync_info.latest_block_hash;
        tracing::info!(target = "mpc", "tx args {:?}", response_ser);

        let action = FunctionCallAction {
            method_name: "respond".to_owned(),
            args: response_ser.into(),
            gas: 300000000000000,
            deposit: 0,
        };
        let transaction = Transaction::V0(TransactionV0 {
            signer_id: key_file.account_id.clone(),
            public_key: key_file.public_key.clone(),
            nonce: 10,
            receiver_id: mpc_contract_id.clone(),
            block_hash,
            actions: vec![action.into()],
        });

        let tx_hash = transaction.get_hash_and_size().0;
        tracing::info!(target = "mpc", "sending response tx {:?}", tx_hash);

        let signature = key_file.secret_key.sign(tx_hash.as_ref());

        metrics::MPC_NUM_SIGN_RESPONSES_SENT.inc();
        let _ = client
            .send(
                near_client::ProcessTxRequest {
                    transaction: SignedTransaction::new(signature, transaction.clone()),
                    is_forwarded: false,
                    check_only: false,
                }
                .with_span_context(),
            )
            .await;
    }
}
