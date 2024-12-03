use crate::metrics;
use crate::sign_request::SignatureRequest;
use cait_sith::FullSignature;
use k256::{AffinePoint, Scalar, Secp256k1};
use near_client;
use near_crypto::KeyFile;
use near_indexer_primitives::near_primitives::transaction::{
    FunctionCallAction, SignedTransaction, Transaction, TransactionV1,
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

#[derive(Serialize)]
struct RespondArgsRequest {
    epsilon: Scalar,
    payload_hash: Scalar,
}

#[derive(Serialize)]
struct RespondArgsResponse {
    big_r: AffinePoint,
    s: Scalar,
    recovery_id: u8,
}

#[derive(Serialize)]
pub struct RespondArgs {
    request: RespondArgsRequest,
    response: RespondArgsResponse,
}

impl RespondArgs {
    pub fn new(request: &SignatureRequest, signature: &FullSignature<Secp256k1>) -> Self {
        RespondArgs {
            request: RespondArgsRequest {
                epsilon: request.tweak,
                payload_hash: request.msg_hash,
            },
            response: RespondArgsResponse {
                big_r: signature.big_r,
                s: signature.s,
                // TODO: figure out what this is
                recovery_id: 0,
            },
        }
    }
}

pub(crate) async fn chain_sender(
    key_file: KeyFile,
    mpc_contract_id: AccountId,
    mut receiver: mpsc::Receiver<RespondArgs>,
    client: actix::Addr<near_client::ClientActor>,
) {
    while let Some(response_args) = receiver.recv().await {
        metrics::MPC_NUM_SIGN_RESPONSES_SENT.inc();
        let Ok(response_ser) = serde_json::to_string(&response_args) else {
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

        let action = FunctionCallAction {
            method_name: "respond".to_owned(),
            args: response_ser.into(),
            gas: 300000000000000,
            deposit: 0,
        };
        let transaction = Transaction::V1(TransactionV1 {
            signer_id: key_file.account_id.clone(),
            public_key: key_file.public_key.clone(),
            nonce: 0,
            receiver_id: mpc_contract_id.clone(),
            block_hash,
            actions: vec![action.into()],
            priority_fee: 0,
        });
        let signature = key_file
            .secret_key
            .sign(transaction.get_hash_and_size().0.as_ref());

        let _ = client
            .send(
                near_client::ProcessTxRequest {
                    transaction: SignedTransaction::new(signature, transaction),
                    is_forwarded: false,
                    check_only: false,
                }
                .with_span_context(),
            )
            .await;
    }
}
