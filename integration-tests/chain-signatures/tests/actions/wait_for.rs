use std::time::Duration;

use crate::actions;
use crate::MultichainTestContext;

use anyhow::Context;
use backon::Retryable;
use backon::{ConstantBuilder, ExponentialBuilder};
use cait_sith::FullSignature;
use crypto_shared::SignatureResponse;
use k256::Secp256k1;
use mpc_contract::ProtocolContractState;
use mpc_contract::RunningContractState;
use mpc_recovery_node::web::StateView;
use near_jsonrpc_client::methods::tx::RpcTransactionStatusRequest;
use near_jsonrpc_client::methods::tx::TransactionInfo;
use near_lake_primitives::CryptoHash;
use near_primitives::errors::ActionErrorKind;
use near_primitives::views::FinalExecutionStatus;
use near_workspaces::Account;

pub async fn running_mpc<'a>(
    ctx: &MultichainTestContext<'a>,
    epoch: Option<u64>,
) -> anyhow::Result<RunningContractState> {
    let is_running = || async {
        let state: ProtocolContractState = ctx
            .rpc_client
            .view(ctx.nodes.ctx().mpc_contract.id(), "state")
            .await
            .map_err(|err| anyhow::anyhow!("could not view state {err:?}"))?
            .json()?;

        match state {
            ProtocolContractState::Running(running) => match epoch {
                None => Ok(running),
                Some(expected_epoch) if running.epoch >= expected_epoch => Ok(running),
                Some(_) => {
                    anyhow::bail!("running with an older epoch: {}", running.epoch)
                }
            },
            _ => anyhow::bail!("not running"),
        }
    };
    let err_msg = format!(
        "mpc did not reach {} in time",
        if epoch.is_some() {
            "expected epoch"
        } else {
            "running state"
        }
    );
    is_running
        .retry(&ExponentialBuilder::default().with_max_times(6))
        .await
        .with_context(|| err_msg)
}

pub async fn has_at_least_triples<'a>(
    ctx: &MultichainTestContext<'a>,
    expected_triple_count: usize,
) -> anyhow::Result<Vec<StateView>> {
    let is_enough_triples = |id| {
        move || async move {
            let state_view: StateView = ctx
                .http_client
                .get(format!("{}/state", ctx.nodes.url(id)))
                .send()
                .await?
                .json()
                .await?;

            match state_view {
                StateView::Running { triple_count, .. }
                    if triple_count >= expected_triple_count =>
                {
                    Ok(state_view)
                }
                StateView::Running { .. } => anyhow::bail!("node does not have enough triples yet"),
                StateView::NotRunning => anyhow::bail!("node is not running"),
            }
        }
    };

    let mut state_views = Vec::new();
    for id in 0..ctx.nodes.len() {
        let state_view = is_enough_triples(id)
            .retry(&ExponentialBuilder::default().with_max_times(6))
            .await
            .with_context(|| format!("mpc node '{id}' failed to generate '{expected_triple_count}' triples before deadline"))?;
        state_views.push(state_view);
    }
    Ok(state_views)
}

pub async fn has_at_least_mine_triples<'a>(
    ctx: &MultichainTestContext<'a>,
    expected_mine_triple_count: usize,
) -> anyhow::Result<Vec<StateView>> {
    let is_enough_mine_triples = |id| {
        move || async move {
            let state_view: StateView = ctx
                .http_client
                .get(format!("{}/state", ctx.nodes.url(id)))
                .send()
                .await?
                .json()
                .await?;

            match state_view {
                StateView::Running {
                    triple_mine_count, ..
                } if triple_mine_count >= expected_mine_triple_count => Ok(state_view),
                StateView::Running { .. } => {
                    anyhow::bail!("node does not have enough mine triples yet")
                }
                StateView::NotRunning => anyhow::bail!("node is not running"),
            }
        }
    };

    let mut state_views = Vec::new();
    for id in 0..ctx.nodes.len() {
        let state_view = is_enough_mine_triples(id)
            .retry(&ExponentialBuilder::default().with_max_times(15))
            .await
            .with_context(|| format!("mpc node '{id}' failed to generate '{expected_mine_triple_count}' triples before deadline"))?;
        state_views.push(state_view);
    }
    Ok(state_views)
}

pub async fn has_at_least_presignatures<'a>(
    ctx: &MultichainTestContext<'a>,
    expected_presignature_count: usize,
) -> anyhow::Result<Vec<StateView>> {
    let is_enough_presignatures = |id| {
        move || async move {
            let state_view: StateView = ctx
                .http_client
                .get(format!("{}/state", ctx.nodes.url(id)))
                .send()
                .await?
                .json()
                .await?;

            match state_view {
                StateView::Running {
                    presignature_count, ..
                } if presignature_count >= expected_presignature_count => Ok(state_view),
                StateView::Running { .. } => {
                    anyhow::bail!("node does not have enough presignatures yet")
                }
                StateView::NotRunning => anyhow::bail!("node is not running"),
            }
        }
    };

    let mut state_views = Vec::new();
    for id in 0..ctx.nodes.len() {
        let state_view = is_enough_presignatures(id)
            .retry(&ExponentialBuilder::default().with_max_times(6))
            .await
            .with_context(|| format!("mpc node '{id}' failed to generate '{expected_presignature_count}' presignatures before deadline"))?;
        state_views.push(state_view);
    }
    Ok(state_views)
}

pub async fn has_at_least_mine_presignatures<'a>(
    ctx: &MultichainTestContext<'a>,
    expected_mine_presignature_count: usize,
) -> anyhow::Result<Vec<StateView>> {
    let is_enough_mine_presignatures = |id| {
        move || async move {
            let state_view: StateView = ctx
                .http_client
                .get(format!("{}/state", ctx.nodes.url(id)))
                .send()
                .await?
                .json()
                .await?;

            match state_view {
                StateView::Running {
                    presignature_mine_count,
                    ..
                } if presignature_mine_count >= expected_mine_presignature_count => Ok(state_view),
                StateView::Running { .. } => {
                    anyhow::bail!("node does not have enough mine presignatures yet")
                }
                StateView::NotRunning => anyhow::bail!("node is not running"),
            }
        }
    };

    let mut state_views = Vec::new();
    for id in 0..ctx.nodes.len() {
        let state_view = is_enough_mine_presignatures(id)
            .retry(&ExponentialBuilder::default().with_max_times(6))
            .await
            .with_context(|| format!("mpc node '{id}' failed to generate '{expected_mine_presignature_count}' presignatures before deadline"))?;
        state_views.push(state_view);
    }
    Ok(state_views)
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("tx final outcome not yet available")]
    NotYetAvailable,
    #[error("tx was unsuccessful: {0}")]
    Failed(String),
}

#[derive(Debug, thiserror::Error)]
pub enum WaitForError {
    #[error("Json RPC request error: {0}")]
    JsonRpc(String),
    #[error("signature tx error: {0}")]
    Signature(SignatureError),
    #[error("Serde json error: {0}")]
    SerdeJson(String),
    #[error("Parsing error")]
    Parsing,
    #[error("Near fetch: {0}")]
    Fetch(String),
}

/// Used locally for testing to circumvent retrying on all errors. This will avoid retrying
/// on failed signatures as we should abort early on those when in the retrying loop.
enum Outcome {
    Signature(FullSignature<Secp256k1>),
    Failed(String),
}

pub async fn signature_responded(
    ctx: &MultichainTestContext<'_>,
    tx_hash: CryptoHash,
) -> Result<FullSignature<Secp256k1>, WaitForError> {
    let is_tx_ready = || async {
        let outcome_view = match ctx
            .jsonrpc_client
            .call(RpcTransactionStatusRequest {
                transaction_info: TransactionInfo::TransactionId {
                    tx_hash,
                    sender_account_id: ctx.nodes.ctx().mpc_contract.id().clone(),
                },
                wait_until: near_primitives::views::TxExecutionStatus::Final,
            })
            .await
        {
            Err(error) => return Err(WaitForError::JsonRpc(format!("{error:?}"))),
            Ok(outcome_view) => outcome_view,
        };

        let Some(outcome) = outcome_view.final_execution_outcome else {
            return Err(WaitForError::Signature(SignatureError::NotYetAvailable));
        };

        let outcome = outcome.into_outcome();

        let FinalExecutionStatus::SuccessValue(payload) = outcome.status else {
            return Ok(Outcome::Failed(format!("{:?}", outcome.status)));
        };

        let result: SignatureResponse = match serde_json::from_slice(&payload) {
            Err(error) => return Err(WaitForError::SerdeJson(format!("{error:?}"))),
            Ok(response) => response,
        };
        Ok(Outcome::Signature(cait_sith::FullSignature::<Secp256k1> {
            big_r: result.big_r.affine_point,
            s: result.s.scalar,
        }))
    };

    let strategy = ConstantBuilder::default()
        .with_delay(Duration::from_secs(20))
        .with_max_times(5);

    match is_tx_ready.retry(&strategy).await? {
        Outcome::Signature(signature) => Ok(signature),
        Outcome::Failed(err) => Err(WaitForError::Signature(SignatureError::Failed(err))),
    }
}

pub async fn signature_payload_responded(
    ctx: &MultichainTestContext<'_>,
    account: Account,
    payload: [u8; 32],
    payload_hashed: [u8; 32],
) -> Result<FullSignature<Secp256k1>, WaitForError> {
    let is_signature_ready = || async {
        let (_, _, _, tx_hash) =
            actions::request_sign_non_random(ctx, account.clone(), payload, payload_hashed).await?;
        let result = signature_responded(ctx, tx_hash).await;
        if let Err(err) = &result {
            println!("failed to produce signature: {err:?}");
        }
        result
    };

    let strategy = ConstantBuilder::default().with_max_times(3);
    is_signature_ready.retry(&strategy).await
}

// Check that the rogue message failed
pub async fn rogue_message_responded(
    ctx: &MultichainTestContext<'_>,
    tx_hash: CryptoHash,
) -> anyhow::Result<String> {
    let is_tx_ready = || async {
        let outcome_view = ctx
            .jsonrpc_client
            .call(RpcTransactionStatusRequest {
                transaction_info: TransactionInfo::TransactionId {
                    tx_hash,
                    sender_account_id: ctx.nodes.ctx().mpc_contract.id().clone(),
                },
                wait_until: near_primitives::views::TxExecutionStatus::Final,
            })
            .await?;

        let Some(outcome) = outcome_view.final_execution_outcome else {
            anyhow::bail!("final execution outcome not available");
        };
        let outcome = outcome.into_outcome();

        let FinalExecutionStatus::Failure(ref failure) = outcome.status else {
            anyhow::bail!("tx finished successfully: {:?}", outcome.status);
        };

        use near_primitives::errors::TxExecutionError;
        let TxExecutionError::ActionError(action_err) = failure else {
            anyhow::bail!("invalid transaction: {:?}", outcome.status);
        };

        let ActionErrorKind::FunctionCallError(ref err) = action_err.kind else {
            anyhow::bail!("Not a function call error {:?}", outcome.status);
        };
        use near_primitives::errors::FunctionCallError;
        let FunctionCallError::ExecutionError(err_msg) = err else {
            anyhow::bail!("Wrong error type: {:?}", err);
        };
        Ok(err_msg.clone())
    };

    let signature = is_tx_ready
        .retry(&ExponentialBuilder::default().with_max_times(6))
        .await
        .with_context(|| "failed to wait for rogue message response")?;

    Ok(signature.clone())
}
