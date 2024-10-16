use std::task::Poll;
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
use mpc_node::web::StateView;
use near_fetch::ops::AsyncTransactionStatus;
use near_primitives::errors::ActionErrorKind;
use near_primitives::views::FinalExecutionStatus;
use near_workspaces::Account;
use url::Url;

pub async fn running_mpc<'a>(
    ctx: &MultichainTestContext<'a>,
    epoch: Option<u64>,
) -> anyhow::Result<RunningContractState> {
    let is_running = || async {
        let state: ProtocolContractState = ctx
            .rpc_client
            .view(ctx.contract().id(), "state")
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
                .get(
                    Url::parse(ctx.nodes.url(id))
                        .unwrap()
                        .join("/state")
                        .unwrap(),
                )
                .send()
                .await?
                .json()
                .await?;

            tracing::debug!(
                "has_at_least_triples state_view from {}: {:?}",
                id,
                state_view
            );

            match state_view {
                StateView::Running { triple_count, .. }
                    if triple_count >= expected_triple_count =>
                {
                    Ok(state_view)
                }
                StateView::Running { .. } => anyhow::bail!("node does not have enough triples yet"),
                state => anyhow::bail!("node is not running {state:?}"),
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
                .get(
                    Url::parse(ctx.nodes.url(id))
                        .unwrap()
                        .join("/state")
                        .unwrap(),
                )
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
                state => anyhow::bail!("node is not running {state:?}"),
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
                .get(
                    Url::parse(ctx.nodes.url(id))
                        .unwrap()
                        .join("/state")
                        .unwrap(),
                )
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
                state => anyhow::bail!("node is not running {state:?}"),
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
                .get(
                    Url::parse(ctx.nodes.url(id))
                        .unwrap()
                        .join("/state")
                        .unwrap(),
                )
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
                state => anyhow::bail!("node is not running {state:?}"),
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
}

/// Used locally for testing to circumvent retrying on all errors. This will avoid retrying
/// on failed signatures as we should abort early on those when in the retrying loop.
enum Outcome {
    Signature(FullSignature<Secp256k1>),
    Failed(String),
}

pub async fn signature_responded(
    status: AsyncTransactionStatus,
) -> Result<FullSignature<Secp256k1>, WaitForError> {
    let is_tx_ready = || async {
        let Poll::Ready(outcome) = status
            .status()
            .await
            .map_err(|err| WaitForError::JsonRpc(format!("{err:?}")))?
        else {
            return Err(WaitForError::Signature(SignatureError::NotYetAvailable));
        };

        if outcome.is_failure() {
            return Ok(Outcome::Failed(format!("{:?}", outcome.status())));
        }

        let result: SignatureResponse = outcome
            .json()
            .map_err(|err| WaitForError::SerdeJson(format!("{err:?}")))?;
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
        let (_, _, _, status) =
            actions::request_sign_non_random(ctx, account.clone(), payload, payload_hashed).await?;
        let result = signature_responded(status).await;
        if let Err(err) = &result {
            println!("failed to produce signature: {err:?}");
        }
        result
    };

    let strategy = ConstantBuilder::default().with_max_times(3);
    is_signature_ready.retry(&strategy).await
}

// Check that the rogue message failed
pub async fn rogue_message_responded(status: AsyncTransactionStatus) -> anyhow::Result<String> {
    let is_tx_ready = || async {
        let Poll::Ready(outcome) = status
            .status()
            .await
            .map_err(|err| WaitForError::JsonRpc(format!("{err:?}")))?
        else {
            return Err(WaitForError::Signature(SignatureError::NotYetAvailable));
        };

        let FinalExecutionStatus::Failure(failure) = outcome.status() else {
            return Err(WaitForError::JsonRpc(format!(
                "rogue: unexpected success {:?}",
                outcome.status()
            )));
        };

        use near_primitives::errors::TxExecutionError;
        let TxExecutionError::ActionError(action_err) = failure else {
            return Err(WaitForError::JsonRpc(format!(
                "rogue: invalid transaction {:?}",
                outcome.status(),
            )));
        };

        let ActionErrorKind::FunctionCallError(ref err) = action_err.kind else {
            return Err(WaitForError::JsonRpc(format!(
                "rogue: not a function call error {:?}",
                outcome.status(),
            )));
        };
        use near_primitives::errors::FunctionCallError;
        let FunctionCallError::ExecutionError(err_msg) = err else {
            return Err(WaitForError::JsonRpc(format!(
                "rogue: wrong execution error {:?}",
                outcome.status(),
            )));
        };
        Ok(err_msg.clone())
    };

    let strategy = ConstantBuilder::default()
        .with_delay(Duration::from_secs(20))
        .with_max_times(5);

    let signature = is_tx_ready
        .retry(&strategy)
        .await
        .with_context(|| "failed to wait for rogue message response")?;

    Ok(signature.clone())
}
