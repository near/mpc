use near_sdk::AccountId;
use tokio_util::sync::CancellationToken;

use crate::{indexer::lib::get_account_balance, metrics};

// function for monitoring signer and responder account balances
pub(crate) async fn monitor_balance(
    signer_account: AccountId,
    responder_account: AccountId,
    view_client: actix::Addr<near_client::ViewClientActor>,
    cancellation_token: CancellationToken,
) {
    tracing::info!("starting balance checker",);
    const BALANCE_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

    while !cancellation_token.is_cancelled() {
        match get_account_balance(signer_account.clone(), &view_client).await {
            Ok(balance) => {
                tracing::info!(
                    "block {}, near signer account balance: {}",
                    balance.0,
                    balance.1
                );
                metrics::NEAR_SIGNER_BALANCE.set(balance.1);
            }
            Err(e) => {
                tracing::info!("Failed to get balance for {}. Waiting for sync?", e);
            }
        }
        match get_account_balance(responder_account.clone(), &view_client).await {
            Ok(balance) => {
                tracing::info!(
                    "block {}, near responder account balance: {}",
                    balance.0,
                    balance.1
                );
                metrics::NEAR_RESPONDER_BALANCE.set(balance.1);
            }

            Err(e) => {
                tracing::info!("Failed to get balance for {}. Waiting for sync?", e);
            }
        }
        tokio::time::sleep(BALANCE_REFRESH_INTERVAL).await;
    }
}
