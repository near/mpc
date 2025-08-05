use near_sdk::AccountId;

use crate::{
    indexer::lib::{get_account_balance, wait_for_full_sync},
    metrics,
};

async fn fetch_and_log_balance(
    label: &str,
    account: AccountId,
    view_client: &actix::Addr<near_client::ViewClientActor>,
    metric: &prometheus::Gauge,
) {
    match get_account_balance(account, view_client).await {
        Ok((block, balance)) => {
            tracing::info!(block, balance, "Near {} account balance", label);
            metric.set(balance);
        }
        Err(e) => {
            tracing::info!(
                account = %label,
                err = %e,
                "Failed to get balance. Waiting for sync?"
            );
        }
    }
}
// function for monitoring signer and responder account balances
pub(crate) async fn monitor_balance(
    signer_account: AccountId,
    responder_account: AccountId,
    client: actix::Addr<near_client::ClientActor>,
    view_client: actix::Addr<near_client::ViewClientActor>,
) {
    tracing::info!("starting balance checker",);
    wait_for_full_sync(&client).await;
    const BALANCE_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
    let mut interval = tokio::time::interval(BALANCE_REFRESH_INTERVAL);
    loop {
        interval.tick().await;
        fetch_and_log_balance(
            "signer",
            signer_account.clone(),
            &view_client,
            &metrics::NEAR_SIGNER_BALANCE,
        )
        .await;
        fetch_and_log_balance(
            "responder",
            responder_account.clone(),
            &view_client,
            &metrics::NEAR_RESPONDER_BALANCE,
        )
        .await;
    }
}
