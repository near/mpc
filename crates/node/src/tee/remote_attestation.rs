use crate::trait_extensions::convert_to_contract_dto::IntoContractInterfaceType;
use mpc_attestation::{
    attestation::{Attestation, VerificationError},
    report_data::{ReportData, ReportDataV1},
};
use mpc_primitives::hash::{DockerImageHash, LauncherDockerComposeHash};
use near_mpc_contract_interface::types::Ed25519PublicKey;
use tee_authority::tee_authority::TeeAuthority;

use mpc_contract::tee::tee_state::NodeId;
use near_account_id::AccountId;
use tokio::sync::watch;

pub fn validate_remote_attestation(
    attestation: &Attestation,
    tls_public_key: Ed25519PublicKey,
    account_public_key: Ed25519PublicKey,
    allowed_docker_image_hashes: &[DockerImageHash],
    allowed_launcher_compose_hashes: &[LauncherDockerComposeHash],
) -> Result<(), VerificationError> {
    let expected_report_data: ReportData =
        ReportDataV1::new(*tls_public_key.as_bytes(), *account_public_key.as_bytes()).into();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    attestation
        .verify(
            expected_report_data.into(),
            now,
            allowed_docker_image_hashes,
            allowed_launcher_compose_hashes,
            mpc_attestation::attestation::default_measurements(),
        )
        .map(|_| ())
}

/// Checks if TEE attestation is available for the given node in the TEE accounts list.
fn is_node_in_contract_tee_accounts(
    tee_accounts_receiver: &mut watch::Receiver<Vec<NodeId>>,
    node_id: &NodeId,
) -> bool {
    let tee_accounts = tee_accounts_receiver.borrow_and_update();
    tee_accounts.contains(node_id)
}

/// Monitors the contract for TEE attestation removal and triggers resubmission when needed.
///
/// This function watches TEE account changes in the contract and resubmits attestations
/// via [`TeeContext`] when the node's TEE attestation is no longer available.
pub async fn monitor_attestation_removal(
    node_account_id: AccountId,
    tee_authority: TeeAuthority,
    tee_ctx: tee_context::TeeContext,
    tls_public_key: Ed25519PublicKey,
    account_public_key: Ed25519PublicKey,
    mut tee_accounts_receiver: watch::Receiver<Vec<NodeId>>,
) -> anyhow::Result<()> {
    let node_id = NodeId {
        account_id: node_account_id.clone(),
        tls_public_key: near_sdk::PublicKey::from(tls_public_key.clone()),
        account_public_key: Some(near_sdk::PublicKey::from(account_public_key.clone())),
    };

    let initially_available =
        is_node_in_contract_tee_accounts(&mut tee_accounts_receiver, &node_id);

    tracing::info!(
        %node_account_id,
        initially_available,
        "starting TEE attestation removal monitoring; initial TEE attestation status"
    );

    let mut was_available = initially_available;
    let report_data: ReportData =
        ReportDataV1::new(*tls_public_key.as_bytes(), *account_public_key.as_bytes()).into();

    while tee_accounts_receiver.changed().await.is_ok() {
        let is_available = is_node_in_contract_tee_accounts(&mut tee_accounts_receiver, &node_id);

        tracing::debug!(
            %node_account_id,
            is_available,
            was_available,
            "TEE attestation status check"
        );

        if was_available && !is_available {
            tracing::warn!(
                %node_account_id,
                "TEE attestation removed from contract, resubmitting"
            );

            let fresh_attestation = tee_authority
                .generate_attestation(report_data.clone())
                .await?;

            // Validate locally before submitting
            let hashes = tee_ctx.watch_allowed_tee_hashes().borrow().clone();
            if let Err(e) = validate_remote_attestation(
                &fresh_attestation,
                tls_public_key.clone(),
                account_public_key.clone(),
                &hashes.allowed_docker_image_hashes,
                &hashes.allowed_launcher_compose_hashes,
            ) {
                tracing::warn!(error = ?e, "local attestation validation failed, submitting anyway");
            }

            tee_ctx
                .submit_attestation(
                    fresh_attestation.into_contract_interface_type(),
                    tls_public_key.clone(),
                )
                .await?;
        }

        was_available = is_available;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    // Tests will be updated in a follow-up
}
