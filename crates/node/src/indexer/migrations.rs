use ed25519_dalek::VerifyingKey;
use near_account_id::AccountId;
use near_contract_transport::ObservedState;
pub use near_mpc_contract_interface::types::MigrationInfo as ContractMigrationInfo;

use crate::migration_service::types::MigrationInfo;

/// Derives this node's [`MigrationInfo`] from an observed contract migration state.
pub(crate) fn my_migration_info(
    my_near_account_id: &AccountId,
    my_p2p_public_key: &VerifyingKey,
    observed: ObservedState<ContractMigrationInfo>,
) -> MigrationInfo {
    MigrationInfo::from_contract_state(my_near_account_id, my_p2p_public_key, &observed.value)
}
