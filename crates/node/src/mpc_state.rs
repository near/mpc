//! The node's view of the MPC contract: the state and lists it acts on, each kept current from a
//! contract view subscription.

mod monitor;
mod subscriptions;

pub use monitor::Monitor;
pub use subscriptions::{ChainSubscriptions, ChainSubscriptionsSlot};

use std::collections::BTreeMap;
use std::fmt::Debug;

use ed25519_dalek::VerifyingKey;
use mpc_primitives::hash::LauncherDockerComposeHash;
use near_account_id::AccountId;
use near_contract_transport::TransportError;
use near_mpc_contract_interface::types::{
    AllowedMpcDockerImageHash, ChainEntry, ForeignChain, GetAttestationResponse,
};

use crate::indexer::foreign_chain::{ForeignChainSupporters, supporters_by_available_chain};
use crate::indexer::migrations::my_migration_info;
use crate::indexer::participants::{ContractState, contract_state_from_observed};
use crate::migration_service::types::MigrationInfo;
use crate::tee::attestation_freshness_metrics::record_stored_attestation;
use monitor::Zip;

/// The contract-derived state the node runs against.
pub struct MpcState {
    pub contract_state: Monitor<ContractState>,
    pub allowed_docker_images: Monitor<Vec<AllowedMpcDockerImageHash>>,
    pub allowed_launcher_compose_hashes: Monitor<Vec<LauncherDockerComposeHash>>,
    pub allowed_foreign_chain_providers: Monitor<BTreeMap<ForeignChain, ChainEntry>>,
    pub migration_info: Monitor<MigrationInfo>,
    pub foreign_chain_supporters: Monitor<ForeignChainSupporters>,
    pub my_attestation: Monitor<Option<GetAttestationResponse>>,
}

impl MpcState {
    /// Returns once the contract state, the migration info and the foreign-chain supporters have
    /// been read once. The allowed lists and the stored attestation start empty and fill in as
    /// their views succeed, so a contract without one of those views does not hold up startup.
    pub async fn watch<E>(
        subscriptions: ChainSubscriptions<E>,
        port_override: Option<u16>,
        my_near_account_id: AccountId,
        my_p2p_public_key: VerifyingKey,
    ) -> Result<Self, TransportError<E>>
    where
        E: Clone + Debug + Send + Sync + 'static,
    {
        let ChainSubscriptions {
            protocol_state,
            allowed_docker_images,
            allowed_launcher_compose_hashes,
            allowed_foreign_chain_providers,
            migration_info,
            available_foreign_chains,
            foreign_chains_configs,
            my_attestation,
        } = subscriptions;
        Ok(Self {
            contract_state: Monitor::after_first_read(
                "contract state",
                protocol_state,
                move |observed| contract_state_from_observed(observed, port_override),
            )
            .await?,
            allowed_docker_images: Monitor::seeded(
                "allowed docker images",
                vec![],
                allowed_docker_images,
                |observed| Some(observed.value),
            ),
            allowed_launcher_compose_hashes: Monitor::seeded(
                "allowed launcher compose hashes",
                vec![],
                allowed_launcher_compose_hashes,
                |observed| Some(observed.value),
            ),
            allowed_foreign_chain_providers: Monitor::seeded(
                "allowed foreign chain providers",
                BTreeMap::new(),
                allowed_foreign_chain_providers,
                |observed| Some(observed.value),
            ),
            migration_info: Monitor::after_first_read(
                "migration info",
                migration_info,
                move |observed| {
                    Some(my_migration_info(
                        &my_near_account_id,
                        &my_p2p_public_key,
                        observed,
                    ))
                },
            )
            .await?,
            foreign_chain_supporters: Monitor::after_first_read(
                "foreign chain supporters",
                Zip(available_foreign_chains, foreign_chains_configs),
                |observed| {
                    let (available_chains, configs) = observed.value;
                    Some(supporters_by_available_chain(&available_chains, &configs))
                },
            )
            .await?,
            my_attestation: Monitor::seeded("my attestation", None, my_attestation, |observed| {
                record_stored_attestation(observed.value.as_ref());
                Some(observed.value)
            }),
        })
    }
}
