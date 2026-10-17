//! The node's view of the MPC contract: the state and lists it acts on, each kept current from a
//! contract view subscription.

use std::cmp::max;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::ops::{Deref, DerefMut};

use ed25519_dalek::VerifyingKey;
use mpc_primitives::hash::LauncherDockerComposeHash;
use near_account_id::AccountId;
use near_contract_transport::{
    HasPollInterval, ObservedState, Subscription, TransportError, ViewContract, WatchContractState,
};
use near_mpc_contract_interface::client::MpcContractHandle;
use near_mpc_contract_interface::types::{
    AllowedMpcDockerImageHash, AvailableForeignChains, ChainEntry, Ed25519PublicKey, ForeignChain,
    ForeignChainsConfigs, GetAttestationResponse, ProtocolContractState,
};
use tokio::sync::watch;

use crate::indexer::foreign_chain::{ForeignChainSupporters, supporters_by_available_chain};
use crate::indexer::migrations::{ContractMigrationInfo, my_migration_info};
use crate::indexer::participants::{ContractState, contract_state_from_observed};
use crate::migration_service::types::MigrationInfo;
use crate::tee::attestation_freshness_metrics::record_stored_attestation;
use crate::tracking::AutoAbortTask;

/// The contract views the node follows, one subscription each. Clones share the poller, so a
/// clone feeds a second consumer without a second stream of view calls.
#[derive(Clone)]
pub struct ChainSubscriptions<E> {
    pub protocol_state: Subscription<ProtocolContractState, E>,
    pub allowed_docker_images: Subscription<Vec<AllowedMpcDockerImageHash>, E>,
    pub allowed_launcher_compose_hashes: Subscription<Vec<LauncherDockerComposeHash>, E>,
    pub allowed_foreign_chain_providers: Subscription<BTreeMap<ForeignChain, ChainEntry>, E>,
    pub migration_info: Subscription<ContractMigrationInfo, E>,
    pub available_foreign_chains: Subscription<AvailableForeignChains, E>,
    pub foreign_chains_configs: Subscription<ForeignChainsConfigs, E>,
    pub my_attestation: Subscription<Option<GetAttestationResponse>, E>,
}

impl<E> ChainSubscriptions<E> {
    pub async fn subscribe<V>(
        contract: &MpcContractHandle<V>,
        my_tls_public_key: Ed25519PublicKey,
    ) -> Self
    where
        V: ViewContract<Error = E> + HasPollInterval + Clone + Send + Sync + 'static,
    {
        Self {
            protocol_state: contract.state().subscribe().await,
            allowed_docker_images: contract.allowed_docker_image_hashes().subscribe().await,
            allowed_launcher_compose_hashes: contract
                .allowed_launcher_compose_hashes()
                .subscribe()
                .await,
            allowed_foreign_chain_providers: contract
                .allowed_foreign_chain_providers()
                .subscribe()
                .await,
            migration_info: contract.migration_info().subscribe().await,
            available_foreign_chains: contract.get_available_foreign_chains().subscribe().await,
            foreign_chains_configs: contract.get_foreign_chains_configs().subscribe().await,
            my_attestation: contract
                .get_attestation(&my_tls_public_key)
                .subscribe()
                .await,
        }
    }
}

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

/// A contract view kept current in a watch channel by a task the monitor owns; dropping the
/// monitor stops the task. Derefs to the receiver.
pub struct Monitor<U> {
    receiver: watch::Receiver<U>,
    /// `None` when another owner feeds the channel, as the fake indexer does.
    _task: Option<AutoAbortTask<()>>,
}

impl<U> Monitor<U>
where
    U: Clone + Debug + PartialEq + Send + Sync + 'static,
{
    /// Starts at `seed` and returns at once; the first successful read replaces it, and a source
    /// that keeps failing leaves it in place.
    pub fn seeded<S, F>(name: &'static str, seed: U, source: S, map: F) -> Self
    where
        S: WatchContractState + Send + 'static,
        S::ViewError: Debug,
        F: Fn(ObservedState<S::Value>) -> Option<U> + Send + 'static,
    {
        let (sender, receiver) = watch::channel(seed);
        let task = tokio::spawn(forward(name, source, sender, map));
        Self {
            receiver,
            _task: Some(task.into()),
        }
    }

    /// Returns once the source succeeded once, so the receiver never holds a placeholder. Fails
    /// only if the source closes first.
    pub async fn after_first_read<S, F>(
        name: &'static str,
        mut source: S,
        map: F,
    ) -> Result<Self, TransportError<S::ViewError>>
    where
        S: WatchContractState + Send + 'static,
        S::ViewError: Debug,
        F: Fn(ObservedState<S::Value>) -> Option<U> + Send + 'static,
    {
        let first = loop {
            match source.latest() {
                Ok(observed) => {
                    if let Some(value) = map(observed) {
                        break value;
                    }
                }
                Err(err) => tracing::error!(target: "mpc", name, ?err, "contract view failed"),
            }
            source.changed().await?;
        };
        Ok(Self::seeded(name, first, source, map))
    }

    #[cfg(test)]
    pub(crate) fn from_receiver(receiver: watch::Receiver<U>) -> Self {
        Self {
            receiver,
            _task: None,
        }
    }
}

impl<U> Deref for Monitor<U> {
    type Target = watch::Receiver<U>;

    fn deref(&self) -> &Self::Target {
        &self.receiver
    }
}

impl<U> DerefMut for Monitor<U> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.receiver
    }
}

async fn forward<S, U, F>(name: &'static str, mut source: S, sender: watch::Sender<U>, map: F)
where
    S: WatchContractState,
    S::ViewError: Debug,
    U: Debug + PartialEq,
    F: Fn(ObservedState<S::Value>) -> Option<U>,
{
    loop {
        match source.latest() {
            Ok(observed) => {
                if let Some(value) = map(observed) {
                    sender.send_if_modified(|current| {
                        if *current == value {
                            return false;
                        }
                        tracing::info!(target: "mpc", "{name} changed: {value:?}");
                        *current = value;
                        true
                    });
                }
            }
            Err(err) => tracing::error!(target: "mpc", name, ?err, "contract view failed"),
        }
        if let Err(err) = source.changed().await {
            tracing::error!(target: "mpc", name, ?err, "contract view subscription closed");
            return;
        }
    }
}

/// Two sources read as one: a change on either side is a change, and the latest value is the
/// pair, stamped with the later of the two heights. The sides poll independently, so the pair
/// can be transiently inconsistent; the next change corrects it.
struct Zip<A, B>(A, B);

impl<A, B> WatchContractState for Zip<A, B>
where
    A: WatchContractState + Send,
    B: WatchContractState<ViewError = A::ViewError> + Send,
{
    type Value = (A::Value, B::Value);
    type ViewError = A::ViewError;

    fn latest(&mut self) -> Result<ObservedState<Self::Value>, TransportError<Self::ViewError>> {
        let a = self.0.latest()?;
        let b = self.1.latest()?;
        Ok(ObservedState {
            observed_at: max(a.observed_at, b.observed_at),
            value: (a.value, b.value),
        })
    }

    async fn changed(&mut self) -> Result<(), TransportError<Self::ViewError>> {
        tokio::select! {
            changed = self.0.changed() => changed,
            changed = self.1.changed() => changed,
        }
    }
}
