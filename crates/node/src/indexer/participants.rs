use super::IndexerState;
use crate::config::{ParticipantInfo, ParticipantStatus, ParticipantsConfig};
use crate::primitives::ParticipantId;
use anyhow::Context;
use ed25519_dalek::VerifyingKey;
use mpc_primitives::KeyEventId as ContractKeyEventId;
use near_account_id::AccountId;
use near_mpc_contract_interface::types as dtos;
use near_mpc_contract_interface::types::{KeyEvent, ProtocolContractState, ThresholdParameters};
use near_mpc_crypto_types::{KeyForDomain as ContractKeyForDomain, Keyset as ContractKeyset};
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::sync::watch;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractKeyEventInstance {
    pub id: ContractKeyEventId,
    pub domain: dtos::DomainConfig,
    pub started: bool,
    pub completed: BTreeSet<ParticipantId>,
    pub completed_domains: Vec<ContractKeyForDomain>,
}

pub fn convert_key_event_to_instance(
    key_event: &KeyEvent,
    current_height: u64,
    completed_domains: Vec<dtos::KeyForDomain>,
) -> anyhow::Result<ContractKeyEventInstance> {
    let completed_domains: Vec<ContractKeyForDomain> = completed_domains
        .into_iter()
        .map(TryInto::try_into)
        .collect::<Result<_, _>>()?;
    Ok(match &key_event.instance {
        Some(current_instance) if current_height < current_instance.expires_on => {
            ContractKeyEventInstance {
                id: dtos::KeyEventId {
                    epoch_id: key_event.epoch_id,
                    domain_id: key_event.domain.id,
                    attempt_id: current_instance.attempt_id,
                },
                domain: key_event.domain.clone(),
                started: true,
                completed: current_instance
                    .completed
                    .iter()
                    .map(|p| (*p).into())
                    .collect(),
                completed_domains,
            }
        }
        _ => ContractKeyEventInstance {
            id: dtos::KeyEventId {
                epoch_id: key_event.epoch_id,
                domain_id: key_event.domain.id,
                attempt_id: key_event.next_attempt_id,
            },
            domain: key_event.domain.clone(),
            started: false,
            completed: BTreeSet::new(),
            completed_domains,
        },
    })
}

impl ContractKeyEventInstance {
    pub fn compare_to_expected_key_event_id(
        &self,
        expected: &ContractKeyEventId,
    ) -> KeyEventIdComparisonResult {
        let contract_state = (
            self.id.epoch_id.get(),
            *self.id.domain_id,
            self.id.attempt_id.get(),
        );
        let expected_state = (
            expected.epoch_id.get(),
            *expected.domain_id,
            expected.attempt_id.get(),
        );
        if contract_state < expected_state {
            KeyEventIdComparisonResult::RemoteBehind
        } else if contract_state > expected_state {
            KeyEventIdComparisonResult::RemoteAhead
        } else if self.started {
            KeyEventIdComparisonResult::RemoteMatches
        } else {
            KeyEventIdComparisonResult::RemoteBehind
        }
    }
}

#[derive(Debug)]
#[expect(clippy::enum_variant_names)]
pub enum KeyEventIdComparisonResult {
    /// Contract has already moved past the expected key event ID, meaning that the computation
    /// corresponding to the expected key event ID should be aborted.
    RemoteAhead,
    /// The active key event ID in the contract matches the expected. The computation should be
    /// carried out.
    RemoteMatches,
    /// The active key event ID in the contract has not yet progressed to the expected. The
    /// computation should wait.
    RemoteBehind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractRunningState {
    pub keyset: ContractKeyset,
    pub domains: Vec<dtos::DomainConfig>,
    pub participants: ParticipantsConfig,
    pub resharing_state: Option<ContractResharingState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractInitializingState {
    pub participants: ParticipantsConfig,
    pub key_event: ContractKeyEventInstance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractResharingState {
    pub new_participants: ParticipantsConfig,
    pub reshared_keys: ContractKeyset,
    pub key_event: ContractKeyEventInstance,
}

/// A stripped-down version of the contract state, containing only the state
/// that the MPC node cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractState {
    Invalid,
    Initializing(ContractInitializingState),
    Running(ContractRunningState),
}

#[cfg(test)]
impl ContractState {
    pub fn change_participant_pk(
        &mut self,
        account_id: &AccountId,
        new_p2p_public_key: VerifyingKey,
    ) {
        match self {
            ContractState::Invalid => panic!("invalid contract state"),
            ContractState::Initializing(init) => {
                init.participants
                    .change_participant_pk(account_id, new_p2p_public_key)
                    .expect("require participant");
            }
            ContractState::Running(running) => {
                if let Some(resharing) = running.resharing_state.as_mut() {
                    resharing
                        .new_participants
                        .change_participant_pk(account_id, new_p2p_public_key)
                        .expect("require participant");
                    let _ = running
                        .participants
                        .change_participant_pk(account_id, new_p2p_public_key);
                } else {
                    running
                        .participants
                        .change_participant_pk(account_id, new_p2p_public_key)
                        .expect("require participant");
                }
            }
        }
    }
}

impl ContractState {
    pub fn from_contract_state(
        state: &ProtocolContractState,
        height: u64,
        port_override: Option<u16>,
    ) -> anyhow::Result<Self> {
        Ok(match state {
            ProtocolContractState::NotInitialized => ContractState::Invalid,
            ProtocolContractState::Initializing(state) => {
                ContractState::Initializing(ContractInitializingState {
                    participants: convert_participant_infos(
                        state.generating_key.parameters.clone(),
                        port_override,
                    )?,
                    key_event: convert_key_event_to_instance(
                        &state.generating_key,
                        height,
                        state.generated_keys.clone(),
                    )
                    .context("failed to convert initializing key event")?,
                })
            }
            ProtocolContractState::Running(running_state) => {
                ContractState::Running(ContractRunningState {
                    keyset: running_state.keyset.clone(),
                    domains: running_state.domains.domains.clone(),
                    participants: convert_participant_infos(
                        running_state.parameters.clone(),
                        port_override,
                    )?,
                    resharing_state: None,
                })
            }
            ProtocolContractState::Resharing(state) => {
                let resharing_state = Some(ContractResharingState {
                    new_participants: convert_participant_infos(
                        state.resharing_key.parameters.clone(),
                        port_override,
                    )?,
                    reshared_keys: dtos::Keyset {
                        epoch_id: state.resharing_key.epoch_id,
                        domains: state.reshared_keys.clone(),
                    },
                    key_event: convert_key_event_to_instance(
                        &state.resharing_key,
                        height,
                        state.reshared_keys.clone(),
                    )
                    .context("failed to convert resharing key event")?,
                });

                let running_state = state.previous_running_state.clone();

                ContractState::Running(ContractRunningState {
                    keyset: running_state.keyset.clone(),
                    domains: running_state.domains.domains.clone(),
                    participants: convert_participant_infos(
                        running_state.parameters.clone(),
                        port_override,
                    )?,
                    resharing_state,
                })
            }
        })
    }

    /// Returns the participation status of the given node in the current contract state.
    ///
    /// Determines whether the node is active or inactive based on its account ID and P2P public key
    /// During a resharing, any participants that are not part of the prospective epochs will be
    /// considered inactive.
    pub fn node_status(
        &self,
        account_id: &AccountId,
        p2p_public_key: &VerifyingKey,
    ) -> ParticipantStatus {
        let participant_set = match self {
            ContractState::Invalid => {
                return ParticipantStatus::Inactive;
            }
            ContractState::Initializing(initializing) => &initializing.participants,
            ContractState::Running(running) => {
                if let Some(resharing) = &running.resharing_state {
                    &resharing.new_participants
                } else {
                    &running.participants
                }
            }
        };
        participant_set.participant_status(account_id, p2p_public_key)
    }
}

/// Continuously monitors the contract state. Every time the state changes,
/// sends the new state via the provided sender. This is a long-running task.
pub async fn monitor_contract_state(
    indexer_state: Arc<IndexerState>,
    port_override: Option<u16>,
    protocol_state_sender: watch::Sender<dtos::ProtocolContractState>,
) -> watch::Receiver<ContractState> {
    const CONTRACT_STATE_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
    let mut refresh_interval_tick = tokio::time::interval(CONTRACT_STATE_REFRESH_INTERVAL);

    let mut fetch_contract_state = async move || {
        loop {
            // first tick returns immediately
            refresh_interval_tick.tick().await;

            //// We wait first to catch up to the chain to avoid reading the participants from an outdated state.
            //// We currently assume the participant set is static and do not detect or support any updates.
            tracing::debug!(target: "indexer", "awaiting full sync to read mpc contract state");
            indexer_state.client.wait_for_full_sync().await;

            tracing::debug!(target: "indexer", "querying contract state");

            let (height, protocol_state) = match indexer_state
                .view_client
                .get_mpc_contract_state_dto(indexer_state.mpc_contract_id.clone())
                .await
            {
                Ok(contract_state) => contract_state,
                Err(e) => {
                    tracing::error!(target: "mpc", "error reading config from chain during get_mpc_contract_state: {:?}", e);
                    tokio::time::sleep(CONTRACT_STATE_REFRESH_INTERVAL).await;
                    continue;
                }
            };

            let result = ContractState::from_contract_state(&protocol_state, height, port_override);

            protocol_state_sender.send(protocol_state).unwrap();

            let state = match result {
                Ok(state) => state,
                Err(e) => {
                    tracing::error!(target: "mpc", "error converting contract state obtained from chain: {:?}", e);
                    continue;
                }
            };

            break state;
        }
    };

    let initial_contract_state = fetch_contract_state().await;
    let (contract_state_sender, contract_state_receiver) = watch::channel(initial_contract_state);

    tokio::spawn(async move {
        loop {
            let contract_state = fetch_contract_state().await;
            tracing::debug!(target: "indexer", "got mpc contract state {:?}", contract_state);

            contract_state_sender.send_if_modified(|watched_state| {
                if *watched_state != contract_state {
                    tracing::info!("Contract state changed: {:?}", contract_state);
                    *watched_state = contract_state;
                    true
                } else {
                    false
                }
            });
        }
    });

    contract_state_receiver
}

pub fn convert_participant_infos(
    threshold_parameters: ThresholdParameters,
    port_override: Option<u16>,
) -> anyhow::Result<ParticipantsConfig> {
    let mut converted = Vec::new();
    for (account_id, id, info) in &threshold_parameters.participants.participants {
        let url = Url::parse(&info.url)
            .with_context(|| format!("could not parse participant url {}", info.url))?;
        let Some(address) = url.host_str() else {
            anyhow::bail!("no host found in participant url {}", info.url);
        };
        let Some(port) = port_override.or(url.port_or_known_default()) else {
            anyhow::bail!("no port found in participant url {}", info.url);
        };

        let p2p_public_key = ed25519_dalek::VerifyingKey::try_from(&info.tls_public_key)
            .with_context(|| {
                format!("Invalid tls_public_key for peer: {:?}", info.tls_public_key)
            })?;

        let near_account_id: AccountId = account_id.clone();

        converted.push(ParticipantInfo {
            id: (*id).into(),
            address: address.to_string(),
            port,
            p2p_public_key,
            near_account_id,
        });
    }
    Ok(ParticipantsConfig {
        participants: converted,
        threshold: threshold_parameters.threshold.0,
    })
}

#[cfg(test)]
pub mod test_utils {

    use crate::config::ParticipantInfo;

    use super::ContractState;

    impl ContractState {
        /// returns the participants of the current or prospective epoch
        pub fn get_current_or_prospective_participants(&self) -> Vec<ParticipantInfo> {
            match &self {
                ContractState::Invalid => vec![],
                ContractState::Initializing(initializing) => {
                    initializing.participants.participants.clone()
                }
                ContractState::Running(running) => running
                    .resharing_state
                    .clone()
                    .map(|resharing| resharing.new_participants.participants.clone())
                    .unwrap_or(running.participants.participants.clone()),
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use crate::{indexer::participants::convert_participant_infos, providers::PublicKeyConversion};
    use near_indexer_primitives::types::AccountId;
    use near_mpc_contract_interface::types::AccountId as DtoAccountId;
    use near_mpc_contract_interface::types::{
        ParticipantId, ParticipantInfo, Participants, Threshold, ThresholdParameters,
    };
    use std::collections::HashMap;

    fn create_participant_data_raw() -> Vec<(String, String, String)> {
        vec![
            (
                "multichain-node-dev-0.testnet".to_string(),
                "http://10.101.0.56:3000".to_string(),
                "ed25519:4upBpJYUrjPBzqNYaY8pvJGQtep7YMT3j9zRsopYQqfG".to_string(),
            ),
            (
                "multichain-node-dev-1.testnet".to_string(),
                "http://10.101.0.81:3000".to_string(),
                "ed25519:6sqMFXkswuH9b7Pnn6dGAy1vA1X3N2CSrKDDkdHzTcrv".to_string(),
            ),
            (
                "multichain-node-dev-2.testnet".to_string(),
                "http://10.101.0.57:3000".to_string(),
                "ed25519:Fru1RoC6dw1xY2J6C6ZSBUt5PEysxTLX2kDexxqoDN6k".to_string(),
            ),
        ]
    }

    fn create_invalid_participant_data_raw() -> Vec<(String, String, String)> {
        // It's really only possible to have bad data in the urls, which are arbitrary strings.
        vec![
            // Bad URL format (missing host)
            (
                "multichain-node-dev-5.testnet".to_string(),
                "http://:3000".to_string(),
                "ed25519:5op5eGtWrVAWmNjyaLhZMm4itc8bWottr8PGUJEzcKHd".to_string(),
            ),
            // Bad URL format (missing http prefix)
            (
                "multichain-node-dev-6.testnet".to_string(),
                "10.101.0.122:3000".to_string(),
                "ed25519:41VQ8NxWF11cjse5WjiJBtbrGDPKLQ712Kg1oGyM9w9P".to_string(),
            ),
        ]
    }

    fn create_dto_participants_from_raw(raw: Vec<(String, String, String)>) -> Participants {
        let mut entries: Vec<(DtoAccountId, ParticipantId, ParticipantInfo)> = Vec::new();

        // Sort by account_id to match contract behavior
        let mut sorted_raw = raw;
        sorted_raw.sort_by(|a, b| a.0.cmp(&b.0));

        for (i, (account_id, url, pk)) in sorted_raw.into_iter().enumerate() {
            entries.push((
                account_id.parse().unwrap(),
                ParticipantId(i as u32),
                ParticipantInfo {
                    url,
                    tls_public_key: pk.parse().unwrap(),
                },
            ));
        }
        let next_id = ParticipantId(entries.len() as u32);
        Participants {
            next_id,
            participants: entries,
        }
    }

    fn create_chain_participant_infos() -> Participants {
        create_dto_participants_from_raw(create_participant_data_raw())
    }

    fn create_invalid_chain_participant_infos() -> Participants {
        create_dto_participants_from_raw(create_invalid_participant_data_raw())
    }

    // Check that the participant ids are assigned 0 to N-1 by AccountId order
    #[test]
    fn test_participant_ids() {
        let chain_infos = create_chain_participant_infos();
        let mut account_ids: Vec<AccountId> = vec![];
        let mut account_id_to_pk =
            HashMap::<AccountId, near_mpc_contract_interface::types::Ed25519PublicKey>::default();
        for (account_id, _, info) in &chain_infos.participants {
            account_ids.push(account_id.clone());
            account_id_to_pk.insert(account_id.clone(), info.tls_public_key.clone());
        }
        assert!(account_ids.is_sorted());
        let params = ThresholdParameters {
            participants: chain_infos.clone(),
            threshold: Threshold(3),
        };

        let converted = convert_participant_infos(params, None).unwrap();
        assert_eq!(converted.threshold, 3);
        for (i, p) in converted.participants.iter().enumerate() {
            assert!(p.near_account_id == account_ids[i]);
            let expected_pk: near_sdk::PublicKey = account_id_to_pk[&account_ids[i]].clone().into();
            assert!(p.p2p_public_key.to_near_sdk_public_key().unwrap() == expected_pk);
            let expected = chain_infos
                .participants
                .iter()
                .find(|(a_id, _, _)| *a_id == account_ids[i])
                .map(|(_, p_id, _)| *p_id)
                .unwrap();
            assert!(p.id.raw() == expected.0);
        }
    }

    // Check that the port override is applied
    #[test]
    fn test_port_override() {
        let chain_infos = create_chain_participant_infos();

        let params = ThresholdParameters {
            participants: chain_infos,
            threshold: Threshold(3),
        };
        let converted = convert_participant_infos(params.clone(), None)
            .unwrap()
            .participants;
        converted.into_iter().for_each(|p| assert!(p.port == 3000));

        let with_override = convert_participant_infos(params, Some(443))
            .unwrap()
            .participants;
        with_override
            .into_iter()
            .for_each(|p| assert!(p.port == 443));
    }

    // It is fatal if any of the participants has bad data, even if the others are OK
    #[test]
    fn test_bad_participant_data() {
        let chain_infos = create_chain_participant_infos();
        for (account_id, _, bad_data) in &create_invalid_chain_participant_infos().participants {
            let mut new_entries = chain_infos.participants.clone();
            // Replace or add the bad entry
            if let Some(entry) = new_entries.iter_mut().find(|(a, _, _)| a == account_id) {
                entry.2 = bad_data.clone();
            } else {
                new_entries.push((
                    account_id.clone(),
                    ParticipantId(new_entries.len() as u32),
                    bad_data.clone(),
                ));
            }
            let new_infos = Participants {
                next_id: ParticipantId(new_entries.len() as u32),
                participants: new_entries,
            };
            let params = ThresholdParameters {
                participants: new_infos,
                threshold: Threshold(3),
            };
            print!("\n\nmy params: \n{:?}\n", params);
            let converted = convert_participant_infos(params, None);
            print!("\n\nmyconverted: \n{:?}\n", converted);
            let _ = converted.expect_err("Invalid participant data should be rejected");
        }
    }
}
