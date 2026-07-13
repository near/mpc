use std::collections::{BTreeMap, HashSet};

use anyhow::Context;
use near_mpc_contract_interface::types as dtos;
use near_mpc_crypto_types::Ed25519PublicKey;
use tokio::sync::watch;

use crate::config::ParticipantsConfig;
use crate::primitives::ParticipantId;

/// Combines the indexer's two foreign-chain channels into one channel mapping each
/// available chain to the participants supporting it (threshold-filtered). Participants
/// are fixed per Running job; resharing restarts the job with a fresh task. The spawned
/// task exits when either upstream sender is dropped (indexer shutdown) or every
/// receiver of the returned channel is dropped.
pub(crate) fn spawn_supporters_by_foreign_chain(
    mut available_chains_receiver: watch::Receiver<dtos::AvailableForeignChains>,
    mut foreign_chain_configs_receiver: watch::Receiver<dtos::ForeignChainsConfigs>,
    participants_config: ParticipantsConfig,
) -> watch::Receiver<BTreeMap<dtos::ForeignChain, HashSet<ParticipantId>>> {
    let init_value = supporters_by_foreign_chain(
        available_chains_receiver.borrow_and_update().clone(),
        foreign_chain_configs_receiver.borrow_and_update().clone(),
        &participants_config,
    );
    let (sender, receiver) = watch::channel(init_value);

    tokio::spawn(async move {
        loop {
            let new_value = tokio::select! {
                res = await_and_update_supporters(
                    &mut available_chains_receiver,
                    &mut foreign_chain_configs_receiver,
                    &participants_config,
                ) => match res {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::info!("stopping foreign-chains monitor: {e:#}");
                        break;
                    }
                },
                _ = sender.closed() => {
                    tracing::debug!("all receivers dropped, stopping foreign-chains monitor");
                    break;
                }
            };
            sender.send_if_modified(|existing| {
                if *existing != new_value {
                    *existing = new_value;
                    true
                } else {
                    false
                }
            });
        }
    });
    receiver
}

async fn await_and_update_supporters(
    available_chains_receiver: &mut watch::Receiver<dtos::AvailableForeignChains>,
    foreign_chain_configs_receiver: &mut watch::Receiver<dtos::ForeignChainsConfigs>,
    participants_config: &ParticipantsConfig,
) -> anyhow::Result<BTreeMap<dtos::ForeignChain, HashSet<ParticipantId>>> {
    tokio::select! {
        res = foreign_chain_configs_receiver.changed() => {
            res.context("foreign_chain_configs sender dropped")?;
        }
        res = available_chains_receiver.changed() => {
            res.context("available_chains sender dropped")?;
        }
    }

    let available_chains = available_chains_receiver.borrow_and_update().clone();
    let configs = foreign_chain_configs_receiver.borrow_and_update().clone();
    Ok(supporters_by_foreign_chain(
        available_chains,
        configs,
        participants_config,
    ))
}

fn supporters_by_foreign_chain(
    available_chains: dtos::AvailableForeignChains,
    configs: dtos::ForeignChainsConfigs,
    participants_config: &ParticipantsConfig,
) -> BTreeMap<dtos::ForeignChain, HashSet<ParticipantId>> {
    resolve_supporters_by_foreign_chain(
        &supporters_by_available_chain(available_chains, configs),
        participants_config,
    )
}

fn supporters_by_available_chain(
    available_chains: dtos::AvailableForeignChains,
    configs: dtos::ForeignChainsConfigs,
) -> BTreeMap<dtos::ForeignChain, HashSet<dtos::Ed25519PublicKey>> {
    let mut res: BTreeMap<dtos::ForeignChain, HashSet<dtos::Ed25519PublicKey>> = BTreeMap::new();
    for (pk, config) in configs.into_iter() {
        for chain in config.into_iter() {
            if available_chains.contains(&chain) {
                res.entry(chain).or_default().insert(pk.clone());
            }
        }
    }
    res
}

/// Chains with fewer than `participants_config.threshold` resolved supporters are omitted.
fn resolve_supporters_by_foreign_chain(
    supporters_by_pk: &BTreeMap<dtos::ForeignChain, HashSet<dtos::Ed25519PublicKey>>,
    participants_config: &ParticipantsConfig,
) -> BTreeMap<dtos::ForeignChain, HashSet<ParticipantId>> {
    supporters_by_pk
        .iter()
        .filter_map(|(chain, pks)| {
            let ids = resolve_participant_ids(pks, participants_config);
            (ids.len() as u64 >= participants_config.threshold).then_some((*chain, ids))
        })
        .collect()
}

/// Resolves TLS keys to the matching participants' ids; keys not belonging to a
/// participant are dropped.
fn resolve_participant_ids(
    tls_keys: &HashSet<dtos::Ed25519PublicKey>,
    participants_config: &ParticipantsConfig,
) -> HashSet<ParticipantId> {
    participants_config
        .participants
        .iter()
        .filter(|info| tls_keys.contains(&Ed25519PublicKey::from(&info.p2p_public_key)))
        .map(|info| info.id)
        .collect()
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::config::{ParticipantInfo, ParticipantsConfig};
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeSet;
    use std::time::Duration;

    fn make_signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn make_participant_info(id: u32, key: &SigningKey) -> ParticipantInfo {
        ParticipantInfo {
            id: ParticipantId::from_raw(id),
            address: "127.0.0.1".to_string(),
            port: 3000,
            p2p_public_key: key.verifying_key(),
            near_account_id: format!("node{id}.near").parse().unwrap(),
        }
    }

    fn tls_key_for(signing_key: &SigningKey) -> Ed25519PublicKey {
        Ed25519PublicKey::from(&signing_key.verifying_key())
    }

    fn bitcoin_chain_config() -> dtos::ForeignChainsConfig {
        BTreeSet::from([dtos::ForeignChain::Bitcoin]).into()
    }

    fn participants(threshold: u64, infos: Vec<ParticipantInfo>) -> ParticipantsConfig {
        ParticipantsConfig {
            threshold,
            participants: infos,
        }
    }

    #[test]
    fn supporters_by_available_chain__should_omit_chain_that_is_not_available() {
        // Given: a node registered for Bitcoin while only Base is available.
        let key1 = make_signing_key(1);
        let configs: dtos::ForeignChainsConfigs =
            BTreeMap::from([(tls_key_for(&key1), bitcoin_chain_config())]).into();
        let available: dtos::AvailableForeignChains =
            BTreeSet::from([dtos::ForeignChain::Base]).into();

        // When
        let supporters = supporters_by_available_chain(available, configs);

        // Then
        assert!(supporters.is_empty());
    }

    #[test]
    fn supporters_by_available_chain__should_map_available_chain_to_supporting_tls_keys() {
        // Given: two nodes registered for Bitcoin, which is available.
        let key1 = make_signing_key(1);
        let key2 = make_signing_key(2);
        let configs: dtos::ForeignChainsConfigs = BTreeMap::from([
            (tls_key_for(&key1), bitcoin_chain_config()),
            (tls_key_for(&key2), bitcoin_chain_config()),
        ])
        .into();
        let available: dtos::AvailableForeignChains =
            BTreeSet::from([dtos::ForeignChain::Bitcoin]).into();

        // When
        let supporters = supporters_by_available_chain(available, configs);

        // Then
        assert_eq!(
            supporters,
            BTreeMap::from([(
                dtos::ForeignChain::Bitcoin,
                HashSet::from([tls_key_for(&key1), tls_key_for(&key2)]),
            )])
        );
    }

    #[test]
    fn resolve_participant_ids__should_ignore_tls_key_of_non_participant() {
        // Given: one participant plus a TLS key belonging to no participant.
        let participant_key = make_signing_key(1);
        let stranger_key = make_signing_key(9);
        let participants_config = participants(1, vec![make_participant_info(1, &participant_key)]);
        let tls_keys = HashSet::from([tls_key_for(&participant_key), tls_key_for(&stranger_key)]);

        // When
        let ids = resolve_participant_ids(&tls_keys, &participants_config);

        // Then
        assert_eq!(ids, HashSet::from([ParticipantId::from_raw(1)]));
    }

    #[test]
    fn resolve_supporters_by_foreign_chain__should_map_chain_to_all_supporting_participants() {
        // Given: three participants, all supporting Bitcoin.
        let keys: Vec<SigningKey> = (1..=3u8).map(make_signing_key).collect();
        let participants_config = participants(
            2,
            vec![
                make_participant_info(1, &keys[0]),
                make_participant_info(2, &keys[1]),
                make_participant_info(3, &keys[2]),
            ],
        );
        let supporters_by_pk = BTreeMap::from([(
            dtos::ForeignChain::Bitcoin,
            keys.iter().map(tls_key_for).collect::<HashSet<_>>(),
        )]);

        // When
        let supporters =
            resolve_supporters_by_foreign_chain(&supporters_by_pk, &participants_config);

        // Then
        assert_eq!(
            supporters,
            BTreeMap::from([(
                dtos::ForeignChain::Bitcoin,
                HashSet::from([
                    ParticipantId::from_raw(1),
                    ParticipantId::from_raw(2),
                    ParticipantId::from_raw(3),
                ]),
            )])
        );
    }

    #[test]
    fn resolve_supporters_by_foreign_chain__should_omit_chain_without_quorum() {
        // Given: threshold 2 but only one participant supports Bitcoin.
        let key1 = make_signing_key(1);
        let key2 = make_signing_key(2);
        let participants_config = participants(
            2,
            vec![
                make_participant_info(1, &key1),
                make_participant_info(2, &key2),
            ],
        );
        let supporters_by_pk = BTreeMap::from([(
            dtos::ForeignChain::Bitcoin,
            HashSet::from([tls_key_for(&key1)]),
        )]);

        // When
        let supporters =
            resolve_supporters_by_foreign_chain(&supporters_by_pk, &participants_config);

        // Then
        assert!(supporters.is_empty());
    }

    #[tokio::test]
    async fn spawn_supporters_by_foreign_chain__should_publish_resolved_map_on_upstream_change() {
        // Given: Bitcoin is registered by the only participant but not yet available.
        let key1 = make_signing_key(1);
        let participants_config = participants(1, vec![make_participant_info(1, &key1)]);
        let configs: dtos::ForeignChainsConfigs =
            BTreeMap::from([(tls_key_for(&key1), bitcoin_chain_config())]).into();
        let (available_sender, available_receiver) =
            watch::channel(dtos::AvailableForeignChains::default());
        let (_configs_sender, configs_receiver) = watch::channel(configs);
        let mut supporters = spawn_supporters_by_foreign_chain(
            available_receiver,
            configs_receiver,
            participants_config,
        );
        assert!(supporters.borrow().is_empty());

        // When: Bitcoin becomes available.
        available_sender
            .send(BTreeSet::from([dtos::ForeignChain::Bitcoin]).into())
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), supporters.changed())
            .await
            .unwrap()
            .unwrap();

        // Then
        assert_eq!(
            *supporters.borrow(),
            BTreeMap::from([(
                dtos::ForeignChain::Bitcoin,
                HashSet::from([ParticipantId::from_raw(1)]),
            )])
        );
    }
}
