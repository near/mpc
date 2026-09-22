use std::collections::{BTreeMap, BTreeSet, HashSet};

use anyhow::Context;
use mpc_primitives::ReconstructionThreshold;
use near_mpc_contract_interface::types as dtos;
use near_mpc_crypto_types::Ed25519PublicKey;
use tokio::sync::watch;

use crate::config::ParticipantsConfig;
use crate::indexer::foreign_chain::ForeignChainSupporters;
use crate::primitives::ParticipantId;
use crate::requests::queue::RefineEligibleLeaders;
use crate::tracking::{self, AutoAbortTask};
use crate::types::VerifyForeignTxRequest;

/// Participants supporting each available foreign chain; chains without a
/// signing quorum are omitted.
pub(crate) type SupportersByForeignChain = BTreeMap<dtos::ForeignChain, HashSet<ParticipantId>>;

/// Resolves the indexer's TLS-key supporters channel against the current
/// participant set. Must be called from a tracked task; dropping the returned
/// [`AutoAbortTask`] stops the resolver.
pub(crate) fn spawn_supporters_by_foreign_chain(
    mut upstream: watch::Receiver<ForeignChainSupporters>,
    participants_config: ParticipantsConfig,
    foreign_tx_reconstruction_threshold: ReconstructionThreshold,
) -> (watch::Receiver<SupportersByForeignChain>, AutoAbortTask<()>) {
    let init_value = resolve_supporters_by_foreign_chain(
        &upstream.borrow_and_update(),
        &participants_config,
        foreign_tx_reconstruction_threshold,
    );
    let (sender, receiver) = watch::channel(init_value);

    let task = tracking::spawn("foreign-chain supporters resolver", async move {
        loop {
            let new_value = tokio::select! {
                res = await_updated_supporters(
                    &mut upstream,
                    &participants_config,
                    foreign_tx_reconstruction_threshold,
                ) => match res {
                    Ok(value) => value,
                    Err(e) => {
                        tracing::info!("stopping foreign-chain supporters monitor: {e:#}");
                        break;
                    }
                },
                _ = sender.closed() => {
                    tracing::debug!("all receivers dropped, stopping foreign-chain supporters monitor");
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
    (receiver, task)
}

async fn await_updated_supporters(
    upstream: &mut watch::Receiver<ForeignChainSupporters>,
    participants_config: &ParticipantsConfig,
    foreign_tx_reconstruction_threshold: ReconstructionThreshold,
) -> anyhow::Result<SupportersByForeignChain> {
    upstream
        .changed()
        .await
        .context("foreign-chain supporters sender dropped")?;
    let supporters = upstream.borrow_and_update().clone();
    Ok(resolve_supporters_by_foreign_chain(
        &supporters,
        participants_config,
        foreign_tx_reconstruction_threshold,
    ))
}

/// Mirrors the contract's availability rule: the max reconstruction threshold
/// across ForeignTx domains.
/// TODO(#3973): revisit threshold calculation for several ForeignTx
/// domains with different thresholds.
pub(crate) fn foreign_tx_reconstruction_threshold(
    domains: &[dtos::DomainConfig],
) -> Option<ReconstructionThreshold> {
    domains
        .iter()
        .filter(|domain| domain.purpose == dtos::DomainPurpose::ForeignTx)
        .map(|domain| domain.reconstruction_threshold)
        .max()
}

/// Recomputed node-side even though the contract already threshold-gates
/// availability: the upstream snapshot keys supporters by TLS key over all
/// registrations (prospective or stale ones included) and may come from a
/// different block than `participants_config`. Only supporters resolving to
/// `participants_config` — the participants this node can sign with — count
/// towards the quorum. An empty map means no chain reaches the quorum.
fn resolve_supporters_by_foreign_chain(
    supporters_by_tls_key: &ForeignChainSupporters,
    participants_config: &ParticipantsConfig,
    foreign_tx_reconstruction_threshold: ReconstructionThreshold,
) -> SupportersByForeignChain {
    supporters_by_tls_key
        .iter()
        .filter_map(|(chain, tls_keys)| {
            let ids = resolve_participant_ids(tls_keys, participants_config);
            u64::try_from(ids.len())
                .is_ok_and(|supporters| supporters >= foreign_tx_reconstruction_threshold.inner())
                .then_some((*chain, ids))
        })
        .collect()
}

/// Resolves TLS keys to the matching participants' ids; keys not belonging to a
/// participant are dropped.
fn resolve_participant_ids(
    tls_keys: &BTreeSet<dtos::Ed25519PublicKey>,
    participants_config: &ParticipantsConfig,
) -> HashSet<ParticipantId> {
    participants_config
        .participants
        .iter()
        .filter(|info| tls_keys.contains(&Ed25519PublicKey::from(&info.p2p_public_key)))
        .map(|info| info.id)
        .collect()
}

/// Narrows verify-foreign-tx leader selection to the participants supporting the
/// request's chain, always reading the freshest supporters snapshot. A leader is
/// only elected when a quorum of supporters is eligible, so an under-quorum
/// request parks instead of burning attempts that cannot find a compatible
/// presignature.
pub(crate) struct ForeignChainLeadersRefiner {
    supporters_receiver: watch::Receiver<SupportersByForeignChain>,
    /// [`foreign_tx_reconstruction_threshold`] of the running domains, `None`
    /// when there is no ForeignTx domain (the snapshot is then always empty).
    quorum: Option<ReconstructionThreshold>,
}

impl ForeignChainLeadersRefiner {
    pub(crate) fn new(
        supporters_receiver: watch::Receiver<SupportersByForeignChain>,
        quorum: Option<ReconstructionThreshold>,
    ) -> Self {
        ForeignChainLeadersRefiner {
            supporters_receiver,
            quorum,
        }
    }
}

impl RefineEligibleLeaders<VerifyForeignTxRequest> for ForeignChainLeadersRefiner {
    fn refine(
        &self,
        request: &VerifyForeignTxRequest,
        eligible: &HashSet<ParticipantId>,
    ) -> HashSet<ParticipantId> {
        let refined = match self
            .supporters_receiver
            .borrow()
            .get(&request.request.chain())
        {
            Some(supporters) => supporters & eligible,
            None => return HashSet::new(),
        };
        match self.quorum {
            None => {
                tracing::error!(
                    chain = ?request.request.chain(),
                    "chain has supporters but there is no ForeignTx domain, this should never happen"
                );
                refined
            }
            Some(quorum) => {
                if u64::try_from(refined.len()).is_ok_and(|count| count >= quorum.inner()) {
                    refined
                } else {
                    HashSet::new()
                }
            }
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::config::{ParticipantInfo, ParticipantsConfig};
    use crate::tracking::start_root_task;
    use ed25519_dalek::SigningKey;
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

    fn participants(threshold: u64, infos: Vec<ParticipantInfo>) -> ParticipantsConfig {
        ParticipantsConfig {
            threshold,
            participants: infos,
        }
    }

    #[test]
    fn resolve_participant_ids__should_ignore_tls_key_of_non_participant() {
        // Given: one participant plus a TLS key belonging to no participant.
        let participant_key = make_signing_key(1);
        let stranger_key = make_signing_key(9);
        let participants_config = participants(1, vec![make_participant_info(1, &participant_key)]);
        let tls_keys = BTreeSet::from([tls_key_for(&participant_key), tls_key_for(&stranger_key)]);

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
        let supporters_by_tls_key = BTreeMap::from([(
            dtos::ForeignChain::Bitcoin,
            keys.iter().map(tls_key_for).collect::<BTreeSet<_>>(),
        )]);

        // When
        let supporters = resolve_supporters_by_foreign_chain(
            &supporters_by_tls_key,
            &participants_config,
            ReconstructionThreshold::new(2),
        );

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
        let supporters_by_tls_key = BTreeMap::from([(
            dtos::ForeignChain::Bitcoin,
            BTreeSet::from([tls_key_for(&key1)]),
        )]);

        // When
        let supporters = resolve_supporters_by_foreign_chain(
            &supporters_by_tls_key,
            &participants_config,
            ReconstructionThreshold::new(2),
        );

        // Then
        assert_eq!(supporters, SupportersByForeignChain::new());
    }

    #[test]
    fn resolve_supporters_by_foreign_chain__should_ignore_participants_threshold() {
        // Given: a participants threshold far above the single supporter.
        let key1 = make_signing_key(1);
        let participants_config = participants(100, vec![make_participant_info(1, &key1)]);
        let supporters_by_tls_key = BTreeMap::from([(
            dtos::ForeignChain::Bitcoin,
            BTreeSet::from([tls_key_for(&key1)]),
        )]);

        // When
        let supporters = resolve_supporters_by_foreign_chain(
            &supporters_by_tls_key,
            &participants_config,
            ReconstructionThreshold::new(1),
        );

        // Then: only the ForeignTx domain threshold applies.
        assert!(supporters.contains_key(&dtos::ForeignChain::Bitcoin));
    }

    #[test]
    fn foreign_tx_reconstruction_threshold__should_return_max_across_foreign_tx_domains() {
        // Given: two ForeignTx domains and one Sign domain with a higher threshold.
        let domain = |id: u64, purpose, threshold: u64| dtos::DomainConfig {
            id: dtos::DomainId(id),
            protocol: dtos::Protocol::CaitSith,
            reconstruction_threshold: dtos::ReconstructionThreshold::new(threshold),
            purpose,
        };
        let domains = vec![
            domain(0, dtos::DomainPurpose::Sign, 7),
            domain(1, dtos::DomainPurpose::ForeignTx, 3),
            domain(2, dtos::DomainPurpose::ForeignTx, 5),
        ];

        // When
        let threshold = foreign_tx_reconstruction_threshold(&domains);

        // Then
        assert_eq!(threshold, Some(ReconstructionThreshold::new(5)));
    }

    #[test]
    fn foreign_tx_reconstruction_threshold__should_return_none_without_foreign_tx_domain() {
        // Given
        let domains = vec![dtos::DomainConfig {
            id: dtos::DomainId(0),
            protocol: dtos::Protocol::CaitSith,
            reconstruction_threshold: dtos::ReconstructionThreshold::new(2),
            purpose: dtos::DomainPurpose::Sign,
        }];

        // When
        let threshold = foreign_tx_reconstruction_threshold(&domains);

        // Then
        assert_eq!(threshold, None);
    }

    #[tokio::test]
    async fn spawn_supporters_by_foreign_chain__should_republish_on_upstream_change() {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given: Bitcoin resolved as available from the first snapshot.
            let key1 = make_signing_key(1);
            let participants_config = participants(1, vec![make_participant_info(1, &key1)]);
            let (upstream_sender, upstream_receiver) = watch::channel(BTreeMap::from([(
                dtos::ForeignChain::Bitcoin,
                BTreeSet::from([tls_key_for(&key1)]),
            )]));
            let (mut supporters, _resolver_task) = spawn_supporters_by_foreign_chain(
                upstream_receiver,
                participants_config,
                ReconstructionThreshold::new(1),
            );
            assert!(
                supporters
                    .borrow()
                    .contains_key(&dtos::ForeignChain::Bitcoin)
            );

            // When: the chain loses its registration upstream.
            upstream_sender.send(BTreeMap::new()).unwrap();
            tokio::time::timeout(Duration::from_secs(5), supporters.changed())
                .await
                .unwrap()
                .unwrap();

            // Then
            assert_eq!(*supporters.borrow(), SupportersByForeignChain::new());
        });
        root.await;
    }

    #[tokio::test]
    async fn spawn_supporters_by_foreign_chain__should_omit_chain_without_quorum_of_participants() {
        let (root, _root_handle) = start_root_task("test-root", async move {
            // Given: threshold 2, Bitcoin registered by one participant and a stranger.
            let key1 = make_signing_key(1);
            let key2 = make_signing_key(2);
            let stranger_key = make_signing_key(9);
            let participants_config = participants(
                2,
                vec![
                    make_participant_info(1, &key1),
                    make_participant_info(2, &key2),
                ],
            );
            let upstream = BTreeMap::from([(
                dtos::ForeignChain::Bitcoin,
                BTreeSet::from([tls_key_for(&key1), tls_key_for(&stranger_key)]),
            )]);

            // When
            let (_upstream_sender, upstream_receiver) = watch::channel(upstream);
            let (supporters, _resolver_task) = spawn_supporters_by_foreign_chain(
                upstream_receiver,
                participants_config,
                ReconstructionThreshold::new(2),
            );

            // Then: the stranger's key does not count towards the quorum.
            assert_eq!(*supporters.borrow(), SupportersByForeignChain::new());
        });
        root.await;
    }

    fn bitcoin_verify_foreign_tx_request() -> VerifyForeignTxRequest {
        VerifyForeignTxRequest {
            id: near_indexer_primitives::CryptoHash([1; 32]),
            receipt_id: near_indexer_primitives::CryptoHash([2; 32]),
            request: dtos::ForeignChainRpcRequest::Bitcoin(dtos::BitcoinRpcRequest {
                tx_id: dtos::BitcoinTxId([3; 32]),
                confirmations: 2.into(),
                extractors: [dtos::BitcoinExtractor::BlockHash].into(),
            }),
            payload_version: dtos::ForeignTxPayloadVersion::V1,
            expected_payload_hash: None,
            entropy: [4; 32],
            timestamp_nanosec: 0,
            domain_id: mpc_primitives::domain::DomainId(0),
        }
    }

    fn participant_set(ids: &[u32]) -> HashSet<ParticipantId> {
        ids.iter().copied().map(ParticipantId::from_raw).collect()
    }

    #[test]
    fn foreign_chain_leaders_refiner__should_allow_nobody_when_chain_has_no_supporters() {
        // Given
        let (_sender, receiver) = watch::channel(SupportersByForeignChain::new());
        let refiner =
            ForeignChainLeadersRefiner::new(receiver, Some(ReconstructionThreshold::new(1)));

        // When
        let refined = refiner.refine(
            &bitcoin_verify_foreign_tx_request(),
            &participant_set(&[0, 1]),
        );

        // Then
        assert!(refined.is_empty());
    }

    #[test]
    fn foreign_chain_leaders_refiner__should_intersect_supporters_with_eligible() {
        // Given
        let supporters = SupportersByForeignChain::from([(
            dtos::ForeignChain::Bitcoin,
            participant_set(&[1, 2]),
        )]);
        let (_sender, receiver) = watch::channel(supporters);
        let refiner =
            ForeignChainLeadersRefiner::new(receiver, Some(ReconstructionThreshold::new(1)));

        // When
        let refined = refiner.refine(
            &bitcoin_verify_foreign_tx_request(),
            &participant_set(&[0, 1]),
        );

        // Then
        assert_eq!(refined, participant_set(&[1]));
    }

    #[test]
    fn foreign_chain_leaders_refiner__should_allow_nobody_when_eligible_supporters_below_quorum() {
        // Given: three supporters, quorum 2, but only one supporter is eligible.
        let supporters = SupportersByForeignChain::from([(
            dtos::ForeignChain::Bitcoin,
            participant_set(&[1, 2, 3]),
        )]);
        let (_sender, receiver) = watch::channel(supporters);
        let refiner =
            ForeignChainLeadersRefiner::new(receiver, Some(ReconstructionThreshold::new(2)));

        // When
        let refined = refiner.refine(
            &bitcoin_verify_foreign_tx_request(),
            &participant_set(&[0, 1]),
        );

        // Then
        assert!(refined.is_empty());
    }

    #[test]
    fn foreign_chain_leaders_refiner__should_allow_supporters_when_eligible_quorum_is_met() {
        // Given: three supporters, quorum 2, two of them eligible.
        let supporters = SupportersByForeignChain::from([(
            dtos::ForeignChain::Bitcoin,
            participant_set(&[1, 2, 3]),
        )]);
        let (_sender, receiver) = watch::channel(supporters);
        let refiner =
            ForeignChainLeadersRefiner::new(receiver, Some(ReconstructionThreshold::new(2)));

        // When
        let refined = refiner.refine(
            &bitcoin_verify_foreign_tx_request(),
            &participant_set(&[0, 1, 2]),
        );

        // Then
        assert_eq!(refined, participant_set(&[1, 2]));
    }

    #[test]
    fn foreign_chain_leaders_refiner__should_pick_up_republished_supporters() {
        // Given
        let (sender, receiver) = watch::channel(SupportersByForeignChain::new());
        let refiner =
            ForeignChainLeadersRefiner::new(receiver, Some(ReconstructionThreshold::new(1)));
        let eligible = participant_set(&[0, 1]);
        assert!(
            refiner
                .refine(&bitcoin_verify_foreign_tx_request(), &eligible)
                .is_empty()
        );

        // When
        sender
            .send(SupportersByForeignChain::from([(
                dtos::ForeignChain::Bitcoin,
                participant_set(&[0]),
            )]))
            .unwrap();
        let refined = refiner.refine(&bitcoin_verify_foreign_tx_request(), &eligible);

        // Then
        assert_eq!(refined, participant_set(&[0]));
    }
}
