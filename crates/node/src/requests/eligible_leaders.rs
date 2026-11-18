use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use mpc_primitives::domain::DomainId;
use near_contract_transport::BlockHeight;
use near_mpc_contract_interface::types as dtos;
use near_time::{Clock, Duration};
use tokio::sync::watch;

use crate::foreign_chain_policy::{SupportersByForeignChain, foreign_tx_required_active_signers};
use crate::network::connectivity::first_hand_indexer_heights::FirstHandIndexerHeights;
use crate::network::readiness::NetworkReadiness;
use crate::primitives::ParticipantId;
use crate::requests::metrics;
use crate::requests::queue::{ReadEligibleLeaders, STALE_PARTICIPANT_THRESHOLD, majority_height};
use crate::types::Request;

/// Reads which participants can lead a request.
#[derive(Clone)]
pub(crate) struct EligibleLeaderReader {
    clique_size_by_domain: HashMap<DomainId, usize>,
    eligible_leaders: watch::Receiver<EligibleLeaders>,
}

impl EligibleLeaderReader {
    /// Returns the reader and the publisher it reads from, which the caller has to run.
    /// `readiness` must be for [`ComputationDuration::Seconds`].
    ///
    /// [`ComputationDuration::Seconds`]: crate::providers::participant_selection::ComputationDuration::Seconds
    pub(crate) fn new(
        me: ParticipantId,
        domains: &[dtos::DomainConfig],
        readiness: watch::Receiver<NetworkReadiness<ParticipantId>>,
        heights: watch::Receiver<FirstHandIndexerHeights<ParticipantId>>,
        foreign_chain_supporters: watch::Receiver<SupportersByForeignChain>,
        publish_interval: Duration,
        clock: Clock,
    ) -> (Self, EligibleLeadersPublisher) {
        // A count that does not fit `usize` exceeds any number of participants, so a domain that
        // needs it gets no eligible leaders.
        let clique_size_by_domain: HashMap<DomainId, usize> = domains
            .iter()
            .filter_map(|domain| {
                let participants_needed = domain
                    .protocol
                    .required_active_signers(domain.reconstruction_threshold);
                Some((domain.id, usize::try_from(participants_needed).ok()?))
            })
            .collect();
        let (eligible_leaders_sender, eligible_leaders) =
            watch::channel(EligibleLeaders::default());
        let publisher = EligibleLeadersPublisher {
            me,
            clique_sizes: clique_size_by_domain.values().copied().collect(),
            foreign_tx_clique_size: foreign_tx_required_active_signers(domains)
                .and_then(|participants_needed| usize::try_from(participants_needed).ok()),
            readiness,
            heights,
            foreign_chain_supporters,
            eligible_leaders: eligible_leaders_sender,
            publish_interval,
            clock,
        };
        let reader = Self {
            clique_size_by_domain,
            eligible_leaders,
        };
        (reader, publisher)
    }
}

impl<RequestType: Request> ReadEligibleLeaders<RequestType> for EligibleLeaderReader {
    fn read_eligible_leaders(&self, request: &RequestType) -> HashSet<ParticipantId> {
        let eligible_leaders = self.eligible_leaders.borrow();
        let for_domain = self
            .clique_size_by_domain
            .get(&request.get_domain_id())
            .and_then(|size| eligible_leaders.participants_by_max_clique_size.get(size));
        let participants = match request.get_foreign_chain() {
            Some(chain) => {
                let for_chain = eligible_leaders.participants_by_foreign_chain.get(&chain);
                if for_chain.is_none_or(BTreeSet::is_empty)
                    && for_domain.is_some_and(|participants| !participants.is_empty())
                {
                    metrics::MPC_NUM_REQUESTS_WITHOUT_REFINED_LEADER_TOTAL
                        .with_label_values(&[
                            RequestType::get_type().to_string().as_str(),
                            chain.label(),
                        ])
                        .inc();
                }
                for_chain
            }
            None => for_domain,
        };
        participants
            .map(|participants| participants.iter().copied().collect())
            .unwrap_or_default()
    }
}

/// Assumes that every participant supports every domain. Only for a foreign chain must the
/// clique come from the chain's supporters.
///
/// A participant that is not connected to us is in none of the sets, so it is never an eligible
/// leader in our view: the cliques are drawn from the participants that are not stale, and
/// staleness is only known for those connected to us.
// todo: store this more compactly. With clique sizes 5, 10 and 16 and every participant in a
// clique of 17, a single set serves all three sizes.
#[derive(Clone, Default, PartialEq)]
struct EligibleLeaders {
    participants_by_max_clique_size: BTreeMap<usize, BTreeSet<ParticipantId>>,
    participants_by_foreign_chain: BTreeMap<dtos::ForeignChain, BTreeSet<ParticipantId>>,
}

/// Recomputes [`EligibleLeaders`] when the readiness, the stale participants or the foreign-chain
/// supporters change.
pub(crate) struct EligibleLeadersPublisher {
    me: ParticipantId,
    clique_sizes: BTreeSet<usize>,
    /// `None` when there is no ForeignTx domain.
    foreign_tx_clique_size: Option<usize>,
    readiness: watch::Receiver<NetworkReadiness<ParticipantId>>,
    heights: watch::Receiver<FirstHandIndexerHeights<ParticipantId>>,
    foreign_chain_supporters: watch::Receiver<SupportersByForeignChain>,
    eligible_leaders: watch::Sender<EligibleLeaders>,
    publish_interval: Duration,
    clock: Clock,
}

impl EligibleLeadersPublisher {
    /// Publishes at once, then looks again when `readiness` or `foreign_chain_supporters` change,
    /// and every `publish_interval` for the heights, which change with every report. Runs until
    /// one of those two channels is gone or nothing reads the result any more.
    pub(crate) async fn run(mut self) {
        let mut published_for = None;
        loop {
            let readiness = self.readiness.borrow_and_update().clone();
            let connected_to_us = readiness.connected_to(&self.me);
            let inputs = (
                readiness,
                not_stale(&self.heights.borrow(), &connected_to_us),
                self.foreign_chain_supporters.borrow_and_update().clone(),
            );
            if published_for.as_ref() != Some(&inputs) {
                let (readiness, not_stale, supporters) = &inputs;
                let eligible_leaders = self.eligible_leaders(readiness, not_stale, supporters);
                self.eligible_leaders.send_replace(eligible_leaders);
                published_for = Some(inputs);
            }
            tokio::select! {
                changed = self.readiness.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
                changed = self.foreign_chain_supporters.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
                _ = self.eligible_leaders.closed() => return,
                _ = self.clock.sleep(self.publish_interval) => {}
            }
        }
    }

    fn eligible_leaders(
        &self,
        readiness: &NetworkReadiness<ParticipantId>,
        not_stale: &BTreeSet<ParticipantId>,
        supporters: &SupportersByForeignChain,
    ) -> EligibleLeaders {
        let mut rng = rand::thread_rng();
        let mut in_clique = |size: usize, among: &BTreeSet<ParticipantId>| {
            readiness.participants_in_clique(size, among, &mut rng)
        };
        let participants_by_max_clique_size = self
            .clique_sizes
            .iter()
            .map(|size| (*size, in_clique(*size, not_stale)))
            .collect();
        let participants_by_foreign_chain = match self.foreign_tx_clique_size {
            Some(clique_size) => supporters
                .iter()
                .map(|(chain, supporters)| {
                    let among = not_stale
                        .iter()
                        .filter(|participant| supporters.contains(participant))
                        .copied()
                        .collect();
                    (*chain, in_clique(clique_size, &among))
                })
                .collect(),
            None => {
                for chain in supporters.keys() {
                    tracing::error!(
                        ?chain,
                        "chain has supporters but there is no ForeignTx domain, this should never happen"
                    );
                }
                BTreeMap::new()
            }
        };
        EligibleLeaders {
            participants_by_max_clique_size,
            participants_by_foreign_chain,
        }
    }
}

/// The participants of `connected_to_us` whose indexer is at most [`STALE_PARTICIPANT_THRESHOLD`]
/// behind the height that a majority of them has reached. A height is what the participant itself
/// last reported to us, so only the heights of those connected to us are current.
fn not_stale(
    heights: &FirstHandIndexerHeights<ParticipantId>,
    connected_to_us: &BTreeSet<ParticipantId>,
) -> BTreeSet<ParticipantId> {
    let heights: Vec<(ParticipantId, BlockHeight)> = heights
        .iter()
        .filter(|(participant, _)| connected_to_us.contains(participant))
        .map(|(participant, height)| (*participant, BlockHeight::new(height.to_wire())))
        .collect();
    let Some(reference_height) = majority_height(heights.iter().map(|(_, height)| *height)) else {
        return BTreeSet::new();
    };
    heights
        .into_iter()
        .filter(|(_, height)| {
            height.saturating_add(STALE_PARTICIPANT_THRESHOLD) >= reference_height
        })
        .map(|(participant, _)| participant)
        .collect()
}
