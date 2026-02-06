use super::queue::{ComputationProgress, PendingRequests, QueuedRequest};
use crate::indexer::types::ChainRespondArgs;
use crate::primitives::ParticipantId;
use crate::types::Request;
use near_indexer_primitives::types::{BlockHeight, NumBlocks};
use std::collections::{BinaryHeap, HashSet};
use std::fmt::Debug;
use std::fmt::Write;
use std::sync::{Arc, Mutex};

const NUM_COMPLETED_REQUESTS_TO_KEEP: usize = 100;

/// A completed request, for exporting to /debug/requests.
pub(super) struct CompletedRequest<RequestType: Request, ChainRespondArgsType: ChainRespondArgs> {
    pub request: RequestType,
    pub progress: Arc<Mutex<ComputationProgress<ChainRespondArgsType>>>,
    pub indexed_block_height: BlockHeight,
    /// The block height at which the request was responded to successfully,
    /// as well as the delay in wall time observed from the indexer.
    pub completion_delay: Option<(NumBlocks, near_time::Duration)>,
}

/// A buffer of completed requests, for exporting to /debug/requests.
/// Keeps the most recent `NUM_COMPLETED_REQUESTS_TO_KEEP` requests.
pub(super) struct CompletedRequests<RequestType: Request, ChainRespondArgsType: ChainRespondArgs> {
    /// Min-heap, so that the oldest requests are at the front to be removed.
    requests: BinaryHeap<CompletedRequest<RequestType, ChainRespondArgsType>>,
}

impl<RequestType: Request, ChainRespondArgsType: ChainRespondArgs> Default
    for CompletedRequests<RequestType, ChainRespondArgsType>
{
    fn default() -> Self {
        Self {
            requests: Default::default(),
        }
    }
}

impl<RequestType: Request, ChainRespondArgsType: ChainRespondArgs> PartialEq
    for CompletedRequest<RequestType, ChainRespondArgsType>
{
    fn eq(&self, other: &Self) -> bool {
        self.indexed_block_height == other.indexed_block_height
            && self.request.get_id() == other.request.get_id()
    }
}

impl<RequestType: Request, ChainRespondArgsType: ChainRespondArgs> Eq
    for CompletedRequest<RequestType, ChainRespondArgsType>
{
}

impl<RequestType: Request, ChainRespondArgsType: ChainRespondArgs> PartialOrd
    for CompletedRequest<RequestType, ChainRespondArgsType>
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<RequestType: Request, ChainRespondArgsType: ChainRespondArgs> Ord
    for CompletedRequest<RequestType, ChainRespondArgsType>
{
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.indexed_block_height, self.request.get_id())
            .cmp(&(other.indexed_block_height, other.request.get_id()))
            // Reverse to invert max heap to min heap.
            .reverse()
    }
}

impl<RequestType: Request, ChainRespondArgsType: ChainRespondArgs>
    CompletedRequests<RequestType, ChainRespondArgsType>
{
    pub fn add_completed_request(
        &mut self,
        request: CompletedRequest<RequestType, ChainRespondArgsType>,
    ) {
        self.requests.push(request);
        if self.requests.len() > NUM_COMPLETED_REQUESTS_TO_KEEP {
            self.requests.pop();
        }
    }
}

impl<RequestType: Request, ChainRespondArgsType: ChainRespondArgs> Debug
    for CompletedRequest<RequestType, ChainRespondArgsType>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (leader, attempts) = {
            let progress = self.progress.lock().unwrap();
            (progress.selected_leader, progress.attempts)
        };
        write!(
            f,
            "  [completed] blk {:>10} -> {:<24} id: {} rx: {:<44} tries: {:<2} leader: {:<2}",
            self.indexed_block_height,
            self.completion_delay
                .map(|(delay_blocks, delay_time)| {
                    let duration_rounded_to_ms =
                        near_time::Duration::milliseconds(delay_time.whole_milliseconds() as i64);
                    format!(
                        "{:>10} (+{}, {})",
                        self.indexed_block_height + delay_blocks,
                        delay_blocks,
                        duration_rounded_to_ms,
                    )
                })
                .unwrap_or("?".to_string()),
            &format!("{:?}", self.request.get_id())[0..6],
            format!("{:?}", self.request.get_receipt_id()),
            attempts,
            leader.map(|x| x.to_string()).unwrap_or("?".to_string()),
        )
    }
}

impl<RequestType: Request, ChainRespondArgsType: ChainRespondArgs>
    QueuedRequest<RequestType, ChainRespondArgsType>
{
    fn debug_print(
        &self,
        clock: &near_time::Clock,
        me: ParticipantId,
        eligible_leaders: &HashSet<ParticipantId>,
    ) -> String {
        let mut output = String::new();
        let current_leader = self.current_leader(eligible_leaders);
        write!(
            &mut output,
            "  {:>11} blk {:>10} -> {:<24} id: {} rx: {:<44} tries: {:<2}",
            if current_leader == Some(me) {
                "[leader]"
            } else {
                ""
            },
            self.block_height,
            "?",
            &format!("{:?}", self.request.get_id())[0..6],
            format!("{:?}", self.request.get_receipt_id()),
            self.computation_progress.lock().unwrap().attempts,
        )
        .unwrap();
        if self.active_attempt.strong_count() > 0 {
            write!(&mut output, " computing").unwrap();
        } else if let Some(time) = self
            .computation_progress
            .lock()
            .unwrap()
            .last_response_submission
        {
            write!(
                &mut output,
                " responded: {}s",
                clock.now().duration_since(time).as_secs()
            )
            .unwrap();
        }
        write!(&mut output, " elect:").unwrap();
        for participant in self.leader_selection_order.iter() {
            if Some(*participant) == current_leader {
                write!(&mut output, " 🗸{participant}").unwrap();
            } else {
                write!(&mut output, " ✗{participant}").unwrap();
            }
        }
        output
    }
}

impl<RequestType: Request + Clone, ChainRespondArgsType: ChainRespondArgs> Debug
    for PendingRequests<RequestType, ChainRespondArgsType>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut request_lines = Vec::new();
        let (eligible_leaders, maximum_height) = self.eligible_leaders_and_maximum_height();
        let online_participants = self.network_api.alive_participants();
        let indexer_heights = self.network_api.indexer_heights();

        for request in self.requests.values() {
            let debug_line =
                request.debug_print(&self.clock, self.my_participant_id, &eligible_leaders);
            request_lines.push((request.block_height, request.request.get_id(), debug_line));
        }

        for completed in &self.recently_completed_requests.requests {
            let debug_line = format!("{completed:?}");
            request_lines.push((
                completed.indexed_block_height,
                completed.request.get_id(),
                debug_line,
            ));
        }

        request_lines.sort_unstable_by_key(|(block_height, id, _)| (*block_height, *id));
        request_lines.reverse();

        writeln!(f, "Participants:")?;
        for participant in &self.all_participants {
            writeln!(
                f,
                "  {:>11}: [{}] eligible leader  [{}] online   index height: {:>10}",
                format!("{}", participant),
                if eligible_leaders.contains(participant) {
                    "🗸"
                } else {
                    " "
                },
                if online_participants.contains(participant) {
                    "🗸"
                } else {
                    " "
                },
                indexer_heights.get(participant).copied().unwrap_or(0),
            )?;
        }

        writeln!(f, "Maximum block height known: {maximum_height}")?;

        writeln!(f, "Recent {}s:", RequestType::get_type())?;
        for (_, _, debug_line) in request_lines {
            writeln!(f, "{debug_line}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{CompletedRequest, CompletedRequests};
    use crate::{
        indexer::types::{ChainCKDRespondArgs, ChainSignatureRespondArgs},
        types::{CKDRequest, SignatureRequest},
    };
    use mpc_contract::primitives::{
        domain::DomainId,
        signature::{Payload, Tweak},
    };
    use near_indexer_primitives::CryptoHash;
    use rand::seq::SliceRandom;

    #[test]
    fn test_completed_ckd_requests() {
        let mut completed = CompletedRequests::<CKDRequest, ChainCKDRespondArgs>::default();
        let mut indices = (0..200).collect::<Vec<_>>();
        indices.shuffle(&mut rand::thread_rng());
        for i in indices {
            completed.add_completed_request(CompletedRequest {
                request: CKDRequest {
                    id: CryptoHash(rand::random()),
                    receipt_id: CryptoHash(rand::random()),
                    app_public_key: "bls12381g1:6KtVVcAAGacrjNGePN8bp3KV6fYGrw1rFsyc7cVJCqR16Zc2ZFg3HX3hSZxSfv1oH6".parse().unwrap(),
                    app_id: [1u8; 32].into(),
                    entropy: [0; 32],
                    timestamp_nanosec: 0,
                    domain_id: DomainId::legacy_ecdsa_id(),
                },
                progress: Default::default(),
                indexed_block_height: i,
                completion_delay: if rand::random::<bool>() {
                    None
                } else {
                    Some((
                        i + rand::random::<u64>() % 100,
                        near_time::Duration::milliseconds(100),
                    ))
                },
            });
        }
        let mut kept_indices = completed
            .requests
            .iter()
            .map(|r| r.indexed_block_height)
            .collect::<Vec<_>>();
        kept_indices.sort_unstable();
        assert_eq!(kept_indices, (100..200).collect::<Vec<_>>());
    }

    #[test]
    fn test_completed_signature_requests() {
        let mut completed =
            CompletedRequests::<SignatureRequest, ChainSignatureRespondArgs>::default();
        let mut indices = (0..200).collect::<Vec<_>>();
        indices.shuffle(&mut rand::thread_rng());
        for i in indices {
            completed.add_completed_request(CompletedRequest {
                request: SignatureRequest {
                    id: CryptoHash(rand::random()),
                    receipt_id: CryptoHash(rand::random()),
                    payload: Payload::from_legacy_ecdsa([0; 32]),
                    tweak: Tweak::new([0; 32]),
                    entropy: Default::default(),
                    timestamp_nanosec: Default::default(),
                    domain: DomainId::legacy_ecdsa_id(),
                },
                progress: Default::default(),
                indexed_block_height: i,
                completion_delay: if rand::random::<bool>() {
                    None
                } else {
                    Some((
                        i + rand::random::<u64>() % 100,
                        near_time::Duration::milliseconds(100),
                    ))
                },
            });
        }
        let mut kept_indices = completed
            .requests
            .iter()
            .map(|r| r.indexed_block_height)
            .collect::<Vec<_>>();
        kept_indices.sort_unstable();
        assert_eq!(kept_indices, (100..200).collect::<Vec<_>>());
    }
}
