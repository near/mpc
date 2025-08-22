use super::queue::{CKDComputationProgress, PendingCKDRequests, QueuedCKDRequest};
use crate::ckd_request::CKDRequest;
use crate::primitives::ParticipantId;
use near_indexer_primitives::types::{BlockHeight, NumBlocks};
use std::collections::{BinaryHeap, HashSet};
use std::fmt::Debug;
use std::fmt::Write;
use std::sync::{Arc, Mutex};

const NUM_COMPLETED_REQUESTS_TO_KEEP: usize = 100;

/// A completed ckd request, for exporting to /debug/ckds.
pub(super) struct CompletedCKDRequest {
    pub request: CKDRequest,
    pub progress: Arc<Mutex<CKDComputationProgress>>,
    pub indexed_block_height: BlockHeight,
    /// The block height at which the request was responded to successfully,
    /// as well as the delay in wall time observed from the indexer.
    pub completion_delay: Option<(NumBlocks, near_time::Duration)>,
}

/// A buffer of completed ckd requests, for exporting to /debug/ckds.
/// Keeps the most recent `NUM_COMPLETED_REQUESTS_TO_KEEP` requests.
#[derive(Default)]
pub(super) struct CompletedCKDRequests {
    /// Min-heap, so that the oldest requests are at the front to be removed.
    requests: BinaryHeap<CompletedCKDRequest>,
}

impl PartialEq for CompletedCKDRequest {
    fn eq(&self, other: &Self) -> bool {
        self.indexed_block_height == other.indexed_block_height
            && self.request.id == other.request.id
    }
}

impl Eq for CompletedCKDRequest {}

impl PartialOrd for CompletedCKDRequest {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CompletedCKDRequest {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.indexed_block_height, self.request.id)
            .cmp(&(other.indexed_block_height, other.request.id))
            // Reverse to invert max heap to min heap.
            .reverse()
    }
}

impl CompletedCKDRequests {
    pub fn add_completed_request(&mut self, request: CompletedCKDRequest) {
        self.requests.push(request);
        if self.requests.len() > NUM_COMPLETED_REQUESTS_TO_KEEP {
            self.requests.pop();
        }
    }
}

impl Debug for CompletedCKDRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "  [completed] blk {:>10} -> {:<24} id: {} rx: {:<44} tries: {:<2}",
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
            &format!("{:?}", self.request.id)[0..6],
            format!("{:?}", self.request.receipt_id),
            self.progress.lock().unwrap().attempts,
        )
    }
}

impl QueuedCKDRequest {
    fn debug_print(
        &self,
        clock: &near_time::Clock,
        me: ParticipantId,
        eligible_leaders: &HashSet<ParticipantId>,
    ) -> String {
        let mut output = String::new();
        let mut leader_selection = Vec::new();
        for participant in &self.leader_selection_order {
            leader_selection.push(*participant);
            if eligible_leaders.contains(participant) {
                break;
            }
        }
        write!(
            &mut output,
            "  {:>11} blk {:>10} -> {:<24} id: {} rx: {:<44} tries: {:<2}",
            if leader_selection.last() == Some(&me) {
                "[leader]"
            } else {
                ""
            },
            self.block_height,
            "?",
            &format!("{:?}", self.request.id)[0..6],
            format!("{:?}", self.request.receipt_id),
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
        for (i, participant) in leader_selection.iter().enumerate() {
            if i == leader_selection.len() - 1 {
                write!(&mut output, " 🗸{}", participant).unwrap();
            } else {
                write!(&mut output, " ✗{}", participant).unwrap();
            }
        }
        output
    }
}

impl Debug for PendingCKDRequests {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ckd_lines = Vec::new();
        let (eligible_leaders, maximum_height) = self.eligible_leaders_and_maximum_height();
        let online_participants = self.network_api.alive_participants();
        let indexer_heights = self.network_api.indexer_heights();

        for request in self.requests.values() {
            let debug_line =
                request.debug_print(&self.clock, self.my_participant_id, &eligible_leaders);
            ckd_lines.push((request.block_height, request.request.id, debug_line));
        }

        for completed in &self.recently_completed_requests.requests {
            let debug_line = format!("{:?}", completed);
            ckd_lines.push((
                completed.indexed_block_height,
                completed.request.id,
                debug_line,
            ));
        }

        ckd_lines.sort_unstable_by_key(|(block_height, id, _)| (*block_height, *id));
        ckd_lines.reverse();

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

        writeln!(f, "Maximum block height known: {}", maximum_height)?;

        writeln!(f, "Recent CKDs:")?;
        for (_, _, debug_line) in ckd_lines {
            writeln!(f, "{}", debug_line)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::CompletedCKDRequest;
    use crate::ckd::debug::CompletedCKDRequests;
    use crate::ckd_request::CKDRequest;
    use mpc_contract::primitives::domain::DomainId;
    use near_indexer_primitives::CryptoHash;
    use rand::seq::SliceRandom;

    #[test]
    fn test_completed_requests() {
        let mut completed = CompletedCKDRequests::default();
        let mut indices = (0..200).collect::<Vec<_>>();
        indices.shuffle(&mut rand::thread_rng());
        for i in indices {
            completed.add_completed_request(CompletedCKDRequest {
                request: CKDRequest {
                    id: CryptoHash(rand::random()),
                    receipt_id: CryptoHash(rand::random()),
                    app_public_key: "secp256k1:4Ls3DBDeFDaf5zs2hxTBnJpKnfsnjNahpKU9HwQvij8fTXoCP9y5JQqQpe273WgrKhVVj1EH73t5mMJKDFMsxoEd".parse().unwrap(),
                    app_id: "test.near".parse().unwrap(),
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
}
