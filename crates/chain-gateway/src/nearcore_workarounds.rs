//! Workarounds for nearcore behaviour, each removable once its linked nearcore issue is resolved.

use std::time::Duration;

use near_indexer_primitives::types::BlockHeight;

use crate::near_internals_wrapper::NearClientActorHandle;

/// Returns once the head has advanced over [`REQUIRED_STABLE_POLLS`] consecutive
/// non-syncing polls. neard clears `syncing` before any peer has reported its height,
/// so the flag alone can report a node still at genesis as synced.
///
/// Can be removed once <https://github.com/near/nearcore/issues/16004> is resolved.
pub(crate) async fn ensure_head_follows_tip(client: &NearClientActorHandle) {
    let mut progress = SyncProgress::default();
    loop {
        tokio::time::sleep(INTERVAL).await;
        if let Ok(sync_info) = client.sync_info().await
            && progress.observe(sync_info.syncing, sync_info.latest_block_height)
        {
            return;
        }
    }
}

const INTERVAL: Duration = Duration::from_millis(500);

/// Consecutive non-syncing polls with head progress before the node counts as caught up.
const REQUIRED_STABLE_POLLS: u32 = 4;

/// Reports caught-up only after [`REQUIRED_STABLE_POLLS`] consecutive
/// non-syncing polls over which the head advances.
#[derive(Default)]
struct SyncProgress {
    run_start_head: Option<BlockHeight>,
    run_polls: u32,
}

impl SyncProgress {
    fn observe(&mut self, syncing: bool, head_height: BlockHeight) -> bool {
        if syncing {
            self.run_start_head = None;
            self.run_polls = 0;
            return false;
        }
        match self.run_start_head {
            None => {
                self.run_start_head = Some(head_height);
                self.run_polls = 1;
                false
            }
            Some(start_head) => {
                self.run_polls += 1;
                self.run_polls >= REQUIRED_STABLE_POLLS && head_height > start_head
            }
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{BlockHeight, REQUIRED_STABLE_POLLS, SyncProgress};

    fn first_caught_up_poll(samples: &[(bool, BlockHeight)]) -> Option<usize> {
        let mut progress = SyncProgress::default();
        samples
            .iter()
            .position(|&(syncing, head)| progress.observe(syncing, head))
    }

    #[test]
    fn observe__should_never_report_caught_up_while_syncing() {
        // Given
        let samples: Vec<_> = (0..10).map(|i| (true, 42_000_000 + i)).collect();

        // When
        let caught_up_at = first_caught_up_poll(&samples);

        // Then
        assert_eq!(caught_up_at, None);
    }

    #[test]
    fn observe__should_never_report_caught_up_with_static_head_at_genesis() {
        // Given
        let genesis = 42_376_888;
        let samples: Vec<_> = (0..10).map(|_| (false, genesis)).collect();

        // When
        let caught_up_at = first_caught_up_poll(&samples);

        // Then
        assert_eq!(caught_up_at, None);
    }

    #[test]
    fn observe__should_not_report_caught_up_before_required_polls() {
        // Given
        let samples: Vec<_> = (0..REQUIRED_STABLE_POLLS - 1)
            .map(|i| (false, 257_000_000 + u64::from(i)))
            .collect();

        // When
        let caught_up_at = first_caught_up_poll(&samples);

        // Then
        assert_eq!(caught_up_at, None);
    }

    #[test]
    fn observe__should_report_caught_up_after_sustained_progress() {
        // Given
        let samples: Vec<_> = (0..REQUIRED_STABLE_POLLS)
            .map(|i| (false, 257_000_000 + u64::from(i)))
            .collect();

        // When
        let caught_up_at = first_caught_up_poll(&samples);

        // Then
        let expected = usize::try_from(REQUIRED_STABLE_POLLS).unwrap() - 1;
        assert_eq!(caught_up_at, Some(expected));
    }

    #[test]
    fn observe__should_wait_for_head_to_advance_past_run_start() {
        // Given
        let head = 257_000_000;
        let mut samples: Vec<_> = (0..REQUIRED_STABLE_POLLS + 2)
            .map(|_| (false, head))
            .collect();
        samples.push((false, head + 1));

        // When
        let caught_up_at = first_caught_up_poll(&samples);

        // Then
        assert_eq!(caught_up_at, Some(samples.len() - 1));
    }

    #[test]
    fn observe__should_reset_run_when_syncing_resumes() {
        // Given
        let pre = [
            (false, 42_000_000),
            (false, 42_000_001),
            (false, 42_000_002),
        ];
        let resync = [(true, 100_000_000)];
        let post: Vec<_> = (0..REQUIRED_STABLE_POLLS)
            .map(|i| (false, 257_000_000 + u64::from(i)))
            .collect();
        let samples: Vec<_> = pre.iter().chain(&resync).chain(&post).copied().collect();

        // When
        let caught_up_at = first_caught_up_poll(&samples);

        // Then
        let expected =
            pre.len() + resync.len() + usize::try_from(REQUIRED_STABLE_POLLS).unwrap() - 1;
        assert_eq!(caught_up_at, Some(expected));
    }
}
