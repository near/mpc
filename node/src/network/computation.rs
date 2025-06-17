use tracing::info;

use super::NetworkTaskChannel;
use crate::tracking;
use std::future::Future;

/// Interface for a computation that is leader-centric:
///  - If any follower's computation returns error, it automatically sends an Abort message to
///    the leader, causing the leader to fail as well.
///  - If the leader's computation returns error, it automatically sends an Abort message to
///    all followers, causing their computation to fail as well.
///
/// If leader_waits_for_success returns true, then additionally:
///  - Followers who succeed send a Success message to the leader.
///  - The leader will wait for all Success messages before returning.
///
/// The leader_waits_for_success is for asset generation, where the owner of the asset wants
/// to only mark it as completed when all followers have persisted their share of the asset.
#[async_trait::async_trait]
pub trait MpcLeaderCentricComputation<T>: Sized + 'static {
    /// Performs the computation itself, without worrying about failure propagation or
    /// waiting for success of followers.
    async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<T>;
    fn leader_waits_for_success(&self) -> bool;

    /// Performs the computation. DO NOT override this function.
    fn perform_leader_centric_computation(
        self,
        mut channel: NetworkTaskChannel,
        timeout: std::time::Duration,
    ) -> impl Future<Output = anyhow::Result<T>> + 'static {
        let leader_waits_for_success = self.leader_waits_for_success();
        let sender = channel.sender();
        let sender_clone = sender.clone();

        // We'll wrap the following future in a timeout below.
        let fut = async move {
            if !sender.is_leader() {
                sender.initialize_all_participants_connections().await?;
            }
            let result = self.compute(&mut channel).await;
            let result = match result {
                Ok(result) => result,
                Err(err) => {
                    sender.communicate_failure(&err);
                    return Err(err);
                }
            };
            if leader_waits_for_success && sender.is_leader() {
                if let Err(err) = channel.wait_for_followers_to_succeed().await {
                    sender.communicate_failure(&err);
                    return Err(err);
                }
            }
            Ok(result)
        };

        async move {
            let sender = sender_clone;
            let result = tokio::time::timeout(timeout, fut).await;
            let result = match result {
                Ok(result) => result,
                Err(_) => {
                    let err = anyhow::anyhow!("Timeout");
                    sender.communicate_failure(&err);
                    return Err(err);
                }
            };
            if result.is_ok() {
                if !sender.is_leader() && leader_waits_for_success {
                    sender.communicate_success()?;
                }
                tracking::set_progress("Computation complete");
            }
            result
        }
    }
}
