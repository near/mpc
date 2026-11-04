use super::handler::ChainBlockUpdate;
use near_indexer_primitives::CryptoHash;
use near_indexer_primitives::types::BlockHeight;
use tokio::sync::{mpsc, oneshot};

/// Blocks to apply in order, as one unit.
pub struct ChainBatch {
    pub blocks: Vec<ChainBlockUpdate>,
    /// The canonical head after this batch. Set by the HTTP indexer, which
    /// replays retained history and may replace a head at the same height.
    pub head: Option<(CryptoHash, BlockHeight)>,
    /// The first block need not descend from any block delivered before, so the
    /// consumer must forget the block ancestry it tracks. Set by the HTTP
    /// indexer when it skips history whose requests have all expired.
    pub discontinuous: bool,
    /// Signaled once every block is applied, so the sender may persist its
    /// checkpoint. A batch dropped unacknowledged is replayed after a restart.
    pub acknowledge: Option<oneshot::Sender<()>>,
}

impl From<ChainBlockUpdate> for ChainBatch {
    fn from(block: ChainBlockUpdate) -> Self {
        Self {
            blocks: vec![block],
            head: None,
            discontinuous: false,
            acknowledge: None,
        }
    }
}

/// Receives a fresh batch sender each time a consumer starts.
pub type ConsumerStarts = mpsc::UnboundedReceiver<mpsc::UnboundedSender<ChainBatch>>;

/// The consuming end of the block feed.
///
/// The embedded indexer streams into one channel that buffers while no consumer
/// runs. The HTTP indexer instead replays retained history to each new consumer,
/// so [`Self::restart`] discards whatever the previous consumer left unapplied.
pub struct BlockUpdateReceiver {
    receiver: mpsc::UnboundedReceiver<ChainBatch>,
    restart: Option<mpsc::UnboundedSender<mpsc::UnboundedSender<ChainBatch>>>,
}

impl BlockUpdateReceiver {
    #[cfg(any(feature = "embedded-node", test))]
    pub fn buffered(receiver: mpsc::UnboundedReceiver<ChainBatch>) -> Self {
        Self {
            receiver,
            restart: None,
        }
    }

    pub fn replayed() -> (Self, ConsumerStarts) {
        let (_, receiver) = mpsc::unbounded_channel();
        let (restart, starts) = mpsc::unbounded_channel();
        (
            Self {
                receiver,
                restart: Some(restart),
            },
            starts,
        )
    }

    /// Called by each new consumer before its first [`Self::recv`].
    pub fn restart(&mut self) -> anyhow::Result<()> {
        if let Some(restart) = &self.restart {
            let (sender, receiver) = mpsc::unbounded_channel();
            self.receiver = receiver;
            restart
                .send(sender)
                .map_err(|_| anyhow::anyhow!("the HTTP indexer has stopped"))?;
        }
        Ok(())
    }

    pub async fn recv(&mut self) -> Option<ChainBatch> {
        self.receiver.recv().await
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{BlockUpdateReceiver, ChainBatch};
    use near_indexer_primitives::CryptoHash;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn restart__should_drop_stale_batches_and_their_acknowledgements() {
        // Given
        let (mut receiver, mut starts) = BlockUpdateReceiver::replayed();
        receiver.restart().unwrap();
        let stale_sender = starts.recv().await.unwrap();
        let (acknowledge, acknowledged) = oneshot::channel();
        stale_sender
            .send(ChainBatch {
                blocks: vec![],
                head: None,
                discontinuous: false,
                acknowledge: Some(acknowledge),
            })
            .map_err(|_| "consumer closed")
            .unwrap();

        // When
        receiver.restart().unwrap();
        let sender = starts.recv().await.unwrap();
        sender
            .send(ChainBatch {
                blocks: vec![],
                head: Some((CryptoHash([1; 32]), 10)),
                discontinuous: false,
                acknowledge: None,
            })
            .map_err(|_| "consumer closed")
            .unwrap();
        let batch = receiver.recv().await.unwrap();

        // Then
        acknowledged.await.unwrap_err();
        assert!(stale_sender.is_closed());
        assert_eq!(batch.head, Some((CryptoHash([1; 32]), 10)));
    }

    #[tokio::test]
    async fn restart__should_keep_buffered_batches() {
        // Given
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        let mut receiver = BlockUpdateReceiver::buffered(receiver);
        sender
            .send(ChainBatch {
                blocks: vec![],
                head: Some((CryptoHash([2; 32]), 20)),
                discontinuous: false,
                acknowledge: None,
            })
            .map_err(|_| "consumer closed")
            .unwrap();

        // When
        receiver.restart().unwrap();
        let batch = receiver.recv().await.unwrap();

        // Then
        assert_eq!(batch.head, Some((CryptoHash([2; 32]), 20)));
    }
}
