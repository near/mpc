use super::handler::ChainBlockUpdate;
use near_indexer_primitives::CryptoHash;
use tokio::sync::{mpsc, oneshot};

pub struct ChainBatch {
    pub blocks: Vec<ChainBlockUpdate>,
    pub head: Option<(CryptoHash, u64)>,
    pub acknowledge: Option<oneshot::Sender<()>>,
}

impl From<ChainBlockUpdate> for ChainBatch {
    fn from(block: ChainBlockUpdate) -> Self {
        Self {
            blocks: vec![block],
            head: None,
            acknowledge: None,
        }
    }
}

pub type ConsumerStarts = mpsc::UnboundedReceiver<mpsc::UnboundedSender<ChainBatch>>;

pub struct BlockUpdateReceiver {
    receiver: mpsc::UnboundedReceiver<ChainBatch>,
    restart: Option<mpsc::UnboundedSender<mpsc::UnboundedSender<ChainBatch>>>,
}

impl BlockUpdateReceiver {
    pub fn legacy(receiver: mpsc::UnboundedReceiver<ChainBatch>) -> Self {
        Self {
            receiver,
            restart: None,
        }
    }

    pub fn http() -> (Self, ConsumerStarts) {
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

    pub fn restart(&mut self) -> anyhow::Result<()> {
        if let Some(restart) = &self.restart {
            let (sender, receiver) = mpsc::unbounded_channel();
            self.receiver = receiver;
            restart
                .send(sender)
                .map_err(|_| anyhow::anyhow!("HTTP indexer has stopped"))?;
        }
        Ok(())
    }

    pub async fn recv(&mut self) -> Option<ChainBatch> {
        self.receiver.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[expect(non_snake_case)]
    async fn consumer_restart__should_drop_stale_batches_and_acknowledgements() {
        // Given
        let (mut receiver, mut starts) = BlockUpdateReceiver::http();
        receiver.restart().unwrap();
        let stale_sender = starts.recv().await.unwrap();
        let (acknowledge, acknowledged) = oneshot::channel();
        stale_sender
            .send(ChainBatch {
                blocks: vec![],
                head: None,
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
}
