use crate::network::{
    run_network_client, MeshNetworkClient, MeshNetworkTransportReceiver,
    MeshNetworkTransportSender, NetworkTaskChannel,
};
use crate::primitives::{MpcMessage, MpcPeerMessage, ParticipantId};
use crate::tracking;
use async_trait::async_trait;
use near_async::test_loop::pending_events_sender::PendingEventsSender;
use near_async::test_loop::TestLoopV2;
use near_time::Duration;
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct TestParticipantData {
    pub latency_to: Vec<Duration>,
}

pub struct TestLoopNetworkSetup {
    test_loop_sender: PendingEventsSender,
    participants: Vec<TestParticipantData>,
    recipient_senders: Vec<mpsc::Sender<MpcPeerMessage>>,
}

pub struct TestLoopNetworkSender {
    setup: Arc<TestLoopNetworkSetup>,
    myself: ParticipantId,
}

pub struct TestLoopNetworkReceiver {
    receiver: mpsc::Receiver<MpcPeerMessage>,
}

#[async_trait]
impl MeshNetworkTransportSender for TestLoopNetworkSender {
    fn my_participant_id(&self) -> ParticipantId {
        self.myself
    }
    fn all_participant_ids(&self) -> Vec<ParticipantId> {
        (0..self.setup.participants.len() as u32)
            .map(ParticipantId)
            .collect()
    }

    async fn send(&self, recipient_id: ParticipantId, message: MpcMessage) -> anyhow::Result<()> {
        let sender = self
            .setup
            .test_loop_sender
            .clone()
            .for_index(self.myself.0 as usize);
        let delay =
            self.setup.participants[self.myself.0 as usize].latency_to[recipient_id.0 as usize];
        let recipient_sender = self
            .setup
            .test_loop_sender
            .clone()
            .for_index(recipient_id.0 as usize);
        let recipient_message_sender =
            self.setup.recipient_senders[recipient_id.0 as usize].clone();
        let myself = self.myself;
        recipient_sender.send_with_delay(
            format!("IncomingMessage({:?})", message),
            Box::new(move |_| {
                recipient_message_sender
                    .try_send(MpcPeerMessage {
                        from: myself,
                        message,
                    })
                    .expect("Sending would saturate the channel");
            }),
            delay,
        );
        // sender.send(
        //     format!("OutgoingMessage({:?})", message),
        //     Box::new(move |_| {
        //         recipient_sender.send_with_delay(
        //             format!("IncomingMessage({:?})", message),
        //             Box::new(move |_| {
        //                 recipient_message_sender
        //                     .try_send(MpcPeerMessage {
        //                         from: myself,
        //                         message,
        //                     })
        //                     .expect("Sending would saturate the channel");
        //             }),
        //             delay,
        //         );
        //     }),
        // );
        Ok(())
    }

    async fn wait_for_ready(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[async_trait]
impl MeshNetworkTransportReceiver for TestLoopNetworkReceiver {
    async fn receive(&mut self) -> anyhow::Result<MpcPeerMessage> {
        self.receiver
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("Channel closed while waiting for message"))
    }
}

pub fn create_test_loop_network_transport(
    test_loop_sender: PendingEventsSender,
    participants: Vec<TestParticipantData>,
) -> (
    Arc<TestLoopNetworkSetup>,
    Vec<(TestLoopNetworkSender, TestLoopNetworkReceiver)>,
) {
    let mut recipient_senders = Vec::new();
    let mut receivers = Vec::new();

    for _ in 0..participants.len() {
        let (sender, receiver) = mpsc::channel(10000);
        recipient_senders.push(sender);
        receivers.push(TestLoopNetworkReceiver { receiver });
    }

    let setup = Arc::new(TestLoopNetworkSetup {
        test_loop_sender,
        participants,
        recipient_senders,
    });

    let mut transports = Vec::new();
    for (i, receiver) in receivers.into_iter().enumerate() {
        transports.push((
            TestLoopNetworkSender {
                setup: setup.clone(),
                myself: ParticipantId(i as u32),
            },
            receiver,
        ));
    }

    (setup, transports)
}

pub fn run_testloop_clients<T: 'static + Send, F, FR>(
    participants: Vec<TestParticipantData>,
    client_runner: F,
    duration: Duration,
) where
    F: Fn(Arc<MeshNetworkClient>, tokio::sync::mpsc::Receiver<NetworkTaskChannel>) -> FR
        + Send
        + Clone
        + 'static,
    FR: std::future::Future<Output = anyhow::Result<T>> + Send + 'static,
{
    let mut testloop = TestLoopV2::new();
    let (_, transports) = create_test_loop_network_transport(testloop.sender(), participants);

    for (i, (sender, receiver)) in transports.into_iter().enumerate() {
        let client_runner = client_runner.clone();
        tracking::testing::start_root_task_in_test_loop(
            async move {
                let (client, new_channel_receiver) =
                    run_network_client(Arc::new(sender), Box::new(receiver));
                client_runner(client, new_channel_receiver).await.unwrap();
            },
            testloop.sender().for_index(i),
        );
    }

    testloop.run_for(duration);
}
