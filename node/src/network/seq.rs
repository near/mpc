use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::VecDeque;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub type GenericMessage = Vec<u8>;

pub struct ReliableSenderState {
    reliability_token: CancellationToken,
    last_ack: u64,
    pending_msgs: VecDeque<GenericMessage>,
    current_sender: Option<mpsc::UnboundedSender<MessageWithSeq>>,
}

pub struct ReliableReceiverState {
    last_recv_seq: u64,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ReliableSenderHandshake {
    pub last_sent: u64,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ReliableReceiverHandshake {
    pub last_recv_seq: u64,
}

#[derive(Debug, Clone)]
pub struct MessageWithSeq {
    pub seq: u64,
    pub msg: GenericMessage,
}

impl ReliableSenderState {
    pub fn new() -> Self {
        Self {
            reliability_token: CancellationToken::new(),
            last_ack: 0,
            pending_msgs: VecDeque::new(),
            current_sender: None,
        }
    }

    fn last_sent(&self) -> u64 {
        self.last_ack + self.pending_msgs.len() as u64
    }

    pub fn send(&mut self, msg: GenericMessage) {
        self.pending_msgs.push_back(msg.clone());
        self.maybe_send(msg, self.last_sent());
    }

    fn maybe_send(&mut self, msg: GenericMessage, seq: u64) {
        if let Some(sender) = self.current_sender.as_ref() {
            if sender.send(MessageWithSeq { msg, seq }).is_err() {
                self.current_sender = None;
            }
        }
    }

    pub fn on_new_connection(
        &mut self,
        handshake: &ReliableReceiverHandshake,
        sender: mpsc::UnboundedSender<MessageWithSeq>,
    ) -> anyhow::Result<()> {
        let last_recv_seq = handshake.last_recv_seq;
        if last_recv_seq == 0 && self.last_ack != 0 {
            self.reset();
            self.current_sender = Some(sender);
            Ok(())
        } else if last_recv_seq < self.last_ack {
            Err(anyhow::anyhow!(
                "Invalid handshake; last_recv_seq ({}) < last_ack ({})",
                last_recv_seq,
                self.last_ack
            ))
        } else if self.last_sent() < last_recv_seq {
            Err(anyhow::anyhow!(
                "Invalid handshake; last_sent ({}) < last_recv_seq ({})",
                last_recv_seq,
                self.last_sent()
            ))
        } else {
            while self.last_ack < last_recv_seq {
                self.pending_msgs.pop_front();
                self.last_ack += 1;
            }
            self.current_sender = Some(sender);
            let msgs_to_send = self.pending_msgs.iter().cloned().collect::<Vec<_>>();
            for (i, msg) in msgs_to_send.into_iter().enumerate() {
                self.maybe_send(msg.clone(), last_recv_seq + i as u64 + 1);
            }
            Ok(())
        }
    }

    pub fn on_ack(&mut self, ack: u64) -> anyhow::Result<()> {
        if ack == self.last_ack + 1 {
            self.pending_msgs.pop_front();
            self.last_ack = ack;
            Ok(())
        } else {
            self.reset();
            Err(anyhow::anyhow!("Invalid ack"))
        }
    }

    fn reset(&mut self) {
        self.last_ack = 0;
        self.pending_msgs.clear();
        self.reliability_token.cancel();
        self.reliability_token = CancellationToken::new();
    }

    pub fn handshake(&self) -> ReliableSenderHandshake {
        ReliableSenderHandshake {
            last_sent: self.last_sent(),
        }
    }

    pub fn reliability_token(&self) -> CancellationToken {
        self.reliability_token.clone()
    }
}

impl ReliableReceiverState {
    pub fn new() -> Self {
        Self { last_recv_seq: 0 }
    }

    pub fn on_recv(&mut self, seq: u64) -> anyhow::Result<()> {
        if seq == self.last_recv_seq + 1 {
            self.last_recv_seq = seq;
            Ok(())
        } else {
            self.reset();
            Err(anyhow::anyhow!("Invalid seq"))
        }
    }

    pub fn on_handshake(
        &mut self,
        handshake: &ReliableSenderHandshake,
    ) -> anyhow::Result<ReliableReceiverHandshakeResult> {
        let last_sent = handshake.last_sent;
        if last_sent == 0 && self.last_recv_seq != 0 {
            self.reset();
            Ok(ReliableReceiverHandshakeResult::ResetConnection)
        } else if last_sent < self.last_recv_seq {
            Err(anyhow::anyhow!(
                "Invalid handshake; last_sent ({}) < last_recv_seq ({})",
                last_sent,
                self.last_recv_seq
            ))
        } else {
            Ok(ReliableReceiverHandshakeResult::ContinueConnection)
        }
    }

    pub fn handshake(&self) -> ReliableReceiverHandshake {
        ReliableReceiverHandshake {
            last_recv_seq: self.last_recv_seq,
        }
    }

    fn reset(&mut self) {
        self.last_recv_seq = 0;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReliableReceiverHandshakeResult {
    ResetConnection,
    ContinueConnection,
}
