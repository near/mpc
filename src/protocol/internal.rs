//! This module exists to provide internal utilities to construct protocols.
//!
//! The [`Protocol`] protocol interface is designed to be easy for outside consumers of the library to use.
//! Internally, we implement protocols by creating a state machine, which can switch between
//! the different states.
//!
//! Writing such a state machine by hand is extremely tedious. You'd need to create logic
//! to buffer messages for different rounds, and to wait for new messages to arrive.
//! This kind of mixing of state machine logic around networking and cryptography is also
//! very error prone, and makes the resulting code harder to understand.
//!
//! Thankfully, Rust already has a great tool for writing state machines: **async**!
//!
//! This module is about creating async utilities, and then providing a way to convert
//! a future created with async/await, which is just a state machine, into an instance
//! of the protocol interface.
//!
//! The basic idea is that you write your protocol using async await, with async functions
//! for sending and receiving messages.
//!
//! The tricky part is coordinating which round messages belong to.
//! The basic idea here is to use *waitpoints*. Each waitpoint represents a distinct point
//! in the protocol. This is sort of like rounds, except that waitpoints don't necessarily
//! have to follow each other sequentially. For example, you can send on waitpoint A,
//! and then on waitpoint B, without first waiting to receive messages from waitpoint A.
//! This kind of decomposition can lead to better performance, and better matches what the
//! dependencies between messages in the protocol actually are.
//!
//! We also need a good way to handle concurrent composition of protocols.
//! This is mainly useful for some more advanced protocols, like triple generation, where we might
//! want to run multiple two-party protocols in parallel across an entire group of participants.
//! To do this, we also need some notion of channel in addition to waitpoints, and the ability
//! to have distinct channels to communicate on.
//!
//! We have two basic kinds of channels: channels which are intended to be shared to communicate
//! to all other participants, and channels which are supposed to be used for two-party
//! protocols. The two kinds won't conflict with each other. Given a channel, we can
//! also get new unique *children* channels, whose children will also be unique.
//!
//! One paramount thing about the identification system for channels is that both parties
//! agree on what the identifier for the channels in each part of the protocol is.
//! This is why we have to take great care that the identifiers a protocol will produce
//! are deterministic, even in the presence of concurrent tasks.
use super::{Action, MessageData, Participant, Protocol, ProtocolError};
use futures::future::BoxFuture;
use futures::task::noop_waker;
use futures::{FutureExt, StreamExt};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use smol::{future, lock::Mutex};
use std::collections::VecDeque;
use std::task::Context;
use std::{collections::HashMap, error, future::Future, sync::Arc};

use crate::crypto::constants::NEAR_CHANNEL_TAGS_DOMAIN;

/// Encode an arbitrary serializable with a tag.
fn encode_with_tag<T: Serialize>(tag: &[u8], val: &T) -> Result<Vec<u8>, ProtocolError> {
    // Matches rmp_serde's internal default.
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(tag);
    rmp_serde::encode::write(&mut out, val).map_err(|_| ProtocolError::ErrorEncoding)?;
    Ok(out)
}

/// Represents a unique tag for a channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Hash)]
struct ChannelTag([u8; Self::SIZE]);

impl ChannelTag {
    /// 256 bit tags, enough for 128 bits of collision security, which should be ample.
    const SIZE: usize = 32;
    /// The channel tag for a shared channel.
    ///
    /// This will always yield the same tag, and is intended to be the root for shared channels.
    fn root_shared() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(NEAR_CHANNEL_TAGS_DOMAIN);
        hasher.update(b"root shared");
        let out = hasher.finalize().into();
        Self(out)
    }

    /// The channel tag for a private channel.
    ///
    /// This will always yield the same tag, and is intended to be the root for private channels.
    ///
    /// This tag will depend on the set of participants used; the order they're passed into this
    /// function does not matter.
    fn root_private(p0: Participant, p1: Participant) -> Self {
        // Sort participants, for uniqueness.
        let (p0, p1) = (p0.min(p1), p0.max(p1));

        let mut hasher = Sha256::new();
        hasher.update(NEAR_CHANNEL_TAGS_DOMAIN);
        hasher.update(b"root private");
        hasher.update(b"p0");
        hasher.update(p0.bytes());
        hasher.update(b"p1");
        hasher.update(p1.bytes());

        let out = hasher.finalize().into();
        Self(out)
    }

    /// Get the ith child of this tag.
    ///
    /// Each child has its own "namespace", with its children being distinct.
    ///
    /// Indexed children have a separate namespace from named children.
    fn child(&self, i: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(NEAR_CHANNEL_TAGS_DOMAIN);
        hasher.update(b"parent");
        hasher.update(self.0);
        hasher.update(b"i");
        hasher.update(i.to_le_bytes());
        let out = hasher.finalize().into();
        Self(out)
    }
}

/// A waitpoint inside of a channel.
pub type Waitpoint = u64;

/// A header used to route the message.
///
/// This header has a base channel, a sub channel, and then a final waitpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Hash)]
struct MessageHeader {
    /// Identifying the channel.
    channel: ChannelTag,
    /// Identifying the specific waitpoint.
    waitpoint: Waitpoint,
}

impl MessageHeader {
    /// The number of bytes in this encoding.
    const LEN: usize = ChannelTag::SIZE + 8;

    fn new(channel: ChannelTag) -> Self {
        Self {
            channel,
            waitpoint: 0,
        }
    }

    fn to_bytes(self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];

        out[..ChannelTag::SIZE].copy_from_slice(&self.channel.0);
        out[ChannelTag::SIZE..].copy_from_slice(&self.waitpoint.to_le_bytes());

        out
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::LEN {
            return None;
        }
        // Unwrapping is fine because we checked the length already.
        let channel = ChannelTag(
            bytes[..ChannelTag::SIZE]
                .try_into()
                .expect("This cannot fail"),
        );
        let waitpoint = u64::from_le_bytes(
            bytes[ChannelTag::SIZE..Self::LEN]
                .try_into()
                .expect("This cannot fail"),
        );

        Some(Self { channel, waitpoint })
    }

    /// Returns a new header with the waitpoint modified.
    fn with_waitpoint(&self, waitpoint: Waitpoint) -> Self {
        Self {
            channel: self.channel,
            waitpoint,
        }
    }

    /// Modify this header, incrementing the waitpoint.
    fn next_waitpoint(&mut self) -> Waitpoint {
        let out = self.waitpoint;
        self.waitpoint += 1;
        out
    }

    fn child(&self, i: u64) -> Self {
        Self {
            channel: self.channel.child(i),
            waitpoint: 0,
        }
    }
}

struct SubMessageQueue {
    sender: futures::channel::mpsc::UnboundedSender<(Participant, MessageData)>,
    receiver: Arc<Mutex<futures::channel::mpsc::UnboundedReceiver<(Participant, MessageData)>>>,
}

impl SubMessageQueue {
    pub fn send(&self, from: Participant, message: MessageData) {
        // This cannot fail because the receiver is also alive.
        self.sender
            .unbounded_send((from, message))
            .expect("unbound_send should not fail");
    }
}

impl Default for SubMessageQueue {
    fn default() -> Self {
        let (sender, receiver) = futures::channel::mpsc::unbounded();
        Self {
            sender,
            receiver: Arc::new(Mutex::new(receiver)),
        }
    }
}

/// A message buffer is a concurrent data structure to buffer messages.
///
/// The idea is that we can put messages, and have them organized according to the
/// header that addentifies where in the protocol those messages will be needed.
/// This data structure also provides async functions which allow efficiently
/// waiting until a particular message is available, by using events to sleep tasks
/// until a message for that slot has arrived.
#[derive(Clone)]
struct MessageBuffer {
    messages: Arc<std::sync::Mutex<HashMap<MessageHeader, SubMessageQueue>>>,
}

impl MessageBuffer {
    fn new() -> Self {
        Self {
            messages: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Push a message into this buffer.
    ///
    /// We also need the header for the message, and the participant who sent it.
    fn push(&self, header: MessageHeader, from: Participant, message: MessageData) {
        let mut messages_lock = self.messages.lock().expect("lock should not fail");
        messages_lock.entry(header).or_default().send(from, message);
    }

    /// Pop a message for a particular header.
    ///
    /// This will block until a message for that header is available. This will
    /// also correctly wake the underlying task when such a message arrives.
    async fn pop(&self, header: MessageHeader) -> (Participant, MessageData) {
        let receiver = {
            let mut messages_lock = self.messages.lock().expect("lock should not fail");
            messages_lock.entry(header).or_default().receiver.clone()
        };
        let mut receiver_lock = receiver.lock().await;
        receiver_lock
            .next()
            .await
            .expect("Reference to sender held")
    }
}

/// Used to represent the different kinds of messages a participant can send.
///
/// This is basically used to communicate between the future and the executor.
#[derive(Debug, Clone)]
pub enum Message {
    Many(MessageData),
    Private(Participant, MessageData),
}

#[derive(Clone)]
pub struct Comms {
    incoming: MessageBuffer,
    outgoing: Arc<std::sync::Mutex<VecDeque<Message>>>,
}

impl Comms {
    pub fn new() -> Self {
        Self {
            incoming: MessageBuffer::new(),
            outgoing: Arc::new(std::sync::Mutex::new(VecDeque::new())),
        }
    }

    fn outgoing(&self) -> Option<Message> {
        let mut outgoing_lock = self.outgoing.lock().expect("lock should not fail");
        outgoing_lock.pop_front()
    }

    fn push_message(&self, from: Participant, message: MessageData) {
        if message.len() < MessageHeader::LEN {
            return;
        }

        let Some(header) = MessageHeader::from_bytes(&message) else {
            return;
        };

        self.incoming.push(header, from, message);
    }

    fn send_raw(&self, data: Message) {
        self.outgoing
            .lock()
            .expect("lock should not fail")
            .push_back(data);
    }

    /// (Indicate that you want to) send a message to everybody else.
    fn send_many<T: Serialize>(
        &self,
        header: MessageHeader,
        data: &T,
    ) -> Result<(), ProtocolError> {
        let header_bytes = header.to_bytes();
        let message_data = encode_with_tag(&header_bytes, data)?;
        self.send_raw(Message::Many(message_data));
        Ok(())
    }

    /// (Indicate that you want to) send a message privately to someone.
    fn send_private<T: Serialize>(
        &self,
        header: MessageHeader,
        to: Participant,
        data: &T,
    ) -> Result<(), ProtocolError> {
        let header_bytes = header.to_bytes();
        let message_data = encode_with_tag(&header_bytes, data)?;
        self.send_raw(Message::Private(to, message_data));
        Ok(())
    }

    async fn recv<T: DeserializeOwned>(
        &self,
        header: MessageHeader,
    ) -> Result<(Participant, T), ProtocolError> {
        let (from, data) = self.incoming.pop(header).await;
        let decoded: Result<T, Box<dyn error::Error + Send + Sync>> =
            rmp_serde::decode::from_slice(&data[MessageHeader::LEN..])
                .map_err(std::convert::Into::into);
        Ok((from, decoded?))
    }

    pub fn private_channel(&self, from: Participant, to: Participant) -> PrivateChannel {
        PrivateChannel::new(self.clone(), from, to)
    }

    pub fn shared_channel(&self) -> SharedChannel {
        SharedChannel::new(self.clone())
    }
}

/// Represents a shared channel.
pub struct SharedChannel {
    header: MessageHeader,
    comms: Comms,
}

impl SharedChannel {
    fn new(comms: Comms) -> Self {
        Self {
            comms,
            header: MessageHeader::new(ChannelTag::root_shared()),
        }
    }

    /// Get the next available waitpoint on this channel.
    pub fn next_waitpoint(&mut self) -> Waitpoint {
        self.header.next_waitpoint()
    }

    pub fn send_many<T: Serialize>(
        &self,
        waitpoint: Waitpoint,
        data: &T,
    ) -> Result<(), ProtocolError> {
        self.comms
            .send_many(self.header.with_waitpoint(waitpoint), data)?;
        Ok(())
    }

    pub fn send_private<T: Serialize>(
        &self,
        waitpoint: Waitpoint,
        to: Participant,
        data: &T,
    ) -> Result<(), ProtocolError> {
        self.comms
            .send_private(self.header.with_waitpoint(waitpoint), to, data)?;
        Ok(())
    }

    pub async fn recv<T: DeserializeOwned>(
        &self,
        waitpoint: Waitpoint,
    ) -> Result<(Participant, T), ProtocolError> {
        self.comms.recv(self.header.with_waitpoint(waitpoint)).await
    }
}

/// Represents a private channel.
///
/// This can be seen as a separate "namespace" for `SharedChannel`.
pub struct PrivateChannel {
    header: MessageHeader,
    to: Participant,
    comms: Comms,
}

impl PrivateChannel {
    fn new(comms: Comms, from: Participant, to: Participant) -> Self {
        Self {
            comms,
            to,
            header: MessageHeader::new(ChannelTag::root_private(from, to)),
        }
    }

    pub fn child(&self, i: u64) -> Self {
        Self {
            comms: self.comms.clone(),
            to: self.to,
            header: self.header.child(i),
        }
    }

    pub fn next_waitpoint(&mut self) -> Waitpoint {
        self.header.next_waitpoint()
    }

    pub fn send<T: Serialize>(&self, waitpoint: Waitpoint, data: &T) -> Result<(), ProtocolError> {
        self.comms
            .send_private(self.header.with_waitpoint(waitpoint), self.to, data)?;
        Ok(())
    }

    pub async fn recv<T: DeserializeOwned>(
        &self,
        waitpoint: Waitpoint,
    ) -> Result<T, ProtocolError> {
        loop {
            let (from, data) = self
                .comms
                .recv(self.header.with_waitpoint(waitpoint))
                .await?;
            if from != self.to {
                future::yield_now().await;
                continue;
            }
            return Ok(data);
        }
    }
}

/// This struct will convert a future into a protocol.
struct ProtocolExecutor<T> {
    comms: Comms,
    fut: Option<BoxFuture<'static, Result<T, ProtocolError>>>,
    result: Option<Result<T, ProtocolError>>,
}

impl<T: Send> ProtocolExecutor<T> {
    fn new(
        comms: Comms,
        fut: impl Future<Output = Result<T, ProtocolError>> + Send + 'static,
    ) -> Self {
        Self {
            comms,
            fut: Some(fut.boxed()),
            result: None,
        }
    }
}

impl<T> Protocol for ProtocolExecutor<T> {
    type Output = T;

    fn poke(&mut self) -> Result<Action<Self::Output>, ProtocolError> {
        let mut polled_once_already = false;
        loop {
            // If there's outgoing messages, request to send them.
            if let Some(outgoing) = self.comms.outgoing() {
                return Ok(match outgoing {
                    Message::Many(m) => Action::SendMany(m),
                    Message::Private(to, m) => Action::SendPrivate(to, m),
                });
            }
            // If we already have a return result, return it.
            if let Some(result) = self.result.take() {
                return Ok(Action::Return(result?));
            }
            // If this is the second iteration, we already polled the future and there's no
            // progress that can be made.
            if polled_once_already {
                return Ok(Action::Wait);
            }
            // If we don't have a future, this is an extraneous poke() call, so return Wait.
            let Some(fut) = self.fut.as_mut() else {
                return Ok(Action::Wait);
            };
            // Now poll the future. It may generate some more messages to send or a return value,
            // so go back and check all of those again.
            polled_once_already = true;
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            if let std::task::Poll::Ready(result) = fut.poll_unpin(&mut cx) {
                self.result = Some(result);
                self.fut = None;
            }
        }
    }

    fn message(&mut self, from: Participant, data: MessageData) {
        self.comms.push_message(from, data);
    }
}

/// Run a protocol, converting a future into an instance of the Protocol trait.
pub fn make_protocol<T: Send>(
    comms: Comms,
    fut: impl Future<Output = Result<T, ProtocolError>> + Send + 'static,
) -> impl Protocol<Output = T> {
    ProtocolExecutor::new(comms, fut)
}
