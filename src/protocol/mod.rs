//! This module provides abstractions for working with protocols.
//!
//! This library tries to abstract away as much of the internal machinery
//! of protocols as much as possible. To use a protocol, you just need to be able
//! to deliver messages to and from that protocol, and eventually it will produce
//! a result, without you having to worry about how many rounds it has, or how
//! to serialize the emssages it produces.
pub(crate) mod echo_broadcast;
pub(crate) mod helpers;
pub(crate) mod internal;

use crate::errors::ProtocolError;
use crate::participants::Participant;

/// Represents the data making up a message.
///
/// We choose to just represent messages as opaque vectors of bytes, with all
/// the serialization logic handled internally.
pub type MessageData = Vec<u8>;

/// Represents an action by a participant in the protocol.
///
/// The basic flow is that each participant receives messages from other participants,
/// and then reacts with some kind of action.
///
/// This action can consist of sending a message, doing nothing, etc.
///
/// Eventually, the participant returns a value, ending the protocol.
#[derive(Debug, Clone)]
pub enum Action<T> {
    /// Don't do anything.
    Wait,
    /// Send a message to all other participants.
    ///
    /// Participants *never* sends messages to themselves.
    SendMany(MessageData),
    /// Send a private message to another participant.
    ///
    /// It's imperactive that only this participant can read this message,
    /// so you might want to use some form of encryption.
    SendPrivate(Participant, MessageData),
    /// End the protocol by returning a value.
    Return(T),
}

/// A trait for protocols.
///
/// Basically, this represents a struct for the behavior of a single participant
/// in a protocol. The idea is that the computation of that participant is driven
/// mainly by receiving messages from other participants.
pub trait Protocol {
    type Output;

    /// Poke the protocol, receiving a new action.
    ///
    /// The idea is that the protocol should be poked until it returns an error,
    /// or it returns an action with a return value, or it returns a wait action.
    ///
    /// Upon returning a wait action, that protocol will not advance any further
    /// until a new message arrives.
    fn poke(&mut self) -> Result<Action<Self::Output>, ProtocolError>;

    /// Inform the protocol of a new message.
    fn message(&mut self, from: Participant, data: MessageData);
}
