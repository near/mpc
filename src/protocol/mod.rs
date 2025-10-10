//! This module provides abstractions for working with protocols.
//!
//! This library tries to abstract away as much of the internal machinery
//! of protocols as much as possible. To use a protocol, you just need to be able
//! to deliver messages to and from that protocol, and eventually it will produce
//! a result, without you having to worry about how many rounds it has, or how
//! to serialize the emssages it produces.
pub(crate) mod echo_broadcast;
pub(crate) mod internal;

use std::collections::HashMap;

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

/// Run a protocol to completion, synchronously.
///
/// This works by executing each participant in order.
///
/// The reason this function exists is as a convenient testing utility.
/// In practice each protocol participant is likely running on a different machine,
/// and so orchestrating the protocol would happen differently.
pub fn run_protocol<T>(
    mut ps: Vec<(Participant, Box<dyn Protocol<Output = T>>)>,
) -> Result<Vec<(Participant, T)>, ProtocolError> {
    let indices: HashMap<Participant, usize> =
        ps.iter().enumerate().map(|(i, (p, _))| (*p, i)).collect();

    let size = ps.len();
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        for i in 0..size {
            while {
                let action = ps[i].1.poke()?;
                match action {
                    Action::Wait => false,
                    Action::SendMany(m) => {
                        for j in 0..size {
                            if i == j {
                                continue;
                            }
                            let from = ps[i].0;
                            ps[j].1.message(from, m.clone());
                        }
                        true
                    }
                    Action::SendPrivate(to, m) => {
                        let from = ps[i].0;
                        ps[indices[&to]].1.message(from, m);
                        true
                    }
                    Action::Return(r) => {
                        out.push((ps[i].0, r));
                        false
                    }
                }
            } {}
        }
    }

    Ok(out)
}

#[cfg(test)]
pub mod test {
    use std::fmt;

    use crate::errors::ProtocolError;
    use crate::protocol::{Action, Participant, Protocol};

    /// Like [`run_protocol()`], except for just two parties.
    ///
    /// This is more useful for testing two party protocols with assymetric results,
    /// since the return types for the two protocols can be different.
    pub fn run_two_party_protocol<T0: fmt::Debug, T1: fmt::Debug>(
        p0: Participant,
        p1: Participant,
        prot0: &mut dyn Protocol<Output = T0>,
        prot1: &mut dyn Protocol<Output = T1>,
    ) -> Result<(T0, T1), ProtocolError> {
        let mut active0 = true;

        let mut out0 = None;
        let mut out1 = None;

        while out0.is_none() || out1.is_none() {
            if active0 {
                let action = prot0.poke()?;
                match action {
                    Action::Wait => active0 = false,
                    Action::SendMany(m) => prot1.message(p0, m),
                    Action::SendPrivate(to, m) if to == p1 => {
                        prot1.message(p0, m);
                    }
                    Action::Return(out) => out0 = Some(out),
                    // Ignore other actions, which means sending private messages to other people.
                    Action::SendPrivate(..) => {}
                }
            } else {
                let action = prot1.poke()?;
                match action {
                    Action::Wait => active0 = true,
                    Action::SendMany(m) => prot0.message(p1, m),
                    Action::SendPrivate(to, m) if to == p0 => {
                        prot0.message(p1, m);
                    }
                    Action::Return(out) => out1 = Some(out),
                    // Ignore other actions, which means sending private messages to other people.
                    Action::SendPrivate(..) => {}
                }
            }
        }

        Ok((
            out0.ok_or_else(|| ProtocolError::Other("out0 is None".to_string()))?,
            out1.ok_or_else(|| ProtocolError::Other("out1 is None".to_string()))?,
        ))
    }
}
