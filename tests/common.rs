#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::HashMap;

use rand::Rng;
use rand_core::OsRng;

use threshold_signatures::{
    self,
    errors::ProtocolError,
    keygen,
    participants::Participant,
    protocol::{Action, Protocol},
    Ciphersuite, Element, KeygenOutput, Scalar,
};

pub type GenProtocol<C> = Vec<(Participant, Box<dyn Protocol<Output = C>>)>;

pub fn generate_participants(number: u32) -> Vec<Participant> {
    (0..number).map(Participant::from).collect::<Vec<_>>()
}

pub fn choose_coordinator_at_random(participants: &[Participant]) -> Participant {
    let index = rand::rngs::OsRng.gen_range(0..participants.len());
    participants[index]
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

#[allow(clippy::missing_panics_doc)]
pub fn run_keygen<C: Ciphersuite>(
    participants: &[Participant],
    threshold: usize,
) -> HashMap<Participant, KeygenOutput<C>>
where
    Element<C>: std::marker::Send,
    Scalar<C>: std::marker::Send,
{
    let protocols: GenProtocol<KeygenOutput<C>> = participants
        .iter()
        .map(|p| {
            let protocol: Box<dyn Protocol<Output = KeygenOutput<C>>> =
                Box::new(keygen::<C>(participants, *p, threshold, OsRng).unwrap());
            (*p, protocol)
        })
        .collect();

    run_protocol(protocols).unwrap().into_iter().collect()
}
