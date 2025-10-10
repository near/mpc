#![allow(clippy::unwrap_used)]
use std::collections::HashMap;

use rand::Rng;
use rand_core::OsRng;

use threshold_signatures::{
    self, keygen,
    protocol::{run_protocol, Participant, Protocol},
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
