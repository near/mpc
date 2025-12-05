use crate::participants::Participant;
use crate::protocol::MessageData;
use crate::test_utils::snapshot::ProtocolSnapshot;

pub struct Simulator {
    /// the `real_participant` we are simulating for
    real_participant: Participant,
    /// the `real_participant` view to deliver
    view: Vec<(Participant, MessageData)>,
}

impl Simulator {
    pub fn new(real_participant: Participant, protocol_snap: ProtocolSnapshot) -> Option<Self> {
        if protocol_snap.number_of_participants() <= 1 {
            return None;
        }
        protocol_snap
            .get_received_messages(&real_participant)
            .map(|view| Self {
                real_participant,
                view,
            })
    }

    pub fn real_participant(&self) -> Participant {
        self.real_participant
    }

    pub fn get_recorded_messages(self) -> Vec<(Participant, MessageData)> {
        self.view
    }
}
