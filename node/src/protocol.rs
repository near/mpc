use crate::network::NetworkTaskChannel;
use crate::primitives::ParticipantId;
use crate::tracking;
use cait_sith::protocol::{Action, Protocol};

pub async fn run_protocol<T>(
    name: &'static str,
    mut channel: NetworkTaskChannel,
    participants: Vec<ParticipantId>,
    me: ParticipantId,
    mut protocol: impl Protocol<Output = T>,
) -> anyhow::Result<T> {
    let mut actions_taken = 0;
    let mut messages_sent = vec![0; participants.len()];
    let mut messages_received = vec![0; participants.len()];
    let result = 'outer: loop {
        loop {
            actions_taken += 1;
            match protocol.poke()? {
                Action::Wait => break,
                Action::SendMany(vec) => {
                    for participant in &participants {
                        if participant == &me {
                            continue;
                        }
                        channel.send(*participant, vec.clone()).await?;
                        messages_sent[participant.0 as usize] += 1;
                    }
                }
                Action::SendPrivate(participant, vec) => {
                    channel.send(ParticipantId(participant.into()), vec).await?;
                    messages_sent[u32::from(participant) as usize] += 1;
                }
                Action::Return(result) => break 'outer result,
            }
        }
        tracking::set_progress(&format!(
            "{}: steps {}, tx {:?}, rx {:?}",
            name, actions_taken, messages_sent, messages_received
        ));

        let msg = channel.receive().await?;
        messages_received[msg.from.0 as usize] += 1;
        protocol.message(msg.from.into(), msg.message.data);
    };
    Ok(result)
}
