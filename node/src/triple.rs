use cait_sith::{
    protocol::{Action, Participant, Protocol},
    triples::TripleGenerationOutput,
};
use k256::Secp256k1;

use crate::tracking::{self};
use crate::{network::NetworkTaskChannel, primitives::ParticipantId};

pub async fn run_triple_generation(
    mut channel: NetworkTaskChannel,
    participants: Vec<ParticipantId>,
    me: ParticipantId,
    threshold: usize,
) -> anyhow::Result<TripleGenerationOutput<Secp256k1>> {
    let cs_participants = participants
        .iter()
        .copied()
        .map(Participant::from)
        .collect::<Vec<_>>();
    let mut protocol =
        cait_sith::triples::generate_triple::<Secp256k1>(&cs_participants, me.into(), threshold)?;
    let mut actions_taken = 0;
    let mut messages_sent = 0;
    let mut messages_received = 0;
    let triple = 'outer: loop {
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
                        messages_sent += 1;
                    }
                }
                Action::SendPrivate(participant, vec) => {
                    channel.send(ParticipantId(participant.into()), vec).await?;
                    messages_sent += 1;
                }
                Action::Return(result) => break 'outer result,
            }
        }
        tracking::set_progress(&format!(
            "steps {}, tx {}, rx {}",
            actions_taken, messages_sent, messages_received
        ));

        let msg = channel.receive().await?;
        protocol.message(msg.from.into(), msg.message.data);
        messages_received += 1;
    };

    Ok(triple)
}

pub fn generate_triple_id(me: ParticipantId) -> u64 {
    rand::random::<u64>() << 12 | me.0 as u64
}

#[cfg(test)]
mod tests {
    use crate::network::testing::run_test_clients;
    use crate::network::{MeshNetworkClient, NetworkTaskChannel};
    use crate::primitives::MpcTaskId;
    use crate::tracing::init_logging;
    use cait_sith::triples::TripleGenerationOutput;
    use futures::{stream, StreamExt, TryStreamExt};
    use k256::Secp256k1;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    use super::{generate_triple_id, run_triple_generation};
    use crate::tracking;

    #[tokio::test]
    async fn test_triple_generation() {
        init_logging();
        tracking::testing::start_root_task_with_periodic_dump(async {
            let results = run_test_clients(4, run_triple_gen_client).await.unwrap();
            println!("{:?}", results);
        })
        .await;
    }

    async fn run_triple_gen_client(
        client: Arc<MeshNetworkClient>,
        mut channel_receiver: mpsc::Receiver<NetworkTaskChannel>,
    ) -> anyhow::Result<Vec<TripleGenerationOutput<Secp256k1>>> {
        {
            let client = client.clone();
            let participant_id = client.my_participant_id();
            let all_participant_ids = client.all_participant_ids();
            tracking::spawn("monitor passive channels", async move {
                loop {
                    let channel = channel_receiver.recv().await.unwrap();
                    tracking::spawn(
                        &format!("passive task {:?}", channel.task_id),
                        run_triple_generation(
                            channel,
                            all_participant_ids.clone(),
                            participant_id,
                            3,
                        ),
                    );
                }
            });
        }

        let triples = stream::iter(0..10)
            .map(move |_| {
                let client = client.clone();
                async move {
                    let participant_id = client.my_participant_id();
                    let all_participant_ids = client.all_participant_ids();
                    let task_id = MpcTaskId::Triple(generate_triple_id(participant_id));
                    let result = tracking::spawn(
                        &format!("task {:?}", task_id),
                        run_triple_generation(
                            client.new_channel_for_task(task_id)?,
                            all_participant_ids.clone(),
                            participant_id,
                            3,
                        ),
                    )
                    .await??;
                    anyhow::Ok(result)
                }
            })
            .buffered(4)
            .try_collect::<Vec<_>>()
            .await?;

        Ok(triples)
    }
}
