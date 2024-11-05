use cait_sith::{
    protocol::{Action, Participant, Protocol},
    triples::TripleGenerationOutput,
};
use k256::Secp256k1;

use crate::tracking::{self};
use crate::{network::NetworkTaskChannel, primitives::ParticipantId};

/// Generates a cait-sith triple.
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

/// Generates a random ID to identify a triple. It has no meaning beyond being
/// an identifier. It is generated in a way such that each participant will
/// generate different IDs. This is useful to ensure that IDs from different
/// participants will not collide.
///
/// There is, however, a chance that the same participant generates an ID that
/// already existed before, so the existence of a triple of such an ID must be
/// checked before using it.
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

    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const PARALLELISM_PER_CLIENT: usize = 4;
    const TRIPLES_TO_GENERATE_PER_CLIENT: usize = 10;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_triple_generation() {
        init_logging();
        tracking::testing::start_root_task_with_periodic_dump(async {
            let results = run_test_clients(NUM_PARTICIPANTS, run_triple_gen_client)
                .await
                .unwrap();
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
                            THRESHOLD,
                        ),
                    );
                }
            });
        }

        let triples = stream::iter(0..TRIPLES_TO_GENERATE_PER_CLIENT)
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
                            THRESHOLD,
                        ),
                    )
                    .await??;
                    anyhow::Ok(result)
                }
            })
            .buffered(PARALLELISM_PER_CLIENT)
            .try_collect::<Vec<_>>()
            .await?;

        Ok(triples)
    }
}
