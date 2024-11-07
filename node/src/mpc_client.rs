use crate::config::MpcConfig;
use crate::key_generation::run_key_generation;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::MpcTaskId;
use crate::tracking;
use crate::triple::{generate_triple_id, run_triple_generation};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Main entry point for the MPC node. Runs all the business logic for doing
/// multiparty computation.
pub async fn run_mpc_client(
    config: Arc<MpcConfig>,
    client: Arc<MeshNetworkClient>,
    mut channel_receiver: mpsc::Receiver<NetworkTaskChannel>,
) -> anyhow::Result<()> {
    // TODO: make it into a config for each kind of task.
    const TASK_TIMEOUT: Duration = Duration::from_secs(5);
    {
        let client = client.clone();
        let config = config.clone();
        tracking::spawn("monitor passive channels", async move {
            loop {
                let channel = channel_receiver.recv().await.unwrap();
                let client = client.clone();
                let config = config.clone();
                tracking::spawn(&format!("passive task {:?}", channel.task_id), async move {
                    match channel.task_id {
                        MpcTaskId::KeyGeneration => {
                            timeout(
                                TASK_TIMEOUT,
                                run_key_generation(
                                    channel,
                                    client.all_participant_ids(),
                                    client.my_participant_id(),
                                    config.participants.threshold as usize,
                                ),
                            )
                            .await??;
                        }
                        MpcTaskId::Triple(_) => {
                            timeout(
                                TASK_TIMEOUT,
                                run_triple_generation(
                                    channel,
                                    client.all_participant_ids(),
                                    client.my_participant_id(),
                                    config.participants.threshold as usize,
                                ),
                            )
                            .await??;
                        }
                    }
                    anyhow::Ok(())
                });
            }
        });
    }

    if client.my_participant_id() == client.all_participant_ids()[0] {
        run_key_generation(
            client.new_channel_for_task(MpcTaskId::KeyGeneration)?,
            client.all_participant_ids(),
            client.my_participant_id(),
            config.participants.threshold as usize,
        )
        .await?;
    }

    // TODO: This is just a PoC to just keep generating triples.
    // Generate 4 triples at once.
    let triples_generated = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for i in 0..4 {
        let client = client.clone();
        let config = config.clone();
        let triples_generated = triples_generated.clone();

        let handle = tracking::spawn(&format!("triple generation thread {}", i), async move {
            loop {
                let channel = client
                    .new_channel_for_task(MpcTaskId::Triple(generate_triple_id(
                        client.my_participant_id(),
                    )))
                    .unwrap();
                match timeout(
                    TASK_TIMEOUT,
                    run_triple_generation(
                        channel,
                        client.all_participant_ids(),
                        client.my_participant_id(),
                        config.participants.threshold as usize,
                    ),
                )
                .await
                {
                    Ok(Ok(_)) => {
                        triples_generated.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if triples_generated.load(std::sync::atomic::Ordering::SeqCst) % 10 == 0 {
                            tracing::info!(
                                "Generated {} triples",
                                triples_generated.load(std::sync::atomic::Ordering::SeqCst)
                            );
                        }
                    }
                    Err(_) => {
                        tracing::error!("Timeout generating triple");
                    }
                    Ok(Err(e)) => {
                        tracing::error!("Error generating triple: {:?}", e);
                    }
                }
            }
        });
        handles.push(handle);
    }
    futures::future::join_all(handles).await;

    Ok(())
}
